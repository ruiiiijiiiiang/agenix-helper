"""Parallel isolation, transport failures, and combining independently processed secrets."""

import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from test_edit import SecretIntegrationFixture

from scripts.agenix_helper.config import HelperConfig, Host, Mode
from scripts.agenix_helper.hosts import processed_hosts
from scripts.agenix_helper.process import run


class ParallelSchedulerTests(unittest.TestCase):
    def test_workers_overlap_obey_limit_and_start_from_independent_copies(self):
        for limit in (1, 2, 10):
            with self.subTest(limit=limit), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                work = root / "work"
                work.mkdir()
                (work / "secret.age").write_text("original")
                (root / "ephemeral-identity").write_text("must not be copied")
                hosts = [Host(str(i), ("/key",), True) for i in range(4)]
                config = HelperConfig(
                    Mode.READ,
                    Path("rules.nix"),
                    (),
                    {},
                    Path("worker.py"),
                    max_concurrency=limit,
                )
                barrier = threading.Barrier(min(limit, len(hosts)))
                lock = threading.Lock()
                active = peak = 0
                paths = set()

                def worker(
                    host_work,
                    helper,
                    host,
                    *_args,
                    lock=lock,
                    paths=paths,
                    barrier=barrier,
                    **_kwargs,
                ):
                    nonlocal active, peak
                    self.assertEqual((host_work / "secret.age").read_text(), "original")
                    self.assertFalse(any(host_work.rglob("ephemeral-identity")))
                    with lock:
                        active += 1
                        peak = max(peak, active)
                        paths.add(host_work)
                    barrier.wait(timeout=5)
                    (host_work / "secret.age").write_text(host.name)
                    with lock:
                        active -= 1

                with (
                    patch("scripts.agenix_helper.hosts.process_host", worker),
                    processed_hosts(work, hosts, config, Path("."), {}) as results,
                ):
                    seen = {}
                    for host, candidate in results:
                        seen[host.name] = (candidate / "secret.age").read_text()
                        # Later workers must still copy the original snapshot.
                        (work / "secret.age").write_text("merged")
                self.assertEqual(seen, {host.name: host.name for host in hosts})
                self.assertEqual(len(paths), len(hosts))
                self.assertEqual(peak, min(limit, len(hosts)))
                self.assertTrue(all(not path.exists() for path in paths))
                self.assertEqual(
                    {p.name for p in root.iterdir()}, {"work", "ephemeral-identity"}
                )

    def test_early_exit_cancels_running_subprocess_before_removing_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / "work"
            work.mkdir()
            pid_file = root / "child.pid"
            started = threading.Event()
            config = HelperConfig(
                Mode.READ, Path("rules.nix"), (), {}, Path("worker.py")
            )
            hosts = [Host("fast", ("/key",), True), Host("slow", ("/key",), True)]

            def worker(host_work, helper, host, *_args, **_kwargs):
                if host.name == "slow":
                    started.set()
                    run(
                        [
                            sys.executable,
                            "-c",
                            f"import os, pathlib, time; pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid())); time.sleep(30)",
                        ],
                        operation="blocked worker",
                    )
                else:
                    self.assertTrue(started.wait(timeout=5))
                    # Wait for the subprocess to be alive before returning.
                    for _ in range(500):
                        if pid_file.exists():
                            return
                        threading.Event().wait(0.01)
                    self.fail("Slow worker did not start")

            with (
                patch("scripts.agenix_helper.hosts.process_host", worker),
                processed_hosts(work, hosts, config, Path("."), {}) as results,
            ):
                next(results)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pid_file.read_text()), 0)
            self.assertFalse(list(root.glob("hosts.*")))

    def test_config_default_override_and_invalid_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.json"
            settings = {"rules": "rules.nix", "sources": ["secrets"], "hosts": {}}
            config_path.write_text(json.dumps(settings))
            config = HelperConfig.load(config_path, Path("worker.py"))
            self.assertEqual(config.max_concurrency, 10)
            for value in (1, 4):
                config_path.write_text(
                    json.dumps({**settings, "maxConcurrency": value})
                )
                self.assertEqual(
                    HelperConfig.load(config_path, Path("worker.py")).max_concurrency,
                    value,
                )
            for value in (0, -1, True, 1.5, "2", None):
                config_path.write_text(
                    json.dumps({**settings, "maxConcurrency": value})
                )
                with self.assertRaisesRegex(ValueError, "positive integer"):
                    HelperConfig.load(config_path, Path("worker.py"))


class ParallelIntegrationTests(SecretIntegrationFixture):
    def setUp(self):
        super().setUp()
        self.settings["mode"] = "read"

    def fail_ssh_at(self, phase, status=255):
        ssh = self.bin / "ssh"
        condition = {
            "send": "args[0] == 'tar' and '-xf' in args",
            "receive": "args[0] == 'tar' and '-cf' in args",
        }.get(phase, f"args[0] == {phase!r}")
        ssh.write_text(
            ssh.read_text().replace(
                "args = shlex.split(command)\n",
                "args = shlex.split(command)\n"
                f"if target == 'offline' and ({condition}): sys.exit({status})\n",
            )
        )
        self.settings["hosts"]["offline"] = {
            "target": "offline",
            "identity": str(self.keys / "host"),
        }

    def test_connection_failure_at_each_transport_phase_is_skipped(self):
        ssh = self.bin / "ssh"
        original = ssh.read_text()
        for phase in ("mktemp", "send", "receive", "nix"):
            with self.subTest(phase=phase):
                ssh.write_text(original)
                self.fail_ssh_at(phase)
                result = self.run_controller(
                    interactive=False,
                    args=["--host", "offline", "--host", "fixture", "--all-secrets"],
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("Skipping unreachable host offline", result.stderr)
                self.assertIn("original secret", result.stdout)
                self.assertIn("unrelated secret", result.stdout)
                self.assertEqual(self.snapshot(), self.before)
                self.assert_remote_cleaned()

    def assert_remote_cleaned(self):
        for line in self.remote_log.read_text().splitlines():
            if ": rm -rf -- " in line:
                self.assertFalse(Path(line.split(": rm -rf -- ", 1)[1]).exists())

    def test_all_hosts_unreachable_fails_without_plaintext(self):
        self.fail_ssh_at("mktemp")
        result = self.run_controller(
            interactive=False, args=["--host", "offline", "--all-secrets"]
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("Skipping unreachable host offline", result.stderr)
        self.assertIn("Selected hosts could not prepare", result.stderr)
        self.assertEqual(self.snapshot(), self.before)

    def test_edit_skips_unreachable_host_and_restores_original_recipients(self):
        self.settings["mode"] = "edit"
        self.fail_ssh_at("mktemp")
        result = self.run_controller(
            args=["--host", "offline", "--host", "fixture", "nested/token.age"]
        )
        self.assert_success(result, b"edited secret\n")
        self.assertIn("Skipping unreachable host offline", result.stderr)
        self.assert_remote_cleaned()

    def test_worker_errors_are_fatal_even_with_another_successful_host(self):
        self.fail_ssh_at("nix", status=7)
        result = self.run_controller(
            interactive=False,
            args=["--host", "offline", "--host", "fixture", "--all-secrets"],
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("exit status 7", result.stderr)
        self.assertNotIn("Skipping unreachable", result.stderr)
        self.assertEqual(self.snapshot(), self.before)
        self.assert_remote_cleaned()

    def split_access(self):
        subprocess.run(
            [
                "age",
                "--encrypt",
                "--recipients-file",
                str(self.keys / "wrong.pub"),
                "--output",
                str(self.other),
            ],
            input=b"other host secret\n",
            check=True,
        )
        self.before = self.snapshot()

    def test_read_merges_disjoint_access_for_serial_and_parallel_workers(self):
        self.split_access()
        for limit in (1, 2):
            with self.subTest(limit=limit):
                # This overrides the Nix configuration's default at runtime.
                self.settings["maxConcurrency"] = 3
                result = self.run_controller(
                    interactive=False,
                    args=["--max-concurrency", str(limit), "--all-secrets"],
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    result.stdout,
                    "==> nested/token.age <==\noriginal secret\n\n==> other.age <==\nother host secret\n\n",
                )
                self.assertEqual(self.snapshot(), self.before)
                self.assert_remote_cleaned()

    def test_rekey_merges_disjoint_access_and_skips_unreachable_host(self):
        self.split_access()
        self.settings["mode"] = "rekey"
        self.fail_ssh_at("mktemp")
        keys = [
            self.host_key,
            (self.keys / "wrong.pub").read_text().strip(),
            self.editor_key,
        ]
        self.keys_file.write_text(
            "[ " + " ".join(json.dumps(key) for key in keys) + " ]\n"
        )
        self.before = self.snapshot()
        result = self.run_controller(interactive=False, args=["--all-secrets"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Skipping unreachable host offline", result.stderr)
        for secret, plaintext in (
            (self.secret, b"original secret\n"),
            (self.other, b"other host secret\n"),
        ):
            decrypted = subprocess.run(
                [
                    "age",
                    "--decrypt",
                    "--identity",
                    str(self.keys / "editor"),
                    str(secret),
                ],
                capture_output=True,
                check=True,
            )
            self.assertEqual(decrypted.stdout, plaintext)
        self.assert_remote_cleaned()

    def test_invalid_cli_limits_fail_before_contacting_hosts(self):
        for value in ("0", "-1", "abc", "1.5"):
            result = self.run_controller(
                interactive=False, args=["--max-concurrency", value, "--all-secrets"]
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("positive integer", result.stderr)
            self.assertFalse(self.remote_log.exists())

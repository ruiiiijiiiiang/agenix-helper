"""Check isolated runtime packaging and subprocess cancellation."""

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from test_edit import PROJECT, SecretIntegrationFixture


class RuntimeBundleTests(SecretIntegrationFixture):
    def test_sigterm_while_editing_stops_editor_and_preserves_repository(self):
        editor_pid = self.root / "blocking-editor.pid"
        identity_record = self.root / "identity-path"
        self.editor.write_text(
            "import os, pathlib, signal\n"
            f"pathlib.Path({str(identity_record)!r}).write_text(str(pathlib.Path(os.environ['TMPDIR']).parent / 'ephemeral-identity'))\n"
            f"pathlib.Path({str(editor_pid)!r}).write_text(str(os.getpid()))\n"
            "signal.pause()\n"
        )
        scratch = self.root / "scratch"
        scratch.mkdir()
        self.env["TMPDIR"] = str(scratch)
        self.config.write_text(json.dumps(self.settings))
        import pty

        master, slave = pty.openpty()
        runner = subprocess.Popen(
            [
                sys.executable,
                str(self.controller),
                "--repo",
                str(self.repo),
                "--host",
                "fixture",
                "nested/token.age",
            ],
            stdin=slave,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=self.env,
        )
        try:
            deadline = time.monotonic() + 8
            while not editor_pid.exists():
                if runner.poll() is not None:
                    stdout, stderr = runner.communicate()
                    self.fail(stdout + stderr)
                if time.monotonic() > deadline:
                    self.fail("Editor did not start")
                time.sleep(0.01)
            identity = Path(identity_record.read_text())
            self.assertTrue(identity.is_file())
            pid = int(editor_pid.read_text())
            runner.send_signal(signal.SIGTERM)
            _, stderr = runner.communicate(timeout=10)
            self.assertEqual(runner.returncode, 130, stderr)
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
            self.assertEqual(self.snapshot(), self.before)
            self.assertEqual(list(scratch.iterdir()), [])
            self.assertFalse(identity.parent.exists())
        finally:
            os.close(slave)
            os.close(master)
            if runner.poll() is None:
                runner.kill()
                runner.communicate()

    def test_controller_and_remote_worker_use_copied_runtime(self):
        runtime = self.root / "runtime"
        shutil.copytree(PROJECT / "scripts", runtime)
        self.controller = runtime / "controller.py"
        self.env["AGENIX_HELPER_WORKER"] = str(runtime / "worker.py")
        self.env["PYTHONPATH"] = ""
        self.assert_success(self.run_controller(), b"edited secret\n")
        self.assertEqual(self.remote_log.read_text().count("mktemp -d"), 1)

    def test_read_and_edit_with_readonly_runtime_directories(self):
        runtime = self.root / "readonly-runtime"
        shutil.copytree(PROJECT / "scripts", runtime)
        # Include a nested directory to exercise recursive permission normalization.
        (runtime / "agenix_helper" / "nested").mkdir()
        (runtime / "agenix_helper" / "nested" / "data").write_text("fixture")
        directories = [runtime, *(p for p in runtime.rglob("*") if p.is_dir())]
        for path in runtime.rglob("*"):
            if path.is_file():
                path.chmod(0o444)
        for path in directories:
            path.chmod(0o555)

        def restore_fixture_permissions():
            for path in directories:
                path.chmod(0o755)

        self.addCleanup(restore_fixture_permissions)
        self.controller = runtime / "controller.py"
        self.env["AGENIX_HELPER_WORKER"] = str(runtime / "worker.py")
        self.env["PYTHONPATH"] = ""
        self.settings["mode"] = "read"
        result = self.run_controller(interactive=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "original secret\n")
        self.assertEqual(self.snapshot(), self.before)
        self.settings["mode"] = "edit"
        self.assert_success(self.run_controller(), b"edited secret\n")
        for path in directories:
            self.assertEqual(path.stat().st_mode & 0o777, 0o555)
        for line in self.remote_log.read_text().splitlines():
            if ": rm -rf -- " in line:
                self.assertFalse(Path(line.split(": rm -rf -- ", 1)[1]).exists())

    @unittest.skipUnless(shutil.which("nix"), "Missing Nix evaluator")
    def test_nix_launcher_captures_package_directory(self):
        expression = f"""
          let
            pkgs = {{
              stdenv.hostPlatform.system = "fixture";
              lib.makeBinPath = _: "/fake/bin";
              writeText = _: _: "/fake/config";
              writeTextFile = attrs: {{ inherit (attrs) text; }};
              symlinkJoin = attrs: attrs.paths;
              python3 = "/fake/python";
              gnutar = "/fake/tar";
              age = "/fake/age";
              nix = "/fake/nix";
              openssh = "/fake/ssh";
            }};
            agenix.packages.fixture.default = "/fake/agenix";
          in (import {PROJECT}/lib {{ inherit agenix; }}).mkPackage {{
            inherit pkgs;
            rules = "secrets/secrets.nix";
            sources = [ "secrets" ];
            hosts.fixture = {{ target = "fixture"; identity = "/fixture-key"; }};
          }}
        """
        result = subprocess.run(
            [
                "nix",
                "--extra-experimental-features",
                "nix-command",
                "eval",
                "--json",
                "--impure",
                "--expr",
                expression,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        launchers = json.loads(result.stdout)
        self.assertEqual(len(launchers), 3)
        for launcher in launchers:
            controller = re.search(r'"([^"\n]+/controller\.py)"', launcher["text"])
            worker = re.search(r'"([^"\n]+/worker\.py)"', launcher["text"])
            self.assertIsNotNone(controller)
            self.assertIsNotNone(worker)
            scripts_root = Path(controller.group(1)).parent
            self.assertEqual(Path(worker.group(1)).parent, scripts_root)
            self.assertTrue((scripts_root / "agenix_helper/cli.py").is_file())
            self.assertTrue((scripts_root / "agenix_helper/crypto.py").is_file())
            self.assertTrue((scripts_root / "agenix_helper/process.py").is_file())


class ProcessCleanupTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(
            prefix="agenix-helper-process-test."
        )
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.env = {
            **os.environ,
            "PYTHONPATH": str(PROJECT / "scripts"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }

    def run_runner(self, source):
        runner = self.root / "runner.py"
        runner.write_text(source)
        return subprocess.Popen(
            [sys.executable, str(runner)],
            env=self.env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def sleeper(self, name, *, consume=False):
        path = self.root / f"{name}.py"
        pid = self.root / f"{name}.pid"
        path.write_text(
            "import os, pathlib, signal, sys\n"
            f"pathlib.Path({str(pid)!r}).write_text(str(os.getpid()))\n"
            + ("sys.stdin.buffer.read()\n" if consume else "signal.pause()\n")
        )
        return path, pid

    def wait_for_children(self, runner, paths):
        deadline = time.monotonic() + 5
        while not all(path.exists() for path in paths):
            if runner.poll() is not None:
                stdout, stderr = runner.communicate()
                self.fail(stdout + stderr)
            if time.monotonic() > deadline:
                self.fail("Child processes did not start")
            time.sleep(0.01)
        return [int(path.read_text()) for path in paths]

    def assert_children_stopped(self, pids):
        for pid in pids:
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_sigterm_reaps_child_and_cleans_temporary_directory(self):
        sleeper, pid_path = self.sleeper("child")
        runner = self.run_runner(
            "import pathlib, sys, tempfile\n"
            "from agenix_helper.process import entrypoint, run\n"
            "def main():\n"
            f"    with tempfile.TemporaryDirectory(dir={str(self.root)!r}, prefix='scratch.') as scratch:\n"
            "        pathlib.Path(scratch, 'staged').write_text('temporary')\n"
            f"        run([sys.executable, {str(sleeper)!r}], operation='Wait for child')\n"
            "    return 0\n"
            "sys.exit(entrypoint(main))\n"
        )
        try:
            pids = self.wait_for_children(runner, [pid_path])
            runner.send_signal(signal.SIGTERM)
            _, stderr = runner.communicate(timeout=8)
            self.assertEqual(runner.returncode, 130, stderr)
            self.assert_children_stopped(pids)
            self.assertEqual(list(self.root.glob("scratch.*")), [])
        finally:
            if runner.poll() is None:
                runner.kill()
                runner.communicate()

    def test_sigterm_reaps_both_pipeline_processes(self):
        producer, producer_pid = self.sleeper("producer")
        consumer, consumer_pid = self.sleeper("consumer", consume=True)
        runner = self.run_runner(
            "import sys\n"
            "from agenix_helper.process import entrypoint, pipe\n"
            "def main():\n"
            f"    pipe([sys.executable, {str(producer)!r}], [sys.executable, {str(consumer)!r}], operation='Test pipe')\n"
            "    return 0\n"
            "sys.exit(entrypoint(main))\n"
        )
        try:
            pids = self.wait_for_children(runner, [producer_pid, consumer_pid])
            runner.send_signal(signal.SIGTERM)
            _, stderr = runner.communicate(timeout=8)
            self.assertEqual(runner.returncode, 130, stderr)
            self.assert_children_stopped(pids)
        finally:
            if runner.poll() is None:
                runner.kill()
                runner.communicate()

    def test_pipeline_reports_failed_producer(self):
        runner = self.run_runner(
            "import sys\n"
            "from agenix_helper.process import entrypoint, pipe\n"
            "def main():\n"
            "    pipe([sys.executable, '-c', 'import sys; sys.exit(7)'],\n"
            "         [sys.executable, '-c', 'import sys; sys.stdin.buffer.read()'], operation='Test pipe')\n"
            "    return 0\n"
            "sys.exit(entrypoint(main))\n"
        )
        _, stderr = runner.communicate(timeout=8)
        self.assertEqual(runner.returncode, 1)
        self.assertIn("producer status 7", stderr)


if __name__ == "__main__":
    unittest.main()

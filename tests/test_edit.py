"""Synthetic integration tests: real age/agenix/Nix, simulated SSH, no real hosts."""

import json
import os
import pty
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
TOOLS = ("age-keygen", "age", "agenix", "nix-instantiate", "ssh-keygen", "tar")


@unittest.skipUnless(
    all(shutil.which(tool) for tool in TOOLS), "Missing integration tools"
)
class SecretIntegrationFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys_directory = tempfile.TemporaryDirectory(
            prefix="agenix-helper-test-keys."
        )
        cls.keys = Path(cls.keys_directory.name)
        for name in ("host", "editor", "wrong"):
            subprocess.run(
                [
                    "ssh-keygen",
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-f",
                    str(cls.keys / name),
                ],
                check=True,
            )
        cls.host_key = (cls.keys / "host.pub").read_text().strip()
        cls.editor_key = (cls.keys / "editor.pub").read_text().strip()

    @classmethod
    def tearDownClass(cls):
        cls.keys_directory.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="agenix-helper-test.")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.repo = self.root / "repo"
        self.secret = self.repo / "secrets/nested/token.age"
        self.secret.parent.mkdir(parents=True)
        self.rules = self.repo / "secrets/secrets.nix"
        self.keys_file = self.repo / "keys.nix"
        self.keys_file.write_text(f"[ {json.dumps(self.host_key)} ]\n")
        self.rules.write_text(
            "let keys = import ../keys.nix; in {\n"
            '  "nested/token.age" = { publicKeys = keys; armor = false; };\n'
            '  "other.age" = { publicKeys = keys; };\n'
            "}\n"
        )
        self.encrypt(self.secret, b"original secret\n")
        self.other = self.repo / "secrets/other.age"
        self.encrypt(self.other, b"unrelated secret\n")
        self.before = self.snapshot()
        self.config = self.root / "config.json"
        self.controller = PROJECT / "scripts/controller.py"
        self.settings = {
            "mode": "edit",
            "rules": "secrets/secrets.nix",
            "sources": ["secrets", "keys.nix"],
            "hosts": {
                "fixture": {"target": "fixture", "identity": str(self.keys / "host")},
                "unreadable": {
                    "target": "unreadable",
                    "identity": str(self.keys / "wrong"),
                },
            },
        }
        self.editor = self.root / "editor.py"
        self.editor.write_text(
            "import os, pathlib, sys\n"
            "path = pathlib.Path(sys.argv[1])\n"
            "assert path.read_bytes() == b'original secret\\n'\n"
            "mode = os.environ.get('TEST_EDITOR_MODE', 'change')\n"
            "if mode != 'noop': path.write_bytes(b'edited secret\\n')\n"
            "if mode == 'conflict': pathlib.Path(os.environ['TEST_RULES']).write_text('external change\\n')\n"
            "if mode == 'fail': sys.exit(7)\n"
        )
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.remote_log = self.root / "remote.log"
        ssh = self.bin / "ssh"
        ssh.write_text(
            f"#!{sys.executable}\n"
            "import os, shlex, shutil, subprocess, sys\n"
            "target, command = sys.argv[1:]\n"
            "with open(os.environ['TEST_REMOTE_LOG'], 'a') as log: log.write(target + ': ' + command + '\\n')\n"
            "args = shlex.split(command)\n"
            "if args[0] == 'mktemp': sys.exit(subprocess.call(args))\n"
            "elif args[0] == 'nix': sys.exit(subprocess.call([sys.executable, args[-1]]))\n"
            "elif args[:3] == ['rm', '-rf', '--']: shutil.rmtree(args[-1])\n"
            "elif args[0] == 'tar': sys.exit(subprocess.call(args))\n"
            "else: sys.exit('Unexpected fake SSH command: ' + command)\n"
        )
        ssh.chmod(0o700)
        self.env = {
            **os.environ,
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "AGENIX_HELPER_CONFIG": str(self.config),
            "AGENIX_HELPER_WORKER": str(PROJECT / "scripts/worker.py"),
            "EDITOR": f"{sys.executable} {self.editor}",
            "TEST_REMOTE_LOG": str(self.remote_log),
            "TEST_RULES": str(self.rules),
        }

    def encrypt(self, path, plaintext, armor=False):
        command = [
            "age",
            "--encrypt",
            "--recipient",
            self.host_key,
            "--output",
            str(path),
        ]
        if armor:
            command.insert(1, "--armor")
        subprocess.run(command, input=plaintext, check=True)

    def snapshot(self):
        return {
            str(p.relative_to(self.repo)): p.read_bytes()
            for p in self.repo.rglob("*")
            if p.is_file()
        }

    def run_controller(
        self, *, mode="change", interactive=True, args=None, binary=False
    ):
        self.config.write_text(json.dumps(self.settings))
        command = [sys.executable, str(self.controller), "--repo", str(self.repo)]
        command += args or ["--host", "fixture", "nested/token.age"]
        self.env["TEST_EDITOR_MODE"] = mode
        master, slave = pty.openpty()
        try:
            result = subprocess.run(
                command,
                stdin=slave if interactive else subprocess.DEVNULL,
                capture_output=True,
                text=not binary,
                env=self.env,
                timeout=30,
            )
        finally:
            os.close(slave)
            os.close(master)
        return result

    def assert_success(self, result, plaintext):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        decrypted = subprocess.run(
            ["age", "-d", "-i", str(self.keys / "host"), str(self.secret)],
            capture_output=True,
            check=True,
        )
        self.assertEqual(decrypted.stdout, plaintext)
        temporary_access = subprocess.run(
            ["age", "-d", "-i", str(self.keys / "editor"), str(self.secret)],
            capture_output=True,
        )
        self.assertNotEqual(temporary_access.returncode, 0)
        for path, contents in self.before.items():
            if path != "secrets/nested/token.age":
                self.assertEqual((self.repo / path).read_bytes(), contents)
        self.assertEqual(set(self.snapshot()), set(self.before))
        checked = subprocess.run(
            ["agenix", "--check"],
            env={**self.env, "AGENIX_RULES": str(self.rules)},
            capture_output=True,
            text=True,
        )
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)


class EditIntegrationTests(SecretIntegrationFixture):
    def test_edit_and_restore_original_recipients(self):
        self.assert_success(self.run_controller(), b"edited secret\n")
        log = self.remote_log.read_text()
        self.assertEqual(log.count("mktemp -d"), 1)
        self.assertNotIn(str(self.keys / "editor"), log)

    def test_unchanged_editor_still_removes_temporary_recipient(self):
        self.assert_success(self.run_controller(mode="noop"), b"original secret\n")

    def test_armored_secret(self):
        self.rules.write_text(
            self.rules.read_text().replace("armor = false", "armor = true")
        )
        self.encrypt(self.secret, b"original secret\n", armor=True)
        self.before = self.snapshot()
        self.assert_success(self.run_controller(), b"edited secret\n")
        self.assertTrue(
            self.secret.read_bytes().startswith(b"-----BEGIN AGE ENCRYPTED FILE-----")
        )

    def test_editor_failure_preserves_repository(self):
        result = self.run_controller(mode="fail")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Editor failed", result.stderr)
        self.assertEqual(self.snapshot(), self.before)

    def test_concurrent_source_change_is_not_overwritten(self):
        result = self.run_controller(mode="conflict")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Source changed while editing", result.stderr)
        self.assertEqual(
            self.secret.read_bytes(), self.before["secrets/nested/token.age"]
        )
        self.assertEqual(self.rules.read_text(), "external change\n")

    def test_unreadable_host_preserves_repository(self):
        self.settings["hosts"]["fixture"]["identity"] = str(self.keys / "wrong")
        result = self.run_controller()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.snapshot(), self.before)

    def test_tries_next_host(self):
        self.assert_success(
            self.run_controller(
                args=[
                    "--host",
                    "unreadable",
                    "--host",
                    "fixture",
                    "nested/token.age",
                ]
            ),
            b"edited secret\n",
        )
        self.assertEqual(self.remote_log.read_text().count("mktemp -d"), 2)

    def test_noninteractive_input_is_rejected(self):
        result = self.run_controller(interactive=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("interactive stdin", result.stderr)
        self.assertFalse(self.remote_log.exists())
        self.assertEqual(self.snapshot(), self.before)

    def test_dry_run_does_not_contact_hosts(self):
        result = self.run_controller(
            interactive=False,
            args=[
                "--host",
                "fixture",
                "--dry-run",
                "nested/token.age",
            ],
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.remote_log.exists())
        self.assertEqual(self.snapshot(), self.before)

    def test_symlink_is_rejected(self):
        self.secret.unlink()
        self.secret.symlink_to(self.other)
        result = self.run_controller()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Symlinks", result.stderr)
        self.assertFalse(self.remote_log.exists())
        self.assertTrue(self.secret.is_symlink())

    def test_unknown_secret_is_rejected(self):
        result = self.run_controller(
            args=[
                "--host",
                "fixture",
                "missing.age",
            ]
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unknown secret", result.stderr)
        self.assertFalse(self.remote_log.exists())
        self.assertEqual(self.snapshot(), self.before)

    def test_original_editor_recipient_is_preserved(self):
        self.keys_file.write_text(
            f"[ {json.dumps(self.host_key)} {json.dumps(self.editor_key)} ]\n"
        )
        result = self.run_controller(mode="noop")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        decrypted = subprocess.run(
            ["age", "-d", "-i", str(self.keys / "editor"), str(self.secret)],
            capture_output=True,
            check=True,
        )
        self.assertEqual(decrypted.stdout, b"original secret\n")
        self.assertEqual(
            self.keys_file.read_text(),
            f"[ {json.dumps(self.host_key)} {json.dumps(self.editor_key)} ]\n",
        )

    def test_existing_rekey_mode_still_works(self):
        self.settings.pop("mode")
        self.keys_file.write_text(
            f"[ {json.dumps(self.host_key)} {json.dumps(self.editor_key)} ]\n"
        )
        result = self.run_controller(
            interactive=False, args=["--host", "fixture", "--all-secrets"]
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for secret in (self.secret, self.other):
            subprocess.run(
                [
                    "age",
                    "-d",
                    "-i",
                    str(self.keys / "editor"),
                    "-o",
                    os.devnull,
                    str(secret),
                ],
                check=True,
            )


@unittest.skipUnless(shutil.which("nix-instantiate"), "Missing Nix evaluator")
class NixAppTests(unittest.TestCase):
    def evaluate(self, expression):
        return subprocess.run(
            ["nix-instantiate", "--eval", "--strict", "--json", "--expr", expression],
            capture_output=True,
            text=True,
        )

    def test_exported_apps_without_building_derivations(self):
        expression = f"""
          let
            pkgs = {{
              stdenv.hostPlatform.system = "fixture";
              lib.makeBinPath = packages: builtins.concatStringsSep ":" packages;
              writeText = name: text: builtins.seq (builtins.fromJSON text) "/fake/${{name}}";
              writeTextFile = attrs: assert builtins.isString attrs.text; "/fake/${{attrs.name}}";
              python3 = "/fake/python";
              gnutar = "/fake/tar";
              age = "/fake/age";
              nix = "/fake/nix";
              openssh = "/fake/ssh";
            }};
            agenix.packages.fixture.default = "/fake/agenix";
            helpers = ((import {PROJECT}/flake.nix).outputs {{ inherit agenix; nixpkgs = {{}}; }}).lib;
            args = {{
              inherit pkgs;
              rules = "secrets/secrets.nix";
              sources = [ "secrets" ];
              hosts.fixture = {{ target = "fixture"; identity = "/fake/key"; }};
            }};
          in {{
            rekey = helpers.mkRekeyApp args;
            edit = helpers.mkEditApp args;
            read = helpers.mkReadApp args;
            combined = helpers.mkApps args;
          }}
        """
        result = self.evaluate(expression)
        self.assertEqual(result.returncode, 0, result.stderr)
        apps = json.loads(result.stdout)
        self.assertEqual(apps["edit"]["type"], "app")
        self.assertEqual(apps["rekey"]["type"], "app")
        self.assertEqual(apps["read"]["type"], "app")
        self.assertEqual(
            apps["edit"]["program"], "/fake/agenix-helper-edit/bin/agenix-helper-edit"
        )
        self.assertEqual(
            apps["rekey"]["program"],
            "/fake/agenix-helper-rekey/bin/agenix-helper-rekey",
        )
        self.assertEqual(
            apps["read"]["program"], "/fake/agenix-helper-read/bin/agenix-helper-read"
        )
        self.assertEqual(
            apps["combined"],
            {
                "agenix-rekey": apps["rekey"],
                "agenix-edit": apps["edit"],
                "agenix-read": apps["read"],
            },
        )


if __name__ == "__main__":
    unittest.main()

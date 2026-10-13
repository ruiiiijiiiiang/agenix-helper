"""Read integration tests using disposable secrets and simulated SSH."""

import json
import subprocess
import unittest
from pathlib import Path

from test_edit import SecretIntegrationFixture


class ReadIntegrationTests(SecretIntegrationFixture):
    def setUp(self):
        super().setUp()
        self.settings["mode"] = "read"
        self.env.pop("EDITOR", None)
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()
        self.env["TMPDIR"] = str(self.scratch)

    def read(self, **kwargs):
        return self.run_controller(interactive=False, **kwargs)

    def assert_read_success(self, result, plaintext="original secret\n"):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, plaintext)
        self.assertEqual(self.snapshot(), self.before)
        self.assert_remote_cleanup()

    def assert_remote_cleanup(self):
        self.assertEqual(list(self.scratch.iterdir()), [])
        if self.remote_log.exists():
            for line in self.remote_log.read_text().splitlines():
                if ": rm -rf -- " in line:
                    remote = line.split(": rm -rf -- ", 1)[1]
                    self.assertFalse(Path(remote).exists())

    def test_reads_without_editor_or_interactive_stdin(self):
        self.assert_read_success(self.read())
        log = self.remote_log.read_text()
        self.assertEqual(log.count("mktemp -d"), 1)
        self.assertNotIn(str(self.keys / "editor"), log)

    def test_progress_goes_to_stderr(self):
        result = self.read()
        self.assert_read_success(result)
        self.assertIn("Rules:", result.stderr)
        self.assertIn("Processing fixture", result.stderr)
        self.assertIn("Rekeyed: 1", result.stderr)

    def test_binary_plaintext_is_preserved(self):
        plaintext = b"\x00\xff\r\nexact bytes without trailing newline\x80"
        self.encrypt(self.secret, plaintext)
        self.before = self.snapshot()
        self.assert_read_success(self.read(binary=True), plaintext)

    def test_empty_plaintext(self):
        self.encrypt(self.secret, b"")
        self.before = self.snapshot()
        self.assert_read_success(self.read(), "")

    def test_armored_secret(self):
        self.rules.write_text(self.rules.read_text().replace("armor = false", "armor = true"))
        self.encrypt(self.secret, b"original secret\n", armor=True)
        self.before = self.snapshot()
        self.assert_read_success(self.read())

    def test_failed_host_checks_print_only_to_stderr(self):
        self.settings["hosts"]["fixture"]["identity"] = str(self.keys / "wrong")
        result = self.read()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("missing:", result.stderr)
        self.assertIn("Selected hosts could not prepare", result.stderr)
        self.assertEqual(self.snapshot(), self.before)
        self.assert_remote_cleanup()

    def test_wrong_local_identity_fails_before_ssh(self):
        result = self.read(identity=self.keys / "wrong")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertFalse(self.remote_log.exists())
        self.assertEqual(self.snapshot(), self.before)

    def test_invalid_public_key_fails_before_ssh(self):
        self.settings["publicKey"] = "invalid recipient"
        result = self.read()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("publicKey must be", result.stderr)
        self.assertFalse(self.remote_log.exists())
        self.assertEqual(self.snapshot(), self.before)

    def test_unknown_secret_is_rejected(self):
        result = self.read(args=[
            "--host", "fixture", "missing.age", "--identity", str(self.keys / "editor"),
        ])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("Unknown secret", result.stderr)
        self.assertFalse(self.remote_log.exists())
        self.assertEqual(self.snapshot(), self.before)

    def test_dry_run_has_empty_stdout_and_no_ssh(self):
        result = self.read(args=[
            "--host", "fixture", "--dry-run", "nested/token.age", "--identity", str(self.keys / "editor"),
        ])
        self.assert_read_success(result, "")
        self.assertIn("Rules:", result.stderr)
        self.assertFalse(self.remote_log.exists())

    def test_all_tries_hosts_until_readable(self):
        self.settings["hosts"] = {
            "a-unreadable": self.settings["hosts"]["unreadable"],
            "z-fixture": self.settings["hosts"]["fixture"],
        }
        self.assert_read_success(self.read(args=[
            "--all", "nested/token.age", "--identity", str(self.keys / "editor"),
        ]))
        self.assertEqual(self.remote_log.read_text().count("mktemp -d"), 2)

    def test_already_prepared_secret_needs_no_ssh(self):
        self.keys_file.write_text(f"[ {json.dumps(self.host_key)} {json.dumps(self.editor_key)} ]\n")
        subprocess.run(
            ["age", "--encrypt", "--recipient", self.host_key, "--recipient", self.editor_key,
             "--output", str(self.secret)], input=b"original secret\n", check=True,
        )
        self.before = self.snapshot()
        self.assert_read_success(self.read())
        self.assertFalse(self.remote_log.exists())


if __name__ == "__main__":
    unittest.main()

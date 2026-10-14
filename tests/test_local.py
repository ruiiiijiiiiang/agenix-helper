"""Local worker integration tests with disposable keys and ciphertext."""

import json
import shutil
import subprocess
import unittest

from test_edit import SecretIntegrationFixture


class LocalIntegrationTests(SecretIntegrationFixture):
    def setUp(self):
        super().setUp()
        self.settings["mode"] = "rekey"
        self.settings["hosts"] = {
            "localhost": {"local": True, "identity": str(self.keys / "host")},
        }
        self.keys_file.write_text(
            f"[ {json.dumps(self.host_key)} {json.dumps(self.editor_key)} ]\n"
        )
        self.before = self.snapshot()

    def rekey(self, args=None):
        return self.run_controller(
            interactive=False, args=args or ["--host", "localhost", "--all-secrets"]
        )

    def assert_rekey_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        checked = subprocess.run(
            ["agenix", "--check"],
            env={**self.env, "AGENIX_RULES": str(self.rules)},
            capture_output=True,
            text=True,
        )
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        for secret, plaintext in (
            (self.secret, b"original secret\n"),
            (self.other, b"unrelated secret\n"),
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
        self.assertEqual(set(self.snapshot()), set(self.before))
        self.assertEqual(self.rules.read_bytes(), self.before["secrets/secrets.nix"])
        self.assertEqual(self.keys_file.read_bytes(), self.before["keys.nix"])

    def test_rekeys_locally_without_ssh(self):
        result = self.rekey()
        self.assert_rekey_success(result)
        self.assertIn("Processing localhost (local)", result.stdout)
        self.assertFalse(self.remote_log.exists())

    def test_all_can_select_only_local_hosts(self):
        self.assert_rekey_success(self.rekey(["--all", "--all-secrets"]))
        self.assertFalse(self.remote_log.exists())

    def test_identity_relative_to_local_home(self):
        self.env["HOME"] = str(self.keys)
        self.settings["hosts"]["localhost"]["identity"] = "host"
        self.assert_rekey_success(self.rekey())
        self.assertFalse(self.remote_log.exists())

    def test_identity_with_tilde(self):
        self.env["HOME"] = str(self.keys)
        self.settings["hosts"]["localhost"]["identity"] = "~/host"
        self.assert_rekey_success(self.rekey())
        self.assertFalse(self.remote_log.exists())

    def test_wrong_identity_preserves_repository(self):
        self.settings["hosts"]["localhost"]["identity"] = str(self.keys / "wrong")
        result = self.rekey()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.snapshot(), self.before)
        self.assertFalse(self.remote_log.exists())

    def test_missing_identity_fails_before_processing(self):
        self.settings["hosts"]["localhost"]["identity"] = str(self.root / "missing-key")
        result = self.rekey()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Processing", result.stdout)
        self.assertEqual(self.snapshot(), self.before)
        self.assertFalse(self.remote_log.exists())

    def test_dry_run_changes_nothing(self):
        result = self.rekey(["--host", "localhost", "--all-secrets", "--dry-run"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Processing", result.stdout)
        self.assertEqual(self.snapshot(), self.before)
        self.assertFalse(self.remote_log.exists())

    def test_already_matching_recipients_changes_nothing(self):
        self.keys_file.write_text(f"[ {json.dumps(self.host_key)} ]\n")
        before = self.snapshot()
        result = self.rekey()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("already match", result.stdout)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.remote_log.exists())

    def test_local_and_remote_hosts_combine_partial_results(self):
        wrong_public_key = (self.keys / "wrong.pub").read_text().strip()
        subprocess.run(
            [
                "age",
                "--encrypt",
                "--recipient",
                wrong_public_key,
                "--output",
                str(self.other),
            ],
            input=b"unrelated secret\n",
            check=True,
        )
        self.before = self.snapshot()
        self.settings["hosts"]["remote"] = {
            "target": "fixture",
            "identity": str(self.keys / "wrong"),
        }
        result = self.rekey(
            ["--host", "localhost", "--host", "remote", "--all-secrets"]
        )
        self.assert_rekey_success(result)
        self.assertIn("Processed: 1; unreadable: 1", result.stdout)
        self.assertEqual(self.remote_log.read_text().count("mktemp -d"), 1)

    def test_local_flag_requires_boolean(self):
        self.settings["hosts"]["localhost"]["local"] = "true"
        result = self.rekey()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be a boolean", result.stderr)
        self.assertEqual(self.snapshot(), self.before)

    def test_local_host_cannot_also_have_ssh_target(self):
        self.settings["hosts"]["localhost"]["target"] = "localhost"
        result = self.rekey()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must omit its SSH target", result.stderr)
        self.assertEqual(self.snapshot(), self.before)

    def test_private_key_in_sources_is_rejected(self):
        identity = self.repo / "secrets/private-key"
        shutil.copy2(self.keys / "host", identity)
        self.settings["hosts"]["localhost"]["identity"] = str(identity)
        before = self.snapshot()
        result = self.rekey()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside sources", result.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.remote_log.exists())

    def test_symlink_in_sources_is_rejected(self):
        self.secret.unlink()
        self.secret.symlink_to(self.other)
        result = self.rekey()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Symlinks", result.stderr)
        self.assertTrue(self.secret.is_symlink())
        self.assertFalse(self.remote_log.exists())

    def test_edit_can_use_a_local_host(self):
        self.settings["mode"] = "edit"
        self.keys_file.write_text(f"[ {json.dumps(self.host_key)} ]\n")
        self.before = self.snapshot()
        result = self.run_controller(
            args=[
                "--host",
                "localhost",
                "nested/token.age",
            ]
        )
        self.assert_success(result, b"edited secret\n")
        self.assertFalse(self.remote_log.exists())

    def test_read_can_use_a_local_host_with_clean_stdout(self):
        self.settings["mode"] = "read"
        result = self.run_controller(
            interactive=False,
            args=[
                "--host",
                "localhost",
                "nested/token.age",
            ],
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "original secret\n")
        self.assertIn("Processing localhost (local)", result.stderr)
        self.assertEqual(self.snapshot(), self.before)
        self.assertFalse(self.remote_log.exists())


if __name__ == "__main__":
    unittest.main()

"""Rekey selection tests with disposable secrets and simulated SSH."""

import json
import subprocess
import unittest

from test_edit import SecretIntegrationFixture


class RekeySelectionTests(SecretIntegrationFixture):
    def setUp(self):
        super().setUp()
        self.settings["mode"] = "rekey"
        self.settings["hosts"]["localhost"] = {
            "local": True,
            "identity": str(self.keys / "host"),
        }
        self.keys_file.write_text(
            f"[ {json.dumps(self.host_key)} {json.dumps(self.editor_key)} ]\n"
        )
        self.before = self.snapshot()

    def rekey(self, *args):
        return self.run_controller(interactive=False, args=list(args))

    def assert_selected_success(self, result, selected):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(set(self.snapshot()), set(self.before))
        changed = {f"secrets/{secret}" for secret in selected}
        for path, before in self.before.items():
            after = (self.repo / path).read_bytes()
            if path in changed:
                self.assertNotEqual(after, before)
            else:
                self.assertEqual(after, before)
        for secret in selected:
            decrypted = subprocess.run(
                [
                    "age",
                    "--decrypt",
                    "--identity",
                    str(self.keys / "editor"),
                    str(self.repo / "secrets" / secret),
                ],
                capture_output=True,
                check=True,
            )
            expected = (
                b"original secret\n"
                if secret == "nested/token.age"
                else b"unrelated secret\n"
            )
            self.assertEqual(decrypted.stdout, expected)

    def test_select_one_local_secret(self):
        result = self.rekey("--host", "localhost", "nested/token.age")
        self.assert_selected_success(result, ["nested/token.age"])
        self.assertIn("secrets: 1", result.stdout)
        self.assertIn("Processed: 1", result.stdout)
        self.assertFalse(self.remote_log.exists())

    def test_select_multiple_secrets(self):
        self.assert_selected_success(
            self.rekey("--host", "localhost", "nested/token.age", "other.age"),
            ["nested/token.age", "other.age"],
        )

    def test_explicit_all_secrets(self):
        self.assert_selected_success(
            self.rekey("--host", "localhost", "--all-secrets"),
            ["nested/token.age", "other.age"],
        )

    def test_all_secrets_flag_selects_all_secrets(self):
        self.assert_selected_success(
            self.rekey("--host", "localhost", "--all-secrets"),
            ["nested/token.age", "other.age"],
        )

    def test_omitting_paths_without_flag_errors(self):
        result = self.rekey("--host", "localhost")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--all-secrets", result.stderr)
        self.assertEqual(self.snapshot(), self.before)

    def test_all_hosts_and_one_secret_are_independent(self):
        self.assert_selected_success(
            self.rekey("--all", "nested/token.age"), ["nested/token.age"]
        )

    def test_unknown_secret_changes_nothing(self):
        result = self.rekey("--host", "fixture", "nested/token.age", "missing.age")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unknown secret: missing.age", result.stderr)
        self.assertEqual(self.snapshot(), self.before)
        self.assertFalse(self.remote_log.exists())

    def test_paths_and_all_secrets_cannot_be_combined(self):
        result = self.rekey("--host", "localhost", "--all-secrets", "nested/token.age")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot be combined", result.stderr)
        self.assertEqual(self.snapshot(), self.before)

    def test_duplicate_paths_are_processed_once(self):
        result = self.rekey(
            "--host", "localhost", "nested/token.age", "nested/token.age"
        )
        self.assert_selected_success(result, ["nested/token.age"])
        self.assertIn("secrets: 1", result.stdout)
        self.assertIn("Processed: 1", result.stdout)

    def test_missing_unselected_ciphertext_does_not_block_rekey(self):
        self.other.unlink()
        self.before = self.snapshot()
        self.assert_selected_success(
            self.rekey("--host", "localhost", "nested/token.age"),
            ["nested/token.age"],
        )

    def test_unreadable_unselected_ciphertext_is_not_decrypted(self):
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
        result = self.rekey("--host", "localhost", "nested/token.age")
        self.assert_selected_success(result, ["nested/token.age"])
        self.assertIn("Processed: 1; unreadable: 0", result.stdout)

    def test_selected_failure_preserves_every_file(self):
        self.settings["hosts"]["localhost"]["identity"] = str(self.keys / "wrong")
        result = self.rekey("--host", "localhost", "nested/token.age")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.snapshot(), self.before)

    def test_targeted_noop_ignores_unselected_mismatch(self):
        self.rules.write_text(
            self.rules.read_text().replace(
                '"nested/token.age" = { publicKeys = keys;',
                f'"nested/token.age" = {{ publicKeys = [ {json.dumps(self.host_key)} ];',
            )
        )
        before = self.snapshot()
        result = self.rekey("--host", "fixture", "nested/token.age")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("already match", result.stdout)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.remote_log.exists())

    def test_remote_targeted_rekey(self):
        result = self.rekey("--host", "fixture", "nested/token.age")
        self.assert_selected_success(result, ["nested/token.age"])
        self.assertIn("Processed: 1", result.stdout)
        self.assertEqual(self.remote_log.read_text().count("mktemp -d"), 1)

    def test_targeted_dry_run_reports_selection_without_ssh(self):
        result = self.rekey("--host", "fixture", "--dry-run", "nested/token.age")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("secrets: 1", result.stdout)
        self.assertIn("Selected secrets: nested/token.age", result.stdout)
        self.assertEqual(self.snapshot(), self.before)
        self.assertFalse(self.remote_log.exists())


if __name__ == "__main__":
    unittest.main()

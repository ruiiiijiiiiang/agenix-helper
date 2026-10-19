"""Identity-list integration and evaluated NixOS default tests."""

import json
import shutil
import subprocess
import unittest
from pathlib import Path

from test_edit import SecretIntegrationFixture

PROJECT = Path(__file__).resolve().parents[1]


class IdentityIntegrationTests(SecretIntegrationFixture):
    def setUp(self):
        super().setUp()
        self.settings["mode"] = "rekey"
        paths = [str(self.keys / "host"), str(self.keys / "wrong")]
        self.settings["hosts"] = {
            "fixture": {"target": "fixture", "identityPaths": paths},
            "localhost": {"local": True, "identityPaths": paths},
        }
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
        self.keys_file.write_text(
            f"[ {json.dumps(self.host_key)} {json.dumps(self.editor_key)} ]\n"
        )
        self.before = self.snapshot()

    def rekey(self, host="localhost", *args):
        extra = list(args) if args else ["--all-secrets"]
        return self.run_controller(interactive=False, args=["--host", host, *extra])

    def assert_rekey_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for path, plaintext in (
            (self.secret, b"original secret\n"),
            (self.other, b"unrelated secret\n"),
        ):
            result = subprocess.run(
                [
                    "age",
                    "--decrypt",
                    "--identity",
                    str(self.keys / "editor"),
                    str(path),
                ],
                capture_output=True,
                check=True,
            )
            self.assertEqual(result.stdout, plaintext)
        self.assertEqual(self.rules.read_bytes(), self.before["secrets/secrets.nix"])
        self.assertEqual(self.keys_file.read_bytes(), self.before["keys.nix"])

    def test_multiple_local_keys_decrypt_different_secrets(self):
        self.assert_rekey_success(self.rekey())
        self.assertFalse(self.remote_log.exists())

    def test_multiple_remote_keys_decrypt_different_secrets(self):
        self.assert_rekey_success(self.rekey("fixture"))
        self.assertEqual(self.remote_log.read_text().count("mktemp -d"), 1)

    def test_missing_local_paths_are_skipped_when_another_key_is_readable(self):
        self.settings["hosts"]["localhost"]["identityPaths"].insert(
            0, str(self.root / "missing-key")
        )
        result = self.rekey()
        self.assert_rekey_success(result)
        self.assertIn("Skipping unreadable identity", result.stderr)

    def test_missing_remote_paths_are_skipped_when_another_key_is_readable(self):
        self.settings["hosts"]["fixture"]["identityPaths"].insert(
            0, str(self.root / "missing-key")
        )
        result = self.rekey("fixture")
        self.assert_rekey_success(result)
        self.assertIn("Skipping unreadable identity", result.stderr)

    def test_no_readable_local_paths_fails_before_processing(self):
        self.settings["hosts"]["localhost"]["identityPaths"] = [
            str(self.root / "missing-key")
        ]
        result = self.rekey()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No readable identity files", result.stderr)
        self.assertNotIn("Processing", result.stdout)
        self.assertEqual(self.snapshot(), self.before)

    def test_no_readable_remote_paths_preserves_repository(self):
        self.settings["hosts"]["fixture"]["identityPaths"] = [
            str(self.root / "missing-key")
        ]
        result = self.rekey("fixture")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No readable identity files", result.stderr)
        self.assertEqual(self.snapshot(), self.before)

    def test_identity_paths_override_legacy_identity(self):
        self.settings["hosts"]["localhost"]["identityPaths"] = [
            str(self.keys / "wrong")
        ]
        self.settings["hosts"]["localhost"]["identity"] = str(self.keys / "host")
        result = self.rekey("localhost", "nested/token.age")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.snapshot(), self.before)

    def test_empty_list_is_rejected(self):
        self.settings["hosts"]["localhost"]["identityPaths"] = []
        result = self.rekey()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("nonempty identityPaths", result.stderr)
        self.assertEqual(self.snapshot(), self.before)

    def test_private_key_in_identity_list_cannot_be_in_sources(self):
        private_key = self.repo / "secrets/private-key"
        shutil.copy2(self.keys / "host", private_key)
        self.settings["hosts"]["localhost"]["identityPaths"].append(str(private_key))
        before = self.snapshot()
        result = self.rekey()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside sources", result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_read_uses_multiple_host_keys_without_changing_stdout(self):
        self.settings["mode"] = "read"
        self.env.pop("EDITOR", None)
        result = self.run_controller(
            interactive=False,
            args=[
                "--host",
                "fixture",
                "other.age",
            ],
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "unrelated secret\n")
        self.assertEqual(self.snapshot(), self.before)


@unittest.skipUnless(shutil.which("nix-instantiate"), "Missing Nix evaluator")
class NixIdentityDefaultsTests(unittest.TestCase):
    def evaluate(
        self,
        host=None,
        configurations="{}",
        expected=None,
        *,
        expected_hosts=None,
    ):
        expected_json = json.dumps(
            expected_hosts
            if expected_hosts is not None
            else {"fixture": expected or {}}
        )
        host_argument = f"hosts.fixture = {host};" if host is not None else ""
        expression = f"""
          let
            expected = builtins.fromJSON {json.dumps(expected_json)};
            pkgs = {{
              stdenv.hostPlatform.system = "fixture";
              lib.makeBinPath = packages: builtins.concatStringsSep ":" packages;
              writeText = name: text:
                let actual = builtins.fromJSON text; in
                assert actual.hosts == expected;
                assert !(actual ? nixosConfigurations);
                "/fake/config";
              writeTextFile = attrs: assert builtins.isString attrs.text; "/fake/${{attrs.name}}";
              symlinkJoin = attrs: attrs.paths;
              python3 = "/fake/python";
              gnutar = "/fake/tar";
              age = "/fake/age";
              nix = "/fake/nix";
              openssh = "/fake/ssh";
            }};
            agenix.packages.fixture.default = "/fake/agenix";
            helpers = import {PROJECT}/lib {{ inherit agenix; }};
            args = {{
              inherit pkgs;
              rules = "secrets/secrets.nix";
              sources = [ "secrets" ];
              {host_argument}
              nixosConfigurations = {configurations};
            }};
          in helpers.mkPackage args
        """
        return subprocess.run(
            ["nix-instantiate", "--eval", "--strict", "--json", "--expr", expression],
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_evaluates(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_omitted_hosts_derive_all_configurations_for_every_command(self):
        configurations = """
          {
            first.config = {
              age.identityPaths = [ "/first-key" ];
              unrelated = throw "must stay lazy";
            };
            second.config.age.identityPaths = [ "/second-key" ];
          }
        """
        expected = {
            "first": {"target": "root@first", "identityPaths": ["/first-key"]},
            "second": {"target": "root@second", "identityPaths": ["/second-key"]},
        }
        self.assert_evaluates(
            self.evaluate(configurations=configurations, expected_hosts=expected)
        )

    def test_explicit_hosts_remain_an_exact_subset(self):
        self.assert_evaluates(
            self.evaluate(
                '{ target = "user@custom"; }',
                '{ fixture.config.age.identityPaths = [ "/key" ]; excluded = throw "must stay lazy"; }',
                {"target": "user@custom", "identityPaths": ["/key"]},
            )
        )

    def test_omitted_hosts_require_nonempty_configurations(self):
        result = self.evaluate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No hosts configured", result.stderr)

    def test_explicit_empty_hosts_do_not_fall_back_to_configurations(self):
        # Exercise the resolver directly to distinguish omitted hosts from {}.
        expression = f"""
          import {PROJECT}/lib/hosts.nix {{
            hosts = {{}};
            nixosConfigurations.fixture.config.age.identityPaths = [ "/key" ];
          }}
        """
        result = subprocess.run(
            ["nix-instantiate", "--eval", "--strict", "--expr", expression],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No hosts configured", result.stderr)

    def test_derived_host_requires_identity_paths(self):
        for configuration, message in (
            ("{ fixture.config = {}; }", "has no age.identityPaths"),
            ("{ fixture.config.age.identityPaths = []; }", "nonempty list"),
        ):
            with self.subTest(configuration=configuration):
                result = self.evaluate(configurations=configuration)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)

    def test_defaults_from_matching_nixos_configuration(self):
        self.assert_evaluates(
            self.evaluate(
                '{ target = "root@fixture"; }',
                '{ fixture.config = { age.identityPaths = [ "/first" "/second" ]; unrelated = throw "must stay lazy"; }; }',
                {"target": "root@fixture", "identityPaths": ["/first", "/second"]},
            )
        )

    def test_package_shares_local_identity_defaults_with_all_commands(self):
        self.assert_evaluates(
            self.evaluate(
                "{ local = true; }",
                '{ fixture.config.age.identityPaths = [ "/key" ]; }',
                {"local": True, "identityPaths": ["/key"]},
            )
        )

    def test_auto_local_options_are_preserved_for_runtime_detection(self):
        self.assert_evaluates(
            self.evaluate(
                '{ local = "auto"; localHostname = "framework"; target = "root@framework"; }',
                '{ fixture.config.age.identityPaths = [ "/key" ]; }',
                {
                    "local": "auto",
                    "localHostname": "framework",
                    "target": "root@framework",
                    "identityPaths": ["/key"],
                },
            )
        )

    def test_explicit_paths_take_precedence_over_identity_and_config(self):
        self.assert_evaluates(
            self.evaluate(
                '{ target = "root@fixture"; identity = "/old"; identityPaths = [ "/override" ]; }',
                '{ fixture = throw "default should not be evaluated"; }',
                {"target": "root@fixture", "identityPaths": ["/override"]},
            )
        )

    def test_explicit_identity_overrides_config(self):
        self.assert_evaluates(
            self.evaluate(
                '{ target = "root@fixture"; identity = "/override"; }',
                '{ fixture = throw "default should not be evaluated"; }',
                {"target": "root@fixture", "identityPaths": ["/override"]},
            )
        )

    def test_missing_config_and_override_produces_clear_error(self):
        result = self.evaluate('{ target = "root@fixture"; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("matching nixosConfigurations entry", result.stderr)

    def test_missing_age_option_produces_clear_error(self):
        result = self.evaluate("{ local = true; }", "{ fixture.config = {}; }")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("has no age.identityPaths", result.stderr)

    def test_empty_default_list_is_rejected(self):
        result = self.evaluate(
            "{ local = true; }", "{ fixture.config.age.identityPaths = []; }"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("nonempty list of path strings", result.stderr)


if __name__ == "__main__":
    unittest.main()

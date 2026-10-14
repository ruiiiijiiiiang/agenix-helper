"""Runtime hostname selection and identity validation."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.agenix_toolkit.config import Host


class AutomaticLocalHostTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="agenix-toolkit-host-test.")
        self.addCleanup(directory.cleanup)
        self.identity = Path(directory.name) / "identity"
        self.identity.write_text("fixture")
        self.definition = {
            "local": "auto",
            "target": "root@framework",
            "identityPaths": [str(self.identity)],
        }

    def resolve(self, hostname, name="framework"):
        with patch("socket.gethostname", return_value=hostname):
            return Host.from_json(name, self.definition)

    def test_matching_short_names_and_fqdn_run_locally(self):
        for hostname in (
            "framework",
            "FRAMEWORK",
            "Framework.example.com",
            "framework.",
        ):
            with self.subTest(hostname=hostname):
                self.assertTrue(self.resolve(hostname).local)

    def test_nonmatching_machine_uses_ssh_without_resolving_local_paths(self):
        with patch(
            "scripts.agenix_toolkit.config.home_path",
            side_effect=AssertionError("remote paths must not be resolved locally"),
        ):
            host = self.resolve("desktop")
        self.assertFalse(host.local)
        self.assertEqual(host.target, "root@framework")

    def test_alias_override_controls_matching(self):
        self.definition["localHostname"] = "framework"
        self.assertTrue(self.resolve("FRAMEWORK.example.com", name="laptop").local)
        self.assertFalse(self.resolve("laptop", name="laptop").local)

    def test_explicit_fqdn_override_requires_matching_domain(self):
        self.definition["localHostname"] = "framework.example.com"
        self.assertTrue(self.resolve("FRAMEWORK.EXAMPLE.COM.").local)
        self.assertFalse(self.resolve("framework.other.com").local)

    def test_matching_host_with_missing_identity_fails_without_ssh_fallback(self):
        self.identity.unlink()
        with self.assertRaisesRegex(ValueError, "No readable identity files"):
            self.resolve("framework")

    def test_auto_requires_ssh_target_even_on_matching_machine(self):
        del self.definition["target"]
        with self.assertRaisesRegex(ValueError, "Unknown or incomplete host"):
            self.resolve("framework")

    def test_invalid_auto_configuration_is_rejected(self):
        for hostname in (None, "", " ", ".", 42):
            with self.subTest(hostname=hostname):
                self.definition["localHostname"] = hostname
                with self.assertRaisesRegex(
                    ValueError, "localHostname must be a nonempty string"
                ):
                    self.resolve("framework")

    def test_hostname_override_requires_auto_mode(self):
        self.definition["localHostname"] = "framework"
        self.definition["local"] = False
        with self.assertRaisesRegex(ValueError, "localHostname requires"):
            self.resolve("framework")

    def test_explicit_remote_mode_does_not_detect_hostname(self):
        self.definition["local"] = False
        with patch("socket.gethostname", side_effect=AssertionError("not needed")):
            self.assertFalse(Host.from_json("framework", self.definition).local)


if __name__ == "__main__":
    unittest.main()

"""Ephemeral identity isolation, lifecycle, and interface integration tests."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import unittest
import test_edit
from test_edit import SecretIntegrationFixture, PROJECT


class EphemeralTests(SecretIntegrationFixture):
    def setUp(self):
        super().setUp()
        # Record disposable generated keys for assertions. This wrapper is test-only.
        self.record = self.root / "generated.json"
        self.env["HOME"] = str(self.root / "empty-home")
        self.env["TMPDIR"] = str(self.root / "ignored-tmp")
        Path(self.env["HOME"]).mkdir()
        Path(self.env["TMPDIR"]).mkdir()
        real = shutil.which("age-keygen")
        wrapper = self.bin / "age-keygen"
        wrapper.write_text(
            f"#!{sys.executable}\n"
            "import json, pathlib, subprocess, sys\n"
            f"result = subprocess.run([{real!r}, *sys.argv[1:]])\n"
            "if '--output' in sys.argv and result.returncode == 0:\n"
            "    key = pathlib.Path(sys.argv[sys.argv.index('--output') + 1])\n"
            f"    pathlib.Path({str(self.record)!r}).write_text(json.dumps({{'path': str(key), 'key': key.read_text(), 'mode': key.stat().st_mode & 0o777, 'directory_mode': key.parent.stat().st_mode & 0o777}}))\n"
            "sys.exit(result.returncode)\n"
        )
        wrapper.chmod(0o700)
        # Inspect every outgoing worker bundle before execution.
        ssh = self.bin / "ssh"
        s = ssh.read_text().replace(
            "elif args[0] == 'nix': sys.exit(subprocess.call([sys.executable, args[-1]]))",
            "elif args[0] == 'nix':\n"
            "    import pathlib\n"
            "    work = pathlib.Path(args[-1]).parent.parent\n"
            "    assert not any(line.startswith(b'AGE-SECRET-KEY-') for p in work.rglob('*') if p.is_file() for line in p.read_bytes().splitlines())\n"
            "    sys.exit(subprocess.call([sys.executable, args[-1]]))",
        )
        ssh.write_text(s)

    def assert_cleaned(self):
        record = json.loads(self.record.read_text())
        path = Path(record['path'])
        self.assertEqual(path.parent.parent, Path('/tmp'))
        self.assertEqual(record['mode'], 0o600)
        self.assertEqual(record['directory_mode'], 0o700)
        self.assertFalse(path.parent.exists())
        return record

    def test_read_needs_no_user_key_and_cleans_unique_ephemeral_keys(self):
        self.settings['mode'] = 'read'
        keys = []
        for _ in range(2):
            result = self.run_controller(interactive=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, 'original secret\n')
            keys.append(self.assert_cleaned()['key'])
            self.assertEqual(self.snapshot(), self.before)
        self.assertNotEqual(*keys)

    def test_edit_restores_original_recipients_and_revokes_ephemeral_key(self):
        result = self.run_controller()
        self.assert_success(result, b'edited secret\n')
        record = self.assert_cleaned()
        saved = self.root / 'test-key'
        saved.write_text(record['key'])
        result = subprocess.run(['age', '-d', '-i', str(saved), str(self.secret)], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.rules.read_bytes(), self.before['secrets/secrets.nix'])

    def test_editor_failure_cleans_key_and_preserves_repository(self):
        result = self.run_controller(mode='fail')
        self.assertNotEqual(result.returncode, 0)
        self.assert_cleaned()
        self.assertEqual(self.snapshot(), self.before)

    def test_unreadable_host_cleans_key_and_preserves_repository(self):
        self.settings['mode'] = 'read'
        self.settings['hosts']['fixture']['identity'] = str(self.keys / 'wrong')
        result = self.run_controller(interactive=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assert_cleaned()
        self.assertEqual(self.snapshot(), self.before)

    def test_dry_run_does_not_generate_key_or_contact_hosts(self):
        self.settings['mode'] = 'read'
        result = self.run_controller(args=['--host', 'fixture', '--dry-run', 'nested/token.age'], interactive=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.record.exists())
        self.assertFalse(self.remote_log.exists())

    def test_removed_options_are_rejected(self):
        for option in ('publicKey', 'publicKeys'):
            self.settings[option] = []
            result = self.run_controller()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('no longer supported', result.stderr)
            del self.settings[option]
        result = self.run_controller(args=['--host', 'fixture', 'nested/token.age', '--identity', str(self.keys / 'editor')])
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.record.exists())


@unittest.skipUnless(shutil.which("nix-instantiate"), "Missing Nix evaluator")
class EphemeralNixTests(unittest.TestCase):
    evaluate = test_edit.NixAppTests.evaluate

    def test_removed_public_key_arguments_are_rejected(self):
        for option in ('publicKey = "key";', 'publicKeys = [ "key" ];'):
            result = self.evaluate(f'((import {PROJECT}/lib {{ agenix = {{}}; }}).mkReadApp {{ pkgs = {{}}; rules = "secrets.nix"; sources = [ "secrets.nix" ]; hosts = {{}}; {option} }}).program')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('unexpected argument', result.stderr)

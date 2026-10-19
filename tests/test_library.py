"""Public package constructor contracts across the shared Nix library."""

import json
import shutil
import subprocess
import unittest

from test_edit import PROJECT


@unittest.skipUnless(shutil.which("nix-instantiate"), "Missing Nix evaluator")
class LibraryTests(unittest.TestCase):
    def test_package_bundles_configured_commands_with_stable_names(self):
        for name_arg, expected_name in (
            ("", "agenix-helper"),
            ('name = "custom-bundle";', "custom-bundle"),
        ):
            with self.subTest(name=expected_name):
                expression = f'''
                  let
                    pkgs = {{
                      stdenv.hostPlatform.system = "fixture";
                      lib.makeBinPath = _: "";
                      writeText = name: text:
                        let config = builtins.fromJSON text; in
                        assert name == "agenix-${{config.mode}}-config.json";
                        assert config.rules == "secrets/secrets.nix";
                        assert config.sources == [ "secrets" ];
                        assert config.maxConcurrency == 3;
                        assert config.hosts.fixture.identityPaths == [ "/host-key" ];
                        "/fake/config";
                      writeTextFile = attrs:
                        assert attrs.destination == "/bin/${{attrs.name}}";
                        assert builtins.isString attrs.text;
                        "/fake/${{attrs.name}}";
                      symlinkJoin = attrs: attrs;
                      python3 = "/fake/python";
                    }};
                    helpers = ((import {PROJECT}/flake.nix).outputs {{
                      agenix = {{}};
                      nixpkgs = {{}};
                    }}).lib;
                  in helpers.mkPackage {{
                    inherit pkgs;
                    rules = "secrets/secrets.nix";
                    sources = [ "secrets" ];
                    hosts.fixture = {{ target = "root@fixture"; identity = "/host-key"; }};
                    maxConcurrency = 3;
                    {name_arg}
                  }}
                '''
                result = subprocess.run(
                    [
                        "nix-instantiate",
                        "--eval",
                        "--strict",
                        "--json",
                        "--expr",
                        expression,
                    ],
                    capture_output=True,
                    check=False,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                package = json.loads(result.stdout)
                self.assertEqual(package["name"], expected_name)
                self.assertEqual(
                    package["paths"],
                    [f"/fake/agenix-{mode}" for mode in ("read", "edit", "rekey")],
                )

    def test_max_concurrency_input_is_shared_and_validated(self):
        for value, valid in (
            ("1", True),
            ("3", True),
            ("0", False),
            ("-1", False),
            ("true", False),
            ('"2"', False),
            ("1.5", False),
        ):
            with self.subTest(value=value):
                expression = f"""let
                  pkgs = {{
                    stdenv.hostPlatform.system = "fixture";
                    lib.makeBinPath = _: "";
                    writeText = _: text:
                      assert (builtins.fromJSON text).maxConcurrency == {value};
                      "/fake/config";
                    writeTextFile = attrs: assert builtins.isString attrs.text; "/fake/package";
                    symlinkJoin = attrs: attrs.paths;
                    python3 = "/fake/python";
                  }};
                  package = (import {PROJECT}/lib {{ agenix = {{}}; }}).mkPackage {{
                    inherit pkgs;
                    rules = "secrets.nix";
                    sources = [ "secrets" ];
                    hosts.fixture = {{ target = "fixture"; identity = "/key"; }};
                    maxConcurrency = {value};
                  }};
                in package"""
                result = subprocess.run(
                    ["nix-instantiate", "--eval", "--strict", "--expr", expression],
                    capture_output=True,
                    check=False,
                    text=True,
                )
                self.assertEqual(result.returncode == 0, valid, result.stderr)

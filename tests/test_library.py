"""Public app constructor contracts across the shared Nix library."""

import json
import shutil
import subprocess
import unittest

from test_edit import PROJECT


@unittest.skipUnless(shutil.which("nix-instantiate"), "Missing Nix evaluator")
class LibraryTests(unittest.TestCase):
    def test_operation_modes_and_custom_names(self):
        for constructor, mode in (
            ("mkReadApp", "read"),
            ("mkEditApp", "edit"),
            ("mkRekeyApp", "rekey"),
        ):
            with self.subTest(constructor=constructor):
                expression = f'''
                  let
                    pkgs = {{
                      stdenv.hostPlatform.system = "fixture";
                      lib.makeBinPath = _: "";
                      writeText = name: text:
                        let config = builtins.fromJSON text; in
                        assert config.mode == "{mode}";
                        assert config.maxConcurrency == 10;
                        assert config.hosts.fixture.identityPaths == [ "/host-key" ];
                        assert name == "custom-config.json";
                        "/fake/config";
                      writeTextFile = attrs:
                        assert attrs.name == "custom";
                        assert attrs.destination == "/bin/custom";
                        assert builtins.isString attrs.text;
                        "/fake/package";
                      python3 = "/fake/python";
                    }};
                    helpers = import {PROJECT}/lib {{ agenix = {{}}; }};
                  in helpers.{constructor} {{
                    inherit pkgs;
                    name = "custom";
                    rules = "secrets/secrets.nix";
                    sources = [ "secrets" ];
                    hosts.fixture = {{ target = "root@fixture"; identity = "/host-key"; }};
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
                app = json.loads(result.stdout)
                self.assertEqual(app["type"], "app")
                self.assertEqual(app["program"], "/fake/package/bin/custom")
                self.assertTrue(
                    app["meta"]["description"].startswith(mode.capitalize())
                )

    def test_max_concurrency_input_is_shared_and_validated(self):
        for constructor in ("mkReadApp", "mkEditApp", "mkRekeyApp", "mkApps"):
            for value, valid in (
                ("1", True),
                ("3", True),
                ("0", False),
                ("-1", False),
                ("true", False),
                ('"2"', False),
                ("1.5", False),
            ):
                with self.subTest(constructor=constructor, value=value):
                    selection = ".agenix-read" if constructor == "mkApps" else ""
                    expression = f"""let
                      pkgs = {{
                        stdenv.hostPlatform.system = "fixture";
                        lib.makeBinPath = _: "";
                        writeText = _: text:
                          assert (builtins.fromJSON text).maxConcurrency == {value};
                          "/fake/config";
                        writeTextFile = attrs: assert builtins.isString attrs.text; "/fake/package";
                        python3 = "/fake/python";
                      }};
                      app = (import {PROJECT}/lib {{ agenix = {{}}; }}).{constructor} {{
                        inherit pkgs;
                        rules = "secrets.nix";
                        sources = [ "secrets" ];
                        hosts.fixture = {{ target = "fixture"; identity = "/key"; }};
                        maxConcurrency = {value};
                      }};
                    in (app{selection}).program"""
                    result = subprocess.run(
                        ["nix-instantiate", "--eval", "--strict", "--expr", expression],
                        capture_output=True,
                        check=False,
                        text=True,
                    )
                    self.assertEqual(result.returncode == 0, valid, result.stderr)

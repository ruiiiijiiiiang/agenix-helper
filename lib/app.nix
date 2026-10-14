{
  agenix,
  mode,
  defaultName,
  description,
}:
{
  pkgs,
  rules,
  sources,
  hosts,
  nixosConfigurations ? { },
  name ? defaultName,
  ageRef ? "nixpkgs#age",
  pythonRef ? "nixpkgs#python3",
}:
let
  system = pkgs.stdenv.hostPlatform.system;
  scriptsRoot = ../scripts;
  resolvedHosts = import ./hosts.nix {
    inherit hosts nixosConfigurations;
  };
  configFile = pkgs.writeText "${name}-config.json" (
    builtins.toJSON {
      hosts = resolvedHosts;
      inherit
        rules
        sources
        ageRef
        pythonRef
        mode
        ;
    }
  );
  runtimePath = pkgs.lib.makeBinPath [
    agenix.packages.${system}.default
    pkgs.gnutar
    pkgs.age
    pkgs.nix
    pkgs.openssh
  ];
  package = pkgs.writeTextFile {
    inherit name;
    destination = "/bin/${name}";
    executable = true;
    text = /* python */ ''
      #!${pkgs.python3}/bin/python3
      import os
      import sys

      os.environ["PATH"] = "${runtimePath}:" + os.environ.get("PATH", "")
      os.environ["AGENIX_TOOLKIT_CONFIG"] = "${configFile}"
      os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
      os.environ["AGENIX_TOOLKIT_WORKER"] = "${scriptsRoot}/worker.py"
      os.execv("${pkgs.python3}/bin/python3", ["python3", "${scriptsRoot}/controller.py", *sys.argv[1:]])
    '';
  };
in
assert builtins.isString rules && rules != "";
assert builtins.isList sources && sources != [ ];
assert builtins.elem mode [
  "rekey"
  "edit"
  "read"
];
{
  type = "app";
  program = "${package}/bin/${name}";
  meta = { inherit description; };
}

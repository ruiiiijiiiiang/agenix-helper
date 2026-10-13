{ agenix }:
{
  pkgs,
  rules,
  sources,
  hosts,
  nixosConfigurations ? { },
  mode ? "rekey",
  publicKey ? null,
  name ? "agenix-toolkit-${mode}",
  ageRef ? "nixpkgs#age",
  pythonRef ? "nixpkgs#python3",
}:
let
  system = pkgs.stdenv.hostPlatform.system;
  scriptsRoot = ../scripts;
  resolvedHosts = builtins.mapAttrs (
    hostname: host:
    let
      identityPaths =
        if host ? identityPaths then
          host.identityPaths
        else if host ? identity then
          [ host.identity ]
        else if builtins.hasAttr hostname nixosConfigurations then
          nixosConfigurations.${hostname}.config.age.identityPaths
            or (throw "Host '${hostname}' has no age.identityPaths in its NixOS configuration")
        else
          throw "Host '${hostname}' requires identityPaths, identity, or a matching nixosConfigurations entry";
    in
    if !builtins.isAttrs host then
      throw "Host '${hostname}' must be an attribute set"
    else if
      !builtins.isList identityPaths
      || identityPaths == [ ]
      || !builtins.all (path: builtins.isString path && path != "") identityPaths
    then
      throw "Host '${hostname}' identityPaths must be a nonempty list of path strings"
    else
      builtins.removeAttrs host [ "identity" ] // { inherit identityPaths; }
  ) hosts;
  configFile = pkgs.writeText "${name}-config.json" (
    builtins.toJSON {
      hosts = resolvedHosts;
      inherit
        rules
        sources
        ageRef
        pythonRef
        mode
        publicKey
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
assert builtins.isAttrs hosts;
assert builtins.isAttrs nixosConfigurations;
assert builtins.elem mode [
  "rekey"
  "edit"
  "read"
];
assert mode == "rekey" || (builtins.isString publicKey && publicKey != "");
{
  type = "app";
  program = "${package}/bin/${name}";
  meta.description =
    if mode == "edit" then
      "Edit a staged agenix secret using a temporary recipient, then restore its original recipients"
    else if mode == "read" then
      "Read a staged agenix secret using a temporary recipient and print its plaintext"
    else
      "Rekey agenix files on declared local or SSH hosts, then verify and copy them back";
}

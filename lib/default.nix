{ agenix }:
let
  mkRekeyApp = import ./rekey.nix { inherit agenix; };
  mkEditApp = import ./edit.nix { inherit agenix; };
  mkReadApp = import ./read.nix { inherit agenix; };
in
{
  inherit mkRekeyApp mkEditApp mkReadApp;

  mkApps = args: {
    rekey-secrets = mkRekeyApp args;
    edit-secret = mkEditApp args;
    read-secret = mkReadApp args;
  };
}

{ agenix }:
let
  mkRekeyApp = import ./rekey.nix { inherit agenix; };
  mkEditApp = import ./edit.nix { inherit agenix; };
  mkReadApp = import ./read.nix { inherit agenix; };
in
{
  inherit mkRekeyApp mkEditApp mkReadApp;

  mkApps = args: {
    agenix-rekey = mkRekeyApp args;
    agenix-edit = mkEditApp args;
    agenix-read = mkReadApp args;
  };
}

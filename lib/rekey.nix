{ agenix }:
import ./app.nix {
  inherit agenix;
  mode = "rekey";
  defaultName = "agenix-helper-rekey";
  description = "Rekey agenix files on declared local or SSH hosts, then verify and copy them back";
}

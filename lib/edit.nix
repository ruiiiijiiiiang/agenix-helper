{ agenix }:
import ./app.nix {
  inherit agenix;
  mode = "edit";
  defaultName = "agenix-helper-edit";
  description = "Edit a staged agenix secret using a temporary recipient, then restore its original recipients";
}

{ agenix }:
import ./app.nix {
  inherit agenix;
  mode = "read";
  defaultName = "agenix-toolkit-read";
  description = "Read a staged agenix secret using a temporary recipient and print its plaintext";
}

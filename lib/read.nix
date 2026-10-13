{ agenix }:
args: import ./rekey.nix { inherit agenix; } (args // { mode = "read"; })

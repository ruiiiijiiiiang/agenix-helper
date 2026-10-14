# agenix-toolkit

Read, edit, and rekey agenix secrets using a local or remote host that can decrypt them, without copying host keys to your workstation. To use a remote host, your workstation must have SSH access to it as the user configured in `target`.

**Private keys and plaintext never transfer between hosts.** Rekeying happens on the selected host. Reading and editing generate a fresh local age key for each operation, temporarily grant it access to staged ciphertext, then decrypt on your workstation. Operations run only when invoked, independently of NixOS builds and deployments.

## Installation

Add the flake input and expose all three apps with `lib.mkApps`:

```nix
{
  inputs.agenix-toolkit.url = "github:ruiiiijiiiiang/agenix-toolkit";

  outputs = inputs@{ nixpkgs, ... }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      apps.${system} = inputs.agenix-toolkit.lib.mkApps {
        inherit pkgs;
        rules = "secrets/secrets.nix";
        sources = [ "secrets" "lib/keys.nix" ];
        hosts = {
          localhost = {
            local = true;
          };
          server = {
            target = "user@server";
          };
        };
      };
    };
}
```

In flake-parts, assign to `apps` inside `perSystem`. Merge with existing apps using `//`. To expose individual apps, use `lib.mkRekeyApp`, `lib.mkReadApp`, or `lib.mkEditApp` with the same configuration.

- `rules` and `sources` are relative to the repository used at runtime. Include the rules, imported Nix files, and encrypted files. Sources must contain regular files and directories without symlinks; local private keys must stay outside them.
- Read/edit need no user decryption key. The `publicKey`, `publicKeys`, and local `--identity` options have been removed. Remove them from existing app configurations and commands. Secret rules still use `publicKeys` to declare their permanent recipients.
- `hosts` defines available workers. Set `target` for SSH, or `local = true` for local execution without SSH. Worker identity paths refer to that host and use its executing user's permissions. Paths may be absolute, start with `~`, or be relative to that user's home.

For multiple worker keys, replace `identity` with a nonempty list:

```nix
identityPaths = [ "/etc/ssh/ssh_host_ed25519_key" "/path/to/another-key" ];
```

Alternatively, pass `nixosConfigurations = self.nixosConfigurations;` to the constructor. Hosts then default to `nixosConfigurations.<host-name>.config.age.identityPaths`; explicit `identityPaths` takes precedence over `identity`, which takes precedence over these defaults. Host names must match configuration names. For aliases, set the paths explicitly, for example `identityPaths = self.nixosConfigurations.framework.config.age.identityPaths;`.

Only identity path strings enter the app configuration. Defaults come from the supplied evaluated configuration, so keep them aligned with deployed hosts. Workers skip unreadable keys with diagnostics and fail if none are readable. These worker keys remain necessary to decrypt the original secrets.

SSH hosts need `nix`, `tar`, and `mktemp`. The worker obtains Python and age through `nix shell`; override their package references with `pythonRef` and `ageRef` if needed. Local workers use the app's bundled runtime.

## Rekey

Run from your secrets repository, or add `--repo /path/to/repo`:

```sh
# Preview without contacting hosts or changing files.
nix run .#rekey-secrets -- --host server --all-secrets --dry-run

# Use a local key without SSH.
nix run .#rekey-secrets -- --host localhost --all-secrets

# Try hosts in the given order, or all configured hosts in sorted order.
nix run .#rekey-secrets -- --host server --host localhost --all-secrets
nix run .#rekey-secrets -- --all --all-secrets

# Rekey only selected secrets.
nix run .#rekey-secrets -- --host server nested/token.age other.age
```

Secret paths are relative to the rules file's directory and must name existing rules. Specify secret paths to rekey specific secrets, or pass `--all-secrets` to rekey every secret. Omitting both secret paths and `--all-secrets` produces an error; `--all-secrets` cannot be combined with secret paths. `--all` selects hosts, independently of secret selection.

Each host re-encrypts the staged files it can decrypt. Processing stops once `agenix --check` confirms every selected secret has the declared recipients. Only selected ciphertext is checked and copied back; unrelated missing secrets or recipient mismatches do not block targeted runs.

Before copying back, the app checks that local sources have not changed. Failures before this copy leave the repository untouched; a failure during the copy can leave some files updated. Failed SSH cleanup may leave encrypted files in a remote temporary directory. Review the diff before committing or deploying; the app does neither automatically.

## Read

Run from your secrets repository; no local decryption identity is needed:

```sh
# Read a single secret (plain decrypted bytes to stdout)
nix run .#read-secret -- --host server nested/token.age

# Read multiple secrets
nix run .#read-secret -- --host server nested/token.age other.age

# Read every secret in the rules
nix run .#read-secret -- --all --all-secrets
```

The app generates an ephemeral native age key pair and adds its public recipient to the staged rule. A selected host re-encrypts the secrets in a single round-trip, then the app verifies temporary access by decrypting to `/dev/null`, decrypts locally, and discards staging. The private key never enters the directory transferred to workers. Repository rules and ciphertext remain unchanged.

Local staging is created directly under `/tmp` (ignoring `TMPDIR`), with a `0700` directory and a `0600` private-key file. Normal completion, errors, and handled cancellation remove staging and the key. `SIGKILL` or power loss can leave artifacts; reboot clears them when `/tmp` is tmpfs, while disk-backed `/tmp` depends on system cleanup. The toolkit does not require `/tmp` to be tmpfs.

When reading a single secret, standard output contains only decrypted bytes without headers. When reading multiple secrets or using `--all-secrets`, each secret is printed with a `==> path.age <==` header and separated by a blank line. Progress and diagnostics go to standard error. Piping and redirection are supported.

Read and edit share these requirements:

- Select local or SSH workers with repeated `--host` arguments, or use `--all`. A selected host must be able to decrypt the secret to grant access to the fresh ephemeral key.
- Reading accepts one or more secret paths relative to the rules directory, or `--all-secrets` to read all secrets (omitting both produces an error). Editing accepts exactly one secret path. Supported path characters are letters, numbers, underscores, dots, slashes, and hyphens.
- Original recipients for selected secrets must still be SSH keys. The temporary native age recipient is verified through decryption; final original recipients are verified with `agenix --check`. Unrelated secrets' recipient mismatches do not block the operation.
- `--dry-run` evaluates the rule and checks paths without generating a key, contacting hosts, or decrypting anything.

## Edit

Set `EDITOR` and run from an interactive terminal:

```sh
# Edit using a specific host
EDITOR=nvim nix run .#edit-secret -- --host server nested/token.age

# Try all configured hosts in sorted order until one can decrypt
EDITOR=nvim nix run .#edit-secret -- --all nested/token.age
```

Editing uses the same temporary access workflow as reading, then opens the secret locally with `agenix --edit`. After the editor succeeds, the app uses the ephemeral identity to re-encrypt for the original recipients, verifies them, checks that sources have not changed, and atomically replaces only the selected `.age` file. This happens even if the editor made no changes. Rules and imported Nix files remain unchanged.

Editor failures, verification failures, source changes, or cancellation before replacement discard staged changes. Forceful termination can leave temporary artifacts, and editors may retain backups. Removing the temporary recipient does not revoke access to intermediate copies; original recipients retain their existing access.

## Development

Contributions are welcome! Feel free to open an issue or submit a pull request.

Use `path:/path/to/your/checkout` as the flake input URL for local development. Run `nix flake update` in the toolkit checkout to update its locked dependencies.

With Python, age, agenix, Nix, SSH key generation, and tar on `PATH`, run:

```sh
python3 -B -m unittest discover -s tests -v
```

Tests generate disposable keys and secrets, run real age and agenix commands, and simulate SSH locally. They do not contact hosts or build derivations. The packaging check uses `nix eval` and requires access to the Nix daemon.

`scripts/controller.py` and `scripts/worker.py` are entry points into the standard-library-only `scripts/agenix_toolkit` package:

| Module          | Responsibility                                        |
| --------------- | ----------------------------------------------------- |
| `cli.py`        | Arguments, validation, and dispatch                   |
| `config.py`     | Typed configuration and identity paths                |
| `staging.py`    | Snapshots, worker bundles, and file replacement       |
| `rules.py`      | Nix rule evaluation and recipient verification        |
| `hosts.py`      | Local execution and SSH transfers                     |
| `operations.py` | Rekey, read, and edit workflows                       |
| `crypto.py`     | Worker identities and age encryption pipes            |
| `process.py`    | Subprocess errors, cleanup, and interruption handling |

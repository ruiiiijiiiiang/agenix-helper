# agenix-toolkit

agenix-toolkit lets you read, edit, and rekey agenix secrets even when your workstation cannot decrypt them. It uses a local or SSH-accessible host that already has a suitable private key, so you can manage secrets without copying host keys to your workstation.

For rekeying, the host decrypts and re-encrypts secrets for the recipients declared in your rules. For reading or editing, the toolkit temporarily adds your public key to a staged copy of the rules and asks the host to re-encrypt the secret for it. Your workstation then decrypts locally with your corresponding private key. Edited secrets are re-encrypted for the original recipients; reading leaves your files unchanged.

**Private keys and secret plaintext never get transferred between hosts.** SSH carries encrypted secret files, public recipient keys, and supporting configuration and code. Plaintext stays on the host during rekeying and is decrypted locally for reading or editing. Operations run only when you invoke an app; NixOS builds and deployments do not trigger them.

## Add the app to a flake

Add `agenix-toolkit` as a flake input, then expose an app:

```nix
{
  inputs.agenix-toolkit.url = "github:ruiiiijiiiiang/agenix-toolkit";

  outputs = inputs@{ nixpkgs, ... }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      apps.${system}.rekey-secrets = inputs.agenix-toolkit.lib.mkRekeyApp {
        inherit pkgs;
        rules = "secrets/secrets.nix";
        sources = [ "secrets" "lib/keys.nix" ];
        hosts = {
          workstation_a = {
            target = "user@workstation-a";
            identity = ".ssh/id_ed25519";
          };
          workstation_b = {
            target = "user@workstation-b";
            identity = ".ssh/id_ed25519";
          };
          server_a = {
            target = "user@server-a";
            identity = ".ssh/id_ed25519";
          };
        };
      };
    };
}
```

The input is named `agenix-toolkit`; the example retains the existing hosted repository URL. After renaming the hosted repository, update the URL to `github:ruiiiijiiiiang/agenix-toolkit`. For local development, set the URL to `path:/path/to/your/checkout`.

`rules` and each `sources` entry are relative to the repo passed at runtime. Include the rules file, every imported Nix file, and the `.age` files. Adjust the example paths to match your repository. For SSH hosts, `identity` is a path on the **remote host**, absolute or relative to that SSH user's home. A host may be named anything; select it with `--host`.

The remote host needs SSH access, `nix`, `tar`, and `mktemp`. The controller starts the worker with `nix shell nixpkgs#python3 nixpkgs#age --command python3 ...`, so Python and `age` do not need to be installed there beforehand. Set `pythonRef = "<flake-ref>#python3";` or `ageRef = "<flake-ref>#age";` in `mkRekeyApp` to select different remote package references. The controller packages its own local Python, age, agenix, Nix, SSH, and tar.

## Expose all apps with one configuration

Use `lib.mkApps` to generate `rekey-secrets`, `edit-secret`, and `read-secret` together:

```nix
apps.${system} = inputs.agenix-toolkit.lib.mkApps {
  inherit pkgs;
  rules = "secrets/secrets.nix";
  sources = [ "secrets" "lib/keys.nix" ];
  publicKey = "ssh-ed25519 AAAA... your-key";
  hosts = {
    localhost = {
      local = true;
      identity = ".ssh/id_ed25519";
    };
    server_a = {
      target = "user@server-a";
      identity = ".ssh/id_ed25519";
    };
  };
};
```

In a flake-parts `perSystem` block, assign the result to `apps` instead of `apps.${system}`. All three apps receive the same configuration; `publicKey` is required for edit and read. Pass the corresponding local private key path with `--identity` when running either app. The individual `mkRekeyApp`, `mkEditApp`, and `mkReadApp` constructors remain available. If you already define other apps, merge this result with that attribute set using `//`.

## Default identities from NixOS configurations

All constructors, including `mkApps`, accept an optional `nixosConfigurations` argument. Supply your evaluated host configurations to omit explicit worker identities:

```nix
apps.${system} = inputs.agenix-toolkit.lib.mkApps {
  inherit pkgs;
  nixosConfigurations = self.nixosConfigurations;
  rules = "secrets/secrets.nix";
  sources = [ "secrets" "lib/keys.nix" ];
  publicKey = "ssh-ed25519 AAAA... your-key";
  hosts = {
    vm-app = {
      target = "root@vm-app";
    };
    framework = {
      local = true;
    };
  };
};
```

For each host, the constructor uses explicit `identityPaths` first, then the single-path `identity` shorthand, then `nixosConfigurations.<host-name>.config.age.identityPaths`. The host entry's name must match the NixOS configuration name when using defaults. For aliases such as `localhost`, explicitly set `identityPaths = self.nixosConfigurations.framework.config.age.identityPaths;`. Only the resolved path strings are stored in the app's JSON configuration; full NixOS configurations and private key contents are not included.

For a manual list, use `identityPaths = [ "/etc/ssh/ssh_host_ed25519_key" "/path/to/another-key" ];`. The worker passes all readable identities to age with repeated `--identity` arguments, allowing different secrets to use different keys on the same host. Missing or unreadable paths are skipped with diagnostics on standard error; the operation fails if none are readable. Explicit lists must be nonempty. Path permissions are those of the SSH user for remote hosts or the user running the app for local hosts. Local identity files must remain outside `sources`.

Defaults come from the evaluated configuration passed to the constructor, rather than querying the running host. Keep these declarations aligned with the deployed hosts. Edit/read's runtime `--identity` remains the local key matching `publicKey`, independently of worker identities.

## Rekey locally without SSH

Declare a local host with `local = true` and omit `target`:

```nix
hosts = {
  localhost = {
    local = true;
    identity = ".ssh/id_ed25519";
  };
};
```

```sh
nix run .#rekey-secrets -- --host localhost --dry-run
nix run .#rekey-secrets -- --host localhost
```

`identity` and `identityPaths` refer to paths on the machine running the app. Absolute paths, `~`, and paths relative to the local user's home are supported. The app reads keys under the current user's permissions; no SSH connection or remote `nix shell` is used. Python and age come from the app's runtime. At least one local identity must be readable, local keys must be outside `sources`, and sources must contain regular files and directories without symlinks.

The same staged rekey, recipient verification, source-change checks, and final copy apply to local hosts. Plaintext passes through an age pipe locally. Declare local and SSH hosts together and select them with repeated `--host` arguments in the desired order, or use `--all` to process names in sorted order. Local hosts also work with the edit and read apps. The name `localhost` is an example; the `local` flag determines how the host runs.

## Run

From the consumer repo:

```sh
nix run .#rekey-secrets -- --host server_a --dry-run
nix run .#rekey-secrets -- --host server_a --host workstation_a
nix run .#rekey-secrets -- --all
nix run .#rekey-secrets -- --host server_a nested/token.age
nix run .#rekey-secrets -- --host localhost nested/token.age other.age
nix run .#rekey-secrets -- --all --all-secrets
```

Pass one or more secret paths to rekey only those files. Paths are relative to the rules file's directory, may contain letters, numbers, underscores, dots, slashes, and hyphens, and must name existing rules. Duplicate paths are processed once. Omit paths to retain the default of rekeying every secret, or use `--all-secrets` to request that explicitly. `--all-secrets` cannot be combined with secret paths. Host selection is independent: `--all` selects all configured hosts, while `--host` selects particular hosts.

For targeted runs, the worker processes only the selected secrets, recipient checks cover only their rules, and only those encrypted files can be copied back. Unselected ciphertext and rules stay unchanged, and unrelated recipient mismatches or missing encrypted files do not block the selected operation. The configured sources are still staged and checked for concurrent changes. A targeted `--dry-run` reports the selected paths and count without contacting hosts or modifying files.

Use `--repo /path/to/repo` if running elsewhere. `--dry-run` checks the local paths, evaluates the rules, and reports the selected hosts and secret count. It does not contact hosts or change files. A normal run processes each selected host in order, sending the staged encrypted inputs and recipient lists only for SSH hosts. Each host reencrypts only files its identity can decrypt. The controller checks the resulting recipients with `agenix --check` after each host; it stops as soon as every file matches. It copies changed `.age` files back only after that check succeeds and confirms the local sources have not changed during the run.

SSH workers never send private keys or plaintext to the controller. Plaintext passes through an `age` pipe on the selected local or remote host. Failures before the final copy leave the local repo untouched; a failure during that copy can leave some files updated. Encrypted files may remain in a remote temporary directory if SSH cleanup is unavailable. The app does not stage Git changes or deploy anything. Review the resulting diff, then commit or deploy it manually.

Keep the helper flake lock file updated with `nix flake update` when you want newer agenix and nixpkgs revisions.

## Edit a secret with a temporary recipient

Expose a separate edit app using the same rules, sources, and hosts:

```nix
apps.${system}.edit-secret = inputs.agenix-toolkit.lib.mkEditApp {
  inherit pkgs;
  rules = "secrets/secrets.nix";
  sources = [ "secrets" "lib/keys.nix" ];
  publicKey = "ssh-ed25519 AAAA... your-editor-key";
  hosts.server_a = {
    target = "user@server-a";
    identity = ".ssh/id_ed25519";
  };
};
```

`publicKey` is the local editor's public SSH Ed25519 or RSA key. Pass the corresponding private key **path** at runtime; never put private key contents in Nix expressions or the Nix store. The private key must be outside every declared `sources` path. The host's `identity` is a path on that selected local or remote host.

```sh
nix run .#edit-secret -- --host server_a --identity ~/.ssh/id_ed25519 --dry-run nested/token.age
EDITOR=nvim nix run .#edit-secret -- --host server_a --identity ~/.ssh/id_ed25519 nested/token.age
```

The secret argument is relative to the rules file's directory. Choose multiple `--host` arguments or `--all` to try more hosts in order. At least one selected host must be able to decrypt the current ciphertext, unless it already matches the temporary recipient list. Paths may contain letters, numbers, underscores, dots, slashes, and hyphens. Editing requires an interactive terminal and `EDITOR`; piped input is rejected. Sources must contain regular files and directories without symlinks. Only the selected secret's recipients are checked, so unrelated recipient mismatches do not block editing. All recipients for that secret must be SSH keys because agenix's recipient checker does not support native age recipients.

The app checks the local key pair before contacting hosts, adds the public key to a generated rule for the selected staged secret, and uses the existing remote worker to reencrypt it. It then runs local `agenix --edit --identity`. Plaintext is temporarily available on the workstation for the editor; the local private key is never sent to hosts. The original rules and imported Nix files are not rewritten.

After the editor succeeds, the app always reencrypts locally for the original recipients, including when the editor made no changes. It verifies the final recipients and checks that the original sources have not changed before atomically replacing the selected `.age` file. Other encrypted files are not updated. If the editor fails, a host cannot decrypt the secret, verification fails, or sources change during editing, staged changes are discarded and the app does not update repository files. Cancellation before the final replacement also leaves the repository untouched. Forceful termination can leave temporary artifacts; editors may retain their own backups. Removing the temporary recipient from the final ciphertext cannot revoke access to previously obtained intermediate copies. If the editor key was already an original recipient, it remains one.

`--dry-run` evaluates the selected rule and checks paths and private key readability. It does not contact hosts, decrypt secrets, launch the editor, or verify the key pair.

## Read a secret with a temporary recipient

Expose a read app with the same configuration as the edit app:

```nix
apps.${system}.read-secret = inputs.agenix-toolkit.lib.mkReadApp {
  inherit pkgs;
  rules = "secrets/secrets.nix";
  sources = [ "secrets" "lib/keys.nix" ];
  publicKey = "ssh-ed25519 AAAA... your-reader-key";
  hosts.server_a = {
    target = "user@server-a";
    identity = ".ssh/id_ed25519";
  };
};
```

```sh
nix run .#read-secret -- --host server_a --identity ~/.ssh/id_ed25519 nested/token.age
nix run .#read-secret -- --all --identity ~/.ssh/id_ed25519 nested/token.age > /path/to/output
```

The app stages the selected encrypted secret, verifies the local key pair, temporarily adds `publicKey` to its recipients, and uses a configured host to reencrypt the staged ciphertext. It then runs local `agenix --decrypt --identity` to print the plaintext and discards its staging directory. Repository rules and ciphertext are never updated, so no final rekey is needed. The local private key remains outside the files sent to hosts.

Standard output contains only the decrypted bytes, with no labels or added newline. Progress messages, worker output, and verification diagnostics go to standard error, allowing piping and redirection. `EDITOR` and interactive stdin are not required; encrypted private keys may still require a terminal to enter their passphrase. All recipient and source restrictions of the edit app also apply to reading. `--dry-run` prints its summary to standard error without contacting hosts or decrypting the secret.

## Development checks

With Python, age, agenix, Nix, SSH key generation, and tar on `PATH`, run:

```sh
python3 -B -m unittest discover -s tests -v
```

The tests generate disposable keys and secrets, invoke the real age and agenix commands, and simulate SSH locally. They do not contact hosts or build Nix derivations. The packaging check uses `nix eval` to verify that the Python package is present in the Nix store, requiring access to the Nix daemon.

## Python layout

`scripts/controller.py` and `scripts/worker.py` are thin entry points. Their implementation lives in the standard-library-only `scripts/agenix_toolkit` package:

| Module          | Responsibility                                                        |
| --------------- | --------------------------------------------------------------------- |
| `cli.py`        | Arguments, source validation, and workflow dispatch                   |
| `config.py`     | Typed toolkit, host, and worker configuration; identity paths         |
| `staging.py`    | Snapshots, worker bundles, source-change checks, and file replacement |
| `rules.py`      | Typed secret rules, Nix evaluation, and recipient verification        |
| `hosts.py`      | Local execution and SSH transfers                                     |
| `operations.py` | Shared temporary access preparation and rekey/edit/read workflows     |
| `crypto.py`     | Worker identity resolution and age encryption pipes                   |
| `process.py`    | Subprocess errors, pipeline cleanup, and interruption handling        |

Nix includes the complete scripts directory so sibling imports work in the store. Staging copies the worker entry point and its package together; the worker locates its stage using the entry point's directory. Both entry points handle interruption with exit status 130. Managed subprocesses are terminated and reaped before their staged resources are discarded, and the editor wrapper records its own exit status so agenix cannot hide a failed edit.

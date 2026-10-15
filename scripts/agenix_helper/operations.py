"""Shared access preparation and the rekey, edit, and read workflows."""

import filecmp
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Sequence

from .config import HelperConfig, Host, Mode, WorkerConfig
from .hosts import process_host
from .process import cancel_editor, run
from .rules import Manifest, SecretRule, check_rules, write_staged_rules
from .staging import Stage, write_changed_file


def prepare_secret(
    stage: Stage,
    config: HelperConfig,
    selected: Sequence[Host],
    secret: str,
    rule: SecretRule,
) -> tuple[Path, Path, Path, Path]:
    """Grant a local identity temporary access to one staged encrypted secret."""
    work, rules, worker = stage.work, config.rules, config.worker_source
    reading = config.mode == Mode.READ
    if any(
        not key.startswith(("ssh-ed25519 ", "ssh-rsa ")) for key in rule.public_keys
    ):
        raise ValueError("Editing and reading currently support only SSH recipients")

    # The private key is outside work, the only directory transferred to workers.
    identity = work.parent / "ephemeral-identity"
    run(
        ["age-keygen", "--output", str(identity)],
        operation="Generate ephemeral identity",
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    identity.chmod(0o600)
    public_key = run(
        ["age-keygen", "-y", str(identity)],
        operation="Derive ephemeral recipient",
        capture_output=True,
        text=True,
    ).stdout.strip()
    temporary_rule = rule.with_recipient(public_key)
    access_rules = write_staged_rules(work, rules, {secret: temporary_rule})
    helper = stage.prepare_worker(worker, {secret: temporary_rule})

    relative = rules.parent / secret
    encrypted = work / relative
    verified = False
    for host in selected:
        if verified:
            break
        process_host(
            work,
            helper,
            host,
            config,
            rules.parent,
            {secret: temporary_rule},
            action="Processed",
            diagnostics_to_stderr=reading,
        )
        # Native age recipients cannot be checked by agenix --check. Prove
        # temporary access by decrypting to /dev/null with this operation's key.
        verified = (
            run(
                [
                    "age",
                    "--decrypt",
                    "--identity",
                    str(identity),
                    "--output",
                    os.devnull,
                    str(encrypted),
                ],
                operation="Verify ephemeral access",
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode
            == 0
        )
    if not verified:
        raise RuntimeError(
            "Selected hosts could not prepare the secret; no local files were changed"
        )
    return access_rules, helper, encrypted, identity


def prepare_secrets(
    stage: Stage,
    config: HelperConfig,
    selected: Sequence[Host],
    manifest: Manifest,
) -> tuple[Path, Path, Path]:
    """Grant a local identity temporary access to all secrets in the manifest."""
    work, rules, worker = stage.work, config.rules, config.worker_source
    if any(
        not key.startswith(("ssh-ed25519 ", "ssh-rsa "))
        for rule in manifest.values()
        for key in rule.public_keys
    ):
        raise ValueError("Reading currently supports only SSH recipients")

    # The private key is outside work, the only directory transferred to workers.
    identity = work.parent / "ephemeral-identity"
    run(
        ["age-keygen", "--output", str(identity)],
        operation="Generate ephemeral identity",
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    identity.chmod(0o600)
    public_key = run(
        ["age-keygen", "-y", str(identity)],
        operation="Derive ephemeral recipient",
        capture_output=True,
        text=True,
    ).stdout.strip()

    temporary_manifest = {
        name: rule.with_recipient(public_key) for name, rule in manifest.items()
    }
    access_rules = write_staged_rules(work, rules, temporary_manifest)
    helper = stage.prepare_worker(worker, temporary_manifest)

    verified = False
    for host in selected:
        if verified:
            break
        process_host(
            work,
            helper,
            host,
            config,
            rules.parent,
            temporary_manifest,
            action="Processed",
            diagnostics_to_stderr=True,
        )
        # Native age recipients cannot be checked by agenix --check. Prove
        # temporary access by decrypting to /dev/null with this operation's key.
        first_secret = next(iter(temporary_manifest))
        encrypted = work / rules.parent / first_secret
        verified = (
            run(
                [
                    "age",
                    "--decrypt",
                    "--identity",
                    str(identity),
                    "--output",
                    os.devnull,
                    str(encrypted),
                ],
                operation="Verify ephemeral access",
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode
            == 0
        )
    if not verified:
        raise RuntimeError(
            "Selected hosts could not prepare the secrets; no local files were changed"
        )
    return access_rules, helper, identity


def read_secrets(
    stage: Stage,
    config: HelperConfig,
    selected: Sequence[Host],
    manifest: Manifest,
) -> int:
    work = stage.work
    access_rules, _, identity = prepare_secrets(stage, config, selected, manifest)
    multiple = len(manifest) > 1
    for secret in manifest:
        if multiple:
            print(f"==> {secret} <==", flush=True)
        run(
            ["agenix", "--decrypt", secret, "--identity", str(identity)],
            operation=f"Read {secret}",
            env={
                **os.environ,
                "AGENIX_RULES": str(work / access_rules),
                "TMPDIR": str(work.parent),
            },
            check=True,
        )
        if multiple:
            print(flush=True)  # blank line between secrets
    return 0


def read_secret(
    stage: Stage,
    config: HelperConfig,
    selected: Sequence[Host],
    secret: str,
    rule: SecretRule,
) -> int:
    """Single-secret read; delegates to read_secrets() for a shared code path."""
    return read_secrets(stage, config, selected, {secret: rule})


def edit_secret(
    stage: Stage,
    config: HelperConfig,
    selected: Sequence[Host],
    secret: str,
    rule: SecretRule,
) -> int:
    work, rules = stage.work, config.rules
    repo = stage.repo
    if not os.isatty(0):
        raise ValueError(
            "Editing requires interactive stdin; piped input is not supported"
        )
    if not os.environ.get("EDITOR") or os.environ["EDITOR"] == ":":
        raise ValueError("Set EDITOR to the editor to use")
    edit_rules, helper, encrypted, identity = prepare_secret(
        stage, config, selected, secret, rule
    )
    relative = rules.parent / secret
    recipients = helper / "recipients" / secret

    # Agenix plaintext stays in a private local directory created after the final transfer.
    editor_temp = work.parent / "editor"
    editor_temp.mkdir(mode=0o700)
    editor_status = editor_temp / "status"
    editor_pid = editor_temp / "pid"
    editor_wrapper = editor_temp / "editor.py"
    # Agenix can continue after a failed editor; record its status independently.
    editor_wrapper.write_text(
        "import os, sys\n"
        "sys.dont_write_bytecode = True\n"
        "sys.path.insert(0, os.environ['AGENIX_HELPER_RUNTIME'])\n"
        "from agenix_helper.process import editor_entrypoint\n"
        "sys.exit(editor_entrypoint())\n"
    )
    try:
        run(
            ["agenix", "--edit", secret, "--identity", str(identity)],
            operation=f"Edit {secret}",
            env={
                **os.environ,
                "AGENIX_RULES": str(work / edit_rules),
                "TMPDIR": str(editor_temp),
                "EDITOR": f"{shlex.quote(sys.executable)} {shlex.quote(str(editor_wrapper))}",
                "AGENIX_HELPER_RUNTIME": str(helper),
                "AGENIX_HELPER_EDITOR": os.environ["EDITOR"],
                "AGENIX_HELPER_EDITOR_STATUS": str(editor_status),
                "AGENIX_HELPER_EDITOR_PID": str(editor_pid),
            },
            check=True,
        )
    finally:
        cancel_editor(editor_pid, editor_status)
    if not editor_status.is_file() or editor_status.read_text() != "0":
        raise RuntimeError("Editor failed; no local files were changed")

    # Always reencrypt, including when agenix skips an unchanged edit. Only this file is processed.
    recipients.write_text("\n".join(rule.public_keys) + "\n")
    WorkerConfig((str(identity),), rules.parent, action="Processed").write(helper)
    run(
        [sys.executable, str(helper / "worker.py")],
        operation="Restore original recipients",
    )
    (work / edit_rules.with_suffix(".json")).write_text(
        json.dumps({secret: rule.to_json()})
    )
    if not check_rules(work, edit_rules, show_output=True):
        raise RuntimeError(
            "Final recipients do not match the original rules; no local files were changed"
        )
    stage.assert_unchanged("editing")
    write_changed_file(encrypted, repo / relative)
    print(f"Updated {relative} in {repo}; original recipients restored")
    return 0


def rekey_secrets(
    stage: Stage,
    config: HelperConfig,
    selected: Sequence[Host],
    manifest: Manifest,
    targeted: bool,
) -> int:
    work, rules = stage.work, config.rules
    check_rules_path = write_staged_rules(work, rules, manifest) if targeted else rules
    helper = stage.prepare_worker(config.worker_source, manifest)
    if check_rules(work, check_rules_path):
        print("All recipients already match the rules; no files were changed.")
        return 0
    verified = False
    for host in selected:
        process_host(
            work, helper, host, config, rules.parent, manifest, action="Processed"
        )
        if check_rules(work, check_rules_path):
            verified = True
            print(f"All recipients match the rules after {host.name}")
            break
    if not verified:
        print(
            "Some secrets still have mismatched recipients; no local files were changed.",
            file=sys.stderr,
        )
        check_rules(work, check_rules_path, show_output=True)
        return 1
    stage.assert_unchanged("rekeying")
    updated = 0
    for secret in manifest:
        relative = rules.parent / secret
        if not filecmp.cmp(stage.original / relative, work / relative, shallow=False):
            write_changed_file(work / relative, stage.repo / relative)
            updated += 1
    print(f"Updated {updated} encrypted files in {stage.repo}")
    return 0

"""Local worker execution and SSH transport of staged ciphertext."""

import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from .config import Host, ToolkitConfig, WorkerConfig
from .process import pipe, run
from .rules import Manifest
from .staging import reject_symlinks

REMOTE_DIRECTORY = re.compile(r"/tmp/agenix-toolkit\.[A-Za-z0-9]{8}\Z")


def transfer_to_host(
    work: Path, target: str, remote: str, diagnostics_to_stderr: bool
) -> None:
    pipe(
        ["tar", "-C", str(work), "-cf", "-", "."],
        ["ssh", target, f"tar -C {shlex.quote(remote)} -xf -"],
        operation=f"Send staged files to {target}",
        consumer_stdout=sys.stderr if diagnostics_to_stderr else None,
    )


def transfer_from_host(
    destination: Path, target: str, remote: str, diagnostics_to_stderr: bool
) -> None:
    pipe(
        ["ssh", target, f"tar -C {shlex.quote(remote)} -cf - ."],
        ["tar", "-C", str(destination), "-xf", "-"],
        operation=f"Receive staged files from {target}",
        consumer_stdout=sys.stderr if diagnostics_to_stderr else None,
    )


def run_host(
    work: Path,
    helper: Path,
    host: Host,
    rules_dir: Path,
    config: ToolkitConfig,
    diagnostics_to_stderr: bool,
) -> Path:
    assert host.target is not None
    target = host.target
    WorkerConfig(host.identity_paths, rules_dir).write(helper)
    result = run(
        ["ssh", target, "mktemp -d /tmp/agenix-toolkit.XXXXXXXX"],
        operation=f"Create staging directory on {target}",
        stdout=subprocess.PIPE,
        text=True,
    )
    remote = result.stdout.strip()
    if not REMOTE_DIRECTORY.fullmatch(remote):
        raise RuntimeError(f"Unexpected remote staging path: {remote!r}")
    try:
        transfer_to_host(work, target, remote, diagnostics_to_stderr)
        worker = f"{remote}/.agenix-toolkit/worker.py"
        command = shlex.join(
            [
                "nix",
                "--extra-experimental-features",
                "nix-command flakes",
                "shell",
                config.python_ref,
                config.age_ref,
                "--command",
                "python3",
                worker,
            ]
        )
        run(
            ["ssh", target, command],
            operation=f"Run worker on {target}",
            stdout=sys.stderr if diagnostics_to_stderr else None,
        )
        returned = work.parent / "returned"
        returned.mkdir()
        transfer_from_host(returned, target, remote, diagnostics_to_stderr)
        return returned
    finally:
        # Cleanup is best effort when a connection fails; preserve the original failure.
        try:
            run(
                ["ssh", target, f"rm -rf -- {shlex.quote(remote)}"],
                operation=f"Clean staging directory on {target}",
                check=False,
                stdout=subprocess.DEVNULL,
            )
        except OSError as error:
            print(
                f"Could not clean staging directory on {target}: {error}",
                file=sys.stderr,
            )


def process_host(
    work: Path,
    helper: Path,
    host: Host,
    config: ToolkitConfig,
    rules_dir: Path,
    manifest: Manifest,
    diagnostics_to_stderr: bool = False,
) -> None:
    target = "local" if host.local else host.target
    print(
        f"Processing {host.name} ({target})",
        file=sys.stderr if diagnostics_to_stderr else sys.stdout,
        flush=True,
    )
    if host.local:
        WorkerConfig(host.identity_paths, rules_dir).write(helper)
        run(
            [sys.executable, str(helper / "worker.py")],
            operation=f"Run local worker for {host.name}",
            stdout=sys.stderr if diagnostics_to_stderr else None,
        )
        return
    returned = run_host(work, helper, host, rules_dir, config, diagnostics_to_stderr)
    try:
        if config.mode.accessing:
            reject_symlinks(returned)
        for secret in manifest:
            relative = rules_dir / secret
            shutil.copy2(returned / relative, work / relative)
    finally:
        shutil.rmtree(returned)

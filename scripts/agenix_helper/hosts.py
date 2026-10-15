"""Local worker execution and SSH transport of staged ciphertext."""

import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from pathlib import Path
from threading import Event

from .config import HelperConfig, Host, WorkerConfig
from .process import CommandError, cancellation, check_cancelled, pipe, run
from .rules import Manifest
from .staging import reject_symlinks

REMOTE_DIRECTORY = re.compile(r"/tmp/agenix-helper\.[A-Za-z0-9]{8}\Z")


def ssh_command(target: str, command: str) -> list[str]:
    return [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ConnectionAttempts=1",
        "-o",
        "ServerAliveInterval=5",
        "-o",
        "ServerAliveCountMax=1",
        target,
        command,
    ]


def transfer_to_host(
    work: Path, target: str, remote: str, diagnostics_to_stderr: bool
) -> None:
    pipe(
        ["tar", "-C", str(work), "-cf", "-", "."],
        ssh_command(target, f"tar -C {shlex.quote(remote)} -xf -"),
        operation=f"Send staged files to {target}",
        consumer_stdout=sys.stderr if diagnostics_to_stderr else None,
    )


def transfer_from_host(
    destination: Path, target: str, remote: str, diagnostics_to_stderr: bool
) -> None:
    pipe(
        ssh_command(target, f"tar -C {shlex.quote(remote)} -cf - ."),
        ["tar", "-C", str(destination), "-xf", "-"],
        operation=f"Receive staged files from {target}",
        consumer_stdout=sys.stderr if diagnostics_to_stderr else None,
    )


def run_host(
    work: Path,
    helper: Path,
    host: Host,
    rules_dir: Path,
    config: HelperConfig,
    diagnostics_to_stderr: bool,
    action: str,
) -> Path:
    assert host.target is not None
    target = host.target
    WorkerConfig(host.identity_paths, rules_dir, action).write(helper)
    result = run(
        ssh_command(target, "mktemp -d /tmp/agenix-helper.XXXXXXXX"),
        operation=f"Create staging directory on {target}",
        stdout=subprocess.PIPE,
        text=True,
    )
    remote = result.stdout.strip()
    if not REMOTE_DIRECTORY.fullmatch(remote):
        raise RuntimeError(f"Unexpected remote staging path: {remote!r}")
    try:
        transfer_to_host(work, target, remote, diagnostics_to_stderr)
        worker = f"{remote}/.agenix-helper/worker.py"
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
            ssh_command(target, command),
            operation=f"Run worker on {target}",
            stdout=sys.stderr if diagnostics_to_stderr else None,
        )
        returned = work.parent / "returned"
        returned.mkdir()
        transfer_from_host(returned, target, remote, diagnostics_to_stderr)
        return returned
    finally:
        # Cleanup is best effort when a connection fails; preserve the original failure.
        token = cancellation.set(None)
        try:
            run(
                ssh_command(target, f"rm -rf -- {shlex.quote(remote)}"),
                operation=f"Clean staging directory on {target}",
                check=False,
                stdout=subprocess.DEVNULL,
            )
        except OSError as error:
            print(
                f"Could not clean staging directory on {target}: {error}",
                file=sys.stderr,
            )
        finally:
            cancellation.reset(token)


def process_host(
    work: Path,
    helper: Path,
    host: Host,
    config: HelperConfig,
    rules_dir: Path,
    manifest: Manifest,
    action: str,
    diagnostics_to_stderr: bool = False,
) -> None:
    target = "local" if host.local else host.target
    print(
        f"Processing {host.name} ({target})",
        file=sys.stderr if diagnostics_to_stderr else sys.stdout,
        flush=True,
    )
    if host.local:
        WorkerConfig(host.identity_paths, rules_dir, action).write(helper)
        run(
            [sys.executable, str(helper / "worker.py")],
            operation=f"Run local worker for {host.name}",
            stdout=sys.stderr if diagnostics_to_stderr else None,
        )
        return
    returned = run_host(
        work, helper, host, rules_dir, config, diagnostics_to_stderr, action
    )
    try:
        if config.mode.accessing:
            reject_symlinks(returned)
        for secret in manifest:
            relative = rules_dir / secret
            shutil.copy2(returned / relative, work / relative)
    finally:
        shutil.rmtree(returned)


@contextmanager
def processed_hosts(
    work: Path,
    selected: Sequence[Host],
    config: HelperConfig,
    rules_dir: Path,
    manifest: Manifest,
    *,
    diagnostics_to_stderr: bool = False,
) -> Iterator[Iterator[tuple[Host, Path]]]:
    """Run workers on independent snapshots; keep results until the caller merges them."""
    stopped = Event()
    with tempfile.TemporaryDirectory(prefix="hosts.", dir=work.parent) as directory:
        root = Path(directory)
        # The shared work directory changes as results are merged. All workers
        # must start from the same immutable snapshot, without the ephemeral key.
        snapshot = root / "snapshot"
        shutil.copytree(work, snapshot, symlinks=True)

        def execute(index: int, host: Host) -> Path | None:
            token = cancellation.set(stopped)
            try:
                check_cancelled()
                host_work = root / str(index) / "work"
                shutil.copytree(snapshot, host_work, symlinks=True)
                process_host(
                    host_work,
                    host_work / ".agenix-helper",
                    host,
                    config,
                    rules_dir,
                    manifest,
                    action="Processed",
                    diagnostics_to_stderr=diagnostics_to_stderr,
                )
                return host_work
            except CommandError as error:
                if not host.local and any(
                    command[0] == "ssh" and status == 255
                    for command, status in error.failed_commands
                ):
                    print(
                        f"Skipping unreachable host {host.name} ({host.target}): {error}",
                        file=sys.stderr,
                        flush=True,
                    )
                    return None
                raise
            finally:
                cancellation.reset(token)

        executor = ThreadPoolExecutor(max_workers=config.max_concurrency)
        futures = {}
        iterator = None
        try:
            for index, host in enumerate(selected):
                futures[executor.submit(execute, index, host)] = host

            def results() -> Iterator[tuple[Host, Path]]:
                for future in as_completed(futures):
                    host_work = future.result()
                    if host_work is not None:
                        try:
                            yield futures[future], host_work
                        finally:
                            shutil.rmtree(host_work.parent)

            iterator = results()
            yield iterator
        finally:
            # Interrupts and worker errors stop subprocesses before removing
            # staging. Each remote attempt still performs best-effort cleanup.
            stopped.set()
            executor.shutdown(wait=True, cancel_futures=True)
            if iterator is not None:
                iterator.close()

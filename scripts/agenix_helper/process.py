"""Argument-list subprocess execution, pipeline cleanup, and entry-point errors."""

import os
import shlex
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Iterator, Sequence
from concurrent.futures import CancelledError
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from threading import Event
from typing import Any


class CommandError(RuntimeError):
    """An external command failed without committing staged results."""

    def __init__(self, message: str, *, failed_commands=()):
        super().__init__(message)
        self.failed_commands = failed_commands


cancellation: ContextVar[Event | None] = ContextVar("cancellation", default=None)


def check_cancelled() -> None:
    event = cancellation.get()
    if event is not None and event.is_set():
        raise CancelledError()


def interrupt(signum: int, frame: object) -> None:
    raise KeyboardInterrupt


def stop(child: subprocess.Popen) -> None:
    if child.poll() is not None:
        return
    try:
        child.terminate()
    except ProcessLookupError:
        return
    try:
        child.wait(timeout=2)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait()


@contextmanager
def spawn(command: Sequence[str], **options: Any) -> Iterator[subprocess.Popen]:
    check_cancelled()
    child = subprocess.Popen(list(command), **options)
    try:
        yield child
    finally:
        stop(child)
        for stream in (child.stdin, child.stdout, child.stderr):
            if stream is not None:
                stream.close()


def run(
    command: Sequence[str], *, operation: str, check: bool = True, **options: Any
) -> subprocess.CompletedProcess:
    input_data = options.pop("input", None)
    if input_data is not None:
        options["stdin"] = subprocess.PIPE
    if options.pop("capture_output", False):
        options["stdout"] = options["stderr"] = subprocess.PIPE
    with spawn(command, **options) as child:
        while True:
            check_cancelled()
            try:
                stdout, stderr = child.communicate(input_data, timeout=0.1)
                break
            except subprocess.TimeoutExpired:
                # communicate retains buffered input/output across retries.
                input_data = None
        result = subprocess.CompletedProcess(
            list(command), child.returncode, stdout, stderr
        )
    if check and result.returncode:
        raise CommandError(
            f"{operation} failed (exit status {result.returncode})",
            failed_commands=((tuple(command), result.returncode),),
        )
    return result


def pipe(
    producer: Sequence[str],
    consumer: Sequence[str],
    *,
    operation: str,
    consumer_stdout: Any = None,
) -> None:
    with spawn(producer, stdout=subprocess.PIPE) as source:
        assert source.stdout is not None
        with spawn(
            consumer, stdin=source.stdout, stdout=consumer_stdout
        ) as destination:
            source.stdout.close()
            destination_status = wait_child(destination)
        source_status = wait_child(source)
    if source_status or destination_status:
        raise CommandError(
            f"{operation} failed (producer status {source_status}, consumer status {destination_status})",
            failed_commands=tuple(
                (tuple(command), status)
                for command, status in (
                    (producer, source_status),
                    (consumer, destination_status),
                )
                if status
            ),
        )


def wait_child(child: subprocess.Popen) -> int:
    while True:
        check_cancelled()
        try:
            return child.wait(timeout=0.1)
        except subprocess.TimeoutExpired:
            pass


def entrypoint(main: Callable[[], int]) -> int:
    signal.signal(signal.SIGTERM, interrupt)
    try:
        return main()
    except KeyboardInterrupt:
        print("Interrupted; staged changes were not committed.", file=sys.stderr)
        return 130
    except (
        KeyError,
        OSError,
        ValueError,
        RuntimeError,
        subprocess.SubprocessError,
    ) as error:
        print(error, file=sys.stderr)
        return 1


def editor_entrypoint() -> int:
    """Record editor status and whether its plaintext changed."""
    Path(os.environ["AGENIX_HELPER_EDITOR_PID"]).write_text(str(os.getpid()))

    def edit() -> int:
        plaintext = Path(sys.argv[-1])
        original = plaintext.read_bytes()
        code = run(
            [*shlex.split(os.environ["AGENIX_HELPER_EDITOR"]), *sys.argv[1:]],
            operation="Run editor",
            check=False,
        ).returncode
        if code == 0:
            changed = plaintext.read_bytes() != original
            Path(os.environ["AGENIX_HELPER_EDITOR_CHANGED"]).write_text(
                "1" if changed else "0"
            )
        return code

    code = entrypoint(edit)
    Path(os.environ["AGENIX_HELPER_EDITOR_STATUS"]).write_text(str(code))
    return code


def cancel_editor(pid_path: Path, status_path: Path) -> None:
    """Stop the owned editor wrapper before discarding its private temporary directory."""
    if status_path.exists() or not pid_path.exists():
        return
    pid = int(pid_path.read_text())
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 3
    while not status_path.exists():
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        if time.monotonic() >= deadline:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            return
        time.sleep(0.02)

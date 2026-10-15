"""Argument-list subprocess execution, pipeline cleanup, and entry-point errors."""

import os
import shlex
import signal
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator, Sequence


class CommandError(RuntimeError):
    """An external command failed without committing staged results."""


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
        stdout, stderr = child.communicate(input_data)
        result = subprocess.CompletedProcess(
            list(command), child.returncode, stdout, stderr
        )
    if check and result.returncode:
        raise CommandError(f"{operation} failed (exit status {result.returncode})")
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
            destination_status = destination.wait()
        source_status = source.wait()
    if source_status or destination_status:
        raise CommandError(
            f"{operation} failed (producer status {source_status}, consumer status {destination_status})"
        )


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
    """Record the editor's status even when agenix continues after its failure."""
    Path(os.environ["AGENIX_HELPER_EDITOR_PID"]).write_text(str(os.getpid()))
    code = entrypoint(
        lambda: (
            run(
                [*shlex.split(os.environ["AGENIX_HELPER_EDITOR"]), *sys.argv[1:]],
                operation="Run editor",
                check=False,
            ).returncode
        )
    )
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

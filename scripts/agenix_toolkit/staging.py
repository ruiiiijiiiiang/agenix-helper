"""Snapshot, stage, and commit ciphertext without changing live source files early."""

from __future__ import annotations

import filecmp
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Sequence

if TYPE_CHECKING:
    from .rules import Manifest


@dataclass(frozen=True)
class Stage:
    repo: Path
    original: Path
    work: Path
    sources: tuple[Path, ...]

    @classmethod
    def create(cls, repo: Path, scratch: Path, sources: tuple[Path, ...]) -> Stage:
        original, work = scratch / "original", scratch / "work"
        original.mkdir()
        work.mkdir()
        for source in sources:
            copy_source(repo / source, original / source)
        for source in sources:
            copy_source(original / source, work / source)
        return cls(repo, original, work, sources)

    def assert_unchanged(self, operation: str) -> None:
        for source in self.sources:
            if not same_source(self.repo / source, self.original / source):
                raise RuntimeError(
                    f"Source changed while {operation}: {source}; no local files were changed"
                )

    def prepare_worker(self, worker_source: Path, manifest: Manifest) -> Path:
        helper = self.work / ".agenix-toolkit"
        if helper.exists():
            raise ValueError("Reserved staging path exists in sources")
        (helper / "recipients").mkdir(parents=True)
        (helper / "armor").mkdir()
        shutil.copy2(worker_source, helper / "worker.py")
        # Imports must work from the isolated staged bundle, without the controller's checkout.
        shutil.copytree(
            worker_source.parent / "agenix_toolkit",
            helper / "agenix_toolkit",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        # copytree preserves read-only Nix store directory modes. The staged
        # copy must be removable locally and after its round trip to a worker.
        runtime = helper / "agenix_toolkit"
        for directory in [runtime, *(path for path in runtime.rglob("*") if path.is_dir())]:
            directory.chmod(stat.S_IMODE(directory.stat().st_mode) | stat.S_IRWXU)
        for name, rule in manifest.items():
            recipients = helper / "recipients" / name
            recipients.parent.mkdir(parents=True, exist_ok=True)
            recipients.write_text("\n".join(rule.public_keys) + "\n")
            if rule.armor:
                armored = helper / "armor" / name
                armored.parent.mkdir(parents=True, exist_ok=True)
                armored.touch()
        return helper


def validate_sources(
    repo: Path, sources: Sequence[Path], identities: Sequence[Path]
) -> None:
    for source in sources:
        source_path = repo / source
        if any(part.is_symlink() for part in [source_path, *source_path.parents]):
            raise ValueError(
                f"Symlinks are not supported for local secret operations: {source}"
            )
        reject_symlinks(source_path)
        if any(key == source_path or source_path in key.parents for key in identities):
            raise ValueError(
                "The local private key must be outside sources sent to hosts"
            )


def copy_source(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.is_symlink():
        destination.symlink_to(os.readlink(source))
    elif source.is_dir():
        shutil.copytree(source, destination, symlinks=True, dirs_exist_ok=True)
    else:
        shutil.copy2(source, destination)


def same_source(left: Path, right: Path) -> bool:
    if left.is_symlink() or right.is_symlink():
        return (
            left.is_symlink()
            and right.is_symlink()
            and os.readlink(left) == os.readlink(right)
        )
    if left.is_file() or right.is_file():
        return (
            left.is_file()
            and right.is_file()
            and filecmp.cmp(left, right, shallow=False)
        )
    if not left.is_dir() or not right.is_dir():
        return False
    left_names = {entry.name for entry in left.iterdir()}
    if left_names != {entry.name for entry in right.iterdir()}:
        return False
    return all(same_source(left / name, right / name) for name in left_names)


def write_changed_file(source: Path, destination: Path) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f"{destination.name}.rekey.", dir=destination.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        shutil.copy2(source, temporary)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def reject_symlinks(path: Path) -> None:
    """Keep staged edits and transfers independent of paths outside the snapshot."""
    if path.is_symlink():
        raise ValueError(
            f"Symlinks are not supported for local secret operations: {path}"
        )
    if path.is_dir():
        for child in path.iterdir():
            reject_symlinks(child)
    elif not path.is_file():
        raise ValueError(f"Not a regular file or directory: {path}")

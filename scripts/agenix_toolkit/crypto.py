"""Identity resolution and age pipes used by the staged worker."""

import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from .config import WorkerConfig, home_path
from .process import pipe, run


def readable_identities(config: WorkerConfig) -> tuple[Path, ...]:
    identities = []
    for value in config.identity_paths:
        path = home_path(value)
        if not path.is_file() or not os.access(path, os.R_OK):
            print(f"Skipping unreadable identity: {path}", file=sys.stderr)
            continue
        identities.append(path)
    if not identities:
        raise RuntimeError("No readable identity files on this host")
    return tuple(identities)


def reencrypt(
    encrypted: Path,
    recipients: Path,
    decrypt: list[str],
    armor: bool,
) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f"{encrypted.name}.rekey.",
        dir=encrypted.parent,
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        encrypt = ["age", "--encrypt", "--recipients-file", str(recipients)]
        if armor:
            encrypt.append("--armor")
        encrypt.extend(["--output", str(temporary)])
        pipe([*decrypt, str(encrypted)], encrypt, operation=f"Rekey {encrypted.name}")
        os.chmod(temporary, stat.S_IMODE(encrypted.stat().st_mode))
        os.replace(temporary, encrypted)
    finally:
        temporary.unlink(missing_ok=True)


def worker_main(helper: Path) -> int:
    config = WorkerConfig.load(helper / "config.json")
    decrypt = ["age", "--decrypt"]
    for identity in readable_identities(config):
        decrypt.extend(["--identity", str(identity)])
    recipients_dir = helper / "recipients"
    rekeyed = skipped = 0
    for recipients in sorted(recipients_dir.rglob("*.age")):
        relative = recipients.relative_to(recipients_dir)
        encrypted = helper.parent / config.rules_dir / relative
        if not encrypted.is_file():
            raise RuntimeError(f"Missing encrypted file: {relative}")
        probe = run(
            [*decrypt, "--output", os.devnull, str(encrypted)],
            operation=f"Probe {relative}",
            check=False,
            stderr=subprocess.DEVNULL,
        )
        if probe.returncode:
            skipped += 1
            continue
        reencrypt(
            encrypted, recipients, decrypt, (helper / "armor" / relative).exists()
        )
        rekeyed += 1
    print(f"Rekeyed: {rekeyed}; unreadable: {skipped}")
    return 0

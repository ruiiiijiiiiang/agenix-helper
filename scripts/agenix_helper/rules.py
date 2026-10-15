"""Evaluate secret rules and verify staged recipients."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Mapping, Sequence

from .config import relative_path
from .process import run


@dataclass(frozen=True)
class SecretRule:
    public_keys: tuple[str, ...]
    armor: bool
    attributes: Mapping[str, object]

    @classmethod
    def from_json(cls, name: str, value: object) -> SecretRule:
        relative_path(name)
        if not name.endswith(".age") or not isinstance(value, dict):
            raise ValueError(f"Invalid secret rule: {name}")
        keys = value.get("publicKeys")
        if (
            not isinstance(keys, list)
            or not keys
            or any(not isinstance(key, str) or not key or "\n" in key for key in keys)
        ):
            raise ValueError(f"Invalid recipient list: {name}")
        return cls(tuple(keys), value.get("armor") is True, value)

    def with_recipient(self, public_key: str) -> SecretRule:
        return replace(
            self, public_keys=tuple(dict.fromkeys([*self.public_keys, public_key]))
        )

    def to_json(self) -> dict[str, object]:
        return {**self.attributes, "publicKeys": list(self.public_keys)}


Manifest = dict[str, SecretRule]


def load_manifest(work: Path, rules: Path, requested: Sequence[str]) -> Manifest:
    result = run(
        [
            "nix-instantiate",
            "--eval",
            "--strict",
            "--json",
            "--expr",
            "{ rules }: import (builtins.toPath rules)",
            "--argstr",
            "rules",
            str(work / rules),
        ],
        operation="Evaluate secret rules",
        capture_output=True,
        text=True,
    )
    values = json.loads(result.stdout)
    if not isinstance(values, dict):
        raise ValueError("Agenix rules must evaluate to an attribute set")
    if requested:
        for name in requested:
            if name not in values:
                raise ValueError(f"Unknown secret: {name}")
        values = {name: values[name] for name in requested}
    manifest = {
        name: SecretRule.from_json(name, value) for name, value in values.items()
    }
    for name in manifest:
        if not (work / rules.parent / name).is_file():
            raise ValueError(f"Missing encrypted file: {name}")
    return manifest


def check_rules(
    work: Path,
    rules: Path,
    show_output: bool = False,
    diagnostics_to_stderr: bool = False,
) -> bool:
    result = run(
        ["agenix", "--check"],
        operation="Check secret recipients",
        env={**os.environ, "AGENIX_RULES": str(work / rules)},
        stdout=(sys.stderr if diagnostics_to_stderr else None)
        if show_output
        else subprocess.DEVNULL,
        stderr=None if show_output else subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def write_staged_rules(work: Path, rules: Path, manifest: Manifest) -> Path:
    """Use JSON to preserve evaluated rule attributes without rewriting Nix source."""
    generated = rules.parent / ".agenix-helper-access.nix"
    data = rules.parent / ".agenix-helper-access.json"
    for relative in (generated, data):
        if (work / relative).exists():
            raise ValueError(f"Reserved staging path exists in sources: {relative}")
    (work / data).write_text(
        json.dumps({name: rule.to_json() for name, rule in manifest.items()})
    )
    (work / generated).write_text(
        "builtins.fromJSON (builtins.readFile ./.agenix-helper-access.json)\n"
    )
    return generated

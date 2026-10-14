"""Typed configuration and identity validation at the JSON boundary."""

import json
import os
import socket
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Mode(str, Enum):
    REKEY = "rekey"
    EDIT = "edit"
    READ = "read"

    @property
    def accessing(self) -> bool:
        return self in (Mode.EDIT, Mode.READ)


def relative_path(value: object) -> Path:
    if not isinstance(value, str) or not value or "\n" in value or "\x00" in value:
        raise ValueError(f"Invalid relative path: {value!r}")
    if value.startswith("/") or any(
        part in ("", ".", "..") for part in value.split("/")
    ):
        raise ValueError(f"Invalid relative path: {value!r}")
    return Path(value)


def identity_paths(data: Mapping[str, object], message: str) -> tuple[str, ...]:
    paths = data.get(
        "identityPaths", [data["identity"]] if "identity" in data else None
    )
    if (
        not isinstance(paths, list)
        or not paths
        or any(
            not isinstance(path, str)
            or not path
            or any(character in path for character in ("\n", "\r", "\x00"))
            for path in paths
        )
    ):
        raise ValueError(message)
    return tuple(dict.fromkeys(paths))


def home_path(value: str) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else Path.home() / path


@dataclass(frozen=True)
class Host:
    name: str
    identity_paths: tuple[str, ...]
    local: bool = False
    target: str | None = None

    @classmethod
    def from_json(cls, name: str, value: object) -> "Host":
        if not isinstance(value, dict):
            raise ValueError(f"Unknown or incomplete host: {name}")
        local_mode = value.get("local", False)
        automatic = local_mode == "auto"
        if not isinstance(local_mode, bool) and not automatic:
            raise ValueError(f"Host local flag must be a boolean or 'auto': {name}")
        if "localHostname" in value and not automatic:
            raise ValueError(f"Host localHostname requires local = 'auto': {name}")
        target = value.get("target")
        if local_mode is True and "target" in value:
            raise ValueError(f"Local host must omit its SSH target: {name}")
        if local_mode is not True and (not isinstance(target, str) or not target):
            raise ValueError(f"Unknown or incomplete host: {name}")
        if automatic:
            expected = value.get("localHostname", name)
            if not isinstance(expected, str) or not expected.strip().rstrip("."):
                raise ValueError(
                    f"Host localHostname must be a nonempty string: {name}"
                )
            current = socket.gethostname().casefold().rstrip(".")
            expected = expected.casefold().rstrip(".")
            local = current == expected or current.split(".", 1)[0] == expected
        else:
            local = local_mode
        paths = identity_paths(
            value, f"Host {name} requires a nonempty identityPaths list or identity"
        )
        if local:
            resolved = tuple(home_path(path).resolve() for path in paths)
            if not any(
                path.is_file() and os.access(path, os.R_OK) for path in resolved
            ):
                raise ValueError(f"No readable identity files for local host {name}")
            paths = tuple(str(path) for path in resolved)
        return cls(name, paths, local, target)


@dataclass(frozen=True)
class ToolkitConfig:
    mode: Mode
    rules: Path
    sources: tuple[Path, ...]
    host_definitions: Mapping[str, object]
    worker_source: Path
    python_ref: str = "nixpkgs#python3"
    age_ref: str = "nixpkgs#age"

    @classmethod
    def load(cls, path: Path, worker_source: Path) -> "ToolkitConfig":
        value = json.loads(path.read_text())
        if not isinstance(value, dict):
            raise ValueError("Toolkit configuration must be an attribute set")
        mode_value = value.get("mode", "rekey")
        try:
            mode = Mode(mode_value)
        except ValueError:
            raise ValueError(f"Unknown mode: {mode_value}") from None
        rules = relative_path(value["rules"])
        source_values = value["sources"]
        if not isinstance(source_values, list) or not source_values:
            raise ValueError("At least one source path is required")
        sources = tuple(relative_path(source) for source in source_values)
        hosts = value["hosts"]
        if not isinstance(hosts, dict):
            raise ValueError("Hosts must be an attribute set")
        if "publicKey" in value or "publicKeys" in value:
            raise ValueError(
                "publicKey/publicKeys are no longer supported; access uses an ephemeral age key"
            )
        python_ref = value.get("pythonRef", "nixpkgs#python3")
        age_ref = value.get("ageRef", "nixpkgs#age")
        if not all(isinstance(ref, str) and ref for ref in (python_ref, age_ref)):
            raise ValueError("Package references must be nonempty strings")
        return cls(
            mode,
            rules,
            sources,
            hosts,
            worker_source,
            python_ref,
            age_ref,
        )

    def select_hosts(self, names: list[str] | None) -> tuple[Host, ...]:
        selected = (
            sorted(self.host_definitions)
            if names is None
            else list(dict.fromkeys(names))
        )
        if not selected:
            raise ValueError("No hosts selected or configured")
        for name in selected:
            if name not in self.host_definitions:
                raise ValueError(f"Unknown or incomplete host: {name}")
        return tuple(
            Host.from_json(name, self.host_definitions[name]) for name in selected
        )


@dataclass(frozen=True)
class WorkerConfig:
    identity_paths: tuple[str, ...]
    rules_dir: Path
    action: str

    @classmethod
    def load(cls, path: Path) -> "WorkerConfig":
        value = json.loads(path.read_text())
        if not isinstance(value, dict):
            raise ValueError("Worker configuration must be an attribute set")
        paths = identity_paths(value, "Worker requires a nonempty identityPaths list")
        directory = value["rules_dir"]
        action = value.get("action")
        if not isinstance(action, str) or not action:
            raise ValueError("Worker requires a nonempty action string")
        return cls(
            paths,
            Path(".") if directory == "." else relative_path(directory),
            action,
        )

    def write(self, helper: Path) -> None:
        (helper / "config.json").write_text(
            json.dumps(
                {
                    "identityPaths": list(self.identity_paths),
                    "rules_dir": str(self.rules_dir),
                    "action": self.action,
                }
            )
        )

"""Controller arguments, validation, and workflow dispatch."""

import argparse
import os
import re
import sys
import tempfile
from pathlib import Path

from .config import HelperConfig, Mode, relative_path
from .operations import edit_secret, read_secrets, rekey_secrets
from .rules import load_manifest
from .staging import Stage, validate_sources


def parse_args(config: HelperConfig) -> tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(
        description="Rekey, edit, or read staged agenix secrets through selected hosts.",
        allow_abbrev=False,
    )
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument(
        "--host",
        action="append",
        dest="hosts",
        metavar="NAME",
        help="Host to use; repeat to try several, or omit to try all configured hosts in sorted order",
    )
    parser.add_argument("--dry-run", action="store_true")
    if config.mode.accessing:
        if config.mode == Mode.READ:
            parser.description = (
                "Read one or more agenix secrets with a temporary local recipient."
            )
            parser.add_argument(
                "secrets",
                nargs="*",
                metavar="SECRET",
                help="Secret paths relative to the rules directory; use --all-secrets to read all",
            )
            parser.add_argument(
                "--all-secrets",
                action="store_true",
                help="Explicitly read every secret in the rules",
            )
        else:
            parser.description = (
                "Edit one agenix secret with a temporary local recipient."
            )
            parser.add_argument(
                "secret", help="Secret path relative to the rules directory"
            )
    else:
        parser.add_argument(
            "secrets",
            nargs="*",
            metavar="SECRET",
            help="Secret paths relative to the rules directory; use --all-secrets to select all",
        )
        parser.add_argument(
            "--all-secrets",
            action="store_true",
            help="Explicitly select every secret in the rules",
        )
    args = parser.parse_args()
    if config.mode == Mode.READ:
        if args.all_secrets and args.secrets:
            parser.error("--all-secrets cannot be combined with secret paths")
        if not args.all_secrets and not args.secrets:
            parser.error(
                "Specify at least one secret, or pass --all-secrets to read all"
            )
    elif not config.mode.accessing:  # rekey
        if args.all_secrets and args.secrets:
            parser.error("--all-secrets cannot be combined with secret paths")
        if not args.all_secrets and not args.secrets:
            parser.error(
                "Specify at least one secret, or pass --all-secrets to select all"
            )
    if config.mode == Mode.READ:
        requested = list(dict.fromkeys(args.secrets))
    elif config.mode == Mode.EDIT:
        requested = [args.secret]
    else:
        requested = list(dict.fromkeys(args.secrets))
    for secret in requested:
        relative_path(secret)
        if not re.fullmatch(r"[A-Za-z0-9_./-]+", secret):
            raise ValueError(
                "Secret paths may contain only letters, numbers, underscores, dots, slashes, and hyphens"
            )
    return args, requested


def main() -> int:
    config = HelperConfig.load(
        Path(os.environ["AGENIX_HELPER_CONFIG"]),
        Path(os.environ["AGENIX_HELPER_WORKER"]),
    )
    args, requested = parse_args(config)
    repo = args.repo.resolve(strict=True)
    selected = config.select_hosts(args.hosts)
    for source in config.sources:
        if not (repo / source).exists():
            raise ValueError(f"Missing source: {source}")
    if not (repo / config.rules).is_file():
        raise ValueError(f"Missing rules: {config.rules}")
    local_identities = [
        Path(path) for host in selected if host.local for path in host.identity_paths
    ]
    if config.mode.accessing or local_identities:
        validate_sources(repo, config.sources, local_identities)
    with tempfile.TemporaryDirectory(
        prefix="agenix-helper.", dir="/tmp"
    ) as scratch_name:
        stage = Stage.create(repo, Path(scratch_name), config.sources)
        manifest = load_manifest(stage.work, config.rules, requested)
        print(
            f"Rules: {config.rules}; secrets: {len(manifest)}; hosts: {' '.join(host.name for host in selected)}",
            file=sys.stderr if config.mode == Mode.READ else sys.stdout,
            flush=True,
        )
        if not config.mode.accessing and requested:
            print(f"Selected secrets: {' '.join(manifest)}", flush=True)
        if args.dry_run:
            return 0
        if config.mode == Mode.READ:
            return read_secrets(stage, config, selected, manifest)
        if config.mode == Mode.EDIT:
            return edit_secret(
                stage,
                config,
                selected,
                args.secret,
                manifest[args.secret],
            )
        return rekey_secrets(stage, config, selected, manifest, bool(requested))

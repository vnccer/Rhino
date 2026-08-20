from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from . import __version__
from .collector import Collector
from .config import CollectorConfig
from .events import host_context
from .http_client import enroll

DEFAULT_CONFIG = Path("/etc/aasm-collector/config.ini")


def _write_credential(path: Path, credential: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "collector_id": credential["collector_id"],
                    "host_id": credential["host_id"],
                    "api_key": credential["api_key"],
                    "credential_expires_at": credential["credential_expires_at"],
                },
                handle,
                separators=(",", ":"),
            )
            handle.write("\n")
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if temporary.exists():
            temporary.unlink()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AI-Agent Security Monitor Linux collector")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--version", action="version", version=__version__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("run", help="run the collector foreground service")
    subcommands.add_parser("check-config", help="validate configuration and credentials")
    enroll_parser = subcommands.add_parser("enroll", help="exchange a one-time token for credentials")
    enroll_parser.add_argument("--token", default=os.environ.get("AASM_ENROLLMENT_TOKEN"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = CollectorConfig.load(args.config)
        if args.command == "enroll":
            if not args.token:
                raise ValueError("provide --token or AASM_ENROLLMENT_TOKEN")
            credential = enroll(
                config.api_url,
                args.token,
                host_context(__version__),
                config.request_timeout_seconds,
                config.ca_cert,
            )
            _write_credential(config.credential_file, credential)
            print(f"enrolled collector {credential['collector_id']} for host {credential['host_id']}")
            return 0
        if not config.credential_file.is_file():
            raise ValueError(f"credential file is missing: {config.credential_file}")
        json.loads(config.credential_file.read_text(encoding="utf-8"))
        if args.command == "check-config":
            print("configuration and credential file are valid")
            return 0
        logging.basicConfig(
            level=os.environ.get("AASM_LOG_LEVEL", "INFO"),
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )
        Collector(config).run()
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"aasm-collector: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


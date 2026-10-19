"""Entry point: `pwmanager` or `python -m pwmanager`."""

from __future__ import annotations

import argparse
from pathlib import Path

from .vault import default_vault_path


def main() -> int:
    parser = argparse.ArgumentParser(prog="pwmanager", description="Local encrypted password manager")
    parser.add_argument(
        "--vault",
        type=Path,
        default=default_vault_path(),
        help=f"path to the vault file (default: {default_vault_path()})",
    )
    args = parser.parse_args()

    from .gui.app import run

    return run(args.vault.expanduser())


if __name__ == "__main__":
    raise SystemExit(main())

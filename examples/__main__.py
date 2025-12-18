#!/usr/bin/env python3
"""Dispatcher for the examples package.

Usage:
  python -m examples ecdh
  python -m examples schnorr
"""

from __future__ import annotations

from pathlib import Path
import argparse
import sys


# Make `src/` importable when running from a source checkout (no pip install needed).
_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if _SRC.exists():
    sys.path.insert(0, str(_SRC))


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m examples")
    p.add_argument(
        "example",
        choices=["ecdh", "schnorr"],
        help="Which example to run",
    )
    return p


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)

    if args.example == "ecdh":
        from . import ecdh as mod
    else:
        from . import schnorr as mod

    return int(mod.main())


if __name__ == "__main__":
    raise SystemExit(main())


#!/usr/bin/env python3
"""ECDH example (Python)

This mirrors the libsecp256k1 C example at:
  https://github.com/bitcoin-core/secp256k1/blob/master/examples/ecdh.c

Run from the project root (no installation required):
  python examples/ecdh.py

Or:
  python -m examples ecdh
"""

from __future__ import annotations

from pathlib import Path
import secrets
import sys


# Make `src/` importable when running from a source checkout (no pip install needed).
_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if _SRC.exists():
    sys.path.insert(0, str(_SRC))


from secp256k1lab.ecdh import ecdh_libsecp256k1
from secp256k1lab.keys import pubkey_gen_plain
from secp256k1lab.secp256k1 import GE


def _rand_seckey() -> bytes:
    """Return a valid 32-byte secp256k1 secret key (1..n-1)."""
    d = secrets.randbelow(GE.ORDER - 1) + 1
    return d.to_bytes(32, byteorder="big")


def _print_hex_line(label: str, b: bytes) -> None:
    print(f"{label}{b.hex()}")


def main() -> int:
    # Key generation (two parties).
    seckey1 = _rand_seckey()
    seckey2 = _rand_seckey()

    pubkey1 = pubkey_gen_plain(seckey1)  # 33-byte compressed pubkey
    pubkey2 = pubkey_gen_plain(seckey2)

    # ECDH shared secret (libsecp256k1 default: SHA256(compressed(shared_point))).
    shared_secret1 = ecdh_libsecp256k1(seckey1, pubkey2)
    shared_secret2 = ecdh_libsecp256k1(seckey2, pubkey1)

    # Both parties should end up with the same shared secret.
    assert shared_secret1 == shared_secret2

    _print_hex_line("Secret Key1: ", seckey1)
    _print_hex_line("Compressed Pubkey1: ", pubkey1)
    print()
    _print_hex_line("Secret Key2: ", seckey2)
    _print_hex_line("Compressed Pubkey2: ", pubkey2)
    print()
    _print_hex_line("Shared Secret: ", shared_secret1)

    # Note: In C you can securely erase sensitive buffers. Python can't guarantee this
    # for immutable `bytes` objects; treat this example as educational only.

    return 0


if __name__ == "__main__":
    raise SystemExit(main())


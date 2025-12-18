#!/usr/bin/env python3
"""Schnorr (BIP340) example (Python)

This mirrors the libsecp256k1 C example at:
  https://github.com/bitcoin-core/secp256k1/blob/master/examples/schnorr.c

Run from the project root (no installation required):
  python examples/schnorr.py

Or:
  python -m examples schnorr
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


from secp256k1lab.bip340 import pubkey_gen, schnorr_sign, schnorr_verify
from secp256k1lab.secp256k1 import GE
from secp256k1lab.util import tagged_hash


def _rand_seckey() -> bytes:
    """Return a valid 32-byte secp256k1 secret key (1..n-1)."""
    d = secrets.randbelow(GE.ORDER - 1) + 1
    return d.to_bytes(32, byteorder="big")


def _print_hex_line(label: str, b: bytes) -> None:
    print(f"{label}{b.hex()}")


def main() -> int:
    # Message and "protocol tag" (domain separation).
    msg = b"Hello World!"
    tag = "my_fancy_protocol"

    # Sign a 32-byte tagged SHA256 hash of the message.
    msg_hash = tagged_hash(tag, msg)
    assert len(msg_hash) == 32

    # Key generation.
    seckey = _rand_seckey()
    pubkey_xonly = pubkey_gen(seckey)  # 32-byte x-only pubkey

    # BIP340 recommends 32 bytes of auxiliary randomness.
    aux_rand = secrets.token_bytes(32)

    # Sign and verify.
    signature = schnorr_sign(msg_hash, seckey, aux_rand)
    is_valid = schnorr_verify(msg_hash, pubkey_xonly, signature)

    print(f"Is the signature valid? {'true' if is_valid else 'false'}")
    _print_hex_line("Secret Key: ", seckey)
    _print_hex_line("Public Key: ", pubkey_xonly)
    _print_hex_line("Signature: ", signature)

    return 0 if is_valid else 1


if __name__ == "__main__":
    raise SystemExit(main())


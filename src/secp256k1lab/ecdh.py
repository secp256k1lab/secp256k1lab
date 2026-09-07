import hashlib

from .secp256k1 import GE, Scalar


def ecdh_compressed_in_raw_out(seckey: bytes, pubkey: bytes) -> GE:
    """Compute the ECDH shared secret point from a secret key and a compressed public key."""
    shared_secret = Scalar.from_bytes_nonzero_checked(seckey) * GE.from_bytes_compressed(pubkey)
    # Write x = seckey and y = dlog(pubkey). Then x != 0 and y != 0
    # imply x*y != 0 because the scalar group has prime order and thus
    # is a finite field (it has the same order as secp256k1).
    assert not shared_secret.infinity
    return shared_secret


def ecdh_libsecp256k1(seckey: bytes, pubkey: bytes) -> bytes:
    """Compute the ECDH shared secret as libsecp256k1 does: SHA256 of the compressed shared point."""
    shared_secret = ecdh_compressed_in_raw_out(seckey, pubkey)
    return hashlib.sha256(shared_secret.to_bytes_compressed()).digest()

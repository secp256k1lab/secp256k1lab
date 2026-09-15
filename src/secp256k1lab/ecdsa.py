import hmac

from .secp256k1 import GE, G, Scalar


def rfc6979_nonce(seckey: bytes, msghash: bytes) -> Scalar:
    """Compute signing nonce using RFC6979."""
    keydata = seckey + msghash
    v = bytes([1] * 32)
    k = bytes([0] * 32)
    k = hmac.new(k, v + b"\x00" + keydata, 'sha256').digest()
    v = hmac.new(k, v, 'sha256').digest()
    k = hmac.new(k, v + b"\x01" + keydata, 'sha256').digest()
    v = hmac.new(k, v, 'sha256').digest()
    return Scalar.from_bytes_checked(hmac.new(k, v, 'sha256').digest())


def ecdsa_sign(msghash: bytes, seckey: bytes) -> bytes:
    """Construct a strictly DER-encoded ECDSA signature.

    See https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm for the
    ECDSA signer algorithm."""
    if len(msghash) != 32:
        raise ValueError("The message hash must be a 32-byte array.")
    if len(seckey) != 32:
        raise ValueError("The secret key must be a 32-byte array.")
    try:
        d = Scalar.from_bytes_nonzero_checked(seckey)
    except ValueError:
        raise ValueError("The secret key must represent an integer in the range 1..n-1.")
    z = Scalar.from_bytes_wrapping(msghash)
    k = rfc6979_nonce(seckey, msghash)
    R = k * G
    r = Scalar(int(R.x))
    s = (k ** (-1)) * (z + d * r)
    if int(s) > GE.ORDER_HALF:
        s = -s
    # Represent in DER format. The byte representations of r and s have
    # length rounded up (255 bits becomes 32 bytes and 256 bits becomes 33
    # bytes).
    rb = int(r).to_bytes((int(r).bit_length() + 8) // 8, 'big')
    sb = int(s).to_bytes((int(s).bit_length() + 8) // 8, 'big')
    return b'\x30' + bytes([4 + len(rb) + len(sb), 2, len(rb)]) + rb + bytes([2, len(sb)]) + sb


def ecdsa_verify(msghash: bytes, pubkey: bytes, sig: bytes) -> bool:
    """Verify a strictly DER-encoded ECDSA signature.

    See https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm for the
    ECDSA verifier algorithm."""
    if len(msghash) != 32:
        raise ValueError("The message hash must be a 32-byte array.")
    if len(pubkey) not in (33, 65):
        raise ValueError("The public key must be a 33-byte or 65-byte array.")

    # Extract r and s from the DER formatted signature. Return false for
    # any DER encoding errors.
    if not (8 <= len(sig) <= 72):
        return False
    if (sig[1] + 2 != len(sig)):
        return False
    if (len(sig) < 4):
        return False
    if (sig[0] != 0x30):
        return False
    if (sig[2] != 0x02):
        return False
    rlen = sig[3]
    if (len(sig) < 6 + rlen):
        return False
    if rlen < 1 or rlen > 33:
        return False
    if sig[4] >= 0x80:
        return False
    if (rlen > 1 and (sig[4] == 0) and not (sig[5] & 0x80)):
        return False
    try:
        r = Scalar.from_bytes_nonzero_checked(sig[4:4+rlen])
    except ValueError:
        return False
    if (sig[4+rlen] != 0x02):
        return False
    slen = sig[5+rlen]
    if slen < 1 or slen > 33:
        return False
    if (len(sig) != 6 + rlen + slen):
        return False
    if sig[6+rlen] >= 0x80:
        return False
    if (slen > 1 and (sig[6+rlen] == 0) and not (sig[7+rlen] & 0x80)):
        return False
    try:
        s = Scalar.from_bytes_nonzero_checked(sig[6+rlen:6+rlen+slen])
    except ValueError:
        return False

    if int(s) > GE.ORDER_HALF:
        return False
    z = Scalar.from_bytes_wrapping(msghash)

    # Run verifier algorithm on r, s
    w = s ** (-1)
    P = GE.from_bytes_compressed(pubkey) if len(pubkey) == 33 else GE.from_bytes_uncompressed(pubkey)
    R = GE.batch_mul((z * w, G), (r * w, P))
    if R.infinity or Scalar(int(R.x)) != r:
        return False
    return True

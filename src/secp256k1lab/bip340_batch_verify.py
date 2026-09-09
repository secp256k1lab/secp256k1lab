# This module implements Schnorr batch verification as specified in BIP340:
# https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#user-content-Batch_Verification
from typing import List

from .secp256k1 import GE, G, Scalar
from .util import tagged_hash


def schnorr_batch_verify(msgs: List[bytes], pubkeys: List[bytes], sigs: List[bytes]) -> bool:
    if not (len(msgs) == len(pubkeys) == len(sigs)):
        raise ValueError("Lists of messages, pubkeys and signatures must have equal sizes.")
    if not all([len(pubkey) == 32 for pubkey in pubkeys]):
        raise ValueError("Public keys must be 32 byte arrays each.")
    if not all([len(sig) == 64 for sig in sigs]):
        raise ValueError("Signatures must be 64 byte arrays each.")

    u = len(sigs)
    P, R, s, e, a = [GE()]*u, [GE()]*u, [Scalar()]*u, [Scalar()]*u, [Scalar()]*u
    for i in range(u):
        try:
            P[i] = GE.from_bytes_xonly(pubkeys[i])
            R[i] = GE.from_bytes_xonly(sigs[i][0:32])
            s[i] = Scalar.from_bytes_checked(sigs[i][32:64])
        except ValueError:
            return False
        e[i] = Scalar.from_bytes_wrapping(tagged_hash("BIP0340/challenge",
                R[i].to_bytes_xonly() + P[i].to_bytes_xonly() + msgs[i]))
        # generate deterministic random coefficients (note that BIP340 suggests doing this using
        # a seeded CSPRNG; we use a hash function instead, in order to keep it simple and avoid
        # additional dependencies in potential low-level implementations like libsecp256k1)
        a[i] = Scalar(1) if i == 0 else Scalar.from_bytes_wrapping(tagged_hash("BIP0340/batch_verify_randomize",
                sigs[i] + msgs[i] + P[i].to_bytes_compressed()))

    # check that the verification equation holds (note that a_1 = 1):
    # (a_1*s_1 + ... + a_u*s_u) * G = a_1*R_1 + ... + a_u*R_u  +  (a_1*e_1)*P_1 + ... + (a_u*e_u)*P_u
    lhs_ge = Scalar.sum(*[a[i] * s[i] for i in range(u)]) * G
    rhs_batch_aps = []
    for i in range(u):
        rhs_batch_aps.extend([(a[i], R[i]), (a[i] * e[i], P[i])])
    return lhs_ge == GE.batch_mul(*rhs_batch_aps)

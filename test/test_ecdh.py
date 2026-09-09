from random import randbytes
import unittest

from secp256k1lab.ecdh import ecdh_libsecp256k1
from secp256k1lab.keys import pubkey_gen_plain


class ECDHTests(unittest.TestCase):
    """Test ECDH module."""

    def test_correctness(self):
        seckey_alice = randbytes(32)
        pubkey_alice = pubkey_gen_plain(seckey_alice)
        seckey_bob = randbytes(32)
        pubkey_bob = pubkey_gen_plain(seckey_bob)
        shared_secret1 = ecdh_libsecp256k1(seckey_alice, pubkey_bob)
        shared_secret2 = ecdh_libsecp256k1(seckey_bob, pubkey_alice)
        self.assertEqual(shared_secret1, shared_secret2)

    def test_known_answer(self):
        # Vector cross-checked against libsecp256k1's default ECDH, which
        # hashes the compressed shared point with SHA256.
        seckey_a = bytes.fromhex("01" * 32)
        pubkey_b = bytes.fromhex(
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        )
        expected = bytes.fromhex(
            "80a9f99957b29af20338037cf06360bc55422e5bba0032bb4136498c278a7db1"
        )
        self.assertEqual(ecdh_libsecp256k1(seckey_a, pubkey_b), expected)

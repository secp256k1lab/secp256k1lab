from hashlib import sha256
import json
from pathlib import Path
from random import randbytes
import unittest

from secp256k1lab.ecdsa import ecdsa_sign, ecdsa_verify
from secp256k1lab.keys import pubkey_gen_plain


class ECDSATests(unittest.TestCase):
    """Test ECDSA signatures."""

    def test_correctness(self):
        seckey = randbytes(32)
        pubkey = pubkey_gen_plain(seckey)
        message = b'this is some arbitrary message'
        msghash = sha256(message).digest()
        signature = ecdsa_sign(msghash, seckey)
        success = ecdsa_verify(msghash, pubkey, signature)
        self.assertTrue(success)

    def test_wycheproof_vectors(self):
        # Test against vectors from the Wycheproof repository
        # [https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/ecdsa_secp256k1_sha256_bitcoin_test.json]
        vectors_file = Path(__file__).parent / "vectors" / "wycheproof-ecdsa_secp256k1_sha256_bitcoin_test.json"
        with open(vectors_file, encoding='utf8') as jsonfile:
            vectors = json.load(jsonfile)
            for group in vectors['testGroups']:
                pubkey = bytes.fromhex(group['publicKey']['uncompressed'])
                for case in group['tests']:
                    with self.subTest(i=case['tcId']):
                        self.subtest_wycheproof_vectors_case(pubkey, case)

    def subtest_wycheproof_vectors_case(self, pubkey, case):
        msghash = sha256(bytes.fromhex(case['msg'])).digest()
        sig = bytes.fromhex(case['sig'])
        result_str = case['result']
        comment = case['comment']

        result = result_str == 'valid'
        assert result or result_str == 'invalid'
        result_actual = ecdsa_verify(msghash, pubkey, sig)
        if result:
            self.assertEqual(result, result_actual, f"ECDSA test vector ({comment}): verification failed unexpectedly")
        else:
            self.assertEqual(result, result_actual, f"ECDSA test vector ({comment}): verification succeeded unexpectedly")

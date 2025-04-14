#!/usr/bin/env python3
from random import randbytes
from secp256k1lab.bip340 import pubkey_gen, schnorr_sign, schnorr_verify
from secp256k1lab.ecdh import ecdh_libsecp256k1
from secp256k1lab.keys import pubkey_gen_plain

# test schnorr signatures (BIP 340)
seckey = randbytes(32)
pubkey_xonly = pubkey_gen(seckey)
aux_rand = randbytes(32)
message = b'this is some arbitrary message'
signature = schnorr_sign(message, seckey, aux_rand)
success = schnorr_verify(message, pubkey_xonly, signature)
assert success

# test ECDH
seckey_alice = randbytes(32)
pubkey_alice = pubkey_gen_plain(seckey_alice)
seckey_bob = randbytes(32)
pubkey_bob = pubkey_gen_plain(seckey_bob)
shared_secret1 = ecdh_libsecp256k1(seckey_alice, pubkey_bob)
shared_secret2 = ecdh_libsecp256k1(seckey_bob, pubkey_alice)
assert shared_secret1 == shared_secret2

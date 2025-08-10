import unittest

from secp256k1lab.secp256k1 import G, GE


class Secp256k1Tests(unittest.TestCase):
    """Test low-level secp256k1 field and group arithmetic classes."""

    def test_group_element_serialization(self):
        # GE serialization and parsing round-trip
        point_at_infinity = GE()
        generator_point = G
        bitcoin_genesis_block_pubkey = GE(
            0x678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6,
            0x49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f
        )

        for ge_orig in [point_at_infinity, generator_point, bitcoin_genesis_block_pubkey]:
            if ge_orig.infinity:
                with self.assertRaises(AssertionError):
                    _ = ge_orig.to_bytes_uncompressed()
                with self.assertRaises(AssertionError):
                    _ = ge_orig.to_bytes_compressed()
                with self.assertRaises(AssertionError):
                    _ = ge_orig.to_bytes_xonly()
            else:
                # uncompressed serialization: 65 bytes, starts with 0x04
                ge_ser = ge_orig.to_bytes_uncompressed()
                self.assertEqual(len(ge_ser), 65)
                self.assertEqual(ge_ser[0], 0x04)
                ge_deser = GE.from_bytes_uncompressed(ge_ser)
                self.assertEqual(ge_deser, ge_orig)

                # compressed serialization: 33 bytes, starts with 0x02 (if y is even) or 0x03 (if y is odd)
                ge_ser = ge_orig.to_bytes_compressed()
                self.assertEqual(len(ge_ser), 33)
                self.assertEqual(ge_ser[0], 0x02 if ge_orig.has_even_y() else 0x03)
                ge_deser = GE.from_bytes_compressed(ge_ser)
                self.assertEqual(ge_deser, ge_orig)

                # x-only serialization: 32 bytes
                ge_ser = ge_orig.to_bytes_xonly()
                self.assertEqual(len(ge_ser), 32)
                ge_deser = GE.from_bytes_xonly(ge_ser)
                if not ge_orig.has_even_y():  # x-only implies even y, so flip if necessary
                    ge_deser = -ge_deser
                self.assertEqual(ge_deser, ge_orig)

            # compressed serialization, supporting also infinity
            ge_ser = ge_orig.to_bytes_compressed_with_infinity()
            self.assertEqual(len(ge_ser), 33)
            if ge_orig.infinity:
                self.assertEqual(ge_ser, b'\x00'*33)
            else:
                self.assertEqual(ge_ser[0], 0x02 if ge_orig.has_even_y() else 0x03)
            ge_deser = GE.from_bytes_compressed_with_infinity(ge_ser)
            self.assertEqual(ge_deser, ge_orig)

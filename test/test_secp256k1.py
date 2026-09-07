"""Test low-level secp256k1 field and group arithmetic classes."""
from random import randint
import unittest

from secp256k1lab.secp256k1 import FE, G, GE, Scalar


class PrimeFieldTests(unittest.TestCase):
    def test_fe_constructors(self):
        P = FE.SIZE
        random_fe_valid = randint(0, P-1)
        random_fe_overflowing = randint(P, 2**256-1)

        # wrapping constructors
        for init_value in [0, P-1, P, P+1, random_fe_valid, random_fe_overflowing]:
            fe1 = FE(init_value)
            fe2 = FE.from_int_wrapping(init_value)
            fe3 = FE.from_bytes_wrapping(init_value.to_bytes(32, 'big'))
            reduced_value = init_value % P
            self.assertEqual(int(fe1), reduced_value)
            self.assertEqual(int(fe1), int(fe2))
            self.assertEqual(int(fe2), int(fe3))

        # checking constructors (should throw on overflow)
        for valid_value in [0, P-1, random_fe_valid]:
            fe1 = FE.from_int_checked(valid_value)
            fe2 = FE.from_bytes_checked(valid_value.to_bytes(32, 'big'))
            self.assertEqual(int(fe1), valid_value)
            self.assertEqual(int(fe1), int(fe2))

        for overflow_value in [P, P+1, random_fe_overflowing]:
            with self.assertRaises(ValueError):
                _ = FE.from_int_checked(overflow_value)
            with self.assertRaises(ValueError):
                _ = FE.from_bytes_checked(overflow_value.to_bytes(32, 'big'))

    def test_scalar_constructors(self):
        N = Scalar.SIZE
        random_scalar_valid = randint(0, N-1)
        random_scalar_overflowing = randint(N, 2**256-1)

        # wrapping constructors
        for init_value in [0, N-1, N, N+1, random_scalar_valid, random_scalar_overflowing]:
            s1 = Scalar(init_value)
            s2 = Scalar.from_int_wrapping(init_value)
            s3 = Scalar.from_bytes_wrapping(init_value.to_bytes(32, 'big'))
            reduced_value = init_value % N
            self.assertEqual(int(s1), reduced_value)
            self.assertEqual(int(s1), int(s2))
            self.assertEqual(int(s2), int(s3))

        # checking constructors (should throw on overflow)
        for valid_value in [0, N-1, random_scalar_valid]:
            s1 = Scalar.from_int_checked(valid_value)
            s2 = Scalar.from_bytes_checked(valid_value.to_bytes(32, 'big'))
            self.assertEqual(int(s1), valid_value)
            self.assertEqual(int(s1), int(s2))

        for overflow_value in [N, N+1, random_scalar_overflowing]:
            with self.assertRaises(ValueError):
                _ = Scalar.from_int_checked(overflow_value)
            with self.assertRaises(ValueError):
                _ = Scalar.from_bytes_checked(overflow_value.to_bytes(32, 'big'))

        # non-zero checking constructors (should throw on zero or overflow, only for Scalar)
        random_nonzero_scalar_valid = randint(1, N-1)
        for valid_value in [1, N-1, random_nonzero_scalar_valid]:
            s1 = Scalar.from_int_nonzero_checked(valid_value)
            s2 = Scalar.from_bytes_nonzero_checked(valid_value.to_bytes(32, 'big'))
            self.assertEqual(int(s1), valid_value)
            self.assertEqual(int(s1), int(s2))

        for invalid_value in [0, N, random_scalar_overflowing]:
            with self.assertRaises(ValueError):
                _ = Scalar.from_int_nonzero_checked(invalid_value)
            with self.assertRaises(ValueError):
                _ = Scalar.from_bytes_nonzero_checked(invalid_value.to_bytes(32, 'big'))


class GeSerializationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.point_at_infinity = GE()
        cls.group_elements_on_curve = [
            # generator point
            G,
            # Bitcoin genesis block public key
            GE(0x678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6,
               0x49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f),
        ]
        # generate a few random points, to likely cover both even/odd y polarity
        cls.group_elements_on_curve.extend([randint(1, Scalar.SIZE-1) * G for _ in range(8)])
        # generate x coordinates that don't have a valid point on the curve
        # (note that ~50% of all x coordinates are valid, so finding one needs two loop iterations on average)
        cls.x_coords_not_on_curve = []
        while len(cls.x_coords_not_on_curve) < 8:
            x = randint(0, FE.SIZE-1)
            if not GE.is_valid_x(x):
                cls.x_coords_not_on_curve.append(x)

        cls.group_elements = [cls.point_at_infinity] + cls.group_elements_on_curve

    def test_infinity_raises(self):
        with self.assertRaises(AssertionError):
            _ = self.point_at_infinity.to_bytes_uncompressed()
        with self.assertRaises(AssertionError):
            _ = self.point_at_infinity.to_bytes_compressed()
        with self.assertRaises(AssertionError):
            _ = self.point_at_infinity.to_bytes_xonly()

    def test_not_on_curve_raises(self):
        # for compressed and x-only GE deserialization, test with invalid x coordinate
        for x in self.x_coords_not_on_curve:
            x_bytes = x.to_bytes(32, 'big')
            with self.assertRaises(ValueError):
                _ = GE.from_bytes_compressed(b'\x02' + x_bytes)
            with self.assertRaises(ValueError):
                _ = GE.from_bytes_compressed(b'\x03' + x_bytes)
            with self.assertRaises(ValueError):
                _ = GE.from_bytes_compressed_with_infinity(b'\x02' + x_bytes)
            with self.assertRaises(ValueError):
                _ = GE.from_bytes_compressed_with_infinity(b'\x03' + x_bytes)
            with self.assertRaises(ValueError):
                _ = GE.from_bytes_xonly(x_bytes)

        # for uncompressed GE serialization, test by invalidating either coordinate
        for ge in self.group_elements_on_curve:
            valid_x = ge.x
            valid_y = ge.y
            invalid_x = ge.x + 1
            invalid_y = ge.y + 1

            # valid cases (if point (x,y) is on the curve, then point(x,-y) is on the curve as well)
            _ = GE.from_bytes_uncompressed(b'\x04' + valid_x.to_bytes() + valid_y.to_bytes())
            _ = GE.from_bytes_uncompressed(b'\x04' + valid_x.to_bytes() + (-valid_y).to_bytes())
            # invalid cases (curve equation y**2 = x**3 + 7 doesn't hold)
            self.assertNotEqual(invalid_y**2, valid_x**3 + 7)
            with self.assertRaises(ValueError):
                _ = GE.from_bytes_uncompressed(b'\x04' + valid_x.to_bytes() + invalid_y.to_bytes())
            self.assertNotEqual(valid_y**2, invalid_x**3 + 7)
            with self.assertRaises(ValueError):
                _ = GE.from_bytes_uncompressed(b'\x04' + invalid_x.to_bytes() + valid_y.to_bytes())

    def test_affine(self):
        # GE serialization and parsing round-trip (variants that only support serializing points on the curve)
        for ge_orig in self.group_elements_on_curve:
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

    def test_affine_with_infinity(self):
        # GE serialization and parsing round-trip (variants that also support serializing the point at infinity)
        for ge_orig in self.group_elements:
            # compressed serialization: 33 bytes, all-zeros for point at infinity
            ge_ser = ge_orig.to_bytes_compressed_with_infinity()
            self.assertEqual(len(ge_ser), 33)
            if ge_orig.infinity:
                self.assertEqual(ge_ser, b'\x00'*33)
            else:
                self.assertEqual(ge_ser[0], 0x02 if ge_orig.has_even_y() else 0x03)
            ge_deser = GE.from_bytes_compressed_with_infinity(ge_ser)
            self.assertEqual(ge_deser, ge_orig)


class GeArithmeticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # a few random on-curve points, likely covering both even/odd y polarity
        cls.points = [randint(1, Scalar.SIZE-1) * G for _ in range(5)]

    def test_batch_mul(self):
        # fixed, hand-checkable case: 2*G + 3*G == 5*G
        self.assertEqual(GE.batch_mul((Scalar(2), G), (Scalar(3), G)), Scalar(5) * G)

        # multi-pair batch_mul against the naive sum of individual scalar multiplications
        pairs = [(Scalar(randint(1, Scalar.SIZE-1)), p) for p in self.points]
        expected = GE()
        for a, p in pairs:
            expected = expected + a * p
        self.assertEqual(GE.batch_mul(*pairs), expected)

        # a zero scalar contributes nothing, so the sum is unchanged
        pairs_with_zero = [(Scalar(0), self.points[0])] + pairs
        self.assertEqual(GE.batch_mul(*pairs_with_zero), expected)

    def test_sum(self):
        P, Q, R = self.points[:3]
        # GE.sum folds the arguments into (GE() + P + Q + R)
        self.assertEqual(GE.sum(P, Q, R), P + Q + R)
        # the empty sum is the point at infinity, the single-element sum is that element
        self.assertEqual(GE.sum(), GE())
        self.assertEqual(GE.sum(P), P)

    def test_from_bytes_dispatch(self):
        for p in self.points:
            # 33-byte input is dispatched to the compressed parser and round-trips
            comp = p.to_bytes_compressed()
            self.assertEqual(GE.from_bytes(comp), GE.from_bytes_compressed(comp))
            self.assertEqual(GE.from_bytes(comp), p)

            # 65-byte input is dispatched to the uncompressed parser and round-trips
            uncomp = p.to_bytes_uncompressed()
            self.assertEqual(GE.from_bytes(uncomp), GE.from_bytes_uncompressed(uncomp))
            self.assertEqual(GE.from_bytes(uncomp), p)

    def test_add_neg_sub_group_law(self):
        P, Q, R = self.points[:3]

        for p in self.points:
            # the point at infinity is the additive identity
            self.assertEqual(GE() + p, p)
            self.assertEqual(p + GE(), p)
            # a point plus its own negation is the point at infinity
            neg_p = -p
            self.assertEqual(p + neg_p, GE())
            # negation is an involution
            self.assertEqual(-neg_p, p)
            # equal inputs take the doubling branch of __add__ (tangent line)
            self.assertEqual(p + p, Scalar(2) * p)
            # subtracting a point from itself is the point at infinity
            self.assertEqual(p - p, GE())

        # distinct inputs take the adding branch, and addition commutes
        self.assertEqual(P + Q, Q + P)
        # addition is associative
        self.assertEqual((P + Q) + R, P + (Q + R))
        # subtraction is addition of the negation
        self.assertEqual(P - Q, P + (-Q))
        # scalar multiples of one point add by adding their scalars: 2*P + 3*P == 5*P
        self.assertEqual(Scalar(2) * P + Scalar(3) * P, Scalar(5) * P)

"""RFC 4231 HMAC-SHA256 known-answer and behavioral tests."""

from __future__ import annotations

import hashlib
import hmac as std_hmac
import random
import unittest

from hmaclab import HmacSha256, hmac_sha256, hmac_sha256_hex


class Rfc4231Tests(unittest.TestCase):
    """RFC 4231 test cases 1-4, 6, 7 for HMAC-SHA-256, asserted exactly."""

    def test_case_1(self):
        key = bytes([0x0B] * 20)
        self.assertEqual(
            hmac_sha256_hex(key, b"Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b"
            "881dc200c9833da726e9376c2e32cff7",
        )

    def test_case_2_short_key(self):
        self.assertEqual(
            hmac_sha256_hex(b"Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c7"
            "5a003f089d2739839dec58b964ec3843",
        )

    def test_case_3(self):
        key = bytes([0xAA] * 20)
        self.assertEqual(
            hmac_sha256_hex(key, bytes([0xDD] * 50)),
            "773ea91e36800e46854db8ebd09181a7"
            "2959098b3ef8c122d9635514ced565fe",
        )

    def test_case_4(self):
        key = bytes(range(1, 26))
        self.assertEqual(
            hmac_sha256_hex(key, bytes([0xCD] * 50)),
            "82558a389a443c0ea4cc819899f2083a"
            "85f0faa3e578f8077a2e3ff46729665b",
        )

    def test_case_6_key_longer_than_block(self):
        """131-byte key must be hashed down before XORing with ipad/opad."""
        key = bytes([0xAA] * 131)
        msg = b"Test Using Larger Than Block-Size Key - Hash Key First"
        self.assertEqual(
            hmac_sha256_hex(key, msg),
            "60e431591ee0b67f0d8a26aacbf5b77f"
            "8e0bc6213728c5140546040f0ee37f54",
        )

    def test_case_7_long_key_and_long_message(self):
        key = bytes([0xAA] * 131)
        msg = (
            b"This is a test using a larger than block-size key and a "
            b"larger than block-size data. The key needs to be hashed "
            b"before being used by the HMAC algorithm."
        )
        self.assertEqual(
            hmac_sha256_hex(key, msg),
            "9b09ffa71b942fcb27635fbcd5b0e944"
            "bfdc63644f0713938a7f51535c3a35e2",
        )


class HmacBehaviorTests(unittest.TestCase):

    def test_streaming_equals_one_shot(self):
        rng = random.Random(4242)
        key = rng.randbytes(rng.randrange(1, 100))
        msg = rng.randbytes(rng.randrange(0, 500))
        streamed = HmacSha256(key)
        pos = 0
        while pos < len(msg):
            step = rng.randrange(1, 64)
            streamed.update(msg[pos:pos + step])
            pos += step
        self.assertEqual(streamed.digest(), hmac_sha256(key, msg))

    def test_differential_against_hmac_module(self):
        rng = random.Random(99)
        for _ in range(50):
            key = rng.randbytes(rng.randrange(0, 200))
            msg = rng.randbytes(rng.randrange(0, 500))
            self.assertEqual(
                hmac_sha256(key, msg),
                std_hmac.new(key, msg, hashlib.sha256).digest(),
            )

    def test_str_key_matches_bytes_key(self):
        self.assertEqual(
            hmac_sha256("secret", b"msg"), hmac_sha256(b"secret", b"msg")
        )

    def test_digest_is_32_bytes(self):
        self.assertEqual(len(hmac_sha256(b"k", b"m")), 32)

    def test_rejects_bad_key_type(self):
        with self.assertRaises(TypeError):
            hmac_sha256(123, b"m")


if __name__ == "__main__":
    unittest.main()

"""FIPS 180-4 known-answer and differential tests for SHA-256."""

from __future__ import annotations

import hashlib
import random
import unittest

from sha256lab import Sha256, sha256_hexdigest


class FipsKnownAnswerTests(unittest.TestCase):
    """Official NIST/FIPS 180-4 SHA-256 test vectors, asserted exactly."""

    def test_empty_message(self):
        self.assertEqual(
            sha256_hexdigest(b""),
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855",
        )

    def test_abc(self):
        self.assertEqual(
            sha256_hexdigest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223"
            "b00361a396177a9cb410ff61f20015ad",
        )

    def test_448_bit_message(self):
        msg = (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )
        self.assertEqual(
            sha256_hexdigest(msg),
            "248d6a61d20638b8e5c026930c3e6039"
            "a33ce45964ff2167f6ecedd419db06c1",
        )

    def test_896_bit_two_block_message(self):
        msg = (
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
            b"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
        )
        self.assertEqual(
            sha256_hexdigest(msg),
            "cf5b16a778af8380036ce59e7b049237"
            "0b249b11e8f07a51afac45037afee9d1",
        )

    def test_million_a(self):
        """The classic long-input vector: SHA-256 of one million 'a'."""
        self.assertEqual(
            sha256_hexdigest(b"a" * 1_000_000),
            "cdc76e5c9914fb9281a1c7e284d73e67"
            "f1809a48a497200e046d39ccc7112cd0",
        )


class StreamingTests(unittest.TestCase):

    def test_streaming_equals_one_shot(self):
        rng = random.Random(0xC0FFEE)
        for _ in range(20):
            data = rng.randbytes(rng.randrange(0, 500))
            hasher = Sha256()
            pos = 0
            while pos < len(data):
                step = rng.randrange(1, 97)
                hasher.update(data[pos:pos + step])
                pos += step
            self.assertEqual(hasher.hexdigest(), hashlib.sha256(data).hexdigest())

    def test_digest_does_not_finalize(self):
        hasher = Sha256(b"hello")
        first = hasher.digest()
        hasher.update(b" world")
        self.assertEqual(
            hasher.hexdigest(), hashlib.sha256(b"hello world").hexdigest()
        )
        self.assertNotEqual(first, hasher.digest())

    def test_block_boundary_lengths_match_hashlib(self):
        for n in (0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128):
            data = bytes(range(256))[:n]
            self.assertEqual(
                sha256_hexdigest(data),
                hashlib.sha256(data).hexdigest(),
                f"length {n}",
            )

    def test_accepts_str_and_bytearray(self):
        self.assertEqual(
            sha256_hexdigest("abc"), sha256_hexdigest(b"abc")
        )
        self.assertEqual(
            Sha256(bytearray(b"abc")).hexdigest(),
            hashlib.sha256(b"abc").hexdigest(),
        )

    def test_rejects_bad_input_type(self):
        with self.assertRaises(TypeError):
            Sha256().update(12345)

    def test_copy_is_independent(self):
        a = Sha256(b"part one")
        b = a.copy()
        b.update(b" part two")
        self.assertEqual(a.hexdigest(), hashlib.sha256(b"part one").hexdigest())
        self.assertEqual(
            b.hexdigest(), hashlib.sha256(b"part one part two").hexdigest()
        )


class DifferentialTests(unittest.TestCase):

    def test_random_inputs_match_hashlib(self):
        rng = random.Random(20260214)
        for _ in range(100):
            data = rng.randbytes(rng.randrange(0, 1024))
            self.assertEqual(
                sha256_hexdigest(data), hashlib.sha256(data).hexdigest()
            )


if __name__ == "__main__":
    unittest.main()

"""Pure-Python SHA-256 following FIPS 180-4.

Exposes a streaming :class:`Sha256` object with ``update`` / ``digest`` /
``hexdigest`` (mirroring :mod:`hashlib`) plus one-shot helpers.

Implementation notes
--------------------
* Padding follows FIPS 180-4 section 5.1: a ``0x80`` byte, zero fill, and the
  original message length as a 64-bit big-endian *bit* count.
* The 64 round constants are the fractional parts of the cube roots of the
  first 64 primes (section 4.2.2); the initial hash values are the cube roots
  of the first 8 primes (section 4.2.1).
* Every intermediate value is masked to 32 bits to mirror the spec's
  arithmetic modulo 2^32.
"""

from __future__ import annotations

import struct

__all__ = [
    "Sha256",
    "sha256",
    "sha256_digest",
    "sha256_hexdigest",
    "BLOCK_SIZE",
    "DIGEST_SIZE",
]

BLOCK_SIZE = 64
DIGEST_SIZE = 32

# First 32 bits of the fractional parts of the cube roots of the first 64
# primes (FIPS 180-4 section 4.2.2).
_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)

# Initial hash values: first 32 bits of the fractional parts of the cube
# roots of the first 8 primes (FIPS 180-4 section 4.2.1).
_H0 = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)

_MASK = 0xFFFFFFFF


def _rotr(x: int, n: int) -> int:
    """Rotate the 32-bit word *x* right by *n* bits."""
    return ((x >> n) | (x << (32 - n))) & _MASK


def _compress(state: list[int], block: bytes) -> list[int]:
    """Run the 64-round compression function over one 64-byte *block*."""
    w = list(struct.unpack(">16I", block)) + [0] * 48

    # Message schedule (FIPS 180-4 section 6.2).
    for i in range(16, 64):
        x = w[i - 15]
        s0 = _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)
        y = w[i - 2]
        s1 = _rotr(y, 17) ^ _rotr(y, 19) ^ (y >> 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & _MASK

    a, b, c, d, e, f, g, h = state
    for i in range(64):
        big_s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        ch = (e & f) ^ ((~e) & g)
        t1 = (h + big_s1 + ch + _K[i] + w[i]) & _MASK
        big_s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (big_s0 + maj) & _MASK
        h = g
        g = f
        f = e
        e = (d + t1) & _MASK
        d = c
        c = b
        b = a
        a = (t1 + t2) & _MASK

    return [
        (x + y) & _MASK
        for x, y in zip(state, (a, b, c, d, e, f, g, h))
    ]


class Sha256:
    """Streaming SHA-256 message digest.

    The interface mirrors :class:`hashlib.sha256`: ``digest()`` does not
    finalize the object, so further ``update`` calls remain valid.
    """

    def __init__(self, data: bytes | str = b"") -> None:
        self._h: list[int] = list(_H0)
        self._buf: bytes = b""
        self._length: int = 0  # total bytes fed in so far
        if data:
            self.update(data)

    def update(self, data: bytes | bytearray | memoryview | str) -> "Sha256":
        """Feed *data* into the digest; strings are encoded as UTF-8."""
        if isinstance(data, str):
            data = data.encode("utf-8")
        elif isinstance(data, (bytearray, memoryview)):
            data = bytes(data)
        elif not isinstance(data, bytes):
            raise TypeError(
                "SHA-256 input must be bytes-like or str, got "
                f"{type(data).__name__}"
            )
        self._length += len(data)
        buf = self._buf + data
        pos = 0
        end = len(buf)
        while end - pos >= BLOCK_SIZE:
            self._h = _compress(self._h, buf[pos:pos + BLOCK_SIZE])
            pos += BLOCK_SIZE
        self._buf = buf[pos:]
        return self

    def _finalized_state(self) -> list[int]:
        """Copy the state and apply FIPS 180-4 section 5.1 padding."""
        h = list(self._h)
        # Append 0x80, then zeros until the length field (8 bytes) lands on
        # a 64-byte boundary with at least 56 bytes used.
        pad_len = (56 - (self._length + 1) % BLOCK_SIZE) % BLOCK_SIZE
        tail = (
            b"\x80"
            + b"\x00" * pad_len
            + struct.pack(">Q", self._length * 8)
        )
        data = self._buf + tail
        for off in range(0, len(data), BLOCK_SIZE):
            h = _compress(h, data[off:off + BLOCK_SIZE])
        return h

    def digest(self) -> bytes:
        """Return the 32-byte digest without finalizing this object."""
        return struct.pack(">8I", *self._finalized_state())

    def hexdigest(self) -> str:
        """Return the digest as 64 lowercase hex characters."""
        return self.digest().hex()

    def copy(self) -> "Sha256":
        """Return an independent copy of this digest object."""
        clone = Sha256()
        clone._h = list(self._h)
        clone._buf = self._buf
        clone._length = self._length
        return clone


def sha256(data: bytes | str = b"") -> Sha256:
    """Return a :class:`Sha256` object seeded with *data* (hashlib-style)."""
    return Sha256(data)


def sha256_digest(data: bytes | str) -> bytes:
    """One-shot SHA-256 digest of *data*."""
    return Sha256(data).digest()


def sha256_hexdigest(data: bytes | str) -> str:
    """One-shot SHA-256 hex digest of *data*."""
    return Sha256(data).hexdigest()

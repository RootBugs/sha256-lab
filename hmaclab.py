"""HMAC-SHA256 (RFC 2104) built on the from-scratch SHA-256.

HMAC(key, msg) = H((K ^ opad) || H((K ^ ipad) || msg)) where ``K`` is the key
zero-padded to the hash block size (64 bytes) and, if longer than one block,
first hashed down to 32 bytes.
"""

from __future__ import annotations

from sha256lab import BLOCK_SIZE, Sha256

__all__ = ["HmacSha256", "hmac_sha256", "hmac_sha256_hex"]

_IPAD = 0x36
_OPAD = 0x5C


def _normalize_key(key: bytes | str) -> bytes:
    """Hash long keys down and zero-pad to exactly one block (RFC 2104)."""
    if isinstance(key, str):
        key = key.encode("utf-8")
    elif isinstance(key, (bytearray, memoryview)):
        key = bytes(key)
    elif not isinstance(key, bytes):
        raise TypeError(f"HMAC key must be bytes-like or str, got {type(key).__name__}")
    if len(key) > BLOCK_SIZE:
        key = Sha256(key).digest()
    return key.ljust(BLOCK_SIZE, b"\x00")


class HmacSha256:
    """Streaming HMAC-SHA256 with the same shape as :class:`hmac.HMAC`."""

    def __init__(self, key: bytes | str, msg: bytes | str = b"") -> None:
        padded = _normalize_key(key)
        self._ipad = bytes(b ^ _IPAD for b in padded)
        self._opad = bytes(b ^ _OPAD for b in padded)
        self._inner = Sha256(self._ipad)
        if msg:
            self._inner.update(msg)

    def update(self, data: bytes | str) -> "HmacSha256":
        """Feed more message bytes into the inner hash."""
        self._inner.update(data)
        return self

    def digest(self) -> bytes:
        """Return the 32-byte HMAC tag (does not finalize this object)."""
        inner = self._inner.digest()
        return Sha256(self._opad + inner).digest()

    def hexdigest(self) -> str:
        """Return the HMAC tag as 64 lowercase hex characters."""
        return self.digest().hex()


def hmac_sha256(key: bytes | str, msg: bytes | str = b"") -> bytes:
    """One-shot HMAC-SHA256 of *msg* under *key*."""
    return HmacSha256(key, msg).digest()


def hmac_sha256_hex(key: bytes | str, msg: bytes | str = b"") -> str:
    """One-shot HMAC-SHA256 hex tag of *msg* under *key*."""
    return HmacSha256(key, msg).hexdigest()

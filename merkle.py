"""Merkle tree construction and proofs of inclusion.

Layout: every leaf is ``SHA-256(item)``; each internal node is
``SHA-256(left || right)``. When a level has an odd number of nodes the last
node is duplicated (Bitcoin-style), which keeps proofs unambiguous.

A proof is a list of ``(sibling_hash, side)`` pairs from the leaf up to the
root, where ``side`` is ``"left"`` or ``"right"`` naming where the sibling
sits relative to the running hash.
"""

from __future__ import annotations

from sha256lab import sha256_digest

__all__ = [
    "MerkleError",
    "merkle_root",
    "build_proof",
    "verify_proof",
    "tree_levels",
]


class MerkleError(ValueError):
    """Raised for empty trees or invalid leaf indices."""


def tree_levels(items: list[bytes]) -> list[list[bytes]]:
    """Return every level of the tree, bottom (leaves) to top (root).

    Each level contains node hashes *before* odd-node duplication is applied
    for pairing; duplication only affects sibling lookup in :func:`build_proof`.
    """
    if not items:
        raise MerkleError("cannot build a Merkle tree from zero leaves")
    level = [sha256_digest(item) for item in items]
    levels = [level]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        level = [
            sha256_digest(level[i] + level[i + 1])
            for i in range(0, len(level), 2)
        ]
        levels.append(level)
    return levels


def merkle_root(items: list[bytes]) -> bytes:
    """Compute the 32-byte Merkle root over *items*."""
    return tree_levels(items)[-1][0]


def build_proof(items: list[bytes], index: int) -> list[tuple[bytes, str]]:
    """Build the inclusion proof for ``items[index]``."""
    if not items:
        raise MerkleError("cannot build a proof from zero leaves")
    if not 0 <= index < len(items):
        raise MerkleError(f"leaf index {index} out of range 0..{len(items) - 1}")
    levels = tree_levels(items)
    proof: list[tuple[bytes, str]] = []
    pos = index
    for level in levels[:-1]:
        if pos % 2 == 0:
            sibling = pos + 1
            side = "right"
            if sibling >= len(level):
                sibling = pos  # odd level: last node duplicated
        else:
            sibling = pos - 1
            side = "left"
        proof.append((level[sibling], side))
        pos //= 2
    return proof


def verify_proof(
    root: bytes,
    item: bytes,
    proof: list[tuple[bytes, str]],
    index: int | None = None,
) -> bool:
    """Recompute the root from *item* + *proof* and compare to *root*.

    Returns ``False`` (never raises) for any mismatch: tampered leaf,
    tampered sibling, or wrong proof order. *index*, when given, must be a
    non-negative integer consistent with the proof length.
    """
    if index is not None:
        if not isinstance(index, int) or index < 0:
            return False
        if index >= (1 << len(proof)):
            return False
    current = sha256_digest(item)
    for sibling, side in proof:
        if side == "left":
            current = sha256_digest(sibling + current)
        elif side == "right":
            current = sha256_digest(current + sibling)
        else:
            return False  # unknown side label
    return current == root

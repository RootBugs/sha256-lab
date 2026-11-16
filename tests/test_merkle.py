"""Merkle tree proof tests: verification and tamper rejection."""

from __future__ import annotations

import random
import unittest

from merkle import MerkleError, build_proof, merkle_root, tree_levels, verify_proof
from sha256lab import sha256_digest


def _leaves(n: int, seed: int = 7) -> list[bytes]:
    rng = random.Random(seed)
    return [rng.randbytes(16) for _ in range(n)]


class MerkleRootTests(unittest.TestCase):

    def test_single_leaf_root_is_leaf_hash(self):
        item = b"only leaf"
        self.assertEqual(merkle_root([item]), sha256_digest(item))

    def test_empty_tree_raises(self):
        with self.assertRaises(MerkleError):
            merkle_root([])

    def test_two_leaf_root(self):
        a, b = b"left", b"right"
        self.assertEqual(
            merkle_root([a, b]), sha256_digest(sha256_digest(a) + sha256_digest(b))
        )

    def test_odd_leaf_count_duplicates_last(self):
        leaves = _leaves(5)
        levels = tree_levels(leaves)
        # level 0: 5 leaves, level 1: ceil(5/2)=3, level 2: ceil(3/2)=2
        self.assertEqual([len(lvl) for lvl in levels], [5, 3, 2, 1])

    def test_root_is_deterministic(self):
        leaves = _leaves(9, seed=11)
        self.assertEqual(merkle_root(leaves), merkle_root(list(leaves)))


class MerkleProofTests(unittest.TestCase):

    def test_proofs_verify_for_every_leaf(self):
        for count in (1, 2, 3, 5, 8, 13):
            leaves = _leaves(count, seed=count)
            root = merkle_root(leaves)
            for i, leaf in enumerate(leaves):
                proof = build_proof(leaves, i)
                self.assertTrue(
                    verify_proof(root, leaf, proof, i), f"count={count} idx={i}"
                )

    def test_tampered_leaf_rejected(self):
        leaves = _leaves(8)
        root = merkle_root(leaves)
        proof = build_proof(leaves, 3)
        self.assertFalse(
            verify_proof(root, leaves[3] + b"\x00", proof, 3)
        )

    def test_tampered_proof_sibling_rejected(self):
        leaves = _leaves(8)
        root = merkle_root(leaves)
        proof = build_proof(leaves, 3)
        bad = list(proof)
        sibling, side = bad[0]
        bad[0] = (bytes(b ^ 0xFF for b in sibling), side)
        self.assertFalse(verify_proof(root, leaves[3], bad, 3))

    def test_wrong_leaf_index_rejected(self):
        leaves = _leaves(8)
        root = merkle_root(leaves)
        proof = build_proof(leaves, 2)
        # proof for leaf 2 presented with leaf 5's data must not verify
        self.assertFalse(verify_proof(root, leaves[5], proof, 5))

    def test_out_of_range_index_rejected(self):
        leaves = _leaves(4)
        root = merkle_root(leaves)
        proof = build_proof(leaves, 0)
        self.assertFalse(verify_proof(root, leaves[0], proof, 99))
        self.assertFalse(verify_proof(root, leaves[0], proof, -1))

    def test_unknown_side_label_rejected(self):
        leaves = _leaves(2)
        root = merkle_root(leaves)
        sibling = sha256_digest(leaves[1])
        self.assertFalse(
            verify_proof(root, leaves[0], [(sibling, "up")], 0)
        )

    def test_build_proof_invalid_index_raises(self):
        leaves = _leaves(3)
        with self.assertRaises(MerkleError):
            build_proof(leaves, 3)
        with self.assertRaises(MerkleError):
            build_proof([], 0)

    def test_single_leaf_has_empty_proof(self):
        leaves = [b"solo"]
        self.assertEqual(build_proof(leaves, 0), [])
        self.assertTrue(
            verify_proof(merkle_root(leaves), leaves[0], [], 0)
        )


if __name__ == "__main__":
    unittest.main()

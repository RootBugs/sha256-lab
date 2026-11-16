"""CLI tests: file hashing, HMAC and Merkle commands run for real."""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import io
import tempfile
import unittest
from pathlib import Path

import cli
from merkle import merkle_root


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def _write(self, name: str, data: bytes) -> str:
        path = self.dir / name
        path.write_bytes(data)
        return str(path)

    def test_hash_command_matches_hashlib(self):
        path = self._write("a.bin", b"payload" * 100)
        code, out, _ = _run(["hash", path])
        self.assertEqual(code, 0)
        digest, printed = out.strip().split("  ")
        self.assertEqual(digest, hashlib.sha256(b"payload" * 100).hexdigest())
        self.assertEqual(printed, path)

    def test_hash_multiple_files_streams(self):
        p1 = self._write("one.txt", b"first file contents")
        p2 = self._write("two.txt", b"second file contents")
        code, out, _ = _run(["hash", p1, p2])
        self.assertEqual(code, 0)
        lines = out.strip().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(
            lines[0].split()[0], hashlib.sha256(b"first file contents").hexdigest()
        )
        self.assertEqual(
            lines[1].split()[0], hashlib.sha256(b"second file contents").hexdigest()
        )

    def test_hmac_command_with_text_key(self):
        path = self._write("msg.txt", b"authenticate me")
        code, out, _ = _run(["hmac", path, "--key", "secret"])
        self.assertEqual(code, 0)
        tag = out.strip().split("  ")[0]
        expected = hmac.new(
            b"secret", b"authenticate me", hashlib.sha256
        ).hexdigest()
        self.assertEqual(tag, expected)

    def test_merkle_root_command(self):
        p1 = self._write("f1", b"alpha")
        p2 = self._write("f2", b"beta")
        p3 = self._write("f3", b"gamma")
        code, out, _ = _run(["merkle", p1, p2, p3])
        self.assertEqual(code, 0)
        expected = merkle_root([b"alpha", b"beta", b"gamma"])
        self.assertIn(f"merkle root: {expected.hex()}", out)

    def test_merkle_proof_prints_sides_and_hashes(self):
        p1 = self._write("f1", b"alpha")
        p2 = self._write("f2", b"beta")
        p3 = self._write("f3", b"gamma")
        code, out, _ = _run(["merkle", p1, p2, p3, "--proof", "0"])
        self.assertEqual(code, 0)
        self.assertIn("inclusion proof for file 0:", out)
        self.assertIn("right", out)

    def test_missing_file_reports_error(self):
        missing = str(self.dir / "nope.dat")
        code, _, err = _run(["hash", missing])
        self.assertEqual(code, 1)
        self.assertIn("error:", err)

    def test_proof_index_out_of_range(self):
        p1 = self._write("f1", b"only")
        code, _, err = _run(["merkle", p1, "--proof", "5"])
        self.assertEqual(code, 2)
        self.assertIn("out of range", err)

    def test_hash_of_hashlib_reference(self):
        """The CLI streams chunks; multi-chunk input must match hashlib."""
        data = bytes(range(256)) * 400  # 102400 bytes, many chunks
        path = self._write("big.bin", data)
        code, out, _ = _run(["hash", path])
        self.assertEqual(code, 0)
        self.assertEqual(out.split()[0], hashlib.sha256(data).hexdigest())


if __name__ == "__main__":
    unittest.main()

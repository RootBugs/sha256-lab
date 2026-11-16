"""File hashing CLI for sha256-lab.

Commands
--------
``hash FILE...``      SHA-256 hexdigests (streamed, sha256sum-style output)
``hmac FILE --key K`` HMAC-SHA256 hex tags
``merkle FILE...``    Merkle root over the files, optional inclusion proof
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from hmaclab import hmac_sha256_hex
from merkle import build_proof, merkle_root
from sha256lab import Sha256

_CHUNK = 65536


def hash_file(path: str | Path, chunk_size: int = _CHUNK) -> bytes:
    """Stream *path* through SHA-256 and return the raw digest."""
    digest = Sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.digest()


def _read_file(path: str | Path) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sha256-lab",
        description="SHA-256, HMAC-SHA256 and Merkle trees from scratch.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_hash = sub.add_parser("hash", help="SHA-256 hexdigest of each file")
    p_hash.add_argument("files", nargs="+", metavar="FILE")

    p_hmac = sub.add_parser("hmac", help="HMAC-SHA256 hex tag of a file")
    p_hmac.add_argument("file", metavar="FILE")
    p_hmac.add_argument("--key", required=True, help="hex or text key")

    p_merkle = sub.add_parser("merkle", help="Merkle root over the files")
    p_merkle.add_argument("files", nargs="+", metavar="FILE")
    p_merkle.add_argument(
        "--proof", type=int, default=None, metavar="N",
        help="also print the inclusion proof for file N",
    )

    args = parser.parse_args(argv)

    try:
        if args.command == "hash":
            for name in args.files:
                print(f"{hash_file(name).hex()}  {name}")
        elif args.command == "hmac":
            key = bytes.fromhex(args.key) if _is_hex(args.key) else args.key.encode()
            print(f"{hmac_sha256_hex(key, _read_file(args.file))}  {args.file}")
        else:  # merkle
            root = merkle_root([_read_file(name) for name in args.files])
            print(f"merkle root: {root.hex()}")
            if args.proof is not None:
                idx = args.proof
                if not 0 <= idx < len(args.files):
                    print(f"error: proof index {idx} out of range", file=sys.stderr)
                    return 2
                proof = build_proof(
                    [_read_file(name) for name in args.files], idx
                )
                print(f"inclusion proof for file {idx}:")
                for sibling, side in proof:
                    print(f"  {side:<5} {sibling.hex()}")
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


def _is_hex(text: str) -> bool:
    if len(text) % 2 != 0 or not text:
        return False
    try:
        bytes.fromhex(text)
    except ValueError:
        return False
    return True


if __name__ == "__main__":
    sys.exit(main())

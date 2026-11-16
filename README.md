# sha256-lab — SHA-256, HMAC & Merkle Trees from Scratch

The hash, rebuilt from the FIPS spec. `sha256-lab` implements **SHA-256 in
pure Python** (block compression, padding, streaming API), **HMAC-SHA256 per
RFC 2104**, and **Merkle trees with proofs of inclusion** — no `hashlib`, no
`hmac` module, no third-party code. The stdlib appears only in the tests, as
an independent oracle.

## Why it's special

- Every constant in the implementation (round constants, initial hash values)
  comes straight from FIPS 180-4 sections 4.2.1–4.2.2, and the known-answer
  vectors are asserted **exactly** — one flipped bit anywhere fails the suite.
- The streaming object mirrors `hashlib` semantics: `digest()` never finalizes
  the object, so `update → digest → update → digest` behaves correctly.
- Merkle proofs carry an explicit `(sibling, "left"/"right")` side label and
  are verified branch-free of exceptions: tampered leaf, tampered sibling or
  wrong index all simply return `False`.
- A differential test hammers 100 seeded random inputs against `hashlib` —
  the from-scratch code must agree byte-for-byte.

## Architecture

| Module | Responsibility |
|---|---|
| `sha256lab.py` | FIPS 180-4 padding, 64-round compression, message schedule, streaming `Sha256` |
| `hmaclab.py` | RFC 2104 HMAC construction (ipad/opad, long-key hashing) over `sha256lab` |
| `merkle.py` | Leaf hashing, odd-node duplication, proof build/verify |
| `cli.py` | `hash`, `hmac`, `merkle` subcommands over real files (streamed) |

## Runnable example

```console
$ python -c "
from sha256lab import sha256_hexdigest
from hmaclab import hmac_sha256_hex
from merkle import merkle_root, build_proof, verify_proof

print(sha256_hexdigest(b'abc'))
print(hmac_sha256_hex(b'Jefe', b'what do ya want for nothing?'))
leaves = [b'alice', b'bob', b'carol']
root = merkle_root(leaves)
proof = build_proof(leaves, 1)
print('root   ', root.hex())
print('verify ', verify_proof(root, leaves[1], proof, 1))
print('tamper ', verify_proof(root, b'eve', proof, 1))
"
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
root    a21df13558d3bcd29831fe5e14344fdd5fc3b9b55752232e2ea059bb2142f168
verify  True
tamper  False
```

CLI over files:

```console
$ python cli.py hash LICENSE
3acba929f23f1375a8d94d08c75daf94e8d82c5c110495694a8f3a34e3fca656  LICENSE
```

## Tests

```console
python -m unittest discover -s tests -v
```

44 tests: FIPS 180-4 known-answer vectors (empty, `abc`, 448-bit, two-block,
one million `a`), streaming-vs-one-shot equivalence, RFC 4231 HMAC vectors
(cases 1–4, 6, 7), differential checks against `hashlib`/`hmac`, Merkle proof
verification with tamper rejection, and CLI tests that hash real temp files.

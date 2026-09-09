"""ChaCha20 stream cipher -- RFC 8439 §2.3/2.4.

Implemented directly rather than pulled from a dependency because the *same
algorithm* has to exist twice: here, in the build tool, and in the generated
Luau runtime.  Keeping both implementations in this repository lets the test
suite cross-check them against the RFC's published test vectors and against
each other, which is the only honest way to be confident the Luau one is
correct.

This is a real, established primitive.  It provides confidentiality *while the
key is unavailable*.  In a client-side protector the key necessarily ships with
the program, so what ChaCha20 buys here is that the payload is not readable by
`strings`/grep and cannot be edited without detection (the Poly1305 tag) -- not
that it is unrecoverable.  See docs/SECURITY.md.
"""

from __future__ import annotations

import struct
from typing import List

MASK32 = 0xFFFFFFFF
CONSTANT = b"expand 32-byte k"


def _rotl32(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & MASK32


# Round indices, 0-based, exactly as in RFC 8439 §2.3.  Single source of
# truth: the Luau emitter imports these rather than retyping them, because a
# hand-copied diagonal index produces a valid-looking but wrong keystream.
COLUMN_ROUNDS = ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15))
DIAGONAL_ROUNDS = ((0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14))


def _quarter_round(state: List[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rotl32(state[b] ^ state[c], 7)


def _initial_state(key: bytes, counter: int, nonce: bytes) -> List[int]:
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("ChaCha20 nonce must be 12 bytes")
    state = list(struct.unpack("<4I", CONSTANT))
    state += list(struct.unpack("<8I", key))
    state.append(counter & MASK32)
    state += list(struct.unpack("<3I", nonce))
    return state


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """One 64-byte keystream block."""
    state = _initial_state(key, counter, nonce)
    working = list(state)
    for _ in range(10):  # 20 rounds = 10 double-rounds
        for q in COLUMN_ROUNDS:
            _quarter_round(working, *q)
        for q in DIAGONAL_ROUNDS:
            _quarter_round(working, *q)
    out = [(working[i] + state[i]) & MASK32 for i in range(16)]
    return struct.pack("<16I", *out)


def chacha20_xor(key: bytes, nonce: bytes, data: bytes, counter: int = 1) -> bytes:
    """Encrypt or decrypt (the operation is symmetric)."""
    out = bytearray()
    for i in range(0, len(data), 64):
        block = chacha20_block(key, counter + (i // 64), nonce)
        chunk = data[i : i + 64]
        out += bytes(a ^ b for a, b in zip(chunk, block))
    return bytes(out)

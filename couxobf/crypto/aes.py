"""AES-128 (FIPS 197) -- the second cipher core a build may draw.

Every artifact this tool produced used to carry the same primitives -- ChaCha20
for confidentiality, HMAC-SHA256 for integrity -- emitted from one fixed source
template with only the identifiers changed.  That made the crypto layer the most
recognisable thing in the file: an analyst does not have to understand the VM to
find ``0x428a2f98`` or ``expand 32-byte k``.

The fix is not a home-brew cipher (the design review rejected those: an
unauthenticated stream cipher of our own invention is weaker than what we
already ship, and "nobody knows the algorithm" is not a property this project
claims).  It is a **second standard core**: AES-128 in counter mode, with the
same HMAC-SHA256 authentication and the same encrypt-then-MAC composition.
A build that draws AES carries no ChaCha constants at all.

Why AES-128 in CTR mode specifically
------------------------------------
* CTR needs only the *forward* cipher -- no inverse tables, no InvMixColumns --
  which halves the emitted code.
* Keystream generation (never plaintext-dependent branching) keeps the timing
  story simple and lets the runtime generate keystream lazily per fragment.
* Every intermediate is a byte, so nothing here depends on Luau's number
  representation beyond exact integer arithmetic below 2^53 -- the same
  constraint ChaCha20 and SHA-256 already satisfy.

The S-box is *computed*, not tabulated.  Emitting 256 bytes of a known constant
is exactly the fingerprint this module exists to remove, so both sides build it
at load from the GF(2^8) generator 3 (exp/log tables plus the standard affine
transform).  The Python and Luau generators are written to the same algorithm
and cross-checked by ``tests/test_crypto_cores.py`` against each other *and*
against the FIPS-197 vector, because a plausible-looking wrong S-box produces a
cipher that still decrypts what it encrypted -- and nothing else.
"""

from __future__ import annotations

import struct
from typing import List, Tuple

BLOCK = 16
KEY_BYTES = 16
ROUNDS = 10
NONCE_BYTES = 12


def _xtime(a: int) -> int:
    """Multiply by ``x`` in GF(2^8) modulo the AES polynomial."""
    a <<= 1
    if a & 0x100:
        a = (a ^ 0x1B) & 0xFF
    return a


def generate_tables() -> Tuple[List[int], List[int], List[int]]:
    """``(sbox, exp, log)`` for GF(2^8) with generator 3.

    The same code, in the same order, as the Luau generator the runtime emits:
    if these two ever disagree the artifact encrypts with one cipher and
    decrypts with a different one, and the only symptom is a MAC failure far
    from here.
    """
    exp = [0] * 256
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        # x *= 3 (the generator), i.e. x ^= xtime(x)
        x ^= _xtime(x)
        x &= 0xFF
    # 3^255 == 1, so the table wraps; exp[255] is the value the loop has just
    # walked back round to, and leaving it zero would make every inverse of 1
    # come out as zero.
    exp[255] = x
    sbox = [0] * 256
    for i in range(256):
        if i == 0:
            inv = 0
        else:
            inv = exp[255 - log[i]]
        s = inv
        for _ in range(4):
            inv = ((inv << 1) | (inv >> 7)) & 0xFF
            s ^= inv
        sbox[i] = s ^ 0x63
    return sbox, exp, log


SBOX, EXP, LOG = generate_tables()


def expand_key(key: bytes) -> List[int]:
    """The 11 round keys as one flat list of 176 bytes.

    Flat rather than word-shaped because the emitted Luau mirrors the indexing
    arithmetic directly: ``rk[round * 16 + i]`` is the byte added to state byte
    ``i`` in that round, which is the one thing both sides must agree on and
    the one thing a word-per-row layout makes easy to get wrong.
    """
    if len(key) != KEY_BYTES:
        raise ValueError("AES-128 key must be 16 bytes")
    rk = [0] * (BLOCK * (ROUNDS + 1))
    for i in range(BLOCK):
        rk[i] = key[i]
    rcon = 1
    for i in range(4, 4 * (ROUNDS + 1)):
        base = (i - 4) * 4
        prev = (i - 1) * 4
        t = rk[prev : prev + 4]
        if i % 4 == 0:
            t = t[1:] + t[:1]                      # RotWord
            t = [SBOX[b] for b in t]               # SubWord
            t = [t[0] ^ rcon] + t[1:]              # Rcon
            rcon = _xtime(rcon)
        for j in range(4):
            rk[i * 4 + j] = rk[base + j] ^ t[j]
    return rk


def encrypt_block(rk: List[int], block: bytes) -> bytes:
    """One AES-128 block. ``rk`` is :func:`expand_key` output."""
    if len(block) != BLOCK:
        raise ValueError("AES block must be 16 bytes")
    s = list(block)
    # Round 0: AddRoundKey only.  The state's flat index is the round key's
    # flat index, which is why both are one array here.
    for i in range(16):
        s[i] ^= rk[i]
    for rnd in range(1, ROUNDS + 1):
        s = [SBOX[b] for b in s]
        # ShiftRows: row r rotates left by r.  With flat index r + 4c this is a
        # rotation of each of the four index classes.
        s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
        s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
        s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]
        if rnd != ROUNDS:
            for c in range(4):
                i0 = 4 * c
                a0, a1, a2, a3 = s[i0], s[i0 + 1], s[i0 + 2], s[i0 + 3]
                t = a0 ^ a1 ^ a2 ^ a3
                s[i0] = a0 ^ t ^ _xtime(a0 ^ a1)
                s[i0 + 1] = a1 ^ t ^ _xtime(a1 ^ a2)
                s[i0 + 2] = a2 ^ t ^ _xtime(a2 ^ a3)
                s[i0 + 3] = a3 ^ t ^ _xtime(a3 ^ a0)
        off = rnd * 16
        for i in range(16):
            s[i] ^= rk[off + i]
    return bytes(s)


def _ctr_block(rk: List[int], nonce: bytes, counter: int) -> bytes:
    if len(nonce) != NONCE_BYTES:
        raise ValueError("AES-CTR nonce must be 12 bytes")
    return encrypt_block(rk, nonce + struct.pack(">I", counter & 0xFFFFFFFF))


def aes128_ctr_xor(key: bytes, nonce: bytes, data: bytes,
                   counter: int = 1) -> bytes:
    """CTR keystream XOR -- the drop-in counterpart to ``chacha20_xor``.

    Same signature, same meaning: ``counter`` is the starting block index and
    the keystream runs for ``len(data)`` bytes.  The key is 16 bytes here
    because that is what AES-128 takes; callers hold 32-byte derived material
    and pass the first half (see :func:`couxobf.crypto.cipher.xor_bytes`).
    """
    if len(key) != KEY_BYTES:
        raise ValueError("AES-128 key must be 16 bytes")
    rk = expand_key(key)
    out = bytearray(len(data))
    blk = 0
    pos = 0
    while pos < len(data):
        ks = _ctr_block(rk, nonce, counter + blk)
        stop = min(pos + BLOCK, len(data))
        for i in range(pos, stop):
            out[i] = data[i] ^ ks[i - pos]
        blk += 1
        pos = stop
    return bytes(out)

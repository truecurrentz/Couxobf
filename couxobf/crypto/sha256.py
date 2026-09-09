"""SHA-256 (FIPS 180-4), pure Python, with the round constants *derived*.

The 64 round constants are computed here from their definition -- the first 32
bits of the fractional part of the cube roots of the first 64 primes -- using
exact integer arithmetic rather than being transcribed from a table.  The test
suite then checks this implementation against :mod:`hashlib` on random inputs,
so a mistake in the derivation cannot survive.

The build tool itself just uses ``hashlib``; this module exists so that:

* the constant table handed to the Luau emitter is provably correct, and
* there is a line-by-line Python counterpart of the generated Luau code, which
  makes reviewing the Luau implementation tractable.
"""

from __future__ import annotations

import hashlib
import struct
from typing import List

MASK32 = 0xFFFFFFFF


def _primes(n: int) -> List[int]:
    out: List[int] = []
    cand = 2
    while len(out) < n:
        if all(cand % p for p in out if p * p <= cand):
            out.append(cand)
        cand += 1
    return out


def _icbrt(x: int) -> int:
    """Integer cube root (largest r with r**3 <= x), by Newton's method."""
    if x < 2:
        return x
    r = 1 << ((x.bit_length() + 2) // 3 + 1)
    while True:
        nxt = (2 * r + x // (r * r)) // 3
        if nxt >= r:
            break
        r = nxt
    while (r + 1) ** 3 <= x:
        r += 1
    while r**3 > x:
        r -= 1
    return r


def _derive_k() -> List[int]:
    """K[i] = first 32 bits of frac(cbrt(prime_i))."""
    out = []
    for p in _primes(64):
        scaled = _icbrt(p * (1 << 96))
        out.append(scaled & MASK32)
    return out


def _derive_h() -> List[int]:
    """H[i] = first 32 bits of frac(sqrt(prime_i))."""
    out = []
    for p in _primes(8):
        # integer sqrt of p * 2^64, then take the low 32 bits
        x = p * (1 << 64)
        r = x
        while True:
            nxt = (r + x // r) // 2
            if nxt >= r:
                break
            r = nxt
        while (r + 1) ** 2 <= x:
            r += 1
        while r * r > x:
            r -= 1
        out.append(r & MASK32)
    return out


K = _derive_k()
H_INIT = _derive_h()


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & MASK32


def _shr(x: int, n: int) -> int:
    return x >> n


def sha256(data: bytes) -> bytes:
    h = list(H_INIT)
    msg = bytearray(data)
    bitlen = len(data) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack(">Q", bitlen)

    w = [0] * 64
    for off in range(0, len(msg), 64):
        block = msg[off : off + 64]
        for i in range(16):
            w[i] = struct.unpack(">I", block[i * 4 : i * 4 + 4])[0]
        for i in range(16, 64):
            s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ _shr(w[i - 15], 3)
            s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ _shr(w[i - 2], 10)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & MASK32
        a, b, c, d, e, f, g, hh = h
        for i in range(64):
            S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            ch = (e & f) ^ ((~e & MASK32) & g)
            t1 = (hh + S1 + ch + K[i] + w[i]) & MASK32
            S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (S0 + maj) & MASK32
            hh = g
            g = f
            f = e
            e = (d + t1) & MASK32
            d = c
            c = b
            b = a
            a = (t1 + t2) & MASK32
        for i, v in enumerate((a, b, c, d, e, f, g, hh)):
            h[i] = (h[i] + v) & MASK32
    return struct.pack(">8I", *h)


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    """RFC 2104 HMAC with SHA-256 (block size 64)."""
    if len(key) > 64:
        key = sha256(key)
    key = key + bytes(64 - len(key))
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)
    return sha256(opad + sha256(ipad + msg))


def matches_stdlib(data: bytes) -> bool:
    """Sanity helper used by the tests."""
    return sha256(data) == hashlib.sha256(data).digest()

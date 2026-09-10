"""The payload protection format actually used by build *and* runtime.

Construction: **ChaCha20 for confidentiality + HMAC-SHA256 for integrity,
composed encrypt-then-MAC.**

Why not ChaCha20-Poly1305 (RFC 8439's AEAD)?  Because Poly1305 cannot be
implemented correctly in pure Luau.  Luau has no integer subtype: every number
is an IEEE-754 double (verified on the pinned toolchain -- ``2^53 + 1 == 2^53``
is ``true``), so only values below 2^53 are exact.  Poly1305's accumulator is
130 bits and even the standard 26-bit-limb reduction needs ~55-bit
intermediates.  A "Poly1305 in Luau" would silently produce wrong tags.  Per
the project's own rule -- never invent or half-implement a primitive -- the
AEAD was dropped in favour of two primitives that *are* exact under doubles:

* ChaCha20 (RFC 8439 §2.4): every state word is < 2^32, and additions are
  reduced mod 2^32, so all intermediates are < 2^33 and exact.
* SHA-256 / HMAC-SHA256 (FIPS 180-4, RFC 2104): likewise entirely 32-bit.

Encrypt-then-MAC over ``(nonce || aad || len(aad) || ciphertext)`` is the
standard secure composition (the one used by TLS 1.2 and SSH), and it is what
lets the runtime reject a tampered payload *before* decrypting it.

Honest scope: this detects modification and defeats casual static reading.  It
does not keep the payload secret from someone who can run the program, because
the keys are derived inside the program.  See docs/SECURITY.md.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import os
import struct
from typing import Tuple

from .chacha20 import chacha20_xor

NONCE_BYTES = 12
TAG_BYTES = 32  # HMAC-SHA256
KEY_BYTES = 32

ENC_DOMAIN = bytes.fromhex("6b7a2d8e317445a994c06fd53b987120")
MAC_DOMAIN = bytes.fromhex("c50f19a6e8774c2b901d4e65b82733da")


def enc_key(key: bytes, nonce: bytes, aad: bytes = b"",
            domain: bytes = ENC_DOMAIN) -> bytes:
    """Derive the actual stream-cipher key for one payload.

    The key stored beside a protected payload is now a wrapping input, not the
    ChaCha20 key used directly on bytes.  Binding the derived cipher key to the
    nonce and AAD means two regions under the same build key still use unrelated
    keystream keys, and an analyst cannot test a guessed key by applying raw
    ChaCha20 without first reproducing the KDF step.
    """
    return hashlib.sha256(domain + key + nonce + aad + struct.pack("<Q", len(aad))).digest()


def mac_key(key: bytes, nonce: bytes, aad: bytes = b"",
            domain: bytes = MAC_DOMAIN) -> bytes:
    """Derive the MAC key from the payload key, nonce and AAD.

    Separate keys for cipher and MAC (never the same value in both roles), and
    the nonce/AAD in the derivation means the MAC key changes per message and
    per authenticated context.
    """
    return hashlib.sha256(domain + key + nonce + aad + struct.pack("<Q", len(aad))).digest()


def compute_tag(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes,
                mac_domain: bytes = MAC_DOMAIN) -> bytes:
    """HMAC-SHA256 over the MAC-covered fields, encrypt-then-MAC order."""
    covered = (
        nonce
        + aad
        + struct.pack("<Q", len(aad))
        + ciphertext
        + struct.pack("<Q", len(ciphertext))
    )
    return _hmac.new(mac_key(key, nonce, aad, mac_domain), covered, hashlib.sha256).digest()


def seal(key: bytes, plaintext: bytes, aad: bytes = b"",
         nonce: bytes = None, enc_domain: bytes = ENC_DOMAIN,
         mac_domain: bytes = MAC_DOMAIN) -> Tuple[bytes, bytes, bytes]:
    """Return ``(nonce, ciphertext, tag)``."""
    if len(key) != KEY_BYTES:
        raise ValueError("payload key must be 32 bytes")
    if nonce is None:
        nonce = os.urandom(NONCE_BYTES)
    if len(nonce) != NONCE_BYTES:
        raise ValueError("nonce must be 12 bytes")
    ct = chacha20_xor(enc_key(key, nonce, aad, enc_domain), nonce, plaintext, counter=1)
    return nonce, ct, compute_tag(key, nonce, ct, aad, mac_domain)


def open_(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes,
          aad: bytes = b"", enc_domain: bytes = ENC_DOMAIN,
          mac_domain: bytes = MAC_DOMAIN) -> bytes:
    """Verify then decrypt.  Raises ``ValueError`` on any mismatch."""
    expected = compute_tag(key, nonce, ciphertext, aad, mac_domain)
    if not _hmac.compare_digest(expected, tag):
        raise ValueError("authentication tag mismatch")
    return chacha20_xor(enc_key(key, nonce, aad, enc_domain), nonce, ciphertext, counter=1)


def sealed_blob(key: bytes, plaintext: bytes, aad: bytes = b"",
                enc_domain: bytes = ENC_DOMAIN,
                mac_domain: bytes = MAC_DOMAIN) -> bytes:
    """Wire format: ``nonce || tag || ciphertext``."""
    nonce, ct, tag = seal(key, plaintext, aad, enc_domain=enc_domain,
                          mac_domain=mac_domain)
    return nonce + tag + ct


def open_blob(key: bytes, blob: bytes, aad: bytes = b"",
              enc_domain: bytes = ENC_DOMAIN,
              mac_domain: bytes = MAC_DOMAIN) -> bytes:
    if len(blob) < NONCE_BYTES + TAG_BYTES:
        raise ValueError("sealed blob too short")
    nonce = blob[:NONCE_BYTES]
    tag = blob[NONCE_BYTES : NONCE_BYTES + TAG_BYTES]
    return open_(key, nonce, blob[NONCE_BYTES + TAG_BYTES :], tag, aad,
                 enc_domain=enc_domain, mac_domain=mac_domain)

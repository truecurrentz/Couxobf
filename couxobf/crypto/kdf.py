"""Key derivation and per-build key material.

There is deliberately **no single master secret embedded in the output**.  The
build starts from a 128-bit build seed (which is not itself a cryptographic key
-- it is public in the sense that the protected file must contain enough
information to run) and derives independent 256-bit keys per *purpose* using
HKDF-SHA256 (RFC 5869):

    string bank, VM bytecode, integrity, constants

Each is further split per region/chunk, so one leaked or recovered key does not
unlock the others.  Purpose separation matters here for a practical reason: the
integrity key is used as a MAC key and the payload key as a cipher key, and
reusing one value across those roles is exactly the mistake that turns a
"looks fine" design into a broken one.

Reminder that the documentation repeats because it is the honest framing: every
one of these keys is computable by the protected program at runtime, so a
sufficiently capable analyst who can run the program can recover them.  Key
material raises the cost of *static* analysis and makes edits detectable; it
does not make client-side data secret.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Dict

from .protected import KEY_BYTES

HKDF_HASH = hashlib.sha256


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = bytes(HKDF_HASH().digest_size)
    return hmac.new(salt, ikm, HKDF_HASH).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    if length > 255 * HKDF_HASH().digest_size:
        raise ValueError("requested key material too long")
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), HKDF_HASH).digest()
        out += block
        counter += 1
    return out[:length]


def derive_key(master: bytes, purpose: str, context: bytes = b"",
               length: int = KEY_BYTES) -> bytes:
    """HKDF with a purpose label baked into the ``info`` field."""
    prk = hkdf_extract(b"couxobf-v1", master)
    info = b"couxobf/" + purpose.encode("utf-8") + b"/" + context
    return hkdf_expand(prk, info, length)


PURPOSES = ("string-bank", "vm-payload", "integrity", "constants", "chunk", "opcode")


@dataclass
class KeyMaterial:
    """One build's derived keys.  Never serialised into the output as-is."""

    seed: bytes
    strings: bytes
    payload: bytes
    integrity: bytes
    constants: bytes

    @classmethod
    def from_seed(cls, seed: bytes) -> "KeyMaterial":
        if len(seed) < 16:
            raise ValueError("build seed too short")
        return cls(
            seed=seed,
            strings=derive_key(seed, "string-bank"),
            payload=derive_key(seed, "vm-payload"),
            integrity=derive_key(seed, "integrity"),
            constants=derive_key(seed, "constants"),
        )

    def region_key(self, purpose: str, region: bytes) -> bytes:
        """A per-region/per-chunk subkey."""
        return derive_key(self.seed, "region-" + purpose, region)

    def fingerprint(self) -> Dict[str, str]:
        """Non-reversible identifiers, safe to print in a build report."""
        return {
            "strings": hashlib.sha256(self.strings).hexdigest()[:16],
            "payload": hashlib.sha256(self.payload).hexdigest()[:16],
            "integrity": hashlib.sha256(self.integrity).hexdigest()[:16],
            "constants": hashlib.sha256(self.constants).hexdigest()[:16],
        }

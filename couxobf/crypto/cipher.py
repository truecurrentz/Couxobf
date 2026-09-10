"""The per-build choice of cipher core, and the shape it is emitted in.

Two decisions live here, and they are deliberately separate.

**Which core.** A build draws one of two standard primitives --
ChaCha20 (RFC 8439) or AES-128 in CTR mode (FIPS 197 / NIST SP 800-38A) --
for confidentiality.  Authentication is HMAC-SHA256 either way, in the same
encrypt-then-MAC composition.  Emitting one fixed ChaCha20 implementation made
the crypto layer the single most recognisable object in the artifact: nobody
has to understand the VM to find ``expand 32-byte k``.  With two cores a build
that drew AES carries no ChaCha constant at all, and the two artifacts do not
share a crypto signature to match on.

**What shape.** The core is emitted from per-build *structure*, not from one
template with the names swapped: which round schedule the block function
walks, whether the loop is rolled or unrolled, how its constant tables are
materialised, and in what order the small pieces of the AEAD composition are
declared.  None of that changes a byte of keystream -- it changes the source an
analyst reads, which is the only thing the artifact *is*.

What this module is not: a place to invent a cipher.  A home-brew stream
cipher would be weaker than both of these and would be a lie to describe as
protection.  Variety here is variety of *spelling and composition*, on top of
primitives that are published, testable, and test-vector-checked in
``tests/test_crypto_cores.py``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Sequence, Tuple

from .aes import BLOCK as AES_BLOCK
from .aes import KEY_BYTES as AES_KEY_BYTES
from .aes import aes128_ctr_xor
from .chacha20 import chacha20_xor

CHA_CHA = "chacha20"
AES_CTR = "aes128"
CORES: Tuple[str, ...] = (CHA_CHA, AES_CTR)

#: The wire block size each core advances its counter by.  The runtime's
#: fragment decoder divides the payload offset by this, so it is part of the
#: emitted format rather than an implementation detail.
BLOCK_SIZE = {CHA_CHA: 64, AES_CTR: AES_BLOCK}


@dataclass(frozen=True)
class CipherSpec:
    """One build's cipher, and the structural variants it is emitted with.

    ``core`` is the only field that changes the bytes.  Everything else
    changes the source, which is why they are recorded here rather than
    drawn independently at emission time: a build has to be reproducible, and
    "the emitter rolled a die" is not reproducible from a saved config.
    """

    core: str = CHA_CHA

    #: ChaCha20: how the 8 quarter-rounds per double round are walked.
    #: ``("direct",)`` keeps the RFC's explicit calls; ``("schedule", rows)``
    #: walks a table of index quadruples -- valid because the four column
    #: quarter-rounds touch disjoint columns and so do the four diagonal
    #: ones, so permuting *within* each group is the same function.
    qr_style: str = "direct"
    qr_order: Tuple[Tuple[int, ...], ...] = ()

    #: ChaCha20/AES: how many rounds the block loop covers per iteration.
    #: ChaCha20 is a multiple of 2 (double rounds); AES is any divisor of 10.
    rounds_per_iteration: int = 2

    #: Constant tables (the sigma words, the AES S-box, SHA-256's K) are
    #: either literal, or split into per-build fragments that the runtime
    #: concatenates back at load, or *generated* at load (the S-box, from
    #: GF(2^8) -- no 256-byte constant in the file at all).
    table_style: str = "literal"

    #: SHA-256 message schedule: the classic 64-word array, or a rolling
    #: 16-word window.  Same schedule, different memory shape.
    sha_schedule: str = "array"

    #: Declaration order of the AEAD composition's small functions.  Empty
    #: means "source order"; a non-empty tuple is a permutation applied to
    #: them, with forward declarations so the order is free.
    compose_order: Tuple[int, ...] = ()

    #: AES only: spell the final round outside the loop instead of branching
    #: on ``rnd ~= 10`` inside it.  Same ten rounds, different shape.
    split_final: bool = False

    #: Build the S-box from GF(2^8) at load instead of tabulating it.
    #: Only meaningful for the AES core.
    generate_sbox: bool = True

    def __post_init__(self) -> None:
        if self.core not in CORES:
            raise ValueError(f"unknown cipher core {self.core!r}")
        if self.rounds_per_iteration < 1:
            raise ValueError("rounds_per_iteration must be >= 1")

    # -- byte-level behaviour -------------------------------------------
    @property
    def block_size(self) -> int:
        return BLOCK_SIZE[self.core]

    def cipher_key(self, key: bytes) -> bytes:
        """The bytes handed to the core.

        Both cores are keyed from the same 32-byte derived material; AES-128
        takes the first half.  Truncating a 256-bit derived key to 128 bits is
        what the cipher is specified for, and both halves are independent
        outputs of SHA-256 -- there is no related-key relationship to exploit
        because there is no attacker-chosen relationship to start from.
        """
        if self.core == AES_CTR:
            return key[:AES_KEY_BYTES]
        return key

    def xor_bytes(self, key: bytes, nonce: bytes, data: bytes,
                  counter: int = 1) -> bytes:
        """Keystream XOR -- the one operation both cores provide."""
        if self.core == AES_CTR:
            return aes128_ctr_xor(self.cipher_key(key), nonce, data, counter)
        return chacha20_xor(self.cipher_key(key), nonce, data, counter)

    # -- reporting -------------------------------------------------------
    def summary(self) -> Dict[str, Any]:
        return {
            "core": self.core,
            "block": self.block_size,
            "qr_style": self.qr_style,
            "rounds_per_iteration": self.rounds_per_iteration,
            "table_style": self.table_style,
            "sha_schedule": self.sha_schedule,
            "generate_sbox": bool(self.generate_sbox),
            "compose_order": list(self.compose_order),
            "split_final": bool(self.split_final),
        }

    #: Whether the composition's declaration order was permuted.
    def identity(self) -> str:
        """A short digest of the *shape*, for the report and the reuse audit.

        Two builds that drew the same core but different shapes are different
        artifacts as far as a matcher is concerned, and the audit scores
        transfer between them -- so the shape has to be part of the identity,
        not just the core name.
        """
        payload = "|".join(str(v) for v in self.summary().values()).encode()
        return hashlib.sha256(payload).hexdigest()[:12]


def draw(rng: Any, cores: Sequence[str] = CORES,
         allow_aes: bool = True) -> CipherSpec:
    """Draw one build's cipher core and emitted shape.

    ``rng`` is the build's crypto stream, so the draw is reproducible from the
    seed and independent of every other draw (a build's block permutation must
    not move because something else consumed a different number of bytes).
    """
    pool = [c for c in cores if c != AES_CTR or allow_aes] or list(cores)
    core = rng.choice(pool)
    if core == CHA_CHA:
        # 1 in 3 chacha builds walks a schedule table instead of spelling the
        # eight quarter-round calls out; the rest keep the direct form.  Both
        # are the RFC's function -- the column rounds are independent of each
        # other, and so are the diagonal rounds.
        if rng.chance(0.34):
            from .chacha20 import COLUMN_ROUNDS, DIAGONAL_ROUNDS
            cols = rng.shuffled([tuple(q) for q in COLUMN_ROUNDS])
            diags = rng.shuffled([tuple(q) for q in DIAGONAL_ROUNDS])
            qr_style, qr_order = "schedule", tuple(cols + diags)
        else:
            qr_style, qr_order = "direct", ()
        rounds_per_iteration = rng.choice((1, 2, 2, 5, 10))
        generate_sbox = False
        split_final = False
    else:
        qr_style, qr_order = "direct", ()
        # The AES round loop is not unrolled: the last round omits
        # MixColumns, so an unrolled body would have to special-case it
        # anyway.  The shape knob is whether that special case is a branch
        # inside the loop or a final round spelled out after it.
        rounds_per_iteration = 1
        split_final = rng.chance(0.5)
        # Generating the S-box costs 256 iterations at load and removes a
        # 256-byte known constant from the file.  Kept for the large majority
        # of AES builds; the tabulated form stays available so the artifact
        # fleet is not uniformly one or the other.
        generate_sbox = rng.chance(0.75)
    table_style = rng.choice(("literal", "literal", "fragmented"))
    sha_schedule = "window" if rng.chance(0.5) else "array"
    compose_order = tuple(rng.permutation(6)) if rng.chance(0.7) else ()
    return CipherSpec(
        core=core,
        qr_style=qr_style,
        qr_order=qr_order,
        rounds_per_iteration=rounds_per_iteration,
        table_style=table_style,
        sha_schedule=sha_schedule,
        compose_order=compose_order,
        generate_sbox=generate_sbox,
        split_final=split_final,
    )


def default_spec() -> CipherSpec:
    """The historical ChaCha20 build -- what a config that names no cipher gets."""
    return CipherSpec()

"""Deterministic, domain-separated randomness for the build pipeline.

Design notes (see docs/SECURITY.md §"Randomness"):

* The build seed is 128 bits.  When the user does not pass ``--seed`` the seed
  comes from :func:`os.urandom` (a CSPRNG), which is what makes every build
  structurally different.  When ``--seed`` *is* passed the build is fully
  reproducible (same source + same version + same config + same seed =>
  byte-identical output).
* Every consumer of randomness draws from its own *domain*.  A domain is a
  short stable label ("identifiers", "cfg", "vm", ...).  Domain streams are
  derived as ``SHA-256(seed || 0x00 || domain || 0x00 || counter)``, so two
  unrelated passes can never accidentally consume each other's stream, and
  inserting a new pass that draws randomness does not perturb the streams of
  the passes that follow it.  Without domain separation, adding one decoy
  block would silently re-key every subsequent identifier in the build.
* The generator is a SHA-256 counter stream (a standard construction: a PRF in
  counter mode).  It is *not* a cryptographic claim about the protected
  output; it exists so that polymorphism is reproducible and auditable.
"""

from __future__ import annotations

import hashlib
import os
from typing import Iterable, List, Sequence, TypeVar

T = TypeVar("T")

SEED_BYTES = 16  # 128-bit build seed


def new_seed() -> bytes:
    """Return a fresh 128-bit seed from the OS CSPRNG."""
    return os.urandom(SEED_BYTES)


def coerce_seed(seed) -> bytes:
    """Normalise a user supplied seed into 128 raw bytes.

    Accepts bytes, an int, or a string (hashed with SHA-256 and truncated so
    that ``--seed hello`` is stable across platforms and Python versions --
    never ``hash()``, which is salted per process).
    """
    if seed is None:
        return new_seed()
    if isinstance(seed, bytes):
        return hashlib.sha256(b"couxobf-seed-bytes\x00" + seed).digest()[:SEED_BYTES]
    if isinstance(seed, int):
        return hashlib.sha256(b"couxobf-seed-int\x00" + seed.to_bytes(16, "big", signed=True)).digest()[
            :SEED_BYTES
        ]
    if isinstance(seed, str):
        return hashlib.sha256(b"couxobf-seed-str\x00" + seed.encode("utf-8", "surrogatepass")).digest()[
            :SEED_BYTES
        ]
    raise TypeError(f"unsupported seed type: {type(seed)!r}")


def seed_repr(seed: bytes) -> str:
    """Stable textual form of a seed, for reports and ``--seed`` round-trips."""
    return seed.hex()


def parse_seed_repr(text: str) -> bytes:
    raw = bytes.fromhex(text.strip())
    if len(raw) != SEED_BYTES:
        raise ValueError(f"seed must be {SEED_BYTES} bytes hex, got {len(raw)}")
    return raw


class Rng:
    """A SHA-256 counter stream bound to one randomness domain."""

    __slots__ = ("_seed", "_domain", "_counter", "_buf", "_pos", "draws")

    def __init__(self, seed: bytes, domain: str = "root") -> None:
        if isinstance(domain, str):
            domain = domain.encode("utf-8")
        if len(seed) != SEED_BYTES:
            raise ValueError("seed must be 16 bytes")
        self._seed = seed
        self._domain = domain
        self._counter = 0
        self._buf = b""
        self._pos = 0
        self.draws = 0

    # -- plumbing ---------------------------------------------------------
    @property
    def domain(self) -> bytes:
        return self._domain

    def _refill(self) -> None:
        h = hashlib.sha256()
        h.update(self._seed)
        h.update(b"\x00")
        h.update(self._domain)
        h.update(b"\x00")
        h.update(self._counter.to_bytes(8, "big"))
        self._counter += 1
        self._buf = h.digest()
        self._pos = 0

    def bytes(self, n: int) -> bytes:
        if n <= 0:
            return b""
        out = bytearray()
        while len(out) < n:
            if self._pos >= len(self._buf):
                self._refill()
            take = min(len(self._buf) - self._pos, n - len(out))
            out += self._buf[self._pos : self._pos + take]
            self._pos += take
        self.draws += 1
        return bytes(out)

    def byte(self) -> int:
        return self.bytes(1)[0]

    def u32(self) -> int:
        return int.from_bytes(self.bytes(4), "big")

    def u64(self) -> int:
        return int.from_bytes(self.bytes(8), "big")

    # -- derived streams --------------------------------------------------
    def fork(self, domain: str) -> "Rng":
        """Create an independent stream in a child domain.

        The child is keyed by ``SHA-256(parent_seed || domain)`` so that the
        child stream does not advance the parent, and two children with
        different labels are independent even when created in the same order.
        """
        label = domain.encode("utf-8") if isinstance(domain, str) else domain
        child_seed = hashlib.sha256(self._seed + b"\x01" + self._domain + b"\x01" + label).digest()[
            :SEED_BYTES
        ]
        return Rng(child_seed, label)

    # -- convenience ------------------------------------------------------
    def randbelow(self, n: int) -> int:
        """Uniform integer in ``[0, n)`` using rejection sampling (no modulo bias)."""
        if n <= 0:
            raise ValueError("randbelow requires n > 0")
        if n == 1:
            return 0
        bits = (n - 1).bit_length()
        nbytes = (bits + 7) // 8
        mask = (1 << bits) - 1
        while True:
            v = int.from_bytes(self.bytes(nbytes), "big") & mask
            if v < n:
                return v

    def randint(self, lo: int, hi: int) -> int:
        """Uniform integer in ``[lo, hi]`` inclusive."""
        if hi < lo:
            raise ValueError("randint requires hi >= lo")
        return lo + self.randbelow(hi - lo + 1)

    def chance(self, probability: float) -> bool:
        if probability <= 0.0:
            return False
        if probability >= 1.0:
            return True
        # 32-bit fixed point: deterministic and platform independent.
        return self.u32() < int(probability * 0x100000000)

    def bool(self) -> bool:
        return (self.byte() & 1) == 1

    def choice(self, seq: Sequence[T]) -> T:
        if not seq:
            raise IndexError("cannot choose from empty sequence")
        return seq[self.randbelow(len(seq))]

    def weighted(self, items: Sequence[tuple[T, float]]) -> T:
        total = sum(w for _, w in items)
        if total <= 0:
            return self.choice([i for i, _ in items])
        target = (self.u32() / 0x100000000) * total
        acc = 0.0
        for item, w in items:
            acc += w
            if target < acc:
                return item
        return items[-1][0]

    def sample(self, seq: Sequence[T], k: int) -> List[T]:
        pool = list(seq)
        if k > len(pool):
            raise ValueError("sample larger than population")
        for i in range(len(pool) - 1, 0, -1):
            j = self.randbelow(i + 1)
            pool[i], pool[j] = pool[j], pool[i]
        return pool[:k]

    def shuffle(self, seq: List[T]) -> List[T]:
        """In-place Fisher-Yates; returns the same list for convenience."""
        for i in range(len(seq) - 1, 0, -1):
            j = self.randbelow(i + 1)
            seq[i], seq[j] = seq[j], seq[i]
        return seq

    def shuffled(self, seq: Iterable[T]) -> List[T]:
        return self.shuffle(list(seq))

    def permutation(self, n: int) -> List[int]:
        """A uniformly random permutation of ``range(n)``."""
        return self.shuffle(list(range(n)))


# Randomness domains used across the pipeline.  Keeping them in one place makes
# it auditable that no two passes share a stream.
DOMAINS = (
    "identifiers",  # local/function/parameter/temporary renames
    "names-final",  # final emitted symbol spelling
    "cfg",  # block splitting / ordering / branch inversion
    "predicates",  # opaque predicate construction
    "constants",  # numeric constant encodings + masks
    "strings",  # string bank layout, fragmentation, keys
    "vm",  # VM architecture choice, layout, chunking
    "opcodes",  # opcode permutation
    "operands",  # operand format + transforms
    "registers",  # logical->physical register permutation
    "handlers",  # handler selection / splitting / fusion
    "dispatch",  # dispatcher family + topology
    "chunks",  # payload chunk boundaries
    "integrity",  # integrity regions + keys
    "decoys",  # decoy blocks / constants / handlers
    "emission",  # statement ordering inside generated blocks
    "pc",  # program-counter / epoch encoding
    "index-to-num",  # R9 table-key -> numeric-handle bijection
)


class RandomDomains:
    """A bundle of per-domain streams derived from one build seed."""

    def __init__(self, seed: bytes):
        self.seed = seed
        self._root = Rng(seed, "root")
        self._streams = {}

    def __call__(self, domain: str) -> Rng:
        stream = self._streams.get(domain)
        if stream is None:
            stream = self._root.fork(domain)
            self._streams[domain] = stream
        return stream

    def get(self, domain: str) -> Rng:
        return self(domain)

    def fork(self, label: str) -> "RandomDomains":
        """A whole new bundle in a sub-domain (used for per-function VMs)."""
        return RandomDomains(hashlib.sha256(self.seed + b"\x02" + label.encode()).digest()[:SEED_BYTES])


def make_domains(seed) -> RandomDomains:
    return RandomDomains(coerce_seed(seed))

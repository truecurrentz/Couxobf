"""Encrypted constant pool.

Every literal a prototype needs -- numbers, strings, booleans, nil -- is
collected into one pool, serialized, and sealed with an authenticated cipher.
The protected build carries only ciphertext; a constant is materialized by the
runtime on first use.

Two properties matter more than the cipher choice:

*The encoding is bit-exact.*  Numbers go through IEEE-754 double bytes, so
precision, NaN payloads, signed zero and the infinities all survive unchanged.
This is deliberately not an arithmetic scheme: any transform expressed in
floating-point arithmetic risks changing the value it protects.

*The key material is per build.*  Keys come from :class:`KeyMaterial`, derived
from the build seed with the ``constants`` purpose, and the sealed blob is
bound to a build context through the AAD, so a pool cannot be lifted out of one
build and dropped into another.

None of this makes constants secret from a determined analyst who runs the code
-- the plaintext is in memory the moment a constant is read.  What it does is
remove the literals from the static artifact, which is the part that reads
easily.  See ``docs/SECURITY.md`` for the threat model.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .crypto.kdf import KeyMaterial
from .crypto.protected import seal
from .rng import Rng

# Wire format tags.  Kept explicit and stable: the Luau decoder in
# :mod:`couxobf.runtime.constpool_runtime` matches these numbers.
TAG_NIL = 0
TAG_BOOL = 1
TAG_NUM = 2
TAG_STR = 3

# Cache policies for materialized constants.  "none" re-materializes on every
# read, which leaves the least plaintext sitting in the heap; "full" keeps
# everything; "bounded" keeps a rolling window.
CACHE_POLICIES = ("none", "bounded", "full")


class ConstantPoolError(Exception):
    pass


#: Suffixes that keep a decoy string the same shape as its neighbours.  All are
#: plausible in the kind of source this tool is pointed at, and none of them is a
#: word that would make a reader stop and look.
DECOY_SUFFIXES = (b"_v2", b"_x", b"2", b"Impl", b"_tmp", b"Id", b"Len")

#: "no decoy this time" -- a sentinel rather than None, which is a real constant.
_NO_DECOY = object()


def encode_value(value: Any) -> bytes:
    """Serialize one constant to its tagged wire form."""
    if value is None:
        return bytes([TAG_NIL])
    # bool must be tested before int: bool is a subclass of int in Python
    if isinstance(value, bool):
        return bytes([TAG_BOOL, 1 if value else 0])
    if isinstance(value, (int, float)):
        # Luau has no integer subtype; every number is a double, and packing
        # as one is exact for the whole domain including NaN and signed zero.
        return bytes([TAG_NUM]) + struct.pack(">d", float(value))
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        return bytes([TAG_STR]) + struct.pack(">I", len(raw)) + raw
    raise ConstantPoolError(f"cannot encode constant of type {type(value).__name__}")


def serialize(values: List[Any]) -> bytes:
    """Serialize a whole pool: a u32 count followed by the tagged entries."""
    out = [struct.pack(">I", len(values))]
    for v in values:
        out.append(encode_value(v))
    return b"".join(out)


@dataclass
class SealedPool:
    """Everything the runtime needs to open a pool, and nothing more."""

    key: bytes
    nonce: bytes
    tag: bytes
    ciphertext: bytes
    aad: bytes
    count: int

    def open_plaintext(self) -> bytes:
        """Decrypt on the Python side -- used to cross-check the Luau runtime."""
        from .crypto.protected import open_

        return open_(self.key, self.nonce, self.ciphertext, self.tag, self.aad)


class ConstantPool:
    """Interns constants and seals them into one authenticated blob."""

    def __init__(
        self,
        keys: KeyMaterial,
        rng: Rng,
        context: bytes,
        cache_policy: str = "full",
        cache_bound: int = 64,
        decoys: int = 0,
    ) -> None:
        if cache_policy not in CACHE_POLICIES:
            raise ConstantPoolError(f"unknown cache policy {cache_policy!r}")
        self.keys = keys
        self.rng = rng
        self.context = context
        self.cache_policy = cache_policy
        self.cache_bound = cache_bound
        self._values: List[Any] = []
        self._index: Dict[Any, int] = {}
        self._sealed: Optional[SealedPool] = None
        # See :meth:`_plant_decoys`.  The budget is per build, not per prototype,
        # because a fixed number per function would make the decoy count a
        # function of how many functions there are -- which is a signal in itself.
        self._decoy_budget = max(0, int(decoys))
        self.decoys_planted = 0

    # -- collection -------------------------------------------------------

    def slot(self, value: Any) -> int:
        """Intern a constant and return its 1-based slot number.

        ``float`` and ``int`` that compare equal share a slot, which is correct
        because Luau cannot distinguish them either.  ``True`` and ``1`` do not,
        because the bool check runs first.
        """
        if self._sealed is not None:
            # The blob is already encrypted, so this value would get a slot
            # number the ciphertext does not contain and the runtime would read
            # nil.  That failure shows up at the use site, far from here, so it
            # is refused at the cause instead.
            raise ConstantPoolError(
                "cannot intern a constant after the pool was sealed")
        key = self._key_for(value)
        hit = self._index.get(key)
        if hit is not None:
            return hit
        self._values.append(value)
        index = len(self._values)
        self._index[key] = index
        self._plant_decoys()
        return index

    # -- decoys ------------------------------------------------------------

    def _plant_decoys(self) -> None:
        """Append plausible-but-unused constants after the one just interned.

        A decoy is a fully encoded entry -- same tag, same encryption, same slot
        arithmetic -- that no instruction reaches, so a recovered pool has to be
        *executed* against the payload to tell which entries are real.  They are
        scattered by construction rather than gathered into one tail, because a run
        of entries that nothing indexes is the one shape that is trivial to filter
        out: the tail is the giveaway, not the entries.

        They are derived from values already in the pool for the same reason a
        random string would fail: an analyst who cannot tell a decoy from a real
        constant is the goal, and ``"xq7f"`` next to ``"GetPartsC"`` is tellable.
        """
        if self._decoy_budget <= 0:
            return
        # A gate that usually passes, then one or two entries: a small pool spends
        # part of its budget and a large one exhausts it, which is what "scales with
        # the real pool" has to mean when the pool's size is not known yet.
        while self._decoy_budget > 0 and self.rng.chance(0.6):
            decoy = self._decoy_value()
            if decoy is _NO_DECOY:
                return
            key = self._key_for(decoy)
            if key in self._index:
                continue          # a duplicate of a real value: not a decoy at all
            self._index[key] = len(self._values) + 1
            self._values.append(decoy)
            self._decoy_budget -= 1
            self.decoys_planted += 1
            if not self.rng.chance(0.75):
                break               # do not clump: one here is often enough

    def _decoy_value(self) -> Any:
        if not self._values:
            return _NO_DECOY
        pick = self.rng.choice(self._values)
        if isinstance(pick, bool) or pick is None:
            return _NO_DECOY
        if isinstance(pick, (int, float)):
            # Off by a small amount rather than by a random one: a decoy that is
            # 4.2e17 next to 3 is a decoy a reader can spot by magnitude alone.
            delta = float(self.rng.randint(1, 9))
            return pick + (delta if self.rng.bool() else -delta)
        raw = bytes(pick)
        if len(raw) < 3:
            return _NO_DECOY
        cut = self.rng.randint(1, max(1, len(raw) - 2))
        keep = raw[:cut] if self.rng.bool() else raw[cut:]
        suffix = DECOY_SUFFIXES[self.rng.randbelow(len(DECOY_SUFFIXES))]
        return keep + suffix

    @staticmethod
    def _key_for(value: Any) -> Any:
        if value is None or isinstance(value, bool):
            return ("special", value)
        if isinstance(value, (int, float)):
            # Key on the IEEE-754 bit pattern, not the value.  Comparing by
            # value would collapse -0.0 into 0.0 (they are `==` in both Python
            # and Luau) and merge distinct NaN payloads, which changes
            # observable behaviour: `1 / -0.0` is -inf while `1 / 0.0` is +inf.
            # Bit patterns still intern 1 with 1.0, which is what we want.
            return ("num", struct.unpack(">Q", struct.pack(">d", float(value)))[0])
        if isinstance(value, (bytes, bytearray)):
            return ("str", bytes(value))
        raise ConstantPoolError(f"cannot intern {type(value).__name__}")

    @property
    def values(self) -> List[Any]:
        return list(self._values)

    def __len__(self) -> int:
        return len(self._values)

    # -- sealing ----------------------------------------------------------

    def seal(self) -> SealedPool:
        """Encrypt the pool.  Idempotent: the same pool seals once."""
        if self._sealed is not None:
            return self._sealed
        if not self._values:
            raise ConstantPoolError("refusing to seal an empty pool")
        plaintext = serialize(self._values)
        # A fresh key per pool region, and a random nonce per build: reusing a
        # (key, nonce) pair across two different pools would leak their XOR.
        region = self.rng.bytes(16)
        key = self.keys.region_key("constants", region)
        nonce = self.rng.bytes(12)
        aad = b"couxobf/constpool/v1\0" + self.context
        nonce_out, ciphertext, tag = seal(key, plaintext, aad, nonce=nonce)
        self._sealed = SealedPool(
            key=key,
            nonce=nonce_out,
            tag=tag,
            ciphertext=ciphertext,
            aad=aad,
            count=len(self._values),
        )
        return self._sealed

    def plaintext(self) -> bytes:
        """The unencrypted pool -- only for tests and cross-checks."""
        return serialize(self._values)


def decode_pool(plaintext: bytes) -> List[Any]:
    """Python mirror of the Luau decoder, used to verify the two agree."""
    if len(plaintext) < 4:
        raise ConstantPoolError("truncated pool header")
    (count,) = struct.unpack_from(">I", plaintext, 0)
    pos = 4
    out: List[Any] = []
    for _ in range(count):
        tag = plaintext[pos]
        pos += 1
        if tag == TAG_NIL:
            out.append(None)
        elif tag == TAG_BOOL:
            out.append(plaintext[pos] != 0)
            pos += 1
        elif tag == TAG_NUM:
            (value,) = struct.unpack_from(">d", plaintext, pos)
            out.append(value)
            pos += 8
        elif tag == TAG_STR:
            (length,) = struct.unpack_from(">I", plaintext, pos)
            pos += 4
            out.append(plaintext[pos : pos + length])
            pos += length
        else:
            raise ConstantPoolError(f"unknown constant tag {tag}")
    if pos != len(plaintext):
        raise ConstantPoolError("trailing bytes after the last constant")
    return out

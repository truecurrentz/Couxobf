"""The string bank: fragmented, scattered, paged, ticket-addressed strings.

The constant pool already encrypts every constant, so why a second mechanism?
Because they defeat different things, and the difference is the ticket.

The pool **interns by value**: a string used five times is stored once and read
through one accessor.  Find the accessor and every string in the program is
yours, in one pass, without running anything.  The bank deliberately does the
opposite.  Every *occurrence* gets its own ticket, so resolving one site tells
you nothing about the next, and there is no single routine whose recovery
yields the whole set.

The construction, in the order the design specifies:

fragment
    Each string is cut into small pieces.  No contiguous run of one string
    survives, so a length-based scan for "the interesting string" has nothing
    to find.

reversible op
    Each fragment is XORed with a cheap pseudorandom mask before encryption.
    This is **obfuscation depth, not confidentiality** -- ChaCha20's output is
    already indistinguishable from random, so the mask adds no secrecy.  What
    it does add is that a guessed decryption cannot be confirmed by looking
    for printable text.  It is labelled as such rather than passed off as a
    second cipher.

scatter, then page, then shuffle
    All fragments go into one flat buffer, which is cut into fixed pages and
    stored in a permuted order.  Storage position and logical position are
    unrelated, and the permutation is itself encrypted.

ChaCha20
    One keystream over the *logical* buffer, so a fragment is decrypted by
    seeking to its offset -- which is what makes lazy acquisition cheap
    instead of requiring the whole bank up front.

Tickets
    An encrypted table mapping each ticket to its fragment list.

Honest scope, same as everywhere else in this project: the keys are derived
inside the artifact, so this raises the cost of static reading and defeats
casual extraction.  It does not keep strings secret from someone who runs the
program and instruments it.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..crypto.cipher import CipherSpec, default_spec
from ..crypto.protected import ENC_DOMAIN, MAC_DOMAIN, open_ as _open
from ..crypto.protected import seal as _seal
from ..rng import Rng

#: Default page size in bytes.  Small enough that resolving one string touches
#: a fraction of the bank; large enough that the page count stays sane.
DEFAULT_PAGE_SIZE = 512

#: Fragments are between these sizes, chosen per fragment.
MIN_FRAGMENT = 3
MAX_FRAGMENT = 11


class StringBankError(Exception):
    pass


@dataclass
class _Fragment:
    """One piece of one string."""

    offset: int
    length: int
    mask_seed: int


@dataclass
class SealedBank:
    """What the runtime needs, and nothing it does not."""

    #: Pages concatenated in *storage* order.
    blob: bytes
    #: Authenticated ticket table: ticket -> fragment list, plus the page
    #: permutation.  Encrypted, because the permutation is the thing that makes
    #: storage order meaningless.
    ticket_nonce: bytes
    ticket_tag: bytes
    ticket_ct: bytes
    ticket_aad: bytes
    key: bytes
    #: Separate key for the ticket table.  Reusing the stream key would let one
    #: recovery give an attacker both the permutation and the keystream.
    ticket_key: bytes
    #: ChaCha20 nonce for the keystream over the logical buffer.
    stream_nonce: bytes
    #: HMAC-SHA256 over ``blob``.  Without it, editing a page produces garbage
    #: strings rather than an error -- confidentiality without integrity.  It is
    #: one MAC over the whole blob, checked once at load, so it costs nothing
    #: per string and does not disturb lazy acquisition.
    blob_key: bytes
    blob_tag: bytes
    page_size: int
    page_count: int
    ticket_count: int
    indirect_ids: bool = False
    enc_domain: bytes = b""
    mac_domain: bytes = b""
    mask_mul: int = 0
    mask_add: int = 0
    mask_shift: int = 0


MASK_MOD = 1 << 31


def _mask_bytes(seed: int, length: int, mul: int, add: int, shift: int) -> bytes:
    out = bytearray()
    x = seed % MASK_MOD
    for _ in range(length):
        x = (x * mul + add) % MASK_MOD
        out.append((x >> shift) & 0xFF)
    return bytes(out)


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


class StringBank:
    """Collects string occurrences and seals them into a protected bank."""

    def __init__(self, keys: Any, rng: Rng, context: bytes,
                 page_size: int = DEFAULT_PAGE_SIZE,
                 per_occurrence: bool = True,
                 randomized_ids: bool = False,
                 enc_domain: bytes = None,
                 mac_domain: bytes = None,
                 cipher: Any = None) -> None:
        # The block size is the drawn cipher's, not a constant of the tool:
        # a build that drew AES-128 seeks its keystream in 16-byte blocks, so
        # the page geometry has to be expressed in the same unit.
        self.cipher = cipher if cipher is not None else default_spec()
        block = self.cipher.block_size
        if page_size < block:
            raise StringBankError(f"page size must be at least {block} bytes")
        if page_size % block != 0:
            # The keystream is addressed in cipher blocks; a page size that is
            # not a multiple would make page and block boundaries interact in
            # ways the runtime does not model.
            raise StringBankError(f"page size must be a multiple of {block}")
        self.keys = keys
        self.rng = rng
        self.context = context
        self.page_size = page_size
        self.per_occurrence = per_occurrence
        self.randomized_ids = bool(randomized_ids)
        self.enc_domain = enc_domain
        self.mac_domain = mac_domain
        self._tickets: List[Tuple[int, List[_Fragment]]] = []
        self._used_ids = set()
        self._flat = bytearray()
        self._mask_mul = (self.rng.randbelow(0x1F0000) + 0x10000) | 1
        if self._mask_mul == ((0x10 << 16) | 0xd69b):
            self._mask_mul ^= 0x2041
        self._mask_add = (self.rng.randbelow(MASK_MOD - 1) + 1) | 1
        if self._mask_add == ((0x30 << 8) | 0x39):
            self._mask_add ^= 0x4041
        self._mask_shift = 8 + self.rng.randbelow(16)
        self._sealed: Optional[SealedBank] = None
        #: When occurrences share fragments, one value maps to one fragment
        #: list.  Off by default: sharing is what makes per-occurrence tickets
        #: pointless.
        self._shared: Dict[bytes, List[_Fragment]] = {}
        self._region = rng.bytes(16)

    def __len__(self) -> int:
        return len(self._tickets)

    # -- collection ------------------------------------------------------
    def ticket(self, value) -> int:
        """Reserve the next ticket for ``value`` and return its number.

        Called once per *occurrence*, not once per distinct string.  That is
        the whole point: two uses of the same literal get two tickets, and
        resolving one says nothing about the other.
        """
        if self._sealed is not None:
            raise StringBankError(
                "cannot issue a ticket after the bank was sealed")
        raw = self._as_bytes(value)
        if self.per_occurrence or raw not in self._shared:
            frags = self._emit_fragments(raw)
            if not self.per_occurrence:
                self._shared[raw] = frags
        else:
            frags = self._shared[raw]
        if self.randomized_ids:
            ticket = self.rng.randbelow(0x7FFFFFFE) + 1
            while ticket in self._used_ids:
                ticket = self.rng.randbelow(0x7FFFFFFE) + 1
        else:
            ticket = len(self._tickets) + 1  # 1-based, so 0 is never valid
        self._used_ids.add(ticket)
        self._tickets.append((ticket, frags))
        return ticket

    @staticmethod
    def _as_bytes(value) -> bytes:
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        if isinstance(value, str):
            return value.encode("utf-8", "surrogatepass")
        raise StringBankError(f"the string bank holds strings, not "
                              f"{type(value).__name__}")

    def _emit_fragments(self, raw: bytes) -> List[_Fragment]:
        """Append ``raw`` to the flat buffer as masked fragments."""
        frags: List[_Fragment] = []
        pos = 0
        while pos < len(raw):
            size = self.rng.randbelow(MAX_FRAGMENT - MIN_FRAGMENT + 1) + MIN_FRAGMENT
            size = min(size, len(raw) - pos)
            piece = raw[pos:pos + size]
            start = self._reserve(size)
            seed = self.rng.randbelow(0x7FFFFFFF)
            masked = _xor(piece, _mask_bytes(seed, len(piece),
                                          self._mask_mul, self._mask_add,
                                          self._mask_shift))
            self._flat[start:start + size] = masked
            frags.append(_Fragment(offset=start, length=size, mask_seed=seed))
            pos += size
        if not frags:
            # An empty string still needs a ticket that resolves to "".  Rather
            # than a special case in the runtime, give it one zero-length
            # fragment: the loop runs once, reads nothing, and concatenates "".
            start = self._reserve(0)
            frags.append(_Fragment(offset=start, length=0, mask_seed=0))
        return frags

    def _reserve(self, size: int) -> int:
        """Claim ``size`` bytes of the flat buffer, never straddling a page.

        Fragments that stayed inside one page would let the runtime seek with a
        single page lookup.  Allowing a straddle would mean every read has to
        consider two pages and two keystream positions, for no gain: the
        straddle hides nothing that fragmentation does not already hide.
        """
        page = self.page_size
        pos = len(self._flat)
        if pos % page + size > page:
            pad = page - (pos % page)
            self._flat.extend(bytes(pad))
            pos = len(self._flat)
        self._flat.extend(bytes(size))
        return pos

    # -- sealing ---------------------------------------------------------
    def seal(self) -> SealedBank:
        """Encrypt the bank.  Idempotent."""
        if self._sealed is not None:
            return self._sealed
        if not self._tickets:
            raise StringBankError("refusing to seal an empty string bank")

        page = self.page_size
        if len(self._flat) % page:
            self._flat.extend(bytes(page - len(self._flat) % page))
        flat = bytes(self._flat)
        page_count = len(flat) // page

        # The keystream runs over the *logical* buffer, so storage order and
        # keystream position are independent: shuffling pages moves ciphertext
        # around without changing how it decrypts.
        stream_nonce = self.rng.bytes(12)
        key = self.keys.region_key("string-bank", self._region)
        cipher = self.cipher.xor_bytes(key, stream_nonce, flat, counter=1)

        order = list(range(page_count))
        self.rng.shuffle(order)          # order[stored] = logical
        perm = [0] * page_count          # perm[logical] = stored
        for stored, logical in enumerate(order):
            perm[logical] = stored

        blob = bytearray()
        for stored, logical in enumerate(order):
            blob += cipher[logical * page:(logical + 1) * page]

        ticket_plain = self._encode_tickets(perm, page_count)
        ticket_key = self.keys.region_key("string-bank",
                                          b"tickets\0" + self._region)
        # A third key, separate from the keystream and the ticket table: one
        # recovery should not hand over the others.
        blob_key = self.keys.region_key("string-bank",
                                        b"blob\0" + self._region)
        ticket_aad = hashlib.sha256(b"bank-aad" + self.context + self._region).digest()
        enc_domain = self.enc_domain if self.enc_domain is not None else ENC_DOMAIN
        mac_domain = self.mac_domain if self.mac_domain is not None else MAC_DOMAIN
        nonce, ct, tag = _seal(ticket_key, ticket_plain, ticket_aad,
                               nonce=self.rng.bytes(12),
                               enc_domain=enc_domain,
                               mac_domain=mac_domain,
                               cipher=self.cipher)

        self._sealed = SealedBank(
            blob=bytes(blob),
            ticket_nonce=nonce,
            ticket_tag=tag,
            ticket_ct=ct,
            ticket_aad=ticket_aad,
            key=key,
            ticket_key=ticket_key,
            blob_key=blob_key,
            blob_tag=_hmac.new(blob_key, bytes(blob), "sha256").digest(),
            stream_nonce=stream_nonce,
            page_size=page,
            page_count=page_count,
            ticket_count=len(self._tickets),
            indirect_ids=self.randomized_ids,
            enc_domain=enc_domain,
            mac_domain=mac_domain,
            mask_mul=self._mask_mul,
            mask_add=self._mask_add,
            mask_shift=self._mask_shift,
        )
        return self._sealed

    def _encode_tickets(self, perm: List[int], page_count: int) -> bytes:
        out = bytearray()
        out += struct.pack(">III", len(self._tickets), page_count,
                           self.page_size)
        for slot in perm:
            out += struct.pack(">I", slot)
        for ticket_id, frags in self._tickets:
            if self.randomized_ids:
                out += struct.pack(">I", ticket_id)
            out += struct.pack(">H", len(frags))
            for f in frags:
                out += struct.pack(">IHI", f.offset, f.length, f.mask_seed)
        return bytes(out)

    # -- reference resolver ---------------------------------------------
    def resolve(self, ticket: int) -> bytes:
        """Recover one ticket's string, in Python.

        Not production code: it is the reference the Luau runtime is checked
        against.  If the two disagree the test fails here, with the ticket
        number, rather than somewhere inside generated Luau.
        """
        sealed = self.seal()
        plain = _open(self.keys.region_key("string-bank",
                                           b"tickets\0" + self._region),
                      sealed.ticket_nonce, sealed.ticket_ct, sealed.ticket_tag,
                      sealed.ticket_aad, enc_domain=sealed.enc_domain,
                      mac_domain=sealed.mac_domain, cipher=self.cipher)
        if plain is None:
            raise StringBankError("ticket table failed authentication")
        tickets, page_count, page_size = struct.unpack_from(">III", plain, 0)
        pos = 12
        perm = []
        for _ in range(page_count):
            perm.append(struct.unpack_from(">I", plain, pos)[0])
            pos += 4
        found = None
        if self.randomized_ids:
            for _ in range(tickets):
                ticket_id = struct.unpack_from(">I", plain, pos)[0]
                pos += 4
                count = struct.unpack_from(">H", plain, pos)[0]
                if ticket_id == ticket:
                    pos += 2
                    found = (pos, count)
                    break
                pos += 2 + count * 10
            if found is None:
                raise StringBankError(f"ticket {ticket} out of range")
            pos, count = found
        else:
            if not 1 <= ticket <= tickets:
                raise StringBankError(f"ticket {ticket} out of range")
            for _ in range(ticket - 1):
                count = struct.unpack_from(">H", plain, pos)[0]
                pos += 2 + count * 10
            count = struct.unpack_from(">H", plain, pos)[0]
            pos += 2

        key = self.keys.region_key("string-bank", self._region)
        out = bytearray()
        for _ in range(count):
            offset, length, seed = struct.unpack_from(">IHI", plain, pos)
            pos += 10
            if length == 0:
                continue
            logical_page = offset // page_size
            stored = perm[logical_page]
            in_page = offset - logical_page * page_size
            ct = sealed.blob[stored * page_size + in_page:
                             stored * page_size + in_page + length]
            block = offset // self.cipher.block_size
            intra = offset % self.cipher.block_size
            ks = self.cipher.xor_bytes(key, sealed.stream_nonce,
                                       bytes(intra + length),
                                       counter=1 + block)
            masked = _xor(ct, ks[intra:])
            out += _xor(masked, _mask_bytes(seed, length, sealed.mask_mul,
                                           sealed.mask_add, sealed.mask_shift))
        return bytes(out)

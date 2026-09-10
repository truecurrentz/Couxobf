"""Dense blob encoding: base85 over a per-build alphabet.

Sealed material (pool ciphertext, bank pages, ticket metadata) used to ship as
``\\xHH`` escapes: four source characters per byte, so a 60 KB payload became
240 KB of quoted text and the size budget started trading real protection
away.  Base85 carries the same bytes at 1.25 characters per byte -- 5 chars
per 4-byte group -- which is the density win without importing a compressor:
a Luau LZMA decoder is large, slow to boot and one of the most fingerprinted
shapes an obfuscator can ship, while the alphabet decoder is a dozen lines
that read like any other generated scaffolding.

The alphabet is a per-build permutation of 85 printable ASCII characters
(no quote, no backslash, no whitespace, so the encoded text can sit inside a
plain double-quoted literal with no escapes at all).  It is emitted as
escaped chunks whose locals are declared in a build-shuffled order and then
concatenated back into the alphabet, so the base never appears as one
contiguous 85-character run a matcher could key on, and the order the pieces
appear in the source carries no information about it.  The reverse table is
rebuilt from it at load, and decoding is one indexing pass per blob.
Load-time only -- the interpreter never calls it.

Convention: 4 bytes encode to 5 characters; a final short group of k bytes
(1..3) encodes to k+1 characters, the value being the big-endian integer of
the group zero-extended, which keeps the decode of a short group exact.
"""

from __future__ import annotations

import hashlib
from typing import Dict, List

from ..rng import Rng

#: Printable ASCII minus quote and backslash: 92 candidates, 85 used.  Every
#: encoded byte string is therefore safe inside a bare ``"..."`` literal.
ALPHABET_CANDIDATES = tuple(
    chr(c) for c in range(33, 127) if chr(c) not in "\"\\"
)
ALPHABET_SIZE = 85


def draw_alphabet(rng: Rng) -> str:
    """One build's 85-character base: a drawn subset in a drawn order."""
    chars = list(ALPHABET_CANDIDATES)
    rng.shuffle(chars)
    return "".join(chars[:ALPHABET_SIZE])


def encode(data: bytes, alphabet: str) -> str:
    """Base85 text for ``data`` under this build's alphabet.

    Big-endian groups: five digits per four bytes, and a trailing group of
    ``k`` bytes takes ``k + 1`` digits (always enough: ``256**3 < 85**4``).
    """
    out: List[str] = []
    for i in range(0, len(data), 4):
        chunk = data[i:i + 4]
        value = int.from_bytes(chunk, "big")
        ndigits = 5 if len(chunk) == 4 else len(chunk) + 1
        digits: List[str] = []
        for _ in range(ndigits):
            digits.append(alphabet[value % ALPHABET_SIZE])
            value //= ALPHABET_SIZE
        digits.reverse()
        out.append("".join(digits))
    return "".join(out)


def _escape(chunk: str) -> str:
    return '"' + "".join("\\x%02x" % ord(c) for c in chunk) + '"'


class DenseCodec:
    """One build's encoder (Python side) and decoder (Luau source).

    ``names`` provides fresh identifiers for the decoder and its reverse
    table; the alphabet itself is carried by the instance, drawn once and
    stable for the whole build, so every blob the build ships speaks the
    same base.
    """

    __slots__ = ("alphabet", "dec", "rev", "_rng_digest")

    def __init__(self, rng: Rng, names: Dict[str, str]) -> None:
        self.alphabet = draw_alphabet(rng)
        self.dec = names["dec"]
        self.rev = names["rev"]
        # Digest of the alphabet: tests and reports can compare codecs without
        # carrying the alphabet itself around.
        self._rng_digest = hashlib.sha256(self.alphabet.encode()).hexdigest()[:16]

    @property
    def digest(self) -> str:
        return self._rng_digest

    def expr(self, data: bytes) -> str:
        """A Luau expression that evaluates to exactly these bytes."""
        if not data:
            return '""'
        return '%s("%s")' % (self.dec, encode(data, self.alphabet))

    def source(self, rng: Rng) -> str:
        """The decoder, as Luau source for the build's preamble.

        The alphabet literal is split at build-random boundaries into escaped
        chunks; the chunk *locals* are declared in a shuffled order and then
        concatenated in alphabet order, so the source order of the pieces
        carries no information about the base, and the base itself never
        appears as one contiguous literal.  Everything else is plain generated
        code: the reverse table keyed by byte value (no substring garbage per
        character), then one accumulation loop.  Integer arithmetic stays in
        the double-exact range throughout: the accumulator tops out below
        ``85**5 < 2**33`` and the byte extracts divide by powers of 256.
        """
        alpha = self.alphabet
        cuts: List[int] = [0]
        pos = 0
        while pos < len(alpha):
            size = 5 + int.from_bytes(rng.bytes(1), "big") % 8
            pos = min(pos + size, len(alpha))
            cuts.append(pos)
        chunks = [alpha[cuts[i]:cuts[i + 1]] for i in range(len(cuts) - 1)]
        order = list(range(len(chunks)))
        rng.shuffle(order)
        # Declare the escaped chunks in a shuffled order, then concatenate
        # them back in alphabet order: the source order of the declarations
        # carries no information about the alphabet, and the alphabet itself
        # never appears as one contiguous literal.
        decls = ["  local c%d = %s" % (i, _escape(chunks[i])) for i in order]
        assembly = " .. ".join("c%d" % i for i in range(len(chunks)))
        return (
            "local %s, %s\n"
            "do\n"
            "%s\n"
            "  local a = %s\n"
            "  local t = {}\n"
            "  for i = 1, #a do t[string.byte(a, i)] = i - 1 end\n"
            "  %s = t\n"
            "  %s = function(s)\n"
            "    local out = table.create((#s + 4) // 5)\n"
            "    local n, acc, cnt = 0, 0, 0\n"
            "    for i = 1, #s do\n"
            "      acc = acc * 85 + t[string.byte(s, i)]\n"
            "      cnt = cnt + 1\n"
            "      if cnt == 5 then\n"
            "        n = n + 1\n"
            "        out[n] = string.char(acc // 16777216 %% 256, "
            "acc // 65536 %% 256, acc // 256 %% 256, acc %% 256)\n"
            "        acc, cnt = 0, 0\n"
            "      end\n"
            "    end\n"
            "    if cnt > 1 then\n"
            "      local k = cnt - 1\n"
            "      local p = 1\n"
            "      for _ = 1, k do p = p * 256 end\n"
            "      local tail = table.create(k)\n"
            "      for _ = 1, k do\n"
            "        p = p // 256\n"
            "        tail[#tail + 1] = string.char(acc // p %% 256)\n"
            "      end\n"
            "      n = n + 1\n"
            "      out[n] = table.concat(tail)\n"
            "    end\n"
            "    return table.concat(out)\n"
            "  end\n"
            "end\n" % (self.dec, self.rev, "\n".join(decls), assembly,
                       self.rev, self.dec)
        )




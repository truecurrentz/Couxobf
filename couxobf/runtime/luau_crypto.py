"""Generated Luau runtime: one build's cipher, hash and AEAD composition.

This emits *source*, never bytecode: the protected program carries an ordinary
Luau implementation of the same primitives the build tool used, so the output
stays portable (no ``loadstring`` of compiled bytecode, no native libs, no
executor-specific APIs).

Why the shape moves between builds
----------------------------------
Every artifact used to carry the same ~8 KB of crypto text with the identifiers
changed and nothing else.  That made it the most recognisable object in the
file: an analyst does not have to understand the VM to find ``expand 32-byte
k`` or ``0x428a2f98``, and a decoder that finds the decrypt routine has found
the one choke point in the artifact.

So the module below is *assembled* per build out of independently drawn pieces:

**Which core.** ChaCha20 (RFC 8439) or AES-128 in CTR mode (FIPS 197).  Both
are published, both are exact under Luau's doubles, and a build that drew AES
contains no ChaCha constant at all.  Authentication is HMAC-SHA256 either way
in the same encrypt-then-MAC composition -- see :mod:`couxobf.crypto.cipher`
for what is and is not claimed here.

**Which shape inside the core.** ChaCha20's eight quarter-rounds are either
spelled out or walked from a shuffled schedule table (legal: the four column
rounds touch disjoint columns, and so do the four diagonal ones).  AES's
final round is either branched inside the loop or split out of it, and its
S-box is either generated at load from GF(2^8) -- no 256-byte constant in the
file -- or tabulated.  SHA-256's message schedule is a 64-word array or a
rolling 16-word window.  Constant tables are literal or assembled from
shuffled fragments.  The AEAD composition's six small functions are declared
in a per-build order behind forward declarations, so "find the decrypt
function" does not locate a fixed block of text.

**Which identifiers.** Every local, including the ones a reader would
recognise (``rotl``, ``le32``, ``compute_tag``), is drawn per build and is
scoped to this module, so nothing inside it is named by its role.

None of that changes a byte of keystream -- it changes the source an analyst
reads, which is the only thing the artifact *is*.  The bytes are pinned by
``tests/test_crypto_cores.py`` against FIPS-197, NIST SP 800-38A and the
Python implementations, for every core and every variant.

Why these two primitives and not RFC 8439's AEAD
------------------------------------------------
Luau has **no integer subtype** -- every number is an IEEE-754 double, and this
was verified on the pinned toolchain (``2^53 + 1 == 2^53`` evaluates to
``true``).  Only magnitudes below 2^53 are exact.

* Poly1305 needs a 130-bit accumulator; even the standard 26-bit-limb
  reduction produces ~55-bit intermediates.  It cannot be written correctly in
  pure Luau, and a wrong MAC is worse than no MAC.  It was dropped.
* ChaCha20 keeps every state word below 2^32 and reduces additions mod 2^32,
  so all intermediates stay below 2^33: exact.
* AES-128 as specified here is byte-oriented: every intermediate is a byte,
  and the only arithmetic is XOR and shifts of values below 2^9.
* SHA-256 is entirely 32-bit for the same reason.

The composition is encrypt-then-MAC, which is what lets the runtime reject a
tampered payload before it is decrypted.

Environment constraints honoured (all verified, not assumed)
------------------------------------------------------------
* ``bit32.rotl`` / ``bit32.rotr`` do not exist in Luau -- rotation is written
  as ``bor(rshift(x, n), lshift(x, 32 - n))``;
* ``bit32`` functions normalize their argument modulo 2^32 before operating,
  so anything that may exceed 32 bits uses ``//`` and ``%`` instead;
* ``math.type`` / ``math.tointeger`` do not exist, so nothing here tries to
  distinguish integers from floats;
* only ``bit32``, ``string``, ``table`` and ``math`` are used -- all present in
  both Roblox Luau and the standalone VM.  ``buffer``, ``task``, ``debug`` and
  ``os`` are not required.

Cost note: pure-Luau ChaCha20 is roughly 1.5k interpreter operations per
64-byte block, AES-128-CTR about 1.6k per 16-byte block, and SHA-256 about 3k
per 64-byte block, which is why payload decoding is chunked and lazy instead
of happening wholesale at startup.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..crypto.aes import SBOX as AES_SBOX
from ..crypto.chacha20 import COLUMN_ROUNDS, DIAGONAL_ROUNDS
from ..crypto.cipher import AES_CTR, CHA_CHA, CipherSpec
from ..crypto.protected import ENC_DOMAIN, MAC_DOMAIN
from ..crypto.sha256 import H_INIT, K

# Sigma constants: little-endian 32-bit words of "expand 32-byte k".
SIGMA = (1634760805, 857760878, 2036477234, 1797285236)

#: Luau reserved words.  Internal module names are drawn, not fixed, and a
#: generated identifier that happens to be a keyword is a compile error that
#: only shows up in the artifact -- so the reserve list is checked, not hoped.
_LUAU_KEYWORDS = frozenset("""
and break continue do else elseif end false for function goto if in local nil
not or repeat return then true until while
""".split())


def _byte_literal(data: bytes) -> str:
    return '"' + ''.join('\\x%02x' % b for b in data) + '"'


# --------------------------------------------------------------------------
# internal names
# --------------------------------------------------------------------------

#: Roles the module needs a local for.  ``public`` names come from the caller
#: and are deliberately absent: they are declared in the enclosing scope and
#: must not be shadowed by anything drawn here.
_INTERNAL_ROLES = (
    "band", "bor", "bxor", "bnot", "lsh", "rsh", "byte", "char", "rep",
    "sub", "m32", "mod", "rotl", "rotr", "le32", "bytes_out",
    # chacha20
    "sigma", "cstate", "cwork", "qr", "cblock", "prepk", "prepn", "ks",
    "qsched",
    # aes128
    "sbox", "gensbox", "xt", "expand", "encrypt", "ctr4",
    # sha256 / hmac
    "shak", "shah", "wbuf", "sblocks", "extend", "sha", "hmac",
    # composition
    "le64", "enckey", "mackey", "ctag", "ceq", "opn", "sl",
)

_FIXED: Dict[str, str] = {
    "band": "band", "bor": "bor", "bxor": "bxor", "bnot": "bnot",
    "lsh": "lshift", "rsh": "rshift", "byte": "byte", "char": "char",
    "rep": "rep", "sub": "sub", "m32": "M32", "mod": "MOD32",
    "rotl": "rotl", "rotr": "rotr", "le32": "le32", "bytes_out": "bytes_out",
    "sigma": "SIGMA", "cstate": "cstate", "cwork": "cwork", "qr": "qr",
    "cblock": "chacha_block", "prepk": "prep_key", "prepn": "prep_nonce",
    "ks": "keystream", "qsched": "QR",
    "sbox": "SBOX", "gensbox": "gen_sbox", "xt": "xtime", "expand": "expand",
    "encrypt": "encrypt_block", "ctr4": "ctr_bytes",
    "shak": "SHA_K", "shah": "SHA_H", "wbuf": "wbuf",
    "sblocks": "sha256_blocks", "extend": "extend", "sha": "sha256",
    "hmac": "hmac",
    "le64": "le64", "enckey": "enc_key", "mackey": "mac_key",
    "ctag": "compute_tag", "ceq": "const_eq", "opn": "open_", "sl": "seal_",
}


def _internal_names(rng: Any, forbidden: Sequence[str]) -> Dict[str, str]:
    """Draw one build's internal local names.

    ``rng`` is the build's crypto-shape stream, so the names are reproducible
    from the seed.  Without an ``rng`` the historical fixed names come back,
    which is what the cross-implementation tests compare against: those pin
    *bytes*, not identifiers, and a fixed spelling keeps a failure readable.
    """
    if rng is None:
        return dict(_FIXED)
    taken = set(forbidden) | set(_FIXED.values()) | _LUAU_KEYWORDS
    out: Dict[str, str] = {}
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    body = alphabet + "0123456789_"
    for role in _INTERNAL_ROLES:
        while True:
            length = 2 + rng.randbelow(6)
            name = rng.choice(alphabet) + "".join(rng.choice(body)
                                                  for _ in range(length))
            if name in taken:
                continue
            taken.add(name)
            out[role] = name
            break
    return out


# --------------------------------------------------------------------------
# constant tables
# --------------------------------------------------------------------------

def _num_rows(values: Sequence[int], width: int = 8,
              per_row: int = 8, fmt: str = "0x%08x") -> str:
    rows = []
    for i in range(0, len(values), per_row):
        rows.append("  " + ", ".join(fmt % v for v in values[i:i + per_row]) + ",")
    return "\n".join(rows)


def _num_table(n: Dict[str, str], name_role: str, values: Sequence[int],
               style: str, rng: Any, per_row: int = 8,
               fmt: str = "0x%08x") -> str:
    """Emit a numeric constant table, literally or from shuffled fragments.

    Fragmented emission splits the table at per-build boundaries, declares the
    pieces under their own drawn names, and concatenates them back in the real
    order inside an immediately-called function -- so the constant sequence
    never appears contiguously and the declaration order carries no
    information.
    """
    name = n[name_role]
    values = list(values)
    if style != "fragmented" or rng is None or len(values) < 8:
        return "local %s = {\n%s\n}\n" % (name, _num_rows(values, per_row=per_row,
                                                           fmt=fmt))
    count = 2 + rng.randbelow(3)
    count = min(count, len(values) - 1)
    cuts = (sorted(rng.sample(list(range(1, len(values))), count - 1))
            if count > 1 else [])
    bounds = [0] + cuts + [len(values)]
    pieces = [values[bounds[i]:bounds[i + 1]] for i in range(len(bounds) - 1)]
    order = rng.permutation(len(pieces))
    decls = []
    piece_names = []
    for i, idx in enumerate(order):
        pname = "%s_%d" % (name, i)
        piece_names.append((idx, pname))
        decls.append("local %s = {\n%s\n}" % (pname, _num_rows(pieces[idx],
                                                               per_row=per_row,
                                                               fmt=fmt)))
    piece_names.sort()                       # concatenate back in real order
    listed = ", ".join(pname for _idx, pname in piece_names)
    return "\n".join(decls) + (
        "\nlocal %s = (function()\n"
        "  local out = table.create(%d)\n"
        "  local i = 1\n"
        "  for _, part in ipairs({%s}) do\n"
        "    for j = 1, #part do out[i] = part[j]; i += 1 end\n"
        "  end\n"
        "  return out\n"
        "end)()\n") % (name, len(values), listed)


# --------------------------------------------------------------------------
# cipher cores
# --------------------------------------------------------------------------

def _chacha_core(n: Dict[str, str], spec: CipherSpec, style: str,
                 rng: Any) -> str:
    """ChaCha20, direct or schedule-walked, rolled to the drawn granularity."""
    qr = n["qr"]
    if spec.qr_style == "schedule" and spec.qr_order:
        order = [tuple(i + 1 for i in q) for q in spec.qr_order]
        rows = ",\n".join("  {%d, %d, %d, %d}" % q for q in order)
        qr_decl = "local %s = {\n%s\n}\n" % (n["qsched"], rows)
        qr_fn = (
            "local function %s(s, q)\n"
            "  local a, b, c, d = q[1], q[2], q[3], q[4]\n"
            "  s[a] = %s(s[a] + s[b], %s)\n"
            "  s[d] = %s(%s(s[d], s[a]), 16)\n"
            "  s[c] = %s(s[c] + s[d], %s)\n"
            "  s[b] = %s(%s(s[b], s[c]), 12)\n"
            "  s[a] = %s(s[a] + s[b], %s)\n"
            "  s[d] = %s(%s(s[d], s[a]), 8)\n"
            "  s[c] = %s(s[c] + s[d], %s)\n"
            "  s[b] = %s(%s(s[b], s[c]), 7)\n"
            "end\n" % ((qr, n["band"], n["m32"], n["rotl"], n["bxor"],
                        n["band"], n["m32"], n["rotl"], n["bxor"],
                        n["band"], n["m32"], n["rotl"], n["bxor"],
                        n["band"], n["m32"], n["rotl"], n["bxor"]))
        )
        one_round = ("  for i = 1, 8 do %s(w, %s[i]) end\n" % (qr, n["qsched"]))
    else:
        qr_decl = ""
        qr_fn = (
            "local function %s(s, a, b, c, d)\n"
            "  s[a] = %s(s[a] + s[b], %s)\n"
            "  s[d] = %s(%s(s[d], s[a]), 16)\n"
            "  s[c] = %s(s[c] + s[d], %s)\n"
            "  s[b] = %s(%s(s[b], s[c]), 12)\n"
            "  s[a] = %s(s[a] + s[b], %s)\n"
            "  s[d] = %s(%s(s[d], s[a]), 8)\n"
            "  s[c] = %s(s[c] + s[d], %s)\n"
            "  s[b] = %s(%s(s[b], s[c]), 7)\n"
            "end\n" % ((qr, n["band"], n["m32"], n["rotl"], n["bxor"],
                        n["band"], n["m32"], n["rotl"], n["bxor"],
                        n["band"], n["m32"], n["rotl"], n["bxor"],
                        n["band"], n["m32"], n["rotl"], n["bxor"]))
        )
        pairs = []
        for q in COLUMN_ROUNDS:
            pairs.append(q)
        for q in DIAGONAL_ROUNDS:
            pairs.append(q)
        calls = "".join("  %s(w, %d, %d, %d, %d)\n" % ((qr,) + tuple(i + 1 for i in q))
                        for q in pairs)
        one_round = calls

    per = max(1, int(spec.rounds_per_iteration))
    if 10 % per:
        per = 2
    outer = 10 // per
    body = one_round * per
    block = "%slocal %s = table.create(16)\nlocal %s = table.create(16)\n%s" % (
        qr_decl, n["cstate"], n["cwork"], qr_fn)
    block += (
        "local function {cblock}(key32, counter, nonce12, out)\n"
        "  local s = {cstate}\n"
        "  s[1], s[2], s[3], s[4] = {sigma}[1], {sigma}[2], {sigma}[3], {sigma}[4]\n"
        "  for i = 1, 8 do s[4 + i] = key32[i] end\n"
        "  s[13] = {band}(counter, {m32})\n"
        "  s[14] = nonce12[1]\n"
        "  s[15] = nonce12[2]\n"
        "  s[16] = nonce12[3]\n"
        "  local w = {cwork}\n"
        "  for i = 1, 16 do w[i] = s[i] end\n"
        "  for _ = 1, {outer} do\n"
        "{body}"
        "  end\n"
        "  local p = 1\n"
        "  for i = 1, 16 do\n"
        "    local v = {band}(w[i] + s[i], {m32})\n"
        "    out[p] = {band}(v, 255)\n"
        "    out[p + 1] = {band}({rsh}(v, 8), 255)\n"
        "    out[p + 2] = {band}({rsh}(v, 16), 255)\n"
        "    out[p + 3] = {band}({rsh}(v, 24), 255)\n"
        "    p += 4\n"
        "  end\n"
        "end\n"
    ).format(cblock=n["cblock"], cstate=n["cstate"], sigma=n["sigma"],
             band=n["band"], m32=n["m32"], cwork=n["cwork"], outer=outer,
             body=body, rsh=n["rsh"])
    block += (
        "local function {prepk}(keystr)\n"
        "  local k = table.create(8)\n"
        "  for i = 1, 8 do k[i] = {le32}(keystr, (i - 1) * 4 + 1) end\n"
        "  return k\n"
        "end\n"
        "local function {prepn}(noncestr)\n"
        "  return {{ {le32}(noncestr, 1), {le32}(noncestr, 5), {le32}(noncestr, 9) }}\n"
        "end\n"
    ).format(prepk=n["prepk"], prepn=n["prepn"], le32=n["le32"])
    return block


def _aes_core(n: Dict[str, str], spec: CipherSpec, style: str,
              rng: Any) -> str:
    """AES-128 block encryption plus CTR, with the drawn shape."""
    if spec.generate_sbox:
        sbox_decl = (
            "local function {gensbox}()\n"
            "  local exp, log = table.create(256), table.create(256)\n"
            "  local x = 1\n"
            "  for i = 0, 254 do\n"
            "    exp[i + 1] = x\n"
            "    log[x + 1] = i\n"
            "    x = {bxor}(x, {xt}(x))\n"
            "  end\n"
            "  exp[256] = x\n"
            "  local sb = table.create(256)\n"
            "  for i = 0, 255 do\n"
            "    local inv = 0\n"
            "    if i ~= 0 then inv = exp[255 - log[i + 1] + 1] end\n"
            "    local s = inv\n"
            "    for _ = 1, 4 do\n"
            "      inv = {bor}({band}({lsh}(inv, 1), 255), {rsh}(inv, 7))\n"
            "      s = {bxor}(s, inv)\n"
            "    end\n"
            "    sb[i + 1] = {bxor}(s, 0x63)\n"
            "  end\n"
            "  return sb\n"
            "end\n"
            "local {sbox} = {gensbox}()\n"
        ).format(gensbox=n["gensbox"], bxor=n["bxor"], xt=n["xt"],
                 bor=n["bor"], band=n["band"], lsh=n["lsh"], rsh=n["rsh"],
                 sbox=n["sbox"])
    else:
        lit = _byte_literal(bytes(AES_SBOX))
        sbox_decl = (
            "local {sbox} = (function()\n"
            "  local src = {lit}\n"
            "  local t = table.create(256)\n"
            "  for i = 1, 256 do t[i] = {byte}(src, i) end\n"
            "  return t\n"
            "end)()\n"
        ).format(sbox=n["sbox"], lit=lit, byte=n["byte"])

    xt = (
        "local function {xt}(a)\n"
        "  local b = {band}({lsh}(a, 1), 255)\n"
        "  if a >= 128 then b = {bxor}(b, 27) end\n"
        "  return b\n"
        "end\n"
    ).format(xt=n["xt"], band=n["band"], lsh=n["lsh"], bxor=n["bxor"])

    expand = (
        "local function {expand}(keystr)\n"
        "  local rk = table.create(176)\n"
        "  for i = 1, 16 do rk[i] = {byte}(keystr, i) end\n"
        "  local rcon = 1\n"
        "  for i = 4, 43 do\n"
        "    local base = (i - 4) * 4\n"
        "    local prev = (i - 1) * 4\n"
        "    local t1, t2, t3, t4 = rk[prev + 1], rk[prev + 2], rk[prev + 3], rk[prev + 4]\n"
        "    if i % 4 == 0 then\n"
        "      t1, t2, t3, t4 = t2, t3, t4, t1\n"
        "      t1, t2, t3, t4 = {sbox}[t1 + 1], {sbox}[t2 + 1], {sbox}[t3 + 1], {sbox}[t4 + 1]\n"
        "      t1 = {bxor}(t1, rcon)\n"
        "      rcon = {xt}(rcon)\n"
        "    end\n"
        "    rk[i * 4 + 1] = {bxor}(rk[base + 1], t1)\n"
        "    rk[i * 4 + 2] = {bxor}(rk[base + 2], t2)\n"
        "    rk[i * 4 + 3] = {bxor}(rk[base + 3], t3)\n"
        "    rk[i * 4 + 4] = {bxor}(rk[base + 4], t4)\n"
        "  end\n"
        "  return rk\n"
        "end\n"
    ).format(expand=n["expand"], byte=n["byte"], sbox=n["sbox"],
             bxor=n["bxor"], xt=n["xt"])

    shift = (
        "  local t = s[2]; s[2] = s[6]; s[6] = s[10]; s[10] = s[14]; s[14] = t\n"
        "  local u = s[3]; local v = s[7]; s[3] = s[11]; s[7] = s[15]; s[11] = u; s[15] = v\n"
        "  local w = s[16]; s[16] = s[12]; s[12] = s[8]; s[8] = s[4]; s[4] = w\n"
    )
    mix = (
        "    for c = 0, 3 do\n"
        "      local i0 = 4 * c + 1\n"
        "      local a0, a1, a2, a3 = s[i0], s[i0 + 1], s[i0 + 2], s[i0 + 3]\n"
        "      local m = {bxor}({bxor}(a0, a1), {bxor}(a2, a3))\n"
        "      s[i0] = {bxor}({bxor}(a0, m), {xt}({bxor}(a0, a1)))\n"
        "      s[i0 + 1] = {bxor}({bxor}(a1, m), {xt}({bxor}(a1, a2)))\n"
        "      s[i0 + 2] = {bxor}({bxor}(a2, m), {xt}({bxor}(a2, a3)))\n"
        "      s[i0 + 3] = {bxor}({bxor}(a3, m), {xt}({bxor}(a3, a0)))\n"
        "    end\n"
    ).format(bxor=n["bxor"], xt=n["xt"])
    sub = "  for i = 1, 16 do s[i] = {sbox}[s[i] + 1] end\n".format(sbox=n["sbox"])
    addkey = (
        "  local off = %s * 16\n"
        "  for i = 1, 16 do s[i] = {bxor}(s[i], rk[off + i]) end\n"
    ).format(bxor=n["bxor"])

    if spec.split_final:
        rounds = (
            "  for rnd = 1, 9 do\n"
            "{sub}{shift}{mix}{add9}"
            "  end\n"
            "{sub}{shift}{add10}"
        ).format(sub=sub, shift=shift, mix=mix,
                 add9=addkey % "rnd", add10=addkey % "10")
    else:
        rounds = (
            "  for rnd = 1, 10 do\n"
            "{sub}{shift}"
            "    if rnd ~= 10 then\n"
            "{mix}"
            "    end\n"
            "{addkey}"
            "  end\n"
        ).format(sub=sub, shift=shift,
                 mix="\n".join("  " + ln if ln.strip() else ln
                               for ln in mix.split("\n")),
                 addkey=addkey % "rnd")

    encrypt = (
        "local function {encrypt}(rk, blk)\n"
        "  local s = table.create(16)\n"
        "  for i = 1, 16 do s[i] = {byte}(blk, i) end\n"
        "  for i = 1, 16 do s[i] = {bxor}(s[i], rk[i]) end\n"
        "{rounds}"
        "  return {bytes_out}(s, 16)\n"
        "end\n"
    ).format(encrypt=n["encrypt"], byte=n["byte"], bxor=n["bxor"],
             rounds=rounds, bytes_out=n["bytes_out"])

    ctr4 = (
        "local function {ctr4}(c)\n"
        "  local v = c % {mod}\n"
        "  return {char}({band}({rsh}(v, 24), 255), {band}({rsh}(v, 16), 255),\n"
        "                {band}({rsh}(v, 8), 255), {band}(v, 255))\n"
        "end\n"
    ).format(ctr4=n["ctr4"], mod=n["mod"], char=n["char"], band=n["band"],
             rsh=n["rsh"])

    # ``xtime`` comes first: the generated S-box calls it, and a Luau local
    # only exists from its declaration onwards -- a closure defined earlier
    # would capture a global of the same name and find nil at load.
    return xt + sbox_decl + expand + encrypt + ctr4


def _cipher_xor(n: Dict[str, str], spec: CipherSpec, public: str) -> str:
    """The public keystream function, for whichever core was drawn."""
    if spec.core == AES_CTR:
        return (
            "local function {x}(keystr, noncestr, data, counter)\n"
            "  local rk = {expand}(keystr)\n"
            "  local len = #data\n"
            "  local out = table.create(len)\n"
            "  local blk = 0\n"
            "  local pos = 1\n"
            "  while pos <= len do\n"
            "    local ks = {encrypt}(rk, noncestr .. {ctr4}(counter + blk))\n"
            "    blk += 1\n"
            "    local stop = pos + 15\n"
            "    if stop > len then stop = len end\n"
            "    for i = pos, stop do\n"
            "      out[i] = {bxor}({byte}(data, i), {byte}(ks, i - pos + 1))\n"
            "    end\n"
            "    pos = stop + 1\n"
            "  end\n"
            "  return {bytes_out}(out, len)\n"
            "end\n"
        ).format(x=public, expand=n["expand"], encrypt=n["encrypt"],
                 ctr4=n["ctr4"], bxor=n["bxor"], byte=n["byte"],
                 bytes_out=n["bytes_out"])
    return (
        "local function {x}(keystr, noncestr, data, counter)\n"
        "  local key32 = {prepk}(keystr)\n"
        "  local nonce12 = {prepn}(noncestr)\n"
        "  local len = #data\n"
        "  local out = table.create(len)\n"
        "  local blk = 0\n"
        "  local pos = 1\n"
        "  while pos <= len do\n"
        "    {cblock}(key32, counter + blk, nonce12, {ks})\n"
        "    blk += 1\n"
        "    local stop = pos + 63\n"
        "    if stop > len then stop = len end\n"
        "    for i = pos, stop do\n"
        "      out[i] = {bxor}({byte}(data, i), {ks}[i - pos + 1])\n"
        "    end\n"
        "    pos = stop + 1\n"
        "  end\n"
        "  return {bytes_out}(out, len)\n"
        "end\n"
    ).format(x=public, prepk=n["prepk"], prepn=n["prepn"], ks=n["ks"],
             cblock=n["cblock"], bxor=n["bxor"], byte=n["byte"],
             bytes_out=n["bytes_out"])


# --------------------------------------------------------------------------
# SHA-256 / HMAC
# --------------------------------------------------------------------------

def _sha_core(n: Dict[str, str], spec: CipherSpec, style: str, rng: Any,
              public: str) -> str:
    k_table = _num_table(n, "shak", K, style, rng)
    h_table = "local %s = {%s}\n" % (
        n["shah"], ", ".join("0x%08x" % v for v in H_INIT))

    if spec.sha_schedule == "window":
        # A rolling 16-word window instead of a 64-word array.  The four
        # offsets the schedule reads (i-2, i-7, i-15, i-16) are distinct mod
        # 16, so overwriting slot ``i mod 16`` after reading is safe -- and
        # the memory shape a reader sees is a different one.
        extend = (
            "local function {extend}(wb, i)\n"
            "  local a = wb[((i - 15 - 1) % 16) + 1]\n"
            "  local b = wb[((i - 2 - 1) % 16) + 1]\n"
            "  local s0 = {bxor}({bxor}({rotr}(a, 7), {rotr}(a, 18)), {rsh}(a, 3))\n"
            "  local s1 = {bxor}({bxor}({rotr}(b, 17), {rotr}(b, 19)), {rsh}(b, 10))\n"
            "  return (wb[((i - 16 - 1) % 16) + 1] + s0 + wb[((i - 7 - 1) % 16) + 1] + s1) % {mod}\n"
            "end\n"
        ).format(extend=n["extend"], bxor=n["bxor"], rotr=n["rotr"],
                 rsh=n["rsh"], mod=n["mod"])
        # The window variant computes w[i] lazily inside the compression loop,
        # so the 17..64 extension pass must not be emitted at all -- running
        # it would write 48 entries a 16-slot table does not have.
        schedule = (
            "    local w\n"
            "    if i <= 16 then\n"
            "      w = wb[i]\n"
            "    else\n"
            "      w = {extend}(wb, i)\n"
            "    end\n"
            "    wb[((i - 1) % 16) + 1] = w\n"
        ).format(extend=n["extend"])
        postfill = ""
    else:
        extend = ""
        schedule = "    local w = wb[i]\n"
        postfill = (
            "    for i = 17, 64 do\n"
            "      local a = wb[i - 15]\n"
            "      local s0 = {bxor}({bxor}({rotr}(a, 7), {rotr}(a, 18)), {rsh}(a, 3))\n"
            "      local c = wb[i - 2]\n"
            "      local s1 = {bxor}({bxor}({rotr}(c, 17), {rotr}(c, 19)), {rsh}(c, 10))\n"
            "      wb[i] = (wb[i - 16] + s0 + wb[i - 7] + s1) % {mod}\n"
            "    end\n"
        ).format(bxor=n["bxor"], rotr=n["rotr"], rsh=n["rsh"], mod=n["mod"])

    # The schedule's scratch table: 64 slots for the array form, 16 for the
    # rolling window.  Sizing it to the variant is not an optimization, it is
    # the difference between the two shapes being visibly different.
    wbuf_decl = "local {wbuf} = table.create({slots})\n".format(
        wbuf=n["wbuf"], slots=16 if spec.sha_schedule == "window" else 64)

    blocks = (
        "local function {sblocks}(state, msg, start, blocks)\n"
        "  local wb = {wbuf}\n"
        "  for b = 0, blocks - 1 do\n"
        "    local base = start + b * 64\n"
        "    for i = 1, 16 do\n"
        "      local o = base + (i - 1) * 4\n"
        "      local x, y, z, t = {byte}(msg, o, o + 3)\n"
        "      wb[i] = x * 16777216 + y * 65536 + z * 256 + t\n"
        "    end\n"
        "{postfill}"
        "    local h1, h2, h3, h4 = state[1], state[2], state[3], state[4]\n"
        "    local h5, h6, h7, h8 = state[5], state[6], state[7], state[8]\n"
        "    for i = 1, 64 do\n"
        "{schedule}"
        "      local S1 = {bxor}({bxor}({rotr}(h5, 6), {rotr}(h5, 11)), {rotr}(h5, 25))\n"
        "      local ch = {bxor}({band}(h5, h6), {band}({bnot}(h5), h7))\n"
        "      local t1 = (h8 + S1 + ch + {shak}[i] + w) % {mod}\n"
        "      local S0 = {bxor}({bxor}({rotr}(h1, 2), {rotr}(h1, 13)), {rotr}(h1, 22))\n"
        "      local maj = {bxor}({bxor}({band}(h1, h2), {band}(h1, h3)), {band}(h2, h3))\n"
        "      local t2 = (S0 + maj) % {mod}\n"
        "      h8 = h7; h7 = h6; h6 = h5; h5 = (h4 + t1) % {mod}\n"
        "      h4 = h3; h3 = h2; h2 = h1; h1 = (t1 + t2) % {mod}\n"
        "    end\n"
        "    state[1] = (state[1] + h1) % {mod}\n"
        "    state[2] = (state[2] + h2) % {mod}\n"
        "    state[3] = (state[3] + h3) % {mod}\n"
        "    state[4] = (state[4] + h4) % {mod}\n"
        "    state[5] = (state[5] + h5) % {mod}\n"
        "    state[6] = (state[6] + h6) % {mod}\n"
        "    state[7] = (state[7] + h7) % {mod}\n"
        "    state[8] = (state[8] + h8) % {mod}\n"
        "  end\n"
        "end\n"
    ).format(sblocks=n["sblocks"], wbuf=n["wbuf"], byte=n["byte"],
             bxor=n["bxor"], rotr=n["rotr"], rsh=n["rsh"], mod=n["mod"],
             band=n["band"], bnot=n["bnot"], shak=n["shak"],
             schedule=schedule, postfill=postfill)

    sha = (
        "local function {sha}(msg)\n"
        "  local state = table.create(8)\n"
        "  for i = 1, 8 do state[i] = {shah}[i] end\n"
        "  local len = #msg\n"
        "  local padded = len + 1\n"
        "  while padded % 64 ~= 56 do padded += 1 end\n"
        "  padded += 8\n"
        "  local tail = table.create(padded - len - 8)\n"
        "  tail[1] = \"\\128\"\n"
        "  for i = 2, padded - len - 8 do tail[i] = \"\\000\" end\n"
        "  local bits = len * 8\n"
        "  local lenbytes = table.create(8)\n"
        "  for i = 8, 1, -1 do\n"
        "    lenbytes[i] = {char}({band}(bits, 255))\n"
        "    bits = (bits - {band}(bits, 255)) // 256\n"
        "  end\n"
        "  local full = msg .. table.concat(tail) .. table.concat(lenbytes)\n"
        "  {sblocks}(state, full, 1, padded // 64)\n"
        "  local out = table.create(32)\n"
        "  for i = 1, 8 do\n"
        "    local v = state[i]\n"
        "    out[(i - 1) * 4 + 1] = {char}({band}({rsh}(v, 24), 255))\n"
        "    out[(i - 1) * 4 + 2] = {char}({band}({rsh}(v, 16), 255))\n"
        "    out[(i - 1) * 4 + 3] = {char}({band}({rsh}(v, 8), 255))\n"
        "    out[(i - 1) * 4 + 4] = {char}({band}(v, 255))\n"
        "  end\n"
        "  return table.concat(out)\n"
        "end\n"
    ).format(sha=public, shah=n["shah"], char=n["char"], band=n["band"],
             rsh=n["rsh"], sblocks=n["sblocks"])

    hmac = (
        "local function {hmac}(key, msg)\n"
        "  if #key > 64 then key = {sha}(key) end\n"
        "  local inner = table.create(64)\n"
        "  local outer = table.create(64)\n"
        "  for i = 1, 64 do\n"
        "    local v = {byte}(key, i) or 0\n"
        "    inner[i] = {char}({bxor}(v, 0x36))\n"
        "    outer[i] = {char}({bxor}(v, 0x5c))\n"
        "  end\n"
        "  return {sha}(table.concat(outer) .. {sha}(table.concat(inner) .. msg))\n"
        "end\n"
    ).format(hmac=n["hmac"], sha=public, byte=n["byte"], char=n["char"],
             bxor=n["bxor"])

    return k_table + h_table + wbuf_decl + extend + blocks + sha + hmac


# --------------------------------------------------------------------------
# assembly
# --------------------------------------------------------------------------

def crypto_runtime(names: Dict[str, str], enc_domain: bytes = None,
                   mac_domain: bytes = None,
                   cipher: Optional[CipherSpec] = None,
                   rng: Any = None) -> str:
    """Emit one build's crypto module.

    ``names`` maps logical roles to generated identifiers: ``xor`` (the
    keystream), ``sha`` (SHA-256), ``mac`` (HMAC-SHA256), ``open`` (verify +
    decrypt), ``seal`` (encrypt + tag).

    ``cipher`` is the drawn :class:`~couxobf.crypto.cipher.CipherSpec`; without
    one the historical ChaCha20 build is emitted, which is what the
    cross-implementation tests pin.  ``rng`` is what makes the *shape* per
    build -- drawn names, table fragmentation, declaration order.  Passing one
    without the other would produce a build whose report could not describe
    it, so both come from the same place in the pipeline.
    """
    n = names
    spec = cipher or CipherSpec()
    internal = _internal_names(rng, list(n.values()))
    n = dict(internal)
    enc_dom = _byte_literal(enc_domain if enc_domain is not None else ENC_DOMAIN)
    mac_dom = _byte_literal(mac_domain if mac_domain is not None else MAC_DOMAIN)

    prelude = (
        "local {band}, {bor}, {bxor}, {bnot} = bit32.band, bit32.bor, bit32.bxor, bit32.bnot\n"
        "local {lsh}, {rsh} = bit32.lshift, bit32.rshift\n"
        "local {byte}, {char}, {rep}, {sub} = string.byte, string.char, string.rep, string.sub\n"
        "local {m32} = 4294967295\n"
        "local {mod} = 4294967296\n"
        "local function {rotl}(v, s)\n"
        "  return {bor}({lsh}(v, s), {rsh}(v, 32 - s))\n"
        "end\n"
        "local function {rotr}(v, s)\n"
        "  return {bor}({rsh}(v, s), {lsh}(v, 32 - s))\n"
        "end\n"
        "local function {le32}(s, i)\n"
        "  local a, b, c, d = {byte}(s, i, i + 3)\n"
        "  return a + b * 256 + c * 65536 + d * 16777216\n"
        "end\n"
        "local function {bytes_out}(t, n)\n"
        "  local chunks = table.create((n + 127) // 128)\n"
        "  local k = 0\n"
        "  local i = 1\n"
        "  while i <= n do\n"
        "    local j = i + 127\n"
        "    if j > n then j = n end\n"
        "    k += 1\n"
        "    chunks[k] = {char}(table.unpack(t, i, j))\n"
        "    i = j + 1\n"
        "  end\n"
        "  return table.concat(chunks)\n"
        "end\n"
    ).format(**n)

    parts = [prelude]
    if spec.core == CHA_CHA:
        parts.append(_num_table(n, "sigma", SIGMA, spec.table_style, rng,
                                per_row=4))
        parts.append(_chacha_core(n, spec, spec.table_style, rng))
    else:
        parts.append(_aes_core(n, spec, spec.table_style, rng))
    parts.append("local {ks} = table.create({blk})\n".format(
        ks=n["ks"], blk=spec.block_size) if spec.core == CHA_CHA else "")
    parts.append(_cipher_xor(n, spec, names["xor"]))
    parts.append(_sha_core(n, spec, spec.table_style, rng, names["sha"]))

    # -- the AEAD composition, split into six small pieces -----------------
    #
    # One monolithic `open` was the artifact's single choke point: find it and
    # the payload format is open.  Split, it is six functions a reader has to
    # reassemble -- and because the declaration order is a per-build
    # permutation behind forward declarations, "the decrypt function" is not
    # at a fixed place in the text.
    le64 = (
        "local function {le64}(x)\n"
        "  local t = table.create(8)\n"
        "  for i = 1, 8 do\n"
        "    t[i] = {char}({band}(x, 255))\n"
        "    x = (x - {band}(x, 255)) // 256\n"
        "  end\n"
        "  return table.concat(t)\n"
        "end\n"
    ).format(le64=n["le64"], char=n["char"], band=n["band"])
    enckey = (
        "{enckey} = function(keystr, noncestr, aad)\n"
        "  return {sha}({enc_dom} .. keystr .. noncestr .. aad .. {le64}(#aad))\n"
        "end\n"
    ).format(enckey=n["enckey"], sha=names["sha"], enc_dom=enc_dom,
             le64=n["le64"])
    mackey = (
        "{mackey} = function(keystr, noncestr, aad)\n"
        "  return {sha}({mac_dom} .. keystr .. noncestr .. aad .. {le64}(#aad))\n"
        "end\n"
    ).format(mackey=n["mackey"], sha=names["sha"], mac_dom=mac_dom,
             le64=n["le64"])
    ctag = (
        "{ctag} = function(keystr, noncestr, ct, aad)\n"
        "  local covered = {{ noncestr, aad, {le64}(#aad), ct, {le64}(#ct) }}\n"
        "  return {hmac}({mackey}(keystr, noncestr, aad), table.concat(covered))\n"
        "end\n"
    ).format(ctag=n["ctag"], le64=n["le64"], hmac=n["hmac"], mackey=n["mackey"])
    ceq = (
        "{ceq} = function(a, b)\n"
        "  if #a ~= #b then return false end\n"
        "  local diff = 0\n"
        "  for i = 1, #a do\n"
        "    diff = {bor}(diff, {bxor}({byte}(a, i), {byte}(b, i)))\n"
        "  end\n"
        "  return diff == 0\n"
        "end\n"
    ).format(ceq=n["ceq"], bor=n["bor"], bxor=n["bxor"], byte=n["byte"])
    opn = (
        "{opn} = function(keystr, noncestr, ct, tag, aad)\n"
        "  aad = aad or \"\"\n"
        "  if not {ceq}({ctag}(keystr, noncestr, ct, aad), tag) then\n"
        "    return nil\n"
        "  end\n"
        "  return {x}({enckey}(keystr, noncestr, aad), noncestr, ct, 1)\n"
        "end\n"
    ).format(opn=n["opn"], ceq=n["ceq"], ctag=n["ctag"], x=names["xor"],
             enckey=n["enckey"])
    sl = (
        "{sl} = function(keystr, noncestr, plain, aad)\n"
        "  aad = aad or \"\"\n"
        "  local ct = {x}({enckey}(keystr, noncestr, aad), noncestr, plain, 1)\n"
        "  return ct, {ctag}(keystr, noncestr, ct, aad)\n"
        "end\n"
    ).format(sl=n["sl"], x=names["xor"], enckey=n["enckey"], ctag=n["ctag"])

    pieces = [le64, enckey, mackey, ctag, ceq, opn, sl]
    movable = [enckey, mackey, ctag, ceq, opn, sl]
    if spec.compose_order and len(spec.compose_order) == len(movable):
        movable = [movable[i] for i in spec.compose_order]
    # ``le64`` is a plain local function and stays first: nothing permuted
    # refers to it before it exists.  The other six are forward-declared so
    # their declaration order is free -- which is the point of the draw.
    decl = ("local {enckey}, {mackey}, {ctag}, {ceq}, {opn}, {sl}\n"
            ).format(enckey=n["enckey"], mackey=n["mackey"],
                     ctag=n["ctag"], ceq=n["ceq"], opn=n["opn"], sl=n["sl"])
    parts.append(decl + le64 + "".join(movable))

    exported = (
        "return {{\n"
        "  {xor} = {xor},\n"
        "  {sha} = {sha},\n"
        "  {mac} = {hmac},\n"
        "  {open} = {opn},\n"
        "  {seal} = {sl},\n"
        "}}\n"
    ).format(xor=names["xor"], sha=names["sha"], mac=names["mac"],
             hmac=n["hmac"], open=names["open"], opn=n["opn"],
             seal=names["seal"], sl=n["sl"])
    parts.append(exported)
    return "\n".join(p for p in parts if p)

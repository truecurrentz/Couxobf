"""Luau source for the encrypted constant pool's runtime half.

The decoder is deliberately small and boring.  It does one authenticated
decrypt, walks a length-prefixed index, and materializes one constant at a
time.  All of the interesting work -- which cipher, which key, which nonce --
happened on the Python side; the runtime just opens what it is handed and
refuses to run if authentication fails.

Field and local names are passed in rather than hardcoded, so the emitted code
carries no self-describing identifiers.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Tuple

from ..constpool import mask_params
from .luau_crypto import crypto_runtime


def _xor_bytes(data: bytes, mask: bytes) -> bytes:
    return bytes(b ^ mask[i % len(mask)] for i, b in enumerate(data))


def byte_literal(data: bytes) -> str:
    """A Luau string literal holding exactly these bytes.

    Every byte is escaped as ``\\xHH``: printable characters would be safe to
    emit raw, but escaping uniformly means no byte can ever terminate the
    literal early or smuggle in an escape sequence.
    """
    return '"' + "".join("\\x%02x" % b for b in data) + '"'

MASK_MOD = 1 << 31


def _mask(seed: int, length: int, mul: int, add: int, shift: int) -> bytes:
    out = bytearray()
    x = seed % MASK_MOD
    for _ in range(length):
        x = (x * mul + add) % MASK_MOD
        out.append((x >> shift) & 0xFF)
    return bytes(out)


def _literal_parts(data: bytes) -> List[Tuple[int, int, int, int, bytes]]:
    """Masked literal fragments for one runtime blob.

    The encrypted pool already protects the payload contents.  This layer keeps
    key/nonce/tag/ciphertext material from appearing as one contiguous quoted
    literal in the emitted runtime; each build reconstructs them from small
    masked pieces through real byte operations.
    """
    if not data:
        return []
    h = hashlib.sha256(len(data).to_bytes(4, "big") + data).digest()
    pos = 0
    idx = 0
    parts: List[Tuple[int, int, int, int, bytes]] = []
    while pos < len(data):
        size = 3 + h[idx % len(h)] % 10
        size = min(size, len(data) - pos)
        row_hash = hashlib.sha256(h + idx.to_bytes(2, "big")).digest()
        seed = int.from_bytes(row_hash[:4], "big") & 0x7fffffff
        mul = (int.from_bytes(row_hash[4:7], "big") & 0x1fffff) | 1
        if mul < 0x10000:
            mul |= 0x10001
        add = (int.from_bytes(row_hash[7:11], "big") & 0x7fffffff) | 1
        shift = 8 + (row_hash[11] & 15)
        piece = data[pos:pos + size]
        masked = bytes(b ^ m for b, m in zip(piece, _mask(seed, size, mul, add, shift)))
        parts.append((seed, mul, add, shift, masked))
        pos += size
        idx += 1
    return parts


def byte_expr(data: bytes, helper: str, dense: Any = None) -> str:
    """The masked-fragment expression for one blob.

    With a dense codec, each fragment's stored bytes ride base85 under the
    build's alphabet (1.25 source chars per byte) instead of ``\\xHH``
    escapes (4 per byte); the decode is one call per fragment at load.  The
    masking layer is unchanged: dense changes how the bytes are *spelled*,
    not how they are protected.
    """
    rows = []
    for seed, mul, add, shift, masked in _literal_parts(data):
        lit = dense.expr(masked) if dense is not None else byte_literal(masked)
        rows.append("{%d,%d,%d,%d,%s}" % (seed, mul, add, shift, lit))
    return "%s({%s})" % (helper, ",".join(rows))


class ConstantPoolRuntime:
    """Emits the decoder and remembers the accessor name to call.

    ``cipher`` and ``shape_rng`` are the build's drawn crypto core and the
    stream the module's shape is drawn from; both come from the pipeline so a
    build's report can describe what it emitted.
    """

    #: The structural choices a build can draw.  Every combination decodes the
    #: same pool; they exist so two artifacts -- or two regions of one
    #: artifact -- do not hand an analyst the same decoder with the names
    #: changed.
    SHAPES = {
        # How the entry offsets are found: all at load, or scanned forward on
        # demand and remembered.
        "offsets": ("eager", "scan"),
        # How a ticket is folded back into a slot number.  All three are the
        # same XOR of one 32-bit mask, spelled three ways.
        "deticket": ("xor", "split", "sum"),
        # How a type byte reaches the code that materializes it.
        "material": ("chain", "table"),
    }

    def __init__(self, names: Dict[str, str], cache_policy: str = "full",
                 cache_bound: int = 64, shape: Optional[Dict[str, str]] = None
                 ) -> None:
        if cache_policy not in ("none", "bounded", "full"):
            raise ValueError(f"unknown cache policy {cache_policy!r}")
        self.n = names
        self.cache_policy = cache_policy
        self.cache_bound = cache_bound
        self.shape = dict(shape or {})
        for key, allowed in self.SHAPES.items():
            if self.shape.get(key) not in allowed:
                self.shape[key] = allowed[0]

    @property
    def accessor(self) -> str:
        """The name generated code calls to read slot ``i``."""
        return self.n["get"]

    def emit(self, key: bytes, nonce: bytes, tag: bytes, ciphertext: bytes,
             aad: bytes, emit_crypto: bool = True,
             guard_check: str = "",
             ticket_mask: int = 0,
             enc_domain: bytes = None,
             mac_domain: bytes = None,
             dense: Any = None,
             cipher: Any = None,
             shape_rng: Any = None,
             shape: Optional[Dict[str, str]] = None) -> str:
        n = self.n
        shape = dict(self.shape if shape is None else (shape or {}))
        ticket_mask &= 0xffffffff
        mask_mul, mask_add, mask_shift = mask_params(key + nonce + aad)
        def fail(site: bytes) -> str:
            return byte_literal(hashlib.sha256(key + nonce + tag + site).digest()[:8])
        trip = (f"  if not {guard_check}() then error({fail(b'guard')}) end\n"
                if guard_check else "")
        meta_name = n.get("meta", n["key"] + "m")
        aad_expr = byte_expr(aad, n["lit"], dense)
        key_mask_material = ciphertext + tag + nonce + aad
        key_image = _xor_bytes(key, hashlib.sha256(key_mask_material).digest())
        meta_items = [("key", key_image), ("nonce", nonce), ("tag", tag), ("ct", ciphertext)]
        meta_items.sort(key=lambda item: hashlib.sha256(tag + item[0].encode()).digest())
        meta_index = {name: i + 1 for i, (name, _data) in enumerate(meta_items)}
        meta_rows = ",".join(byte_expr(data, n["lit"], dense) for _name, data in meta_items)
        unwrap_name = n.get("unwrap", n["key"] + "u")
        deticket_mode = shape.get("deticket", "xor")
        if not ticket_mask:
            deticket = ""
        elif deticket_mode == "split":
            # m1 ^ m2 == mask, so the two steps are one XOR -- but the mask
            # itself never appears as a literal.
            half = (ticket_mask ^ 0x5A17C0DE) & 0xffffffff
            other = (ticket_mask ^ half) & 0xffffffff
            deticket = (
                f"  i = bit32.bxor(i, (string.unpack(\">I4\", %s, 1)))\n"
                f"  i = bit32.bxor(i, (string.unpack(\">I4\", %s, 1)))\n"
                % (byte_literal(half.to_bytes(4, "big")),
                   byte_literal(other.to_bytes(4, "big"))))
        elif deticket_mode == "sum":
            # m1 + m2 == mask (mod 2^32), so the mask is reassembled by
            # arithmetic inside the fold rather than read from a literal.
            half = (ticket_mask - 0x13579BDF) & 0xffffffff
            other = (ticket_mask - half) & 0xffffffff
            deticket = (
                f"  i = bit32.bxor(i, bit32.band((string.unpack(\">I4\", %s, 1))\n"
                f"                                + (string.unpack(\">I4\", %s, 1)), 4294967295))\n"
                % (byte_literal(half.to_bytes(4, "big")),
                   byte_literal(other.to_bytes(4, "big"))))
        else:
            ticket_expr = '(string.unpack(">I4", %s, 1))' % byte_literal(
                ticket_mask.to_bytes(4, "big"))
            deticket = f"  i = bit32.bxor(i, {ticket_expr})\n"
        literal_helper = f"""local function {n['lit']}(parts)
  local out = table.create(#parts)
  for i = 1, #parts do
    local row = parts[i]
    local seed = row[1]
    local s = row[5]
    local t = table.create(#s)
    for j = 1, #s do
      seed = (seed * row[2] + row[3]) % 2147483648
      t[j] = string.char(bit32.bxor(string.byte(s, j), bit32.band(bit32.rshift(seed, row[4]), 255)))
    end
    out[i] = table.concat(t)
  end
  return table.concat(out)
end
"""
        # The crypto module ends in `return {...}`, so wrapping it in a call
        # turns it into a value without needing a require.
        crypto = crypto_runtime(
            {"xor": n["c_xor"], "sha": n["c_sha"], "mac": n["c_mac"],
             "open": n["c_open"], "seal": n["c_seal"]},
            enc_domain=enc_domain, mac_domain=mac_domain,
            cipher=cipher, rng=shape_rng,
        )

        if self.cache_policy == "none":
            cache_block = (
                f"local function {n['get']}(i)\n"
                f"{trip}"
                f"{deticket}"
                f"  {n['load']}()\n"
                f"  return {n['mat']}(i)\n"
                f"end\n"
            )
        else:
            bound_guard = ""
            if self.cache_policy == "bounded":
                bound_guard = (
                    f"  {n['live']} += 1\n"
                    f"  if {n['live']} > {int(self.cache_bound)} then\n"
                    f"    {n['cache']} = {{}}\n"
                    f"    {n['seen']} = {{}}\n"
                    f"    {n['live']} = 0\n"
                    f"  end\n"
                )
            cache_block = (
                f"local {n['cache']} = {{}}\n"
                f"local {n['seen']} = {{}}\n"
                f"local {n['live']} = 0\n"
                f"local function {n['get']}(i)\n"
                f"{trip}"
                f"{deticket}"
                f"  {n['load']}()\n"
                f"  if {n['seen']}[i] then\n"
                f"    return {n['cache']}[i]\n"
                f"  end\n"
                f"  local v = {n['mat']}(i)\n"
                f"  {n['cache']}[i] = v\n"
                f"  {n['seen']}[i] = true\n"
                f"{bound_guard}"
                f"  return v\n"
                f"end\n"
            )

        # -- the index: built all at once, or scanned forward on demand ----
        def _advance(cur: str) -> str:
            """Skip one entry of the stream, advancing `cur` past it."""
            return f"""    local t = string.byte(p, {cur})
    {cur} += 1
    if t == 2 then
      {cur} += 8
    elseif t == 3 then
      {cur} += 4 + string.unpack(">I4", p, {cur})
    elseif t == 4 then
      {cur} += 12
    elseif t == 6 then
      {cur} += 8
    elseif t == 5 then
      local c = string.unpack(">I2", p, {cur})
      {cur} += 2
      for _ = 1, c do
        local len = string.unpack(">I2", p, {cur} + 4)
        {cur} += 6 + len
      end
    elseif t == 1 then
      {cur} += 1
    end"""

        if shape.get("offsets", "eager") == "scan":
            scan_name = n.get("scan", n["off"] + "s")
            scan_src = (
                f"local {n['off']} = {{}}\n"
                f"local {scan_name}_q = 5\n"
                f"local {scan_name}_n = 0\n"
                f"local function {scan_name}(upto)\n"
                f"  local p = {n['plain']}\n"
                f"  while {scan_name}_n < upto do\n"
                f"    {scan_name}_n += 1\n"
                f"    {n['off']}[{scan_name}_n] = {scan_name}_q\n"
                f"{_advance(scan_name + '_q')}\n"
                f"  end\n"
                f"end\n")
            index_src = ""
            # The scan declares the offset table itself: it is a cursor that
            # fills as it walks, not a table `load` writes in one go.
            off_decl = ""
            offset_lookup = f"  if {scan_name}_n < i then\n    {scan_name}(i)\n  end\n"
        else:
            scan_src = ""
            off_decl = f"local {n['off']} = nil\n"
            index_src = (
                f"  local o = {{}}\n"
                f"  local count = string.unpack(\">I4\", p, 1)\n"
                f"  local q = 5\n"
                f"  for i = 1, count do\n"
                f"    o[i] = q\n"
                f"{_advance('q')}\n"
                f"  end\n"
                f"  {n['off']} = o\n")
            offset_lookup = ""

        # -- materializers: one if-chain, or a table of per-type readers ---
        if shape.get("material", "chain") == "table":
            mat_table_src = f"""local {n['mat']}_M = {{
  [0] = function(p, q) return nil end,
  [1] = function(p, q) return string.byte(p, q + 1) ~= 0 end,
  [2] = function(p, q) return string.unpack(">d", p, q + 1) end,
  [3] = function(p, q)
    local len = string.unpack(">I4", p, q + 1)
    return string.sub(p, q + 5, q + 4 + len)
  end,
  [4] = function(p, q)
    local seed = string.unpack(">I4", p, q + 1)
    return string.unpack(">d", {n['dyn']}(string.sub(p, q + 5, q + 12), seed), 1)
  end,
  [6] = function(p, q)
    -- Exact-integer split: two 32-bit halves rebuilt by integer arithmetic.
    -- Both terms are exact doubles by the encoder's eligibility rule, so the
    -- sum is the original value bit-for-bit -- no rounding anywhere.
    local hi, lo = string.unpack(">i4I4", p, q + 1)
    return hi * 4294967296 + lo
  end,
  [5] = function(p, q)
    local parts = {{}}
    local m = 0
    local count = string.unpack(">I2", p, q + 1)
    q += 3
    for _ = 1, count do
      local seed, len = string.unpack(">I4I2", p, q)
      q += 6
      m += 1
      parts[m] = {n['dyn']}(string.sub(p, q, q + len - 1), seed)
      q += len
    end
    return table.concat(parts)
  end,
}}
"""
            mat_dispatch = (
                f"  local f = {n['mat']}_M[t]\n"
                f"  if f == nil then\n"
                f"    f = {n['mat']}_M[5]\n"
                f"  end\n"
                f"  return f(p, q)\n")
        else:
            mat_table_src = ""
            mat_dispatch = f"""  if t == 0 then
    return nil
  elseif t == 1 then
    return string.byte(p, q + 1) ~= 0
  elseif t == 2 then
    return string.unpack(">d", p, q + 1)
  elseif t == 3 then
    local len = string.unpack(">I4", p, q + 1)
    return string.sub(p, q + 5, q + 4 + len)
  elseif t == 4 then
    local seed = string.unpack(">I4", p, q + 1)
    return string.unpack(">d", {n['dyn']}(string.sub(p, q + 5, q + 12), seed), 1)
  elseif t == 6 then
    -- Exact-integer split: two 32-bit halves rebuilt by integer arithmetic.
    -- Both terms are exact doubles by the encoder's eligibility rule, so the
    -- sum is the original value bit-for-bit -- no rounding anywhere.
    local hi, lo = string.unpack(">i4I4", p, q + 1)
    return hi * 4294967296 + lo
  else
    local parts = {{}}
    local m = 0
    local count = string.unpack(">I2", p, q + 1)
    q += 3
    for _ = 1, count do
      local seed, len = string.unpack(">I4I2", p, q)
      q += 6
      m += 1
      parts[m] = {n['dyn']}(string.sub(p, q, q + len - 1), seed)
      q += len
    end
    return table.concat(parts)
  end
"""

        # When the string bank is present too, one crypto module serves both.
        # A second copy would be another 8KB of decoder for an analyst to find,
        # and a second place for the two to drift apart.
        head = f"local {n['crypto']} = (function()\n{crypto}end)()\n" \
            if emit_crypto else ""

        return f"""{head}{literal_helper}local {meta_name} = {{{meta_rows}}}
local function {unwrap_name}(v, m)
  local h = {n['crypto']}.{n['c_sha']}(m)
  local t = table.create(#v)
  for i = 1, #v do
    t[i] = string.char(bit32.bxor(string.byte(v, i), string.byte(h, ((i - 1) % #h) + 1)))
  end
  return table.concat(t)
end
local {n['plain']} = nil
{off_decl}local {n['loaded']} = false
{scan_src}local function {n['load']}()
  if {n['loaded']} then
    return
  end
  {n['loaded']} = true
  local p = {n['crypto']}.{n['c_open']}({unwrap_name}({meta_name}[{meta_index['key']}], {meta_name}[{meta_index['ct']}] .. {meta_name}[{meta_index['tag']}] .. {meta_name}[{meta_index['nonce']}] .. {aad_expr}), {meta_name}[{meta_index['nonce']}], {meta_name}[{meta_index['ct']}], {meta_name}[{meta_index['tag']}], {aad_expr})
  if p == nil then
    error({fail(b'open')})
  end
  {n['plain']} = p
{index_src}end
local function {n['dyn']}(s, seed)
  local x = seed % 2147483648
  local out = table.create(#s)
  for j = 1, #s do
    x = (x * {mask_mul} + {mask_add}) % 2147483648
    out[j] = string.char(bit32.bxor(string.byte(s, j), bit32.band(bit32.rshift(x, {mask_shift}), 255)))
  end
  return table.concat(out)
end
{mat_table_src}local function {n['mat']}(i)
  local p = {n['plain']}
{offset_lookup}  local q = {n['off']}[i]
  local t = string.byte(p, q)
{mat_dispatch}end
{cache_block}"""


#: The one message every runtime failure path raises.
#:
#: Deliberately not "failed authentication": that names the check, confirms to
#: an analyst that their edit was noticed, and is a stable string to grep for.
#: Every failure in the emitted runtimes -- tag mismatch, wrong AAD, bad page
#: size, unknown ticket -- raises this, so none of them is distinguishable from
#: the others from outside.
FAILURE_MESSAGE = ""


def default_names(prefix: str = "_kQ") -> Dict[str, str]:
    """Consistent internal names.

    The prefix must not collide with anything the reconstructor emits: it uses
    ``_kR<pid>`` for register files, ``_kC<pid>`` for program counters and
    ``_kP<pid>_<i>`` for parameters, so ``_kC`` here would shadow a program
    counter in any build with more than a handful of prototypes.

    These are placeholders; a real build replaces them through the identifier
    randomizer so the emitted code carries no readable labels.
    """
    return {
        "crypto": prefix + "0",
        "key": prefix + "1",
        "nonce": prefix + "2",
        "tag": prefix + "3",
        "ct": prefix + "4",
        "meta": prefix + "m",
        "unwrap": prefix + "u",
        "plain": prefix + "5",
        "off": prefix + "6",
        # Only the "scan" offset shape uses this one: the cursor-advancing
        # reader that walks the stream on demand instead of indexing it.
        "scan": prefix + "6s",
        "loaded": prefix + "7",
        "load": prefix + "8",
        "mat": prefix + "9",
        "dyn": prefix + "z",
        "lit": prefix + "y",
        "get": prefix + "10",
        "cache": prefix + "11",
        "seen": prefix + "12",
        "live": prefix + "13",
        "c_xor": prefix + "a",
        "c_sha": prefix + "b",
        "c_mac": prefix + "c",
        "c_open": prefix + "d",
        "c_seal": prefix + "e",
    }

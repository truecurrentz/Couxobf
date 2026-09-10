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
from typing import Dict, List, Tuple

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


def byte_expr(data: bytes, helper: str) -> str:
    rows = ["{%d,%d,%d,%d,%s}" % (seed, mul, add, shift, byte_literal(masked))
            for seed, mul, add, shift, masked in _literal_parts(data)]
    return "%s({%s})" % (helper, ",".join(rows))


class ConstantPoolRuntime:
    """Emits the decoder and remembers the accessor name to call."""

    def __init__(self, names: Dict[str, str], cache_policy: str = "full",
                 cache_bound: int = 64) -> None:
        if cache_policy not in ("none", "bounded", "full"):
            raise ValueError(f"unknown cache policy {cache_policy!r}")
        self.n = names
        self.cache_policy = cache_policy
        self.cache_bound = cache_bound

    @property
    def accessor(self) -> str:
        """The name generated code calls to read slot ``i``."""
        return self.n["get"]

    def emit(self, key: bytes, nonce: bytes, tag: bytes, ciphertext: bytes,
             aad: bytes, emit_crypto: bool = True,
             guard_check: str = "",
             ticket_mask: int = 0,
             enc_domain: bytes = None,
             mac_domain: bytes = None) -> str:
        n = self.n
        ticket_mask &= 0xffffffff
        mask_mul, mask_add, mask_shift = mask_params(key + nonce + aad)
        def fail(site: bytes) -> str:
            return byte_literal(hashlib.sha256(key + nonce + tag + site).digest()[:8])
        trip = (f"  if not {guard_check}() then error({fail(b'guard')}) end\n"
                if guard_check else "")
        meta_name = n.get("meta", n["key"] + "m")
        aad_expr = byte_expr(aad, n["lit"])
        key_mask_material = ciphertext + tag + nonce + aad
        key_image = _xor_bytes(key, hashlib.sha256(key_mask_material).digest())
        meta_items = [("key", key_image), ("nonce", nonce), ("tag", tag), ("ct", ciphertext)]
        meta_items.sort(key=lambda item: hashlib.sha256(tag + item[0].encode()).digest())
        meta_index = {name: i + 1 for i, (name, _data) in enumerate(meta_items)}
        meta_rows = ",".join(byte_expr(data, n["lit"]) for _name, data in meta_items)
        unwrap_name = n.get("unwrap", n["key"] + "u")
        ticket_expr = 'string.unpack(">I4", %s, 1)' % byte_literal(ticket_mask.to_bytes(4, "big"))
        deticket = (f"  i = bit32.bxor(i, {ticket_expr})\n" if ticket_mask else "")
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
local {n['off']} = nil
local {n['loaded']} = false
local function {n['load']}()
  if {n['loaded']} then
    return
  end
  {n['loaded']} = true
  local p = {n['crypto']}.{n['c_open']}({unwrap_name}({meta_name}[{meta_index['key']}], {meta_name}[{meta_index['ct']}] .. {meta_name}[{meta_index['tag']}] .. {meta_name}[{meta_index['nonce']}] .. {aad_expr}), {meta_name}[{meta_index['nonce']}], {meta_name}[{meta_index['ct']}], {meta_name}[{meta_index['tag']}], {aad_expr})
  if p == nil then
    error({fail(b'open')})
  end
  {n['plain']} = p
  local o = {{}}
  local count = string.unpack(">I4", p, 1)
  local q = 5
  for i = 1, count do
    o[i] = q
    local t = string.byte(p, q)
    q += 1
    if t == 2 then
      q += 8
    elseif t == 3 then
      q += 4 + string.unpack(">I4", p, q)
    elseif t == 4 then
      q += 12
    elseif t == 5 then
      local c = string.unpack(">I2", p, q)
      q += 2
      for _ = 1, c do
        local len = string.unpack(">I2", p, q + 4)
        q += 6 + len
      end
    elseif t == 1 then
      q += 1
    end
  end
  {n['off']} = o
end
local function {n['dyn']}(s, seed)
  local x = seed % 2147483648
  local out = table.create(#s)
  for j = 1, #s do
    x = (x * {mask_mul} + {mask_add}) % 2147483648
    out[j] = string.char(bit32.bxor(string.byte(s, j), bit32.band(bit32.rshift(x, {mask_shift}), 255)))
  end
  return table.concat(out)
end
local function {n['mat']}(i)
  local p = {n['plain']}
  local q = {n['off']}[i]
  local t = string.byte(p, q)
  if t == 0 then
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
end
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

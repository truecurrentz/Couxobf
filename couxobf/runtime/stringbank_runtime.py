"""Luau source for the string bank's runtime half.

The decoder is small on purpose.  It authenticates one ticket table, then for
each ticket walks that ticket's fragments, seeks into the keystream, unmasks,
and concatenates.  Everything interesting -- fragmentation, masking, page
shuffling, key derivation -- happened on the Python side.

Two things this file is careful about, because both would be silent bugs:

*The mask uses integer arithmetic that stays exact under doubles.*  Luau has
no integer subtype, so anything above 2^53 rounds.  The constants come from
:mod:`couxobf.strings.bank` rather than being retyped here, so the Python and
Luau sides cannot drift.

*Page indices are 1-based here and 0-based there.*  ``string.sub`` and
``string.byte`` are 1-based; the wire format is 0-based.  Every conversion is
written out rather than folded into an expression, because an off-by-one in a
seek reads plausible bytes from the wrong place instead of failing.
"""

from __future__ import annotations

from typing import Dict

from ..strings.bank import MASK_ADD, MASK_MOD, MASK_MUL
from .constpool_runtime import byte_literal


def default_names(prefix: str = "_kS") -> Dict[str, str]:
    """Internal names for one bank.

    The prefix must not collide with anything else the build emits: the
    constant pool uses ``_kQ``, the reconstructor uses ``_kR<pid>`` for
    register files, ``_kC<pid>`` for program counters and ``_kP<pid>_<i>`` for
    parameters.  ``_kS`` is free.
    """
    return {
        "crypto": prefix + "0",
        "blob": prefix + "1",
        "tkey": prefix + "2",
        "tnonce": prefix + "3",
        "ttag": prefix + "4",
        "tct": prefix + "5",
        "skey": prefix + "6",
        "snonce": prefix + "7",
        "bkey": prefix + "q",
        "btag": prefix + "r",
        "plain": prefix + "8",
        "perm": prefix + "9",
        "index": prefix + "a",
        "psize": prefix + "b",
        "loaded": prefix + "c",
        "load": prefix + "d",
        "unmask": prefix + "e",
        "frag": prefix + "f",
        "resolve": prefix + "p",
        "get": prefix + "g",
        "cache": prefix + "h",
        "seen": prefix + "i",
        "live": prefix + "j",
        "c_xor": prefix + "k",
        "c_sha": prefix + "l",
        "c_mac": prefix + "m",
        "c_open": prefix + "n",
        "c_seal": prefix + "o",
    }


class StringBankRuntime:
    """Emits the bank's decoder and remembers the accessor to call."""

    def __init__(self, names: Dict[str, str], cache_policy: str = "none",
                 cache_bound: int = 16, emit_crypto: bool = True) -> None:
        # "none" is the default and the preferred setting: a cache of decrypted
        # strings is a table sitting in memory that an analyst can dump in one
        # go, which undoes the per-occurrence ticket work entirely.
        if cache_policy not in ("none", "bounded", "full"):
            raise ValueError(f"unknown cache policy {cache_policy!r}")
        self.n = names
        self.cache_policy = cache_policy
        self.cache_bound = cache_bound
        self.emit_crypto = emit_crypto

    @property
    def accessor(self) -> str:
        """The name generated code calls to resolve a ticket."""
        return self.n["get"]

    def emit(self, sealed, crypto_src: str = "") -> str:
        n = self.n
        if self.emit_crypto:
            head = f"local {n['crypto']} = (function()\n{crypto_src}end)()\n"
        else:
            # The constant pool already declared it; a second copy would be a
            # second 8KB decoder for an analyst to find, which is exactly what
            # the design warns against.
            head = ""

        if self.cache_policy == "none":
            cache_block = (
                f"local function {n['get']}(ticket)\n"
                f"  {n['load']}()\n"
                f"  return {n['resolve']}(ticket)\n"
                f"end\n"
            )
        else:
            guard = ""
            if self.cache_policy == "bounded":
                guard = (
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
                f"local function {n['get']}(ticket)\n"
                f"  {n['load']}()\n"
                f"  if {n['seen']}[ticket] then\n"
                f"    return {n['cache']}[ticket]\n"
                f"  end\n"
                f"  local v = {n['resolve']}(ticket)\n"
                f"  {n['cache']}[ticket] = v\n"
                f"  {n['seen']}[ticket] = true\n"
                f"{guard}"
                f"  return v\n"
                f"end\n"
            )

        return f"""{head}local {n['blob']} = {byte_literal(sealed.blob)}
local {n['tkey']} = {byte_literal(sealed.ticket_key)}
local {n['tnonce']} = {byte_literal(sealed.ticket_nonce)}
local {n['ttag']} = {byte_literal(sealed.ticket_tag)}
local {n['tct']} = {byte_literal(sealed.ticket_ct)}
local {n['skey']} = {byte_literal(sealed.key)}
local {n['snonce']} = {byte_literal(sealed.stream_nonce)}
local {n['bkey']} = {byte_literal(sealed.blob_key)}
local {n['btag']} = {byte_literal(sealed.blob_tag)}
local {n['plain']} = nil
local {n['perm']} = nil
local {n['index']} = nil
local {n['psize']} = {int(sealed.page_size)}
local {n['loaded']} = false
local function {n['load']}()
  if {n['loaded']} then
    return
  end
  {n['loaded']} = true
  -- Verified before anything is decrypted.  One MAC over the whole blob, so
  -- per-string laziness is untouched; without it, editing a page would yield
  -- garbage strings instead of an error.
  --
  -- Every failure path in this runtime raises the same neutral message.  A
  -- message reading "failed authentication" tells an analyst both where the
  -- check is and that the edit they just made was detected, and it is a stable
  -- string to grep for.  "invalid state" is what an ordinary bad lookup says
  -- too, so the two are not distinguishable from the outside.
  if {n['crypto']}.{n['c_mac']}({n['bkey']}, {n['blob']}) ~= {n['btag']} then
    error("invalid state")
  end
  local p = {n['crypto']}.{n['c_open']}({n['tkey']}, {n['tnonce']}, {n['tct']}, {n['ttag']}, {byte_literal(sealed.ticket_aad)})
  if p == nil then
    error("invalid state")
  end
  {n['plain']} = p
  local tickets, pages = string.unpack(">I4I4", p, 1)
  -- the page size is a constant here, so it is read back only to check it
  local psize = string.unpack(">I4", p, 9)
  if psize ~= {n['psize']} then
    error("invalid state")
  end
  local pm = {{}}
  for i = 1, pages do
    pm[i] = string.unpack(">I4", p, 13 + (i - 1) * 4) + 1
  end
  {n['perm']} = pm
  -- index every ticket once, rather than walking the table on every read
  local q = 13 + pages * 4
  local ix = {{}}
  for i = 1, tickets do
    ix[i] = q
    q += 2 + string.unpack(">I2", p, q) * 10
  end
  {n['index']} = ix
end
local function {n['unmask']}(s, seed)
  local x = seed % {MASK_MOD}
  local t = table.create(#s)
  for i = 1, #s do
    x = (x * {MASK_MUL} + {MASK_ADD}) % {MASK_MOD}
    t[i] = string.char(bit32.bxor(string.byte(s, i), bit32.band(bit32.rshift(x, 16), 255)))
  end
  return table.concat(t)
end
local function {n['frag']}(off, len, seed)
  -- 0-based logical offset in, 1-based string.sub indices out.  Written out
  -- rather than folded together: an off-by-one here reads plausible bytes from
  -- the wrong place instead of failing.
  local page = off // {n['psize']}
  local stored = {n['perm']}[page + 1]
  local inpage = off - page * {n['psize']}
  local at = (stored - 1) * {n['psize']} + inpage
  local ct = string.sub({n['blob']}, at + 1, at + len)
  local block = off // 64
  local intra = off - block * 64
  local ks = {n['crypto']}.{n['c_xor']}({n['skey']}, {n['snonce']}, string.rep("\\0", intra + len), 1 + block)
  local out = table.create(len)
  for i = 1, len do
    out[i] = string.char(bit32.bxor(string.byte(ct, i), string.byte(ks, intra + i)))
  end
  return {n['unmask']}(table.concat(out), seed)
end
local function {n['resolve']}(ticket)
  local p = {n['plain']}
  local q = {n['index']}[ticket]
  if q == nil then
    error("invalid state")
  end
  local count = string.unpack(">I2", p, q)
  q += 2
  local parts = {{}}
  local m = 0
  for _ = 1, count do
    local off, len, seed = string.unpack(">I4I2I4", p, q)
    q += 10
    if len > 0 then
      m += 1
      parts[m] = {n['frag']}(off, len, seed)
    end
  end
  return table.concat(parts)
end
{cache_block}"""

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

import hashlib
from typing import Dict

from .constpool_runtime import byte_literal, _xor_bytes


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
        "meta": prefix + "w",
        "unwrap": prefix + "x",
        "plain": prefix + "8",
        "perm": prefix + "9",
        "index": prefix + "a",
        "psize": prefix + "b",
        "loaded": prefix + "c",
        "load": prefix + "d",
        "unmask": prefix + "e",
        "frag": prefix + "f",
        "f_off": prefix + "A",
        "f_len": prefix + "B",
        "f_seed": prefix + "C",
        "f_page": prefix + "D",
        "f_stored": prefix + "E",
        "f_inpage": prefix + "F",
        "f_at": prefix + "G",
        "f_ct": prefix + "H",
        "f_block": prefix + "I",
        "f_intra": prefix + "J",
        "f_ks": prefix + "K",
        "f_out": prefix + "L",
        "resolve": prefix + "p",
        "resolve_alt": prefix + "u",
        "resolve_alt2": prefix + "v",
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

    def emit(self, sealed, crypto_src: str = "", guard_check: str = "",
             ticket_mask: int = 0) -> str:
        n = self.n
        ticket_mask &= 0xffffffff
        def fail(site: bytes) -> str:
            return byte_literal(hashlib.sha256(sealed.ticket_key + sealed.ticket_nonce + sealed.ticket_tag + site).digest()[:8])
        trip = (f"  if not {guard_check}() then error({fail(b'guard')}) end\n"
                if guard_check else "")
        ticket_expr = '(string.unpack(">I4", %s, 1))' % byte_literal(ticket_mask.to_bytes(4, "big"))
        deticket = (f"  ticket = bit32.bxor(ticket, {ticket_expr})\n"
                    if ticket_mask else "")
        meta_name = n.get("meta", n["tkey"] + "m")
        unwrap_name = n.get("unwrap", n["tkey"] + "u")
        ticket_aad_expr = byte_literal(sealed.ticket_aad)
        tkey_material = sealed.ticket_ct + sealed.ticket_tag + sealed.ticket_nonce + sealed.ticket_aad
        skey_material = sealed.blob + sealed.blob_tag + sealed.stream_nonce
        bkey_material = sealed.blob + sealed.blob_tag
        meta_items = [
            ("tkey", _xor_bytes(sealed.ticket_key, hashlib.sha256(tkey_material).digest())),
            ("tnonce", sealed.ticket_nonce), ("ttag", sealed.ticket_tag),
            ("tct", sealed.ticket_ct),
            ("skey", _xor_bytes(sealed.key, hashlib.sha256(skey_material).digest())),
            ("snonce", sealed.stream_nonce),
            ("bkey", _xor_bytes(sealed.blob_key, hashlib.sha256(bkey_material).digest())),
            ("btag", sealed.blob_tag),
        ]
        meta_items.sort(key=lambda item: hashlib.sha256(sealed.ticket_tag + item[0].encode()).digest())
        meta_index = {name: i + 1 for i, (name, _data) in enumerate(meta_items)}
        meta_rows = ",".join(byte_literal(data) for _name, data in meta_items)
        if self.emit_crypto:
            if not crypto_src:
                from .luau_crypto import crypto_runtime
                crypto_src = crypto_runtime({"xor": n["c_xor"], "sha": n["c_sha"],
                                             "mac": n["c_mac"], "open": n["c_open"],
                                             "seal": n["c_seal"]},
                                            enc_domain=getattr(sealed, "enc_domain", None),
                                            mac_domain=getattr(sealed, "mac_domain", None))
            head = f"local {n['crypto']} = (function()\n{crypto_src}end)()\n"
        else:
            # The constant pool already declared it; a second copy would be a
            # second 8KB decoder for an analyst to find, which is exactly what
            # the design warns against.
            head = ""

        if self.cache_policy == "none":
            cache_block = (
                f"local function {n['get']}(ticket)\n"
                f"{trip}"
                f"{deticket}"
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
                f"{trip}"
                f"{deticket}"
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
local {meta_name} = {{{meta_rows}}}
local function {unwrap_name}(v, m)
  local h = {n['crypto']}.{n['c_sha']}(m)
  local t = table.create(#v)
  for i = 1, #v do
    t[i] = string.char(bit32.bxor(string.byte(v, i), string.byte(h, ((i - 1) % #h) + 1)))
  end
  return table.concat(t)
end
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
  if {n['crypto']}.{n['c_mac']}({unwrap_name}({meta_name}[{meta_index['bkey']}], {n['blob']} .. {meta_name}[{meta_index['btag']}]), {n['blob']}) ~= {meta_name}[{meta_index['btag']}] then
    error({fail(b'blob')})
  end
  local p = {n['crypto']}.{n['c_open']}({unwrap_name}({meta_name}[{meta_index['tkey']}], {meta_name}[{meta_index['tct']}] .. {meta_name}[{meta_index['ttag']}] .. {meta_name}[{meta_index['tnonce']}] .. {ticket_aad_expr}), {meta_name}[{meta_index['tnonce']}], {meta_name}[{meta_index['tct']}], {meta_name}[{meta_index['ttag']}], {ticket_aad_expr})
  if p == nil then
    error({fail(b'open')})
  end
  {n['plain']} = p
  local tickets, pages = string.unpack(">I4I4", p, 1)
  local psize = string.unpack(">I4", p, 9)
  if psize ~= {n['psize']} then
    error({fail(b'psize')})
  end
  local pm = {{}}
  for i = 1, pages do
    pm[i] = string.unpack(">I4", p, 13 + (i - 1) * 4) + 1
  end
  {n['perm']} = pm
  local q = 13 + pages * 4
  local ix = {{}}
  for i = 1, tickets do
    local ticket = i
    if {'true' if getattr(sealed, 'indirect_ids', False) else 'false'} then
      ticket = string.unpack(">I4", p, q)
      q += 4
    end
    ix[ticket] = q
    q += 2 + string.unpack(">I2", p, q) * 10
  end
  {n['index']} = ix
end
local function {n['unmask']}(s, seed)
  local x = seed % 2147483648
  local t = table.create(#s)
  for i = 1, #s do
    x = (x * {int(sealed.mask_mul)} + {int(sealed.mask_add)}) % 2147483648
    t[i] = string.char(bit32.bxor(string.byte(s, i), bit32.band(bit32.rshift(x, {int(sealed.mask_shift)}), 255)))
  end
  return table.concat(t)
end
local function {n['frag']}({n['f_off']}, {n['f_len']}, {n['f_seed']})
  local {n['f_page']} = {n['f_off']} // {n['psize']}
  local {n['f_stored']} = {n['perm']}[{n['f_page']} + 1]
  local {n['f_inpage']} = {n['f_off']} - {n['f_page']} * {n['psize']}
  local {n['f_at']} = ({n['f_stored']} - 1) * {n['psize']} + {n['f_inpage']}
  local {n['f_ct']} = string.sub({n['blob']}, {n['f_at']} + 1, {n['f_at']} + {n['f_len']})
  local {n['f_block']} = {n['f_off']} // 64
  local {n['f_intra']} = {n['f_off']} - {n['f_block']} * 64
  local {n['f_ks']} = {n['crypto']}.{n['c_xor']}({unwrap_name}({meta_name}[{meta_index['skey']}], {n['blob']} .. {meta_name}[{meta_index['btag']}] .. {meta_name}[{meta_index['snonce']}]), {meta_name}[{meta_index['snonce']}], string.rep("\\0", {n['f_intra']} + {n['f_len']}), 1 + {n['f_block']})
  local {n['f_out']} = table.create({n['f_len']})
  for i = 1, {n['f_len']} do
    {n['f_out']}[i] = string.char(bit32.bxor(string.byte({n['f_ct']}, i), string.byte({n['f_ks']}, {n['f_intra']} + i)))
  end
  return {n['unmask']}(table.concat({n['f_out']}), {n['f_seed']})
end
local function {n['resolve']}(ticket)
  local p = {n['plain']}
  local q = {n['index']}[ticket]
  if q == nil then
    error({fail(b'lookup1')})
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
local function {n['resolve_alt']}(ticket)
  local p = {n['plain']}
  local q = {n['index']}[ticket]
  if q == nil then
    error({fail(b'lookup2')})
  end
  local count = string.unpack(">I2", p, q)
  q += 2
  local out = ""
  for _ = 1, count do
    local off, len, seed = string.unpack(">I4I2I4", p, q)
    q += 10
    if len > 0 then
      out = out .. {n['frag']}(off, len, seed)
    end
  end
  return out
end
local function {n['resolve_alt2']}(ticket)
  local p = {n['plain']}
  local q = {n['index']}[ticket]
  if q == nil then
    error({fail(b'lookup3')})
  end
  local count = string.unpack(">I2", p, q)
  q += 2
  local parts = table.create(count)
  for i = 1, count do
    local off, len, seed = string.unpack(">I4I2I4", p, q)
    q += 10
    parts[i] = len > 0 and {n['frag']}(off, len, seed) or ""
  end
  local out = ""
  for i = #parts, 1, -1 do
    out = parts[i] .. out
  end
  return out
end
{cache_block}"""

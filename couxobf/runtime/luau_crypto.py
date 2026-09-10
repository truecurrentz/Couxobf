"""Generated Luau runtime: ChaCha20 + SHA-256/HMAC-SHA256.

This emits *source*, never bytecode: the protected program carries an ordinary
Luau implementation of the same primitives the build tool used, so the output
stays portable (no ``loadstring`` of compiled bytecode, no native libs, no
executor-specific APIs).

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
* SHA-256 is entirely 32-bit for the same reason.

The composition is encrypt-then-MAC, which is what lets the runtime reject a
tampered payload before it is decrypted.

Environment constraints honoured (all verified, not assumed)
-----------------------------------------------------------
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
64-byte block and SHA-256 about 3k, which is why payload decoding is chunked
and lazy instead of happening wholesale at startup.
"""

from __future__ import annotations

from typing import Dict

from ..crypto.chacha20 import COLUMN_ROUNDS, DIAGONAL_ROUNDS
from ..crypto.sha256 import H_INIT, K
from ..crypto.protected import ENC_DOMAIN, MAC_DOMAIN

# Sigma constants: little-endian 32-bit words of "expand 32-byte k".
SIGMA = (1634760805, 857760878, 2036477234, 1797285236)

def _byte_literal(data: bytes) -> str:
    return '"' + ''.join('\\x%02x' % b for b in data) + '"'


def _k_table() -> str:
    rows = []
    for i in range(0, 64, 8):
        rows.append("  " + ", ".join("0x%08x" % v for v in K[i : i + 8]) + ",")
    return "\n".join(rows)


def crypto_runtime(names: Dict[str, str], enc_domain: bytes = None,
                   mac_domain: bytes = None) -> str:
    """Emit the crypto runtime.

    ``names`` maps logical roles to generated identifiers: ``xor`` (ChaCha20),
    ``sha`` (SHA-256), ``mac`` (HMAC-SHA256), ``open`` (verify + decrypt),
    ``seal`` (encrypt + tag).
    """
    n = names
    enc_dom = _byte_literal(enc_domain if enc_domain is not None else ENC_DOMAIN)
    mac_dom = _byte_literal(mac_domain if mac_domain is not None else MAC_DOMAIN)
    return f"""local band, bor, bxor, bnot = bit32.band, bit32.bor, bit32.bxor, bit32.bnot
local lshift, rshift = bit32.lshift, bit32.rshift
local byte, char, rep, sub = string.byte, string.char, string.rep, string.sub
local M32 = 4294967295
local MOD32 = 4294967296

local function rotl(v, s)
  return bor(lshift(v, s), rshift(v, 32 - s))
end

local function rotr(v, s)
  return bor(rshift(v, s), lshift(v, 32 - s))
end

local function le32(s, i)
  local a, b, c, d = byte(s, i, i + 3)
  return a + b * 256 + c * 65536 + d * 16777216
end

local function bytes_out(t, n)
  local chunks = table.create((n + 127) // 128)
  local k = 0
  local i = 1
  while i <= n do
    local j = i + 127
    if j > n then j = n end
    k += 1
    chunks[k] = char(table.unpack(t, i, j))
    i = j + 1
  end
  return table.concat(chunks)
end

-- ---------------------------------------------------------------- ChaCha20
local SIGMA = {{{SIGMA[0]}, {SIGMA[1]}, {SIGMA[2]}, {SIGMA[3]}}}
local cstate = table.create(16)
local cwork = table.create(16)

local function qr(s, a, b, c, d)
  s[a] = band(s[a] + s[b], M32)
  s[d] = rotl(bxor(s[d], s[a]), 16)
  s[c] = band(s[c] + s[d], M32)
  s[b] = rotl(bxor(s[b], s[c]), 12)
  s[a] = band(s[a] + s[b], M32)
  s[d] = rotl(bxor(s[d], s[a]), 8)
  s[c] = band(s[c] + s[d], M32)
  s[b] = rotl(bxor(s[b], s[c]), 7)
end

local function chacha_block(key32, counter, nonce12, out)
  local s = cstate
  s[1], s[2], s[3], s[4] = SIGMA[1], SIGMA[2], SIGMA[3], SIGMA[4]
  for i = 1, 8 do
    s[4 + i] = key32[i]
  end
  s[13] = band(counter, M32)
  s[14] = nonce12[1]
  s[15] = nonce12[2]
  s[16] = nonce12[3]
  local w = cwork
  for i = 1, 16 do w[i] = s[i] end
  for _ = 1, 10 do
    qr(w, 1, 5, 9, 13)
    qr(w, 2, 6, 10, 14)
    qr(w, 3, 7, 11, 15)
    qr(w, 4, 8, 12, 16)
    qr(w, 1, 6, 11, 16)
    qr(w, 2, 7, 12, 13)
    qr(w, 3, 8, 9, 14)
    qr(w, 4, 5, 10, 15)
  end
  local p = 1
  for i = 1, 16 do
    local v = band(w[i] + s[i], M32)
    out[p] = band(v, 255)
    out[p + 1] = band(rshift(v, 8), 255)
    out[p + 2] = band(rshift(v, 16), 255)
    out[p + 3] = band(rshift(v, 24), 255)
    p += 4
  end
end

local function prep_key(keystr)
  local k = table.create(8)
  for i = 1, 8 do
    k[i] = le32(keystr, (i - 1) * 4 + 1)
  end
  return k
end

local function prep_nonce(noncestr)
  return {{le32(noncestr, 1), le32(noncestr, 5), le32(noncestr, 9)}}
end

local keystream = table.create(64)

local function {n["xor"]}(keystr, noncestr, data, counter)
  local key32 = prep_key(keystr)
  local nonce12 = prep_nonce(noncestr)
  local len = #data
  local out = table.create(len)
  local ks = keystream
  local blk = 0
  local pos = 1
  while pos <= len do
    chacha_block(key32, counter + blk, nonce12, ks)
    blk += 1
    local stop = pos + 63
    if stop > len then stop = len end
    for i = pos, stop do
      out[i] = bxor(byte(data, i), ks[i - pos + 1])
    end
    pos = stop + 1
  end
  return bytes_out(out, len)
end

-- ----------------------------------------------------------------- SHA-256
local SHA_K = {{
{_k_table()}
}}

local SHA_H = {{{", ".join("0x%08x" % v for v in H_INIT)}}}

local wbuf = table.create(64)

local function sha256_blocks(state, msg, start, blocks)
  local w = wbuf
  for b = 0, blocks - 1 do
    local base = start + b * 64
    for i = 1, 16 do
      local o = base + (i - 1) * 4
      local x, y, z, t = byte(msg, o, o + 3)
      w[i] = x * 16777216 + y * 65536 + z * 256 + t
    end
    for i = 17, 64 do
      local a = w[i - 15]
      local s0 = bxor(bxor(rotr(a, 7), rotr(a, 18)), rshift(a, 3))
      local c = w[i - 2]
      local s1 = bxor(bxor(rotr(c, 17), rotr(c, 19)), rshift(c, 10))
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) % MOD32
    end
    local h1, h2, h3, h4 = state[1], state[2], state[3], state[4]
    local h5, h6, h7, h8 = state[5], state[6], state[7], state[8]
    for i = 1, 64 do
      local S1 = bxor(bxor(rotr(h5, 6), rotr(h5, 11)), rotr(h5, 25))
      local ch = bxor(band(h5, h6), band(bnot(h5), h7))
      local t1 = (h8 + S1 + ch + SHA_K[i] + w[i]) % MOD32
      local S0 = bxor(bxor(rotr(h1, 2), rotr(h1, 13)), rotr(h1, 22))
      local maj = bxor(bxor(band(h1, h2), band(h1, h3)), band(h2, h3))
      local t2 = (S0 + maj) % MOD32
      h8 = h7
      h7 = h6
      h6 = h5
      h5 = (h4 + t1) % MOD32
      h4 = h3
      h3 = h2
      h2 = h1
      h1 = (t1 + t2) % MOD32
    end
    state[1] = (state[1] + h1) % MOD32
    state[2] = (state[2] + h2) % MOD32
    state[3] = (state[3] + h3) % MOD32
    state[4] = (state[4] + h4) % MOD32
    state[5] = (state[5] + h5) % MOD32
    state[6] = (state[6] + h6) % MOD32
    state[7] = (state[7] + h7) % MOD32
    state[8] = (state[8] + h8) % MOD32
  end
end

local function {n["sha"]}(msg)
  local state = table.create(8)
  for i = 1, 8 do state[i] = SHA_H[i] end
  local len = #msg
  local padded = len + 1
  while padded % 64 ~= 56 do
    padded += 1
  end
  padded += 8
  -- every slot must be assigned: table.concat raises on nil holes
  local tail = table.create(padded - len - 8)
  tail[1] = "\\128"
  for i = 2, padded - len - 8 do
    tail[i] = "\\000"
  end
  -- 64-bit big-endian bit length.  Luau doubles are exact below 2^53, which
  -- covers any payload this protector will ever produce.
  local bits = len * 8
  local lenbytes = table.create(8)
  for i = 8, 1, -1 do
    lenbytes[i] = char(band(bits, 255))
    bits = (bits - band(bits, 255)) // 256
  end
  local full = msg .. table.concat(tail) .. table.concat(lenbytes)
  sha256_blocks(state, full, 1, padded // 64)
  local out = table.create(32)
  for i = 1, 8 do
    local v = state[i]
    out[(i - 1) * 4 + 1] = char(band(rshift(v, 24), 255))
    out[(i - 1) * 4 + 2] = char(band(rshift(v, 16), 255))
    out[(i - 1) * 4 + 3] = char(band(rshift(v, 8), 255))
    out[(i - 1) * 4 + 4] = char(band(v, 255))
  end
  return table.concat(out)
end

local function {n["mac"]}(key, msg)
  -- RFC 2104 HMAC-SHA256, block size 64.
  if #key > 64 then
    key = {n["sha"]}(key)
  end
  local inner = table.create(64)
  local outer = table.create(64)
  for i = 1, 64 do
    local v = byte(key, i) or 0
    inner[i] = char(bxor(v, 0x36))
    outer[i] = char(bxor(v, 0x5c))
  end
  return {n["sha"]}(table.concat(outer) .. {n["sha"]}(table.concat(inner) .. msg))
end

-- ------------------------------------------------- payload MAC + AEAD-ish
local function le64(n)
  local t = table.create(8)
  for i = 1, 8 do
    t[i] = char(band(n, 255))
    n = (n - band(n, 255)) // 256
  end
  return table.concat(t)
end

local function enc_key(keystr, noncestr, aad)
  return {n["sha"]}({enc_dom} .. keystr .. noncestr .. aad .. le64(#aad))
end

local function mac_key(keystr, noncestr, aad)
  return {n["sha"]}({mac_dom} .. keystr .. noncestr .. aad .. le64(#aad))
end

local function compute_tag(keystr, noncestr, ct, aad)
  local covered = {{noncestr, aad, le64(#aad), ct, le64(#ct)}}
  return {n["mac"]}(mac_key(keystr, noncestr, aad), table.concat(covered))
end

local function const_eq(a, b)
  if #a ~= #b then return false end
  local diff = 0
  for i = 1, #a do
    diff = bor(diff, bxor(byte(a, i), byte(b, i)))
  end
  return diff == 0
end

local function {n["open"]}(keystr, noncestr, ct, tag, aad)
  aad = aad or ""
  if not const_eq(compute_tag(keystr, noncestr, ct, aad), tag) then
    return nil
  end
  return {n["xor"]}(enc_key(keystr, noncestr, aad), noncestr, ct, 1)
end

local function {n["seal"]}(keystr, noncestr, plain, aad)
  aad = aad or ""
  local ct = {n["xor"]}(enc_key(keystr, noncestr, aad), noncestr, plain, 1)
  return ct, compute_tag(keystr, noncestr, ct, aad)
end

-- Field names are generated too: exporting keys named "open" and "mac" would
-- hand a reader a map of the runtime.
return {{
  {n["xor"]} = {n["xor"]},
  {n["sha"]} = {n["sha"]},
  {n["mac"]} = {n["mac"]},
  {n["open"]} = {n["open"]},
  {n["seal"]} = {n["seal"]},
}}
"""

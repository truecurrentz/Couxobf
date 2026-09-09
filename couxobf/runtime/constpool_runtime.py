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

from typing import Dict

from .luau_crypto import crypto_runtime


def byte_literal(data: bytes) -> str:
    """A Luau string literal holding exactly these bytes.

    Every byte is escaped as ``\\xHH``: printable characters would be safe to
    emit raw, but escaping uniformly means no byte can ever terminate the
    literal early or smuggle in an escape sequence.
    """
    return '"' + "".join("\\x%02x" % b for b in data) + '"'


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
             aad: bytes, emit_crypto: bool = True) -> str:
        n = self.n
        # The crypto module ends in `return {...}`, so wrapping it in a call
        # turns it into a value without needing a require.
        crypto = crypto_runtime(
            {"xor": n["c_xor"], "sha": n["c_sha"], "mac": n["c_mac"],
             "open": n["c_open"], "seal": n["c_seal"]}
        )

        if self.cache_policy == "none":
            cache_block = (
                f"local function {n['get']}(i)\n"
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

        return f"""{head}local {n['key']} = {byte_literal(key)}
local {n['nonce']} = {byte_literal(nonce)}
local {n['tag']} = {byte_literal(tag)}
local {n['ct']} = {byte_literal(ciphertext)}
local {n['plain']} = nil
local {n['off']} = nil
local {n['loaded']} = false
local function {n['load']}()
  if {n['loaded']} then
    return
  end
  {n['loaded']} = true
  local p = {n['crypto']}.{n['c_open']}({n['key']}, {n['nonce']}, {n['ct']}, {n['tag']}, {byte_literal(aad)})
  if p == nil then
    error("invalid state")
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
    elseif t == 1 then
      q += 1
    end
  end
  {n['off']} = o
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
  else
    local len = string.unpack(">I4", p, q + 1)
    return string.sub(p, q + 5, q + 4 + len)
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
FAILURE_MESSAGE = "invalid state"


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
        "plain": prefix + "5",
        "off": prefix + "6",
        "loaded": prefix + "7",
        "load": prefix + "8",
        "mat": prefix + "9",
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

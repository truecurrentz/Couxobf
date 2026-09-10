"""End-to-end hardening checks for generated VM artifacts.

The corpus is intentionally small but semantic-heavy: metatables, closures,
varargs, pcall, loops, pairs/ipairs and arithmetic all have to survive the
obfuscation pipeline.  The structural assertions are a deliberately simple
"static lifter": it only recognizes old direct dispatcher idioms.  A hardened
artifact should give that lifter little to recover.
"""

from __future__ import annotations

import re

import pytest

from couxobf.config import Config
from couxobf.pipeline import build
from couxobf.toolchain import execute, find_toolchain

TOOLCHAIN = find_toolchain()

CORPUS = r'''
local mt = { __index = function(_, k) return #k end }
local obj = setmetatable({x = 3}, mt)
local function fold(seed, ...)
  local acc = seed
  local function add(v) acc = acc + v; return acc end
  for i, v in ipairs({...}) do
    if i % 2 == 0 then acc = add(v) else acc = acc + v * obj.missing end
  end
  for k, v in pairs({a = 2, bb = 4}) do acc = acc + #k + v end
  local ok, value = pcall(function(a, b) return (a // b) + (a % b) end, acc, 5)
  if ok then return value, acc else return -1, acc end
end
local a, b = fold(1, 2, 3, 4)
print(a, b, obj.x, obj.zz)
'''


def _protected(seed: int = 77) -> str:
    cfg = Config(reproducible_seed=seed, min_virtualize_body_nodes=1,
                 env_guard=1, dump_guard=1, minify=False)
    return build(CORPUS, cfg, name="differential.luau", verify=False).source


def test_semantic_corpus_matches_after_obfuscation():
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    protected = _protected()
    original = execute(TOOLCHAIN, CORPUS, "orig.luau", timeout=30)
    obfuscated = execute(TOOLCHAIN, protected, "obf.luau", timeout=30)
    assert obfuscated.returncode == original.returncode, obfuscated.stderr[:400]
    assert obfuscated.stdout == original.stdout
    assert obfuscated.stderr == original.stderr


def test_simple_static_lifter_recovers_no_direct_dispatch_table():
    src = _protected()
    # Old direct-dispatch lifters keyed on a monolithic opcode chain/tree/bucket.
    direct = re.findall(r"\bif\s+op\s*==|\belseif\s+op\s*==|\bop\s*<=|\b_bk\b|\(op\s*\*", src)
    assert direct == []
    assert src.count("local function") >= 3
    assert re.search(r"\[[0-9]+\]\s*=\s*_[A-Za-z]+", src)


def test_surface_names_and_failure_strings_are_not_plaintext_signatures():
    src = _protected()
    for needle in ("hookfunction", "getgc", "saveinstance", "getrawmetatable",
                   "invalid state", "ticket % 3", "couxobf/stringbank"):
        assert needle not in src

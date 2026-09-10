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
from couxobf.verify.output import OutputValidationError
from couxobf.toolchain import execute, find_toolchain
from couxobf.verify.analyzer import analyze, opcode_frequency

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
  local function divmix() return (acc // 5) + (acc % 5) end
  local ok, value = pcall(divmix)
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
    report = analyze(src)
    # Old direct-dispatch lifters keyed on a monolithic opcode chain/tree/bucket.
    direct = re.findall(r"\bif\s+op\s*==|\belseif\s+op\s*==|\bop\s*<=|\b_bk\b|\(op\s*\*", src)
    assert direct == []
    assert report.count("flat_opcode_chain") == 0
    assert report.count("dispatcher_loop") == 0
    assert report.count("flat_handler_table") == 0
    assert src.count("local function") >= 3


def test_static_analyzer_tracks_remaining_architecture_surface():
    src = _protected()
    report = analyze(src)
    freq = opcode_frequency(src)
    # Handler functions and crypto still exist in a self-contained script, but
    # they should no longer sit behind the old flat dispatcher/table signatures.
    assert report.count("handler_function") > 0
    assert report.count("xor_crypto") > 0
    assert report.count("flat_handler_table") == 0
    assert len(freq) == 0


def test_surface_names_and_failure_strings_are_not_plaintext_signatures():
    src = _protected()
    for needle in ("hookfunction", "getgc", "saveinstance", "getrawmetatable",
                   "invalid state", "ticket % 3", "couxobf/stringbank"):
        assert needle not in src


def test_build_verify_runs_round_trip_when_toolchain_can_execute():
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    cfg = Config(reproducible_seed=123, min_virtualize_body_nodes=1,
                 env_guard=0, dump_guard=0, minify=False, self_test=True)
    result = build(CORPUS, cfg, name="roundtrip.luau", toolchain=TOOLCHAIN,
                   verify=True)
    assert result.validation.differential is True
    assert result.validation.differential_reason == ""


def test_build_verify_rejects_round_trip_mismatch_when_enabled(monkeypatch):
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    from couxobf.verify.difftest import DiffResult
    import couxobf.pipeline as pipeline

    def bad_pair(*_args, **_kwargs):
        return DiffResult(False, "stdout differs", details={"original_stdout": "1", "protected_stdout": "2"})

    monkeypatch.setattr(pipeline, "run_pair", bad_pair)
    cfg = Config(reproducible_seed=123, virtualization_level="none",
                 self_test=True, minify=False)
    with pytest.raises(OutputValidationError):
        build("print(1)", cfg, name="bad-roundtrip.luau", toolchain=TOOLCHAIN,
              verify=True)

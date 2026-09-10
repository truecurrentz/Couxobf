"""R9: index-to-number rewriting of provably-static local tables (opt-in).

The pass replaces the keys of certain tables with per-build numeric
handles so the key strings never reach the artifact.  The price of that
guarantee is a strict whitelist: the table must be a plain local bound
once to a literal-key constructor, never reassigned, never captured, and
used nowhere except as ``t.name`` or ``t["literal"]``.  These tests pin
both sides -- the rewrites that happen, and the rejections that must,
because a rewrite that escaped the whitelist would change runtime
behaviour, and that is the one thing this tool never does.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from couxobf import ast_nodes as A
from couxobf import comments, index_to_num, parser, sema
from couxobf.config import Config
from couxobf.pipeline import build
from couxobf.rng import Rng
from couxobf.toolchain import execute, find_toolchain

TOOLCHAIN = find_toolchain()


def _prep(src):
    tree = parser.parse(src, "r9.luau")
    sema.ScopeAnalyzer().analyze(tree)
    return tree


def _rewrite(src, seed=b"\x21" * 16, directives=()):
    tree = _prep(src)
    stats = index_to_num.rewrite(tree, Rng(seed), directives=directives)
    return tree, stats


def _tables(tree):
    return [n for n in A.walk(tree) if isinstance(n, A.Table)]


def _string_keys_left(tree):
    """String keys still present: field items, or `["..."]` items."""
    left = []
    for t in _tables(tree):
        for item in t.items:
            if item.kind == "field":
                left.append(item.key_name)
            elif item.kind == "key" and isinstance(item.key_expr, A.Str):
                left.append(item.key_expr.raw)
    return left


# ---------------------------------------------------------------------------
# the happy path
# ---------------------------------------------------------------------------

ELIGIBLE = (
    "local function read()\n"
    "  local cfg = { mode = 1, retries = 3, [\"timeout\"] = 30 }\n"
    "  cfg.mode = cfg.mode + 1\n"
    "  return cfg.mode + cfg[\"retries\"] + cfg.timeout\n"
    "end\n"
    "print(read())\n"
)


def test_an_eligible_table_loses_every_string_key():
    tree, stats = _rewrite(ELIGIBLE)
    assert stats.tables == 1
    assert stats.keys == 3
    assert _string_keys_left(tree) == []
    # No Field access on the table survives either.
    fields = [n for n in A.walk(tree) if isinstance(n, A.Field)]
    assert fields == []


def test_dot_and_bracket_forms_of_one_key_get_one_handle():
    src = ("local function f()\n"
           "  local t = { alpha = 1 }\n"
           "  return t.alpha + t[\"alpha\"]\n"
           "end\n"
           "print(f())\n")
    tree, stats = _rewrite(src)
    assert stats.keys == 1, "t.alpha and t[\"alpha\"] are the same key"
    indexes = [n for n in A.walk(tree) if isinstance(n, A.Index)]
    handles = {n.key.value for n in indexes if isinstance(n.key, A.Number)}
    assert len(handles) == 1


def test_duplicate_keys_still_collapse_to_one_handle():
    src = ("local function f()\n"
           "  local t = { k = 1, [\"k\"] = 2 }\n"
           "  return t.k\n"
           "end\n"
           "print(f())\n")
    tree, stats = _rewrite(src)
    assert stats.keys == 1
    items = _tables(tree)[0].items
    assert all(it.kind == "key" for it in items)
    assert items[0].key_expr.value == items[1].key_expr.value, (
        "duplicate keys map to the same handle, so the last one still wins")


def _handles(tree):
    return sorted(n.key.value for n in A.walk(tree)
                  if isinstance(n, A.Index) and isinstance(n.key, A.Number))


def test_the_same_seed_reproduces_and_a_new_seed_disagrees():
    tree1, s1 = _rewrite(ELIGIBLE, seed=b"\x21" * 16)
    tree1b, _ = _rewrite(ELIGIBLE, seed=b"\x21" * 16)
    tree2, _ = _rewrite(ELIGIBLE, seed=b"\x22" * 16)
    assert s1.tables == 1
    assert _handles(tree1) == _handles(tree1b), "same seed, same handles"
    # Three handles in a 2**24 space: a fresh seed keeps every one of them
    # with probability ~1.
    assert _handles(tree2) != _handles(tree1)


# ---------------------------------------------------------------------------
# the whitelist: every escape path must be refused
# ---------------------------------------------------------------------------

def _refused(src, note):
    tree, stats = _rewrite(src)
    assert stats.tables == 0, note
    assert stats.skipped >= 1, note
    assert stats.sites == 0, note + " (nothing may be rewritten on refusal)"


def test_a_table_captured_by_a_nested_function_is_refused():
    _refused(
        "local cfg = { mode = 1 }\n"
        "local function read()\n  return cfg.mode\nend\n"
        "print(read())\n",
        "captured as an upvalue")


def test_a_reassigned_binding_is_refused():
    _refused(
        "local function f()\n"
        "  local t = { a = 1 }\n"
        "  t = { a = 2 }\n"
        "  return t.a\n"
        "end\n"
        "print(f())\n",
        "reassigned")


def test_a_table_passed_to_a_call_is_refused():
    _refused(
        "local function f()\n"
        "  local t = { a = 1 }\n"
        "  return print(t) or t.a\n"
        "end\n"
        "f()\n",
        "passed as an argument")


def test_a_returned_table_is_refused():
    _refused(
        "local function f()\n"
        "  local t = { a = 1 }\n"
        "  return t\n"
        "end\n"
        "print(f().a)\n",
        "returned")


def test_a_dynamic_index_is_refused():
    _refused(
        "local function f(k)\n"
        "  local t = { a = 1 }\n"
        "  return t[k]\n"
        "end\n"
        "print(f(\"a\"))\n",
        "dynamically indexed")


def test_a_method_call_on_the_table_is_refused():
    _refused(
        "local function f()\n"
        "  local t = { a = function(self) return 1 end }\n"
        "  return t:a()\n"
        "end\n"
        "print(f())\n",
        "method-called")


def test_length_of_the_table_is_refused():
    _refused(
        "local function f()\n"
        "  local t = { a = 1 }\n"
        "  return #t\n"
        "end\n"
        "print(f())\n",
        "length operator")


def test_an_array_part_is_refused():
    _refused(
        "local function f()\n"
        "  local t = { 1, 2, a = 3 }\n"
        "  return t.a\n"
        "end\n"
        "print(f())\n",
        "array part -- numeric handles could collide")


def test_a_computed_key_is_refused():
    _refused(
        "local function f(k)\n"
        "  local t = { [k] = 1 }\n"
        "  return t[k]\n"
        "end\n"
        "print(f(\"a\"))\n",
        "computed key")


def test_an_aliased_table_is_refused():
    _refused(
        "local function f()\n"
        "  local t = { a = 1 }\n"
        "  local u = t\n"
        "  return u.a\n"
        "end\n"
        "print(f())\n",
        "aliased into another local")


def test_shadowing_does_not_leak_the_rewrite():
    """The inner `t` is a different symbol; rewriting the outer one must not
    touch it, and the inner one's dynamic use keeps *it* refused."""
    src = ("local function f()\n"
           "  local t = { a = 1 }\n"
           "  do\n"
           "    local t = setmetatable({}, {})\n"
           "    print(t)\n"
           "  end\n"
           "  return t.a\n"
           "end\n"
           "print(f())\n")
    tree, stats = _rewrite(src)
    # The outer table is eligible; the inner one is not even a candidate
    # shape the whitelist would accept on its own merits, but it must not
    # block the outer rewrite.
    assert stats.tables == 1


# ---------------------------------------------------------------------------
# the escape hatch
# ---------------------------------------------------------------------------

def test_the_no_index_to_num_directive_exempts_the_next_declaration():
    src = ("--!couxobf:no_index_to_num\n"
           "local function f()\n"
           "  local t = { a = 1 }\n"
           "  return t.a\n"
           "end\n"
           "print(f())\n")
    tree = _prep(src)
    directives = [(d.line, d.name) for d in comments.find_directives(src)]
    stats = index_to_num.rewrite(tree, Rng(b"\x21" * 16), directives=directives)
    assert stats.tables == 0
    assert stats.skipped == 1


def test_the_directive_only_exempts_its_own_declaration():
    src = ("local function f()\n"
           "  --!couxobf:no_index_to_num\n"
           "  local kept = { a = 1 }\n"
           "  local changed = { b = 2 }\n"
           "  return kept.a + changed.b\n"
           "end\n"
           "print(f())\n")
    tree = _prep(src)
    directives = [(d.line, d.name) for d in comments.find_directives(src)]
    stats = index_to_num.rewrite(tree, Rng(b"\x21" * 16), directives=directives)
    assert stats.tables == 1
    assert stats.skipped == 1


# ---------------------------------------------------------------------------
# pipeline behaviour
# ---------------------------------------------------------------------------

def test_off_by_default_and_invisible_in_the_report():
    out = build(ELIGIBLE, Config(reproducible_seed=7), name="r9.luau",
                verify=False)
    assert out.stats.index_to_num == {}


def _artifact_key_leaks(source, keys):
    """Key strings that survive as structure in the emitted program.

    A raw substring grep would be wrong here: the VM runtime happens to
    declare locals named `step` or `base`, and an identifier collision is
    not a leak.  What must not survive is the key *as a key* -- a field
    access or a string literal with that spelling.
    """
    art = parser.parse(source, "artifact.luau")
    fields = {n.name for n in A.walk(art) if isinstance(n, A.Field)}
    strs = {n.raw for n in A.walk(art) if isinstance(n, A.Str)}
    return (fields & set(keys)) | (strs & {k.encode() for k in keys})


def test_keys_disappear_from_the_artifact_when_enabled():
    out = build(ELIGIBLE, Config(reproducible_seed=7, index_to_num=True),
                name="r9.luau", verify=True)
    assert out.stats.index_to_num["tables"] == 1
    assert _artifact_key_leaks(out.source, ("mode", "retries", "timeout")) == set()
    assert "index-to-num" in out.report


def test_keys_leave_the_constant_pool():
    """The discriminating check.  Emitted text is the wrong place to look:
    every literal rides the encrypted pool, so the keys were never visible
    text either way.  What R9 changes is the *pool contents* -- with the
    pass on, the keys are small integers, and breaking the pool no longer
    yields the table's shape."""
    from couxobf import ir

    def pool_consts(src, on):
        tree = parser.parse(src, "r9.luau")
        sema.ScopeAnalyzer().analyze(tree)
        if on:
            index_to_num.rewrite(tree, Rng(b"\x21" * 16))
        module = ir.Lowerer(table_key_protection=False).lower(tree)
        consts = []
        for p in module.walk():
            consts.extend(p.consts)
        return consts

    leaky = {b"mode", b"retries", b"timeout"}
    assert leaky & set(pool_consts(ELIGIBLE, False)), (
        "sanity: without the pass, the keys are pool strings")
    assert not leaky & set(pool_consts(ELIGIBLE, True)), (
        "with the pass, the keys are integers and gone from the pool")


def test_a_protected_build_executes_like_its_source():
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    out = build(ELIGIBLE, Config(reproducible_seed=11, index_to_num=True),
                name="r9.luau", verify=True)
    want = execute(TOOLCHAIN, ELIGIBLE, "want.luau", timeout=30)
    got = execute(TOOLCHAIN, out.source, "got.luau", timeout=30)
    assert got.returncode == 0, got.stderr[:300]
    assert got.stdout == want.stdout


def test_rewritten_tables_compose_with_virtualization():
    """The function holding the table is virtualized; the VM must execute the
    numeric-keyed table exactly as the native path would."""
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    src = (
        "local function busy(n)\n"
        "  local t = { step = 2, base = 10, [\"cap\"] = 1000 }\n"
        "  local acc = t.base\n"
        "  for i = 1, n do\n"
        "    if acc < t.cap then\n"
        "      acc = acc + i * t.step\n"
        "    else\n"
        "      acc = acc - t.step\n"
        "    end\n"
        "  end\n"
        "  return acc\n"
        "end\n"
        "print(busy(200))\n"
    )
    out = build(src, Config(reproducible_seed=13, index_to_num=True),
                name="r9.luau", verify=True)
    assert out.stats.virtualized >= 1
    assert out.stats.index_to_num["tables"] == 1
    want = execute(TOOLCHAIN, src, "want.luau", timeout=60)
    got = execute(TOOLCHAIN, out.source, "got.luau", timeout=120)
    assert got.returncode == 0, got.stderr[:300]
    assert got.stdout == want.stdout


def test_two_builds_of_one_source_disagree_on_the_handles():
    a = build(ELIGIBLE, Config(reproducible_seed=7, index_to_num=True),
              name="r9.luau", verify=False)
    b = build(ELIGIBLE, Config(reproducible_seed=8, index_to_num=True),
              name="r9.luau", verify=False)
    assert a.source != b.source

"""Tests for the IR optimizer.

The optimizer's whole risk is that it changes behaviour, so the suite is built
around the cases where Luau and Python disagree.  Each "declined" assertion
below is as important as each "folded" one: declining is always safe, being
wrong never is.
"""

import glob
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from couxobf import ir, lower_back, optimize, parser
from couxobf.config import Config
from couxobf.crypto.kdf import KeyMaterial
from couxobf.emit import printer
from couxobf.ir import OP, compute_liveness, def_use
from couxobf.optimize import Stats
from couxobf.rng import make_domains, new_seed
from couxobf.toolchain import find_toolchain, execute

TOOLCHAIN = find_toolchain()
MICRO_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "micro")


def main(src: str):
    return ir.Lowerer().lower(parser.parse(src, "test.luau")).main


def instrs(proto):
    return [i for b in proto.blocks for i in b.instrs]


def ops(proto):
    return [i.op for i in instrs(proto)]


def run(src: str, optimize_it: bool = True) -> str:
    """Lower, optionally optimize, reconstruct, execute; return stdout."""
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    module = ir.Lowerer().lower(parser.parse(src, "test.luau"))
    if optimize_it:
        optimize.optimize_module(module)
    out = lower_back.HELPERS_SRC + printer.emit(
        lower_back.Reconstructor().reconstruct(module))
    result = execute(TOOLCHAIN, out, "optimized.luau", timeout=20)
    assert result.returncode == 0, result.stderr[:300]
    return result.stdout


def assert_same(src: str) -> None:
    """Optimized and original must behave identically."""
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    original = execute(TOOLCHAIN, src, "original.luau", timeout=20)
    assert run(src, optimize_it=True) == original.stdout
    assert run(src, optimize_it=False) == original.stdout


# ---------------------------------------------------------------------------
# constant folding


@pytest.mark.parametrize("expr,expected", [
    ("2 * 3 + 10", "16"),
    ("10 % 3", "1"),
    ("-7 // 2", "-4"),       # floor division: Luau and Python agree here
    ("7 // 2", "3"),
    ("-7 % 2", "1"),
    ("7.5 // 2", "3"),
    ("2 ^ 10", "1024"),
    ("100 - 1", "99"),
    ("-(3 + 4)", "-7"),
])
def test_folding_matches_the_runtime(expr, expected):
    proto = main(f"return {expr}\n")
    optimize.optimize_proto(proto)
    loads = [i for i in instrs(proto) if i.op == OP.LOADK]
    assert any(proto.consts[i.args[1].index] == float(expected) for i in loads), (
        f"{expr} did not fold to {expected}: {ops(proto)}")


def test_folded_value_is_verified_by_execution():
    """Belt and braces: the folded constant must be the one Luau computes."""
    assert run("print(10 % 3, -7 // 2, 2 ^ 10, 7.5 // 2)\n") == "1\t-4\t1024\t3\n"


@pytest.mark.parametrize("expr", [
    "1 / 0",       # inf in Luau; ZeroDivisionError in Python
    "0 / 0",       # NaN
    "1 // 0",      # inf
    "1 % 0",       # NaN
    "2 ^ 1024",    # inf; OverflowError from Python's **
    "-(2 ^ 1024)",
])
def test_non_finite_results_are_never_folded(expr):
    """Luau produces infinities and NaN where Python raises or overflows.
    Folding these is how a "harmless" optimization silently changes a program.
    """
    proto = main(f"return {expr}\n")
    optimize.optimize_proto(proto)
    # the operands are still LOADKs, so the check is that the *operation*
    # survived rather than being replaced by a precomputed constant
    remaining = {i.op for i in instrs(proto)} & {OP.DIV, OP.IDIV, OP.MOD, OP.POW, OP.UNM}
    assert remaining, f"{expr} was folded; non-finite results must reach the runtime"


def test_division_by_zero_still_behaves():
    assert run("print(1 / 0, -1 / 0, (0 / 0) ~= (0 / 0))\n") == "inf\t-inf\ttrue\n"


@pytest.mark.parametrize("expr", [
    '"10" + 1',      # Luau coerces: 11
    '-"5"',          # -5
    '"a" .. "b"',    # "ab"
    "1 .. 2",        # "12" -- CONCAT stringifies numbers
    "#'abc'",        # 3
])
def test_string_and_concat_are_not_folded(expr):
    """Luau coerces strings in arithmetic and stringifies numbers in ``..``.
    Replicating those rules is exactly where a divergence would hide."""
    proto = main(f"return {expr}\n")
    optimize.optimize_proto(proto)
    assert OP.CONCAT in ops(proto) or OP.ADD in ops(proto) or OP.UNM in ops(proto) \
        or OP.LEN in ops(proto), f"{expr} was folded away"


def test_string_coercion_still_works():
    assert run('print("10" + 1, -"5", 1 .. 2, #"abc")\n') == "11\t-5\t12\t3\n"


def test_boolean_is_not_treated_as_a_number():
    """Python has ``True == 1``; Luau's ``true + 1`` is an error."""
    proto = main("local a = true\nreturn a\n")
    optimize.optimize_proto(proto)
    assert OP.LOADK in ops(proto)


def test_negative_zero_is_not_produced_by_folding():
    """``-0.0`` and ``0.0`` are ``==`` but ``1 / -0.0`` is ``-inf``, so a fold
    that produced the wrong sign would be observable."""
    proto = main("return -(0)\n")
    optimize.optimize_proto(proto)
    assert OP.UNM in ops(proto), "a zero result must not be folded to a literal"


def test_folding_is_idempotent():
    src = "local a = 2\nlocal b = 3\nreturn a * b + 10\n"
    once, twice = main(src), main(src)
    s1 = optimize.optimize_proto(once, passes=2)
    s2 = optimize.optimize_proto(twice, passes=2)
    s3 = optimize.optimize_proto(twice, passes=2)
    assert s3.folded == s2.folded, "a second run must find nothing new"


# ---------------------------------------------------------------------------
# dead store elimination


def test_dead_store_is_removed():
    proto = main("local a = 1\nlocal unused = 999\nreturn a\n")
    stats = optimize.optimize_proto(proto)
    assert stats.dead_removed >= 1
    values = [proto.consts[i.args[1].index] for i in instrs(proto) if i.op == OP.LOADK]
    assert 999 not in values


def test_live_store_is_kept():
    proto = main("local a = 1\nreturn a + 1\n")
    optimize.optimize_proto(proto)
    values = [proto.consts[i.args[1].index] for i in instrs(proto) if i.op == OP.LOADK]
    assert 1 in values


def test_calls_are_never_removed_even_when_unused():
    """A call may do anything.  Only provably pure instructions are candidates."""
    proto = main("sideEffect()\nreturn 1\n")
    optimize.optimize_proto(proto)
    assert OP.CALL in ops(proto)


def test_captured_register_is_never_eliminated():
    """Regression: a store to a register a closure captured was deleted because
    liveness stops at the end of the CFG, while the closure lives past it."""
    src = (
        "local v = 1\n"
        "local function a()\n"
        "  local function b()\n"
        "    local function c() return v end\n"
        "    return c\n"
        "  end\n"
        "  return b\n"
        "end\n"
        "print(a()()())\n"
        "v = 2\n"
        "print(a()()())\n"
    )
    assert run(src) == "1\n2\n"


# ---------------------------------------------------------------------------
# liveness for closures


def test_def_use_reports_captured_registers():
    """The root cause of the bug above: CLOSURE's operands are (dest, child
    prototype), so a generic operand walk finds no registers at all."""
    proto = main("local x = 1\nlocal y = 2\nlocal f = function() return x + y end\nreturn f\n")
    closure = next(i for i in instrs(proto) if i.op == OP.CLOSURE)
    defs, uses = def_use(closure)
    assert uses == {0, 1}, "both captured registers must be reported as reads"


def test_def_use_for_a_capturing_nothing_closure():
    proto = main("local f = function() return 1 end\nreturn f\n")
    closure = next(i for i in instrs(proto) if i.op == OP.CLOSURE)
    _, uses = def_use(closure)
    assert uses == set()


# ---------------------------------------------------------------------------
# unreachable blocks


def test_unreachable_blocks_are_removed_and_ids_stay_positional():
    """Block ids *are* list positions -- ``compute_liveness`` indexes
    ``proto.blocks[succ]`` -- so removal has to renumber."""
    proto = main("for i = 1, 3 do\n  if i == 2 then\n    print(i)\n  end\nend\n")
    stats = optimize.optimize_proto(proto)
    assert stats.unreachable_removed >= 1
    assert [b.id for b in proto.blocks] == list(range(len(proto.blocks)))
    compute_liveness(proto)   # would raise IndexError if ids drifted
    for b in proto.blocks:
        for s in b.succ:
            assert 0 <= s < len(proto.blocks)
        for p in b.pred:
            assert 0 <= p < len(proto.blocks)


def test_jump_targets_are_rewritten_when_blocks_are_removed():
    proto = main("for i = 1, 3 do\n  if i == 2 then\n    print(i)\n  else\n    print(0)\n  end\nend\n")
    optimize.optimize_proto(proto)
    valid = {b.id for b in proto.blocks}
    assert valid == set(range(len(proto.blocks)))
    for b in proto.blocks:
        term = b.terminator
        if term is not None and term.op in optimize._JUMP_TARGET:
            slot = optimize._JUMP_TARGET[term.op]
            assert term.args[slot] in valid, f"{term.op} targets a removed block"


def test_loops_still_work_after_block_removal():
    assert run(
        "local n = 0\n"
        "for i = 1, 10 do\n"
        "  if i % 3 == 0 then n = n + i end\n"
        "end\n"
        "local w = 0\n"
        "while n > 0 do n = n - 1; w = w + 1 end\n"
        "print(w)\n"
    ) == "18\n"


# ---------------------------------------------------------------------------
# module level


def test_optimize_module_returns_stats():
    module = ir.Lowerer().lower(parser.parse(
        "local a = 1\nlocal b = 2\nlocal dead = 3\nreturn a + b\n", "t.luau"))
    stats = optimize.optimize_module(module)
    assert isinstance(stats, Stats)
    assert stats.dead_removed >= 1
    assert stats.total_removed >= 1


def test_stats_account_for_every_prototype_touched():
    module = ir.Lowerer().lower(parser.parse(
        "local function f(x)\n  local dead = 1\n  return x * 2 + 4\nend\nreturn f(3)\n",
        "t.luau"))
    stats = optimize.optimize_module(module)
    for proto_id in stats.per_proto:
        assert any(p.proto_id == proto_id for p in module.walk())


def test_passes_are_bounded():
    """Folding exposes dead stores which expose more folding; it must stop."""
    module = ir.Lowerer().lower(parser.parse(
        "local a = 1 + 1\nlocal b = a + 1\nlocal c = b + 1\nreturn c\n", "t.luau"))
    optimize.optimize_module(module, passes=1)
    optimize.optimize_module(module, passes=50)   # must terminate, not loop


# ---------------------------------------------------------------------------
# differential: the real test


def _micro():
    return sorted(glob.glob(os.path.join(MICRO_DIR, "*.luau")))


@pytest.mark.parametrize("path", _micro(), ids=lambda p: os.path.basename(p))
def test_optimizing_preserves_behaviour(path):
    """Every fixture, run optimized and unoptimized, against the original."""
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    with open(path, encoding="utf-8") as fh:
        assert_same(fh.read())


@pytest.mark.parametrize("path", _micro(), ids=lambda p: os.path.basename(p))
def test_optimized_protected_output_preserves_behaviour(path):
    """The combination that ships: optimize, then protect."""
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    name = os.path.basename(path)
    original = execute(TOOLCHAIN, src, "original.luau", timeout=20)
    module = ir.Lowerer().lower(parser.parse(src, name))
    optimize.optimize_module(module)
    seed = new_seed()
    protected = lower_back.reconstruct_protected(
        module, KeyMaterial.from_seed(seed),
        make_domains(seed).get("constants"), name.encode("utf-8"),
        cache_policy="bounded")
    result = execute(TOOLCHAIN, protected, "protected.luau", timeout=30)
    assert (original.returncode, original.stdout) == (
        result.returncode, result.stdout
    ), "%s: %r -> %r  %s" % (name, original.stdout[:200], result.stdout[:200],
                             result.stderr.splitlines()[:1])

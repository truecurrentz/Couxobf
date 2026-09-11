"""R5 (third increment): virtualizing a function that creates closures.

The first two increments let varargs and upvalue *access* into the VM.  This
one crosses the last line of the old refusal: a prototype whose body builds
closures of its own.  The mechanism is deliberately narrow -- only children
that capture nothing qualify -- and the tests below are mostly about where
that line falls.

Why the line is there.  A closure the interpreter builds is an ordinary Luau
function.  Anything it captures has to be reachable from ordinary Luau, and a
VM frame is a table: a register the parent owns is not.  A child with no
upvalues needs nothing from the frame it was born in, so the interpreter can
build its entry point out of its own locals -- the descriptor row, the
environment, `false` for the accessor list.  A child that captures one
variable cannot be built that way at all, which is why the refusal stands.

The second constraint shapes the selection rather than the encoding: the
interpreter has no function value for a child left native -- it can name a
descriptor row or nothing -- so a virtualized prototype takes its whole
virtualizable subtree in with it.  A helper is usually below the classifier's
size floor *on its own*, and refusing the parent instead would have made the
flag near-useless, so small children are pulled in rather than costing their
parent the VM.  What cannot be pulled in is a child that captures something a
virtualized ancestor owns; that child unselects its parent, and the removal
runs to a fixpoint from the leaves up.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from couxobf import ir, parser
from couxobf.config import Config
from couxobf.pipeline import build
from couxobf.toolchain import execute, find_toolchain
from couxobf.vm import encode

TOOLCHAIN = find_toolchain()

DIRECT = "--!couxobf:virtualize\n"


def _equivalent(src, seed, expect_virtualized=2, **cfg):
    """Build with ``vm_closures`` on and require the source's own behaviour."""
    config = Config(reproducible_seed=seed, vm_closures=True, vm_upvalues=True,
                    **cfg)
    out = build(src, config, name="cl.luau", verify=True)
    if expect_virtualized:
        assert out.stats.virtualized >= expect_virtualized, (
            "expected the parent and its closure in the VM: %s"
            % [(d.name, d.reason) for d in out.stats.decisions])
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    want = execute(TOOLCHAIN, src, "want.luau", timeout=30)
    got = execute(TOOLCHAIN, out.source, "got.luau", timeout=120)
    assert got.returncode == 0, got.stderr[:400]
    assert got.stdout == want.stdout, (
        "protected build printed something else\n  want %r\n  got  %r"
        % (want.stdout[:200], got.stdout[:200]))
    return out


# ---------------------------------------------------------------------------
# the gate
# ---------------------------------------------------------------------------

def test_off_by_default_and_still_refused():
    """Without the flag, creating a closure is still a refusal -- the default
    build changes shape for no one."""
    src = ("local function outer(n)\n"
           "  local function twice(x) return x * 2 end\n"
           "  return twice(n)\n"
           "end\n"
           "print(outer(3))\n")
    module = ir.Lowerer().lower(parser.parse(src, "cl.luau"))
    protos = {p.proto_id: p for p in module.walk()}
    ok, reason = encode.can_virtualize(protos[1])
    assert not ok and "closure" in reason
    assert Config().vm_closures is False


def test_the_flag_opens_the_gate_for_captures_free_children_only():
    """A child that captures nothing is fine; one that captures is not, and
    the refusal names the reason rather than hiding it behind 'closures'."""
    free = ("local function outer(n)\n"
            "  local function twice(x) return x * 2 end\n"
            "  return twice(n)\n"
            "end\n"
            "print(outer(3))\n")
    capturing = ("local function outer(n)\n"
                 "  local bias = n\n"
                 "  local function twice(x) return x * 2 + bias end\n"
                 "  return twice(n)\n"
                 "end\n"
                 "print(outer(3))\n")
    for src, wanted in ((free, True), (capturing, False)):
        module = ir.Lowerer().lower(parser.parse(src, "cl.luau"))
        protos = {p.proto_id: p for p in module.walk()}
        ok, reason = encode.can_virtualize(protos[1], closures_ok=True)
        assert ok is wanted, (src, reason)
        if not wanted:
            assert "captures" in reason


def test_the_config_field_is_wired_not_pending():
    """A field the build does not read is worse than a missing one."""
    assert "vm_closures" in Config.IMPLEMENTED


# ---------------------------------------------------------------------------
# semantics, checked against the source itself
# ---------------------------------------------------------------------------

def test_a_nested_helper_runs_in_the_vm_with_its_parent():
    out = _equivalent(
        DIRECT +
        "local function outer(n)\n"
        "  local function scale(x, k)\n"
        "    local acc = 0\n"
        "    for j = 1, k do\n"
        "      acc = acc + x * j\n"
        "    end\n"
        "    if acc > 100 then\n"
        "      acc = acc - 7\n"
        "    end\n"
        "    return acc\n"
        "  end\n"
        "  local total = 0\n"
        "  for i = 1, n do\n"
        "    total = total + scale(i, 3)\n"
        "  end\n"
        "  return total\n"
        "end\n"
        "print(outer(6))\n",
        seed=11, expect_virtualized=2)
    assert out.stats.virtualized == 2


def test_a_closure_handed_to_table_sort():
    """The callback is built by the interpreter and called by native code --
    the value has to be a real Luau function, not a VM-internal handle."""
    _equivalent(
        "local t = {5, 3, 9, 1, 7}\n" +
        DIRECT +
        "local function sortem(list)\n"
        "  local function cmp(a, b)\n"
        "    local da = a % 4\n"
        "    local db = b % 4\n"
        "    if da == db then\n"
        "      return a < b\n"
        "    end\n"
        "    return da < db\n"
        "  end\n"
        "  table.sort(list, cmp)\n"
        "  return table.concat(list, ',')\n"
        "end\n"
        "print(sortem(t))\n",
        seed=21)


def test_three_levels_of_nesting():
    _equivalent(
        DIRECT +
        "local function outer(n)\n"
        "  local function mid(x)\n"
        "    local function inner(y)\n"
        "      local s = 0\n"
        "      for i = 1, y do\n"
        "        s = s + i * 2\n"
        "      end\n"
        "      return s\n"
        "    end\n"
        "    return inner(x) + inner(x + 1)\n"
        "  end\n"
        "  local t = 0\n"
        "  for i = 1, n do\n"
        "    t = t + mid(i)\n"
        "  end\n"
        "  return t\n"
        "end\n"
        "print(outer(4))\n",
        seed=31, expect_virtualized=3)


def test_a_loop_declared_closure_is_one_function_value():
    """Luau hoists a closure that captures nothing, so `f == f` holds across
    iterations of the loop that declares it -- and across calls of the function
    that contains it.  A CLOSURE arm that built a stub per execution would
    answer differently from the unprotected program, which is a silent
    divergence rather than a crash: nothing raises, `f == f` is simply false.

    The closure deliberately captures nothing: capturing the loop variable is
    the case this increment still refuses, and a test that needed it would
    only be re-testing that refusal.  (For the record, Luau gives *that* case
    a fresh closure per iteration -- which is exactly why it cannot be
    virtualized this way.)
    """
    _equivalent(
        DIRECT +
        "local function outer(n)\n"
        "  local same = 0\n"
        "  local first = nil\n"
        "  for i = 1, n do\n"
        "    local function at(x)\n"
        "      local s = 0\n"
        "      for j = 1, x do s = s + j end\n"
        "      return s + x\n"
        "    end\n"
        "    if first == nil then\n"
        "      first = at\n"
        "    elseif first == at then\n"
        "      same = same + 1\n"
        "    end\n"
        "  end\n"
        "  return same\n"
        "end\n"
        "print(outer(4))\n",
        seed=41, expect_virtualized=2)


def test_a_closure_that_calls_itself():
    """Recursion through a VM-built closure: the child's own body contains the
    call, and the register holding it is the one the CLOSURE arm wrote."""
    _equivalent(
        DIRECT +
        "local function outer(n)\n"
        "  local function fact(x)\n"
        "    if x <= 1 then\n"
        "      return 1\n"
        "    end\n"
        "    return x * fact(x - 1)\n"
        "  end\n"
        "  return fact(n)\n"
        "end\n"
        "print(outer(6))\n",
        seed=51, expect_virtualized=1)


def test_the_child_survives_its_parent_returning():
    """A closure returned out of a virtualized function is called after the
    frame that built it is gone."""
    _equivalent(
        DIRECT +
        "local function outer(n)\n"
        "  local function mul(x, y)\n"
        "    local s = 0\n"
        "    for i = 1, y do\n"
        "      s = s + x\n"
        "    end\n"
        "    return s\n"
        "  end\n"
        "  return mul\n"
        "end\n"
        "local f = outer(3)\n"
        "print(f(4, 5), f(1, 2))\n",
        seed=61, expect_virtualized=1)


def test_multiple_children_from_one_parent():
    _equivalent(
        DIRECT +
        "local function outer(n)\n"
        "  local function up(x)\n"
        "    local s = 0\n"
        "    for i = 1, x do s = s + i end\n"
        "    return s\n"
        "  end\n"
        "  local function down(x)\n"
        "    local s = 0\n"
        "    for i = 1, x do s = s - i end\n"
        "    return s\n"
        "  end\n"
        "  local t = 0\n"
        "  for i = 1, n do\n"
        "    t = t + up(i) + down(i)\n"
        "  end\n"
        "  return t\n"
        "end\n"
        "print(outer(5))\n",
        seed=71, expect_virtualized=3)


def test_a_native_parent_sees_one_stub_per_prototype():
    """The same question from the other side: the stub a native caller holds is
    one value too, because the prelude builds it once per prototype rather
    than at every closure site.  This is the case every build already had --
    the divergence predates this increment, and sharing the stub is what
    closes it.
    """
    _equivalent(
        "local function outer(n)\n"
        "  local first = nil\n"
        "  local same = 0\n"
        "  for i = 1, n do\n" +
        DIRECT +
        "    local function leaf(x)\n"
        "      local s = 0\n"
        "      for j = 1, x do s = s + j end\n"
        "      return s + x\n"
        "    end\n"
        "    if first == nil then\n"
        "      first = leaf\n"
        "    elseif first == leaf then\n"
        "      same = same + 1\n"
        "    end\n"
        "  end\n"
        "  return same\n"
        "end\n"
        "print(outer(4))\n",
        seed=5, expect_virtualized=1)


# ---------------------------------------------------------------------------
# where the line falls
# ---------------------------------------------------------------------------

def test_a_capturing_child_keeps_its_parent_native():
    """The refusal is per child, and it costs the parent -- with a reason the
    report can print."""
    src = ("local x = 3\n" + DIRECT +
           "local function outer(n)\n"
           "  local function withcap(k)\n"
           "    local s = 0\n"
           "    for i = 1, k do s = s + i + x end\n"
           "    return s\n"
           "  end\n"
           "  local t = 0\n"
           "  for i = 1, n do t = t + withcap(i) end\n"
           "  return t\n"
           "end\n"
           "print(outer(4))\n")
    out = build(src, Config(reproducible_seed=81, vm_closures=True,
                            vm_upvalues=True), name="cl.luau", verify=True)
    reasons = " ".join(out.stats.native_reasons)
    assert "captures" in reasons, out.stats.native_reasons
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    want = execute(TOOLCHAIN, src, "want.luau", timeout=30)
    got = execute(TOOLCHAIN, out.source, "got.luau", timeout=60)
    assert got.stdout == want.stdout


def test_a_child_the_classifier_passed_over_comes_in_with_its_parent():
    """A nested helper is nearly always below the classifier's size floor on
    its own, and a helper is exactly what this increment is for.  So the tree
    closes the other way: a virtualized parent takes its virtualizable
    children in with it, however small they are, and the report is silent
    about a child that would otherwise have cost the parent its VM."""
    src = ("--!couxobf:virtualize\n"
           "local function outer(n)\n"
           "  local function tiny(x) return x * 2 end\n"
           "  local t = 0\n"
           "  for i = 1, n do\n"
           "    t = t + tiny(i) + i * 3 + 1\n"
           "  end\n"
           "  return t\n"
           "end\n"
           "print(outer(5))\n")
    out = build(src, Config(reproducible_seed=91, vm_closures=True,
                            vm_upvalues=True), name="cl.luau", verify=True)
    # Both of them: the child is a real prototype in the VM, not a native
    # function the interpreter cannot name.
    assert out.stats.virtualized == 2, out.stats.native_reasons
    reasons = " ".join(out.stats.native_reasons)
    assert "stayed native" not in reasons, out.stats.native_reasons
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    want = execute(TOOLCHAIN, src, "want.luau", timeout=30)
    got = execute(TOOLCHAIN, out.source, "got.luau", timeout=60)
    assert got.stdout == want.stdout, (want.stdout[:200], got.stdout[:200])


def test_a_whole_subtree_comes_in_or_the_parent_stays_native():
    """The tree is all-or-nothing, and the fixpoint is what enforces it.

    Three levels deep with every level virtualizable: all three go in.  Put
    one capturing leaf at the bottom and the chain unravels upwards -- the
    grandchild is unencodable, so its parent cannot be built either, so the
    root cannot.  All or nothing, decided from the leaves up.
    """
    deep = ("--!couxobf:virtualize\n"
            "local function outer(n)\n"
            "  local function middle(x)\n"
            "    local function inner(y)\n"
            "      local s = 0\n"
            "      for j = 1, y do s = s + j end\n"
            "      return s\n"
            "    end\n"
            "    return inner(x) + 1\n"
            "  end\n"
            "  local t = 0\n"
            "  for i = 1, n do t = t + middle(i) end\n"
            "  return t\n"
            "end\n"
            "print(outer(6))\n")
    out = build(deep, Config(reproducible_seed=91, vm_closures=True,
                             vm_upvalues=True), name="cl.luau", verify=True)
    assert out.stats.virtualized == 3, out.stats.native_reasons
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    want = execute(TOOLCHAIN, deep, "want.luau", timeout=30)
    got = execute(TOOLCHAIN, out.source, "got.luau", timeout=60)
    assert got.stdout == want.stdout, (want.stdout[:200], got.stdout[:200])

    blocked = ("--!couxobf:virtualize\n"
               "local x = 3\n"
               "local function outer(n)\n"
               "  local function middle(k)\n"
               "    local function inner(y)\n"
               "      return y + x\n"
               "    end\n"
               "    return inner(k) + 1\n"
               "  end\n"
               "  local t = 0\n"
               "  for i = 1, n do t = t + middle(i) end\n"
               "  return t\n"
               "end\n"
               "print(outer(6))\n")
    out = build(blocked, Config(reproducible_seed=91, vm_closures=True,
                                vm_upvalues=True), name="cl.luau", verify=True)
    # Not one of the three: the innermost captures, so its parent cannot be
    # built, so its parent's parent cannot either.
    assert out.stats.virtualized == 0, out.stats.native_reasons
    reasons = " ".join(out.stats.native_reasons)
    assert "captures" in reasons, out.stats.native_reasons


def test_a_closure_lands_in_its_parents_group():
    """The parent's CLOSURE arm names *this* interpreter's entry point, so a
    child in another group would need an entry point it cannot see."""
    src = ("--!couxobf:virtualize\n"
           "local function outer(n)\n"
           "  local function scale(x, k)\n"
           "    local out = 0\n"
           "    for j = 1, k do out = out + x * j end\n"
           "    return out\n"
           "  end\n"
           "  local total = 0\n"
           "  for i = 1, n do total = total + scale(i, 3) end\n"
           "  return total\n"
           "end\n"
           "print(outer(6))\n")
    for variety in (2, 3):
        out = build(src, Config(reproducible_seed=101, vm_closures=True,
                                vm_upvalues=True, vm_variety=variety,
                                max_output_growth=0),
                    name="cl.luau", verify=True)
        live = [g for g in out.runtime_names["vm_plan"] if g.get("protos")]
        assert len(live) == 1, (
            "a closure tree is one indivisible unit: %s"
            % [g.get("protos") for g in out.runtime_names["vm_plan"]])
        assert live[0]["protos"] == 2
        if not TOOLCHAIN.can_execute:
            pytest.skip("luau runtime not available")
        want = execute(TOOLCHAIN, src, "want.luau", timeout=30)
        got = execute(TOOLCHAIN, out.source, "got.luau", timeout=60)
        assert got.stdout == want.stdout, (variety, got.stderr[:300])


# ---------------------------------------------------------------------------
# the whole configuration
# ---------------------------------------------------------------------------

def test_maximum_profile_across_seeds():
    """Every knob at once, including aliases, edge indirection and several
    groups: the shape the corpus does not cover on its own."""
    src = ("--!couxobf:virtualize\n"
           "local function outer(n)\n"
           "  local function scale(x, k)\n"
           "    local out = 0\n"
           "    for j = 1, k do out = out + x * j end\n"
           "    if out > 20 then out = out - 3 end\n"
           "    return out\n"
           "  end\n"
           "  local total = 0\n"
           "  for i = 1, n do total = total + scale(i, 3) end\n"
           "  return total\n"
           "end\n"
           "print(outer(6))\n")
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    want = execute(TOOLCHAIN, src, "want.luau", timeout=30)
    for seed in (1, 2, 3):
        out = build(src, Config.from_profile("maximum").overrides(
            reproducible_seed=seed, vm_closures=True, vm_upvalues=True),
            name="cl.luau", verify=True)
        got = execute(TOOLCHAIN, out.source, "got.luau", timeout=120)
        assert got.returncode == 0, (seed, got.stderr[:400])
        assert got.stdout == want.stdout, (seed, got.stdout[:200])

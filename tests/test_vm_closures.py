"""R5 (third and fourth increments): a function that creates closures.

The first two increments let varargs and upvalue *access* into the VM.  The
third crosses the old refusal outright: a prototype whose body builds closures
of its own.  The fourth crosses what the third still drew a line at -- a child
that *captures* something its virtualized parent owns.

Why the third increment's line was where it was.  A closure the interpreter
builds is an ordinary Luau function.  Anything it captures has to be reachable
from ordinary Luau, and a VM frame is a table: a register the parent owns is
not.  A child with no upvalues needs nothing from the frame it was born in, so
the interpreter can hand out a stub built once, in the prelude, out of its own
locals -- the descriptor row, the environment, `false` for the accessor list.

What the fourth increment adds is that the interpreter is the one place that
*can* see the frame.  Building the accessor there, over the parent's own slot,
is the whole trick: a getter and a setter closing over `R[slot]`, a cell
holding a snapshot when the variable is a loop variable and Luau gives each
iteration its own, and the parent's own accessor pair relayed unchanged for an
upvalue the parent carries.  What still cannot be served is nothing much: the
only refusal left is a build that has not asked for ``vm_upvalues``, since the
accessors are that increment's machinery.

The other constraint shapes the selection rather than the encoding: the
interpreter has no function value for a child left native -- it can name a
descriptor row or nothing -- so a virtualized prototype takes its whole
virtualizable subtree in with it.  A helper is usually below the classifier's
size floor *on its own*, and refusing the parent instead would have made the
flag near-useless, so small children are pulled in rather than costing their
parent the VM.  What cannot be pulled in is a child that cannot be encoded at
all, which unselects its parent, and its parent's parent.
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

CAPTURING = ("local x = 3\n" + DIRECT +
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


def test_a_capturing_child_runs_with_its_parent():
    """R5's fourth increment: the child captures a global of its parent's, and
    both of them run in the VM anyway -- the interpreter builds the accessor
    itself, over the frame slot it owns."""
    out = build(CAPTURING, Config(reproducible_seed=81, vm_closures=True,
                                  vm_upvalues=True), name="cl.luau",
                verify=True)
    assert out.stats.virtualized == 2, out.stats.native_reasons
    reasons = " ".join(out.stats.native_reasons)
    assert "captures" not in reasons, out.stats.native_reasons
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    want = execute(TOOLCHAIN, CAPTURING, "want.luau", timeout=30)
    got = execute(TOOLCHAIN, out.source, "got.luau", timeout=60)
    assert got.stdout == want.stdout, (want.stdout[:200], got.stdout[:200],
                                       got.stderr[:300])


def test_a_capturing_child_still_needs_vm_upvalues():
    """The refusal that is left, and the only one: without ``vm_upvalues`` a
    capturing child is out, because the accessors are that increment's
    machinery.  The report names the flag rather than just counting."""
    out = build(CAPTURING, Config(reproducible_seed=81, vm_closures=True,
                                  vm_upvalues=False), name="cl.luau",
                verify=True)
    assert out.stats.virtualized == 0, out.stats.native_reasons
    reasons = " ".join(out.stats.native_reasons)
    assert "vm_upvalues" in reasons, out.stats.native_reasons
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    want = execute(TOOLCHAIN, CAPTURING, "want.luau", timeout=30)
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
    # All three, not none of them: R5's fourth increment builds the innermost
    # capture over its parent's frame, so a capture is no longer what takes a
    # tree out of the VM.  What still takes one out is a child that cannot be
    # encoded at all, and with the capture servable there is nothing left here
    # to refuse.
    assert out.stats.virtualized == 3, out.stats.native_reasons
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    want = execute(TOOLCHAIN, blocked, "want.luau", timeout=30)
    got = execute(TOOLCHAIN, out.source, "got.luau", timeout=60)
    assert got.stdout == want.stdout, (want.stdout[:200], got.stdout[:200],
                                       got.stderr[:300])


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



# ---------------------------------------------------------------------------
# the capturing half (R5's fourth increment)
# ---------------------------------------------------------------------------
#
# Everything above draws the line at a child that captures.  This section is
# the other side of it: a child that captures a variable its virtualized
# parent owns, which lives in a frame table no Luau closure can see -- unless
# the closure is built by the interpreter that owns the frame, which is what
# makes it work.  The tests are about the three ways a capture has to be
# served, and about the semantics that are easy to get wrong in each.


def test_a_capturing_child_sees_the_parents_live_variable():
    """Reads through the accessor are live, not a copy: the child is created
    before the parent writes again, and it sees the later value."""
    src = (DIRECT +
           "local function outer(n)\n"
           "  local scale = 3\n"
           "  local function scale_it(x) return x * scale end\n"
           "  local t = 0\n"
           "  for i = 1, n do t = t + scale_it(i) end\n"
           "  return t\n"
           "end\n"
           "print(outer(4))\n"
           "print(outer(1))\n")
    # 3 * (1+2+3+4) = 30, and 3 again for n = 1 -- not the 4 of `n`, which is
    # what an off-by-one in the frame slot reads.
    _equivalent(src, seed=7, expect_virtualized=2)


def test_a_capturing_child_writes_through_to_the_parent():
    """The setter closes over the same slot, so a write the child makes is a
    write the parent sees.  A snapshot would lose every one of them."""
    src = (DIRECT +
           "local function outer(n)\n"
           "  local count = 0\n"
           "  local function bump() count += 1 end\n"
           "  for i = 1, n do bump() end\n"
           "  return count\n"
           "end\n"
           "print(outer(5))\n"
           "print(outer(0))\n")
    _equivalent(src, seed=7, expect_virtualized=2)


def test_two_children_share_the_variable_they_capture():
    """Both accessors close over one slot, so the two children are looking at
    one variable and not at two copies of it."""
    src = (DIRECT +
           "local function outer(n)\n"
           "  local total = 0\n"
           "  local function add(x) total += x end\n"
           "  local function get() return total end\n"
           "  for i = 1, n do add(i) end\n"
           "  return get()\n"
           "end\n"
           "print(outer(5))\n")
    _equivalent(src, seed=7, expect_virtualized=3)


def test_a_loop_variable_is_captured_per_iteration():
    """Luau gives every iteration its own loop variable, so a closure declared
    in the body captures *that* iteration's value.  The frame slot keeps
    moving, so the accessor has to close over a cell holding a snapshot."""
    src = (DIRECT +
           "local function outer(n)\n"
           "  local fns = {}\n"
           "  for i = 1, n do\n"
           "    fns[i] = function() return i * i end\n"
           "  end\n"
           "  local s = 0\n"
           "  for j = 1, n do s = s + fns[j]() end\n"
           "  return s\n"
           "end\n"
           "print(outer(3))\n"
           "print(outer(1))\n")
    # 1 + 4 + 9 == 14.  A shared slot answers 9 + 9 + 9, or 1 + 1 + 1.
    _equivalent(src, seed=7, expect_virtualized=2)


def test_a_capture_relayed_through_a_virtualized_parent():
    """The child names a variable its parent only has as an upvalue of its
    own.  The interpreter relays the parent's accessor pair rather than
    re-deriving one, so a chain ends where the native site built it."""
    src = ("local x = 7\n" + DIRECT +
           "local function mid(n)\n"
           "  local function inner(v) return v + x end\n"
           "  local s = 0\n"
           "  for i = 1, n do s = s + inner(i) end\n"
           "  return s\n"
           "end\n"
           "print(mid(3))\n")
    _equivalent(src, seed=7, expect_virtualized=2)


def test_three_levels_with_the_capture_at_the_bottom():
    """A capture two frames down: the deepest prototype names a variable of
    the outermost one, relayed through the middle."""
    src = (DIRECT +
           "local function outer(n)\n"
           "  local k = 2\n"
           "  local function mid(x)\n"
           "    local function deep(y) return y * k + x end\n"
           "    return deep(x) + 1\n"
           "  end\n"
           "  local t = 0\n"
           "  for i = 1, n do t = t + mid(i) end\n"
           "  return t\n"
           "end\n"
           "print(outer(4))\n")
    _equivalent(src, seed=7, expect_virtualized=3)


def test_a_capturing_closure_outlives_its_parents_frame():
    """The closure is handed back to native code and called after the frame
    that built it is gone.  The slot it closed over has to stay reachable,
    which it does because the closure holds the frame -- not a copy of it."""
    src = (DIRECT +
           "local function make(scale)\n"
           "  local function apply(x) return x * scale end\n"
           "  return apply\n"
           "end\n"
           "local f = make(5)\n"
           "print(f(3), f(4))\n")
    _equivalent(src, seed=7, expect_virtualized=2)


def test_a_capturing_child_is_a_fresh_value_every_time():
    """Luau builds a new closure each time a capturing closure expression is
    evaluated -- the opposite of the non-capturing case, which it hoists.
    Two closures from one site are therefore different values, and a build
    that shared one stub would answer `==` differently."""
    src = (DIRECT +
           "local function outer(n)\n"
           "  local first = nil\n"
           "  local same = 0\n"
           "  for i = 1, n do\n"
           "    local f = function() return n end\n"
           "    if first == nil then\n"
           "      first = f\n"
           "    elseif first == f then\n"
           "      same += 1\n"
           "    end\n"
           "  end\n"
           "  return same\n"
           "end\n"
           "print(outer(4))\n")
    _equivalent(src, seed=7, expect_virtualized=2)


def test_a_capturing_child_is_handed_to_native_code():
    """table.sort calls back into the VM-built closure from C.  The value the
    interpreter builds has to be an ordinary Luau function, not something
    only the interpreter can call."""
    src = (DIRECT +
           "local function rank(words)\n"
           "  local bias = 2\n"
           "  local function score(w) return #w + bias end\n"
           "  table.sort(words, function(a, b) return score(a) < score(b) end)\n"
           "  return table.concat(words, \",\")\n"
           "end\n"
           "print(rank({\"aaa\", \"a\", \"aaaaa\", \"aa\"}))\n"
           "print(rank({\"xx\", \"y\"}))\n")
    _equivalent(src, seed=7, expect_virtualized=3)


def test_the_capturing_half_under_the_maximum_profile():
    """Every knob at once, several groups, seeds 1..3: the capture table rides
    the same plan as everything else, and a group that is not group 0 has to
    build its own accessors from its own frame."""
    src = (DIRECT +
           "local function outer(n)\n"
           "  local scale = 3\n"
           "  local function helper(x)\n"
           "    local s = 0\n"
           "    for i = 1, x do s = s + i * scale end\n"
           "    return s\n"
           "  end\n"
           "  local t = 0\n"
           "  for i = 1, n do t = t + helper(i) end\n"
           "  return t\n"
           "end\n"
           "print(outer(4))\n")
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    want = execute(TOOLCHAIN, src, "want.luau", timeout=30)
    for seed in (1, 2, 3):
        config = Config.maximum()
        config.reproducible_seed = seed
        config.vm_closures = True
        config.vm_upvalues = True
        out = build(src, config, name="cl.luau", verify=True)
        assert out.stats.virtualized >= 2, out.stats.native_reasons
        got = execute(TOOLCHAIN, out.source, "got.luau", timeout=120)
        assert got.returncode == 0, got.stderr[:300]
        assert got.stdout == want.stdout, (seed, want.stdout[:200],
                                           got.stdout[:200])


# ---------------------------------------------------------------------------
# per-iteration identity
# ---------------------------------------------------------------------------
#
# Luau gives every iteration its own copy of a local declared inside a loop
# body, while the obfuscator gives that local one register for the whole
# loop.  These tests are the two halves of that gap: the cases where a
# closure must see the iteration it was built in, and the cases where it must
# see the *variable*, writes and all, because the two are not the same rule.
#
# They run at two profiles on purpose.  The bug this section was written for
# reproduced at `compact`, which virtualizes nothing, so a test that only
# built at `maximum` would have passed against the broken code.

_PER_ITERATION_PROFILES = ("compact", "maximum")


def _both_profiles(src, seed=7):
    """Build at a native profile and at the maximum one, and require both."""
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    want = execute(TOOLCHAIN, src, "want.luau", timeout=30)
    for profile in _PER_ITERATION_PROFILES:
        config = Config.from_profile(profile)
        config.reproducible_seed = seed
        config.vm_upvalues = True
        config.vm_closures = True
        out = build(src, config, name="pi.luau", verify=True)
        got = execute(TOOLCHAIN, out.source, "got.luau", timeout=120)
        assert got.returncode == 0, (profile, got.stderr[:300])
        assert got.stdout == want.stdout, (
            "%s printed something else\n  want %r\n  got  %r"
            % (profile, want.stdout[:200], got.stdout[:200]))
    return want.stdout


def test_a_loop_body_local_is_fresh_in_every_iteration():
    """The classic closure-in-a-loop shape: three iterations, three
    variables.  One shared register answers 3 3 3."""
    src = ("local fns = {}\n"
           "for i = 1, 3 do\n"
           "  local x = i\n"
           "  fns[i] = function() return x end\n"
           "end\n"
           "print(fns[1](), fns[2](), fns[3]())\n")
    assert _both_profiles(src) == "1\t2\t3\n"


def test_the_same_in_a_while_loop():
    """Not a property of `for`: any loop body re-entered per iteration."""
    src = ("local fns = {}\n"
           "local i = 1\n"
           "while i <= 3 do\n"
           "  local x = i * 10\n"
           "  fns[i] = function() return x end\n"
           "  i += 1\n"
           "end\n"
           "print(fns[1](), fns[2](), fns[3]())\n")
    assert _both_profiles(src) == "10\t20\t30\n"


def test_the_same_in_a_generic_for():
    """Both loop variables of a generic `for`, plus a local beside them."""
    src = ("local fns = {}\n"
           "for k, v in ipairs({5, 6, 7}) do\n"
           "  local both = k * 100 + v\n"
           "  fns[k] = function() return both end\n"
           "end\n"
           "print(fns[1](), fns[2](), fns[3]())\n")
    assert _both_profiles(src) == "105\t206\t307\n"


def test_a_loop_control_variable_is_fresh_per_iteration():
    """The control variable itself, which Luau also makes per-iteration."""
    src = ("local g = {}\n"
           "for i = 1, 3 do g[i] = function() return i end end\n"
           "print(g[1](), g[2](), g[3]())\n")
    assert _both_profiles(src) == "1\t2\t3\n"


def test_nested_loops_capture_both_levels():
    """The inner body's local is per inner iteration, and the outer one it
    was built from is per outer iteration."""
    src = ("local fns = {}\n"
           "for i = 1, 2 do\n"
           "  for j = 1, 2 do\n"
           "    local pair = i * 10 + j\n"
           "    fns[i * 2 + j] = function() return pair end\n"
           "  end\n"
           "end\n"
           "print(fns[3](), fns[4](), fns[5](), fns[6]())\n")
    assert _both_profiles(src) == "11\t12\t21\t22\n"


def test_a_variable_written_after_the_closure_is_built_is_shared():
    """The other half of the rule: a local the loop body assigns again is one
    variable, not one per iteration, so the write has to reach the closure.
    A snapshot taken at closure creation would answer 0 0 0."""
    src = ("local t = {}\n"
           "for i = 1, 3 do\n"
           "  local c = 0\n"
           "  local f = function() return c end\n"
           "  c = i\n"
           "  t[i] = f()\n"
           "end\n"
           "print(t[1], t[2], t[3])\n")
    assert _both_profiles(src) == "1\t2\t3\n"


def test_two_closures_built_in_one_iteration_share_the_variable():
    """Both closures belong to the same iteration, so a write through one is
    visible through the other.  Snapshotting each closure separately gives
    them two private copies and answers 0 0 0."""
    src = ("local fns = {}\n"
           "local out = {}\n"
           "for i = 1, 3 do\n"
           "  local acc = 0\n"
           "  local function add(v) acc += v end\n"
           "  fns[i] = function() return acc end\n"
           "  add(i)\n"
           "  add(i * 2)\n"
           "  out[i] = fns[i]()\n"
           "end\n"
           "print(out[1], out[2], out[3])\n")
    assert _both_profiles(src) == "3\t6\t9\n"


def test_a_loop_body_capture_inside_a_virtualized_parent():
    """The same property on the VM path, where the accessor is built by the
    interpreter over the parent's frame: the cell has to be the iteration's,
    not the last one's."""
    src = (DIRECT +
           "local function outer(n)\n"
           "  local fns = {}\n"
           "  for i = 1, n do\n"
           "    local x = i * 3\n"
           "    fns[i] = function() return x end\n"
           "  end\n"
           "  local s = 0\n"
           "  for j = 1, n do s = s + fns[j]() end\n"
           "  return s\n"
           "end\n"
           "print(outer(3))\n"
           "print(outer(1))\n")
    # 3 + 6 + 9 == 18, and 3 alone for n = 1 -- not 9 + 9 + 9.
    _equivalent(src, seed=7, expect_virtualized=2)


def test_a_closure_that_writes_the_loop_body_local_shares_it():
    """The case a snapshot cannot serve.  Each iteration has its own counter,
    and both calls on the first one move *that* counter: 3 4, then the second
    iteration's 5, then the third's 7.  A snapshot would give every call its
    own copy and answer 3 3 3 3, and one shared register would answer
    7 8 9 10."""
    src = ("local makers = {}\n"
           "for i = 1, 3 do\n"
           "  local n = i * 2\n"
           "  makers[i] = function() n += 1 return n end\n"
           "end\n"
           "print(makers[1](), makers[1](), makers[2](), makers[3]())\n")
    assert _both_profiles(src) == "3\t4\t5\t7\n"


def test_a_write_after_the_closure_is_built_reaches_it():
    """Still one variable per iteration, but a shared one inside it -- so the
    body's own write has to land where the closure will look.  A snapshot
    taken when the closure is built would answer 0 0 0, and one register
    shared by every iteration would answer 3 3 3."""
    src = ("local fns = {}\n"
           "for i = 1, 3 do\n"
           "  local c = 0\n"
           "  fns[i] = function() return c end\n"
           "  c = i\n"
           "end\n"
           "print(fns[1](), fns[2](), fns[3]())\n")
    assert _both_profiles(src) == "1\t2\t3\n"


def test_a_local_the_body_initialises_from_a_call_is_a_cell_too():
    """`local n = f()` is the same variable as any other.  It is also the
    shape a cell is hardest to give: a call writes its own base, and that base
    is where its arguments are counted from, so the store has to be a separate
    instruction rather than the call's destination."""
    src = ("local function mk(v) return v * 2 end\n"
           "local makers = {}\n"
           "for i = 1, 3 do\n"
           "  local n = mk(i)\n"
           "  makers[i] = function() n += 1 return n end\n"
           "end\n"
           "print(makers[1](), makers[1](), makers[2](), makers[3]())\n")
    assert _both_profiles(src) == "3\t4\t5\t7\n"


def test_the_parents_own_writes_go_through_the_same_cell():
    """The loop body writes the variable after the closure is built, and the
    closure is the one that has to see it -- so the write cannot go to the
    register the closure is not reading."""
    src = ("local fns = {}\n"
           "for i = 1, 3 do\n"
           "  local n = i\n"
           "  fns[i] = function() return n end\n"
           "  n = n * 10\n"
           "  fns[i] = function() return n end\n"
           "end\n"
           "print(fns[1](), fns[2](), fns[3]())\n")
    assert _both_profiles(src) == "10\t20\t30\n"


def test_the_parent_reads_what_a_closure_wrote():
    """The other direction: the body calls a closure that increments, then
    reads the variable itself.  Both have to be looking at the same place."""
    src = ("local out = {}\n"
           "for i = 1, 3 do\n"
           "  local n = i\n"
           "  local bump = function() n += 5 end\n"
           "  bump()\n"
           "  out[i] = n\n"
           "end\n"
           "print(out[1], out[2], out[3])\n")
    assert _both_profiles(src) == "6\t7\t8\n"


def test_two_closures_of_one_iteration_share_that_iterations_cell():
    """A reader and a writer built in the same iteration, driven after the
    loop has finished: each pair moves its own counter and no other."""
    src = ("local incs, gets = {}, {}\n"
           "for i = 1, 3 do\n"
           "  local n = i * 10\n"
           "  incs[i] = function() n += 1 end\n"
           "  gets[i] = function() return n end\n"
           "end\n"
           "for i = 1, 3 do\n"
           "  incs[i]()\n"
           "  incs[i]()\n"
           "end\n"
           "print(gets[1](), gets[2](), gets[3]())\n")
    assert _both_profiles(src) == "12\t22\t32\n"


def test_a_three_deep_capture_writes_the_outer_iterations_cell():
    """The write happens two closures down, through a relay.  The cell
    belongs to the iteration that declared it, not to whichever one the
    register happens to hold when the innermost closure runs."""
    src = ("local out = {}\n"
           "for i = 1, 3 do\n"
           "  local n = i\n"
           "  out[i] = (function() return function() n += 1 return n end end)()\n"
           "end\n"
           "print(out[1](), out[1](), out[2](), out[3]())\n")
    assert _both_profiles(src) == "2\t3\t3\t4\n"


def test_a_mutating_capture_inside_a_virtualized_parent():
    """The same property on the VM path, where the accessor is built by the
    interpreter over the parent's frame: the cell it hands the child is that
    iteration's table, so two closures of one iteration agree and two
    iterations do not."""
    src = (DIRECT +
           "local function outer(n)\n"
           "  local fns = {}\n"
           "  for i = 1, n do\n"
           "    local x = i * 3\n"
           "    fns[i] = function() x += 1 return x end\n"
           "  end\n"
           "  local s = 0\n"
           "  for j = 1, n do s = s + fns[j]() end\n"
           "  return s\n"
           "end\n"
           "print(outer(3))\n"
           "print(outer(1))\n")
    # 4 + 7 + 10 == 21 for three iterations, and 4 alone for one -- not
    # 10 + 10 + 10, which is what one shared counter would give.
    _equivalent(src, seed=7, expect_virtualized=2)

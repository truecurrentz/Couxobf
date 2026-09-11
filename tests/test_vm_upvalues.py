"""R5 (second increment): virtualizing functions that capture upvalues.

The first increment let vararg functions into the VM because call arguments
are private to the call.  Upvalues are the other half of the boundary: a
captured variable is shared, mutable state that real Luau closures outside
the call can see, so a VM frame -- an ordinary table -- cannot simply hold
it.

The mechanism these tests pin down: the stub replacing a virtualized
upvalue-capturing function builds, for each upvalue, a *getter* and a
*setter* closure over the very expression the native reconstruction uses to
reach that variable (the enclosing prototype's register slot, or the
per-iteration snapshot local Luau's semantics demand).  The interpreter's
GETUPVAL calls the getter; SETUPVAL calls the setter.  Because the accessors
target the same storage the native code uses, reads and writes stay live and
agree with any native sibling sharing the variable -- including writes that
happen *between* two of the child's reads.

The safety line does not move for the hard case: an upvalue whose home is
another virtualized prototype's frame is still refused, and the tests say
so.  The whole feature is gated behind ``vm_upvalues`` (default off).
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


def _equivalent(src, seed, expect_virtualized=True, **cfg):
    config = Config(reproducible_seed=seed, vm_upvalues=True, **cfg)
    out = build(src, config, name="uv.luau", verify=True)
    if expect_virtualized:
        assert out.stats.virtualized >= 1, (
            "expected the directive to land a function in the VM: %s"
            % [(d.name, d.reason) for d in out.stats.decisions])
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    want = execute(TOOLCHAIN, src, "want.luau", timeout=30)
    got = execute(TOOLCHAIN, out.source, "got.luau", timeout=120)
    assert got.returncode == 0, got.stderr[:400]
    assert got.stdout == want.stdout
    return out


# ---------------------------------------------------------------------------
# the gate
# ---------------------------------------------------------------------------

def test_off_by_default_and_still_refused():
    """Without the flag, upvalue capture is still a refusal -- the default
    build changes shape for no one."""
    src = ("local x = 1\n"
           "local function f(...) return x end\n"
           "print(f())\n")
    module = ir.Lowerer().lower(parser.parse(src, "uv.luau"))
    protos = {p.name: p for p in module.walk()}
    ok, reason = encode.can_virtualize(protos["f"])
    assert not ok and "upvalue" in reason
    assert Config().vm_upvalues is False


def test_the_flag_opens_the_gate():
    src = ("local x = 1\n"
           "local function f(...) return x end\n"
           "print(f())\n")
    module = ir.Lowerer().lower(parser.parse(src, "uv.luau"))
    protos = {p.name: p for p in module.walk()}
    ok, reason = encode.can_virtualize(protos["f"], upvalues_ok=True)
    assert ok, reason


# ---------------------------------------------------------------------------
# semantics, checked against the source itself
# ---------------------------------------------------------------------------

def test_read_only_capture_from_a_native_scope():
    _equivalent(
        "local setting = 41\n"
        "local label = 'answer'\n" +
        DIRECT +
        "local function f()\n"
        "  return setting + 1, label\n"
        "end\n"
        "print(f())\n",
        seed=71)


def test_the_child_writes_and_the_native_parent_sees_it():
    """SETUPVAL across the boundary: the VM child bumps the counter, the
    native parent reads the bump afterwards.  A snapshot-passing scheme would
    fail this; live accessors pass it."""
    _equivalent(
        "local count = 0\n" +
        DIRECT +
        "local function bump()\n"
        "  count = count + 1\n"
        "  return count\n"
        "end\n"
        "print(bump(), bump(), count)\n",
        seed=72)


def test_the_native_side_writes_between_the_childs_reads():
    """Liveness in the other direction: the child reads, a native write
    happens, the child reads again and must see the new value."""
    _equivalent(
        "local x = 1\n" +
        "local function set(v) x = v end\n" +
        DIRECT +
        "local function probe()\n"
        "  local a = x\n"
        "  set(9)\n"
        "  return a + x\n"
        "end\n"
        "print(probe())\n",
        seed=73)


def test_shared_counter_between_a_vm_child_and_a_native_sibling():
    """Two closures over one variable, one on each side of the boundary.
    Both must observe one counter, not two."""
    _equivalent(
        "local n = 0\n"
        "local function native_add(v) n = n + v return n end\n" +
        DIRECT +
        "local function vm_add(v)\n"
        "  n = n + v\n"
        "  return n\n"
        "end\n"
        "print(native_add(2), vm_add(3), native_add(5), n)\n",
        seed=74)


def test_capture_of_a_loop_variable_is_per_iteration():
    """The Luau semantics the snapshot machinery exists for: each iteration's
    closure captures *that iteration's* value.  Getting this wrong turns
    [10, 20, 30] into [30, 30, 30].  The snapshot local the CLOSURE site
    declares is what the stub's accessor closes over, so a VM child and a
    native child get the same per-iteration capture.  (Captured *loop-body
    locals* sit in shared registers today -- a cell-model limitation the
    native path has always had; SECURITY.md owns it.)"""
    _equivalent(
        "local fns = {}\n"
        "for i = 1, 3 do\n" +
        DIRECT +
        "  local function get() return i * 10 end\n"
        "  fns[i] = get\n"
        "end\n"
        "print(fns[1](), fns[2](), fns[3]())\n",
        seed=75)


def test_two_upvalues_and_a_local_in_one_body():
    _equivalent(
        "local a = 3\n"
        "local b = 'x'\n" +
        DIRECT +
        "local function f(k)\n"
        "  local t = k * a\n"
        "  a = a + 1\n"
        "  return t, b, a\n"
        "end\n"
        "print(f(2))\n"
        "print(f(2))\n",
        seed=76)


def test_upvalue_capture_composes_with_varargs():
    _equivalent(
        "local base = 100\n" +
        DIRECT +
        "local function f(...)\n"
        "  local t = table.pack(...)\n"
        "  local s = base\n"
        "  for i = 1, t.n do s = s + (tonumber(t[i]) or 0) end\n"
        "  return s\n"
        "end\n"
        "print(f(1, 2, 3), f(), f('x', 5))\n",
        seed=77)


def test_pcall_into_a_vm_closure_with_upvalues():
    """Error paths must cross the boundary intact: the pcall sees the VM
    child as an ordinary function, success and failure alike."""
    _equivalent(
        "local limit = 5\n" +
        DIRECT +
        "local function guarded(v)\n"
        "  if v > limit then error('too big') end\n"
        "  return v * 2\n"
        "end\n"
        "local ok1, r1 = pcall(guarded, 3)\n"
        "local ok2, r2 = pcall(guarded, 9)\n"
        "print(ok1, r1, ok2, string.find(tostring(r2), 'too big') ~= nil)\n",
        seed=78)


def test_deep_nesting_relays_through_native_scopes():
    """The upvalue is the grandparent's local, relayed through the parent.
    The accessor targets the relayed expression, so depth is free."""
    _equivalent(
        "local top = 7\n"
        "local function outer()\n"
        "  local function inner()\n" +
        DIRECT +
        "    local function leaf() return top + 1 end\n"
        "    return leaf()\n"
        "  end\n"
        "  return inner()\n"
        "end\n"
        "print(outer())\n",
        seed=79)


# ---------------------------------------------------------------------------
# the safety line that must not move
# ---------------------------------------------------------------------------

def test_two_vm_siblings_share_one_upvalue():
    """Both siblings forced into the VM, sharing one variable through two
    independent accessor pairs aimed at the same register slot: the writer's
    bumps must be visible to the reader and to the native parent alike."""
    src = (
        "local function outer()\n"
        "  local x = 1\n"
        "  --!couxobf:virtualize\n"
        "  local function writes() x = x + 1 return x end\n"
        "  --!couxobf:virtualize\n"
        "  local function reads() return x end\n"
        "  writes()\n"
        "  return reads(), x\n"
        "end\n"
        "print(outer())\n"
    )
    out = _equivalent(src, seed=80)
    vm = {d.name for d in out.stats.decisions if d.level > 0}
    assert "writes" in vm and "reads" in vm, (
        [(d.name, d.level, d.reason) for d in out.stats.decisions])


def test_a_function_captured_as_a_value_runs_in_the_vm():
    """Capturing a closure *as a value* is just a GETUPVAL of it; calling it
    goes through the ordinary CALL path.  Nothing here needs the host."""
    src = (
        "local helper = function(v) return v * 2 end\n" +
        DIRECT +
        "local function uses(v)\n"
        "  return helper(v) + 1\n"
        "end\n"
        "print(uses(20))\n"
    )
    _equivalent(src, seed=81)


# ---------------------------------------------------------------------------
# the safety line that must not move
# ---------------------------------------------------------------------------

def test_fixpoint_unselects_a_proto_whose_upvalue_home_is_virtualized():
    """An upvalue whose home prototype runs in the VM has its storage inside
    a frame no closure can see, so the selector must remove the capturing
    prototype.  Today no home can actually be virtualized -- the home is an
    ancestor that creates a closure, which the encoder refuses -- so this test
    forces the encoder's blessing to prove the fixpoint itself works, then
    checks the honest path leaves the capture in the VM and the home native.
    """
    from couxobf import pipeline
    from couxobf.vm import encode as _encode

    src = ("local function outer()\n"
           "  local x = 1\n"
           "  local function reads() return x end\n"
           "  return reads()\n"
           "end\n"
           "print(outer())\n")
    module = ir.Lowerer().lower(parser.parse(src, "home.luau"))
    pids = {p.name: p.proto_id for p in module.walk()}

    class _All:
        def level(self, pid: int) -> int:
            return 2

    # Forced blessing: everything "encodes", so the home lands in the
    # selection and the fixpoint must evict the capturing prototype.
    saved = _encode.can_virtualize
    # ``closures_ok`` in the signature because the selector passes it: R5's
    # third increment added it, and a stand-in that drops keyword arguments
    # would break here rather than in the feature it is standing in for.
    _encode.can_virtualize = lambda proto, fmt=None, upvalues_ok=False, \
        closures_ok=False: (True, "")
    try:
        chosen = pipeline._select_for_vm(module, _All(), upvalues_ok=True)
    finally:
        _encode.can_virtualize = saved
    assert pids["outer"] in chosen
    assert pids["reads"] not in chosen, (
        "a prototype whose upvalue home is virtualized must be unselected")

    # The honest path: the home creates a closure, so the encoder refuses it,
    # the home never enters the selection, and the capture stays eligible.
    chosen = pipeline._select_for_vm(module, _All(), upvalues_ok=True)
    assert pids["reads"] in chosen
    assert pids["outer"] not in chosen


def test_default_builds_are_untouched_by_the_flag_existing():
    """A source with upvalue capture, built with defaults: identical stats to
    a pre-R5 build's behaviour -- the function is left native for the old
    reason."""
    src = (
        "local n = 0\n"
        "local function bump() n = n + 1 return n end\n"
        "print(bump())\n"
    )
    out = build(src, Config(reproducible_seed=82), name="uv.luau",
                verify=True)
    assert out.stats.virtualized == 0
    reasons = " ".join(out.stats.native_reasons)
    assert "upvalue" in reasons

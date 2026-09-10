"""R5 (first increment): vararg-capable virtualization.

Before this, a function that accepted `...` was refused by the VM outright:
the frame is a table, and the caller's extra arguments had nowhere to live.
The fix is that the entry point already packs every argument the caller sent;
it now stashes that pack in the frame, and a VARARG instruction is a slice of
it.  Nothing outside the call can observe the stash, which is exactly why
varargs could cross the boundary while upvalues -- which real Luau closures
outside the call *can* observe -- still cannot.

These tests pin the IR-side gate (vararg protos are now encodable), the
operand encoding (count travels biased like CALL's nres, because it shares
the MULTIRET meaning), and -- the part that matters -- the runtime semantics
against the source itself, value for value, trailing nils included.  Counts
are taken from `table.pack(...).n`, which is exact; the tests never ask `#`
about a holey table, because that length is undefined in Luau itself and the
VM documents it as such rather than pretending to pin it.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from couxobf import ir, parser
from couxobf.config import Config
from couxobf.pipeline import build
from couxobf.toolchain import execute, find_toolchain
from couxobf.vm import encode, isa
from couxobf.vm.format import LEGACY_SPEC

TOOLCHAIN = find_toolchain()


# ---------------------------------------------------------------------------
# the gate and the encoding
# ---------------------------------------------------------------------------

VARARG_SRC = (
    "local function va(...)\n"
    "  local t = table.pack(...)\n"
    "  local s = 0\n"
    "  for i = 1, t.n do\n"
    "    if type(t[i]) == \"number\" then s = s + t[i] end\n"
    "  end\n"
    "  return s, t.n\n"
    "end\n"
    "print(va(1, 2, 3))\n"
)


def _vararg_proto():
    module = ir.Lowerer().lower(parser.parse(VARARG_SRC, "va.luau"))
    for proto in module.walk():
        if proto.name == "va":
            return proto
    raise AssertionError("no va proto")


def test_a_vararg_prototype_is_now_encodable():
    proto = _vararg_proto()
    assert proto.is_vararg
    ok, reason = encode.can_virtualize(proto)
    assert ok, reason


def _opmap():
    from couxobf import rng as rngmod
    return isa.OpcodeMap.shuffled(rngmod.make_domains(b"\x07" * 16).get("opcodes"))


def test_vararg_encodes_to_a_walkable_stream():
    """The operand layout must decode by width alone: a VARARG instruction in
    the stream cannot desync the walk, in either of its two modes."""
    proto = _vararg_proto()
    opmap = _opmap()
    enc = encode.encode_proto(proto, opmap, fmt=LEGACY_SPEC)
    pc, seen = enc.lua_entry - 1, set()
    while pc < len(enc.code):
        name = opmap.to_op[enc.code[pc]]
        assert name in isa.FORMATS, f"{name} has no format"
        seen.add(name)
        pc += isa.operand_size(name)
    assert pc == len(enc.code)
    assert "VARARG" in seen, "the vararg use really did lower to a VARARG"


def test_upvalues_and_closures_stay_refused():
    """The boundary moved for varargs and *only* for varargs: the reasons the
    VM still gives for upvalues and nested closures are the point of the
    increment's scope, and a future edit that drops them silently would be a
    miscompile, not a feature."""
    src = (
        "local x = 1\n"
        "local function reads(...)\n  return x + select('#', ...)\nend\n"
        "local function makes(...)\n"
        "  return (function() return ... end)\nend\n"
        "print(reads(1), makes()())\n"
    )
    module = ir.Lowerer().lower(parser.parse(src, "uv.luau"))
    protos = {p.name: p for p in module.walk()}
    ok, reason = encode.can_virtualize(protos["reads"])
    assert not ok and "upvalue" in reason
    ok, reason = encode.can_virtualize(protos["makes"])
    assert not ok and "closure" in reason


# ---------------------------------------------------------------------------
# runtime semantics, checked against the source itself
# ---------------------------------------------------------------------------

def _equivalent(src, seed, **cfg):
    """Build with the directive-forced VM and demand identical output."""
    out = build(src, Config(reproducible_seed=seed, **cfg),
                name="va.luau", verify=True)
    assert out.stats.virtualized >= 1, (
        "expected the directive to land at least one function in the VM: %s"
        % [(d.name, d.reason) for d in out.stats.decisions])
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    want = execute(TOOLCHAIN, src, "want.luau", timeout=30)
    got = execute(TOOLCHAIN, out.source, "got.luau", timeout=120)
    assert got.returncode == 0, got.stderr[:400]
    assert got.stdout == want.stdout
    return out


DIRECT = "--!couxobf:virtualize\n"


def test_fixed_count_reads_and_nil_padding():
    _equivalent(
        DIRECT +
        "local function f(...)\n"
        "  local a, b, c = ...\n"
        "  return tostring(a) .. '/' .. tostring(b) .. '/' .. tostring(c)\n"
        "end\n"
        "print(f(7))\n"
        "print(f(7, 8))\n"
        "print(f(7, 8, 9, 10))\n"
        "print(f())\n",
        seed=51)


def test_splice_into_calls_and_returns():
    _equivalent(
        DIRECT +
        "local function inner(...)\n"
        "  return select('#', ...)\n"
        "end\n"
        "--!couxobf:virtualize\n"
        "local function splice(...)\n"
        "  return inner(...)\n"
        "end\n"
        "--!couxobf:virtualize\n"
        "local function retall(...)\n"
        "  return ...\n"
        "end\n"
        "print(splice('a', 'b', 'c'))\n"
        "local x, y, z = retall(1, nil, 3)\n"
        "print(tostring(x), tostring(y), tostring(z))\n",
        seed=52)


def test_table_pack_is_bit_exact_including_trailing_nils():
    """The exact-count idiom: table.pack keeps every value and its true count,
    holes and all.  This is the assertion that would catch a vararg tail
    truncated to its last non-nil value."""
    _equivalent(
        DIRECT +
        "local function f(...)\n"
        "  local t = table.pack(...)\n"
        "  local s = 'n=' .. t.n\n"
        "  for i = 1, t.n do s = s .. ',' .. tostring(t[i]) end\n"
        "  return s\n"
        "end\n"
        "print(f(1, nil, nil))\n"
        "print(f(nil))\n"
        "print(f())\n"
        "print(f('a', nil, 'z'))\n",
        seed=53)


def test_constructor_and_select_forms():
    _equivalent(
        DIRECT +
        "local function f(prefix, ...)\n"
        "  local t = { ... }\n"
        "  local s = prefix .. ':' .. tostring(t[1]) .. ',' .. tostring(t[2])\n"
        #  (parens truncate the select to one value, so an empty tail is nil,
        #  not a zero-argument tostring error -- the source must be valid
        #  before the VM can be asked to match it)
        "  return s .. ':' .. select('#', ...) .. ':' .. tostring((select(2, ...)))\n"
        "end\n"
        "print(f('p', 9))\n"
        "print(f('p', 9, 8))\n"
        "print(f('p'))\n",
        seed=54)


def test_vararg_used_twice_in_one_body():
    _equivalent(
        DIRECT +
        "local function f(...)\n"
        "  local n = select('#', ...)\n"
        "  local first = (...)\n"
        "  local again = select('#', ...)\n"
        "  return tostring(first) .. ':' .. n .. ':' .. again\n"
        "end\n"
        "print(f(5, 6))\n"
        "print(f())\n",
        seed=55)


def test_tail_call_with_varargs():
    _equivalent(
        DIRECT +
        "local function inner(...)\n"
        "  return select('#', ...) * 10\n"
        "end\n"
        "--!couxobf:virtualize\n"
        "local function t(...)\n"
        "  return inner(...)\n"
        "end\n"
        "print(t(1, 2, 3, 4))\n",
        seed=56)


def test_multi_group_builds_agree():
    """Every group's entry point carries the stash; a vararg function landing
    in any of the three interpreters must behave the same."""
    src = (
        DIRECT +
        "local function f(...)\n"
        "  local t = table.pack(...)\n"
        "  local s = 0\n"
        "  for i = 1, t.n do s = s + (tonumber(t[i]) or 0) end\n"
        "  return s\n"
        "end\n"
        "--!couxobf:virtualize\n"
        "local function g(...)\n"
        "  return f(...) + select('#', ...)\n"
        "end\n"
        "print(g(1, 2, 3), g(), g('x', 4))\n"
    )
    for seed in (61, 62):
        _equivalent(src, seed, vm_variety=3)


def test_maximum_profile_stays_exact():
    """Everything on at once: guards, pools, split arms, several VM groups.
    Values are checked element-wise (never `#` on a holey pack)."""
    src = (
        DIRECT +
        "local function join(prefix, ...)\n"
        "  local t = table.pack(...)\n"
        "  local out = prefix\n"
        "  for i = 1, t.n do out = out .. '|' .. tostring(t[i]) end\n"
        "  return out\n"
        "end\n"
        "--!couxobf:virtualize\n"
        "local function pass(...)\n"
        "  return join('hdr', ...)\n"
        "end\n"
        "print(pass('a', 'b', 'c'))\n"
        "print(pass())\n"
        "print(join('only', 1, nil, 'z'))\n"
    )
    config = Config.from_profile("maximum")
    config.reproducible_seed = 57
    out = build(src, config, name="va.luau", verify=True)
    assert out.stats.virtualized >= 1
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    want = execute(TOOLCHAIN, src, "want.luau", timeout=30)
    got = execute(TOOLCHAIN, out.source, "got.luau", timeout=180)
    assert got.returncode == 0, got.stderr[:400]
    assert got.stdout == want.stdout


def test_native_and_vm_callers_agree():
    """A native function calling the virtualized vararg one, and the reverse,
    both see the argument list unchanged."""
    src = (
        DIRECT +
        "local function vmva(...)\n"
        "  local t = table.pack(...)\n"
        "  return t.n\n"
        "end\n"
        "local function native(...)\n"
        "  return vmva(...) + 100\n"
        "end\n"
        "--!couxobf:virtualize\n"
        "local function vmcallsnative(...)\n"
        "  return native(...) + 1000\n"
        "end\n"
        "print(native(1, 2))\n"
        "print(vmcallsnative(1, 2, 3))\n"
    )
    _equivalent(src, seed=58)

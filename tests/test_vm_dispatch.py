"""Dispatch-shape tests: does every number this build assigns reach its arm?

The three dispatch shapes are *routing*, and routing can be wrong in a way that
never shows up in the encoder, the payload, or the build-time integrity check: an
arm can exist somewhere in the tree and still be unreachable for the number it
accepts.  That bug was real -- the decision tree partitioned the *entries* by
their first number, so an opcode whose alias sat far away was routed to a subtree
that could not contain it, and the only symptom was a valid payload falling
through to ``error("invalid state")`` a few instructions into a function.

The emitters therefore record what they emit: each arm appends its accepted
numbers and the full chain of comparisons that reach it to a trace list, and the
tests walk that trace for every value a byte can hold.  What is checked is the
shape that went out, not a model assembled next to it.
"""

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from couxobf import rng as rngmod
from couxobf.toolchain import find_toolchain
from couxobf.vm import runtime
from couxobf.vm.format import FUSION_RULES, FormatSpec, HeaderLayout
from couxobf.vm.isa import OpcodeMap

#: Interpreter locals, fixed here so a failure names the shape it came from.
NAMES = {
    "code": "_kS", "exec": "_kX", "enter": "_kGo", "call": "_kAp",
    "getfenv": "_kGe", "acc": "_kAc", "stack": "_kSt", "sp": "_kSp",
    "append": "_kapp", "iter": "_kiter", "iterpack": "_kiterpack",
    "itercheck": "_kitercheck", "pc": "_kPc", "regs": "_kR",
    "consts": "_kK", "env": "_kE", "edges": "_kEG",
    # R5: the frame key holding the caller's packed arguments and the pack
    # field recording the named-parameter count
    "vpack": "_kVp", "vnp": "_kVn",
    # R5's second increment: the frame key holding the upvalue accessor list
    "uvs": "_kUv",
}

#: The layouts worth crossing with the shapes: the historical one, a padded
#: two-byte opcode, wide registers with relative jumps, and both dispatch
#: shapes -- the closure bank and the inlined chain, whose ladder must route
#: every assigned number through its scramble exactly like the bank does.
FORMATS = (
    FormatSpec(),
    FormatSpec(op_bytes=2, pad=2),
    FormatSpec(reg_bytes=2, wide_bytes=3, reg_mask=0x5A, target_mode="rel"),
    FormatSpec(dispatch_shape="chain", dispatch_salt=0x39, arm_seed=7),
    FormatSpec(op_bytes=2, dispatch_shape="chain", dispatch_salt=0x7F1,
               arm_seed=41, pad=1),
    # Inline operand reads: the field arithmetic is spelled at the read site
    # instead of calling the generated readers, so routing must hold without
    # the reader functions being the decode path.
    FormatSpec(inline_reads=True, arm_seed=19),
    FormatSpec(dispatch_shape="chain", dispatch_salt=0x55, arm_seed=5,
               inline_reads=True),
    # R2's predicate tap: the dispatch key is folded with a header filler
    # byte that every payload of the group carries, so the ladder's constants
    # are an image of the numbering under a salt the payload holds.  Routing
    # must stay exact with the extra term, for both dispatch shapes.
    FormatSpec(dispatch_shape="chain", dispatch_salt=0x4B, arm_seed=9,
               header=HeaderLayout(
                   fields=(("nparams", 1), ("flags", 1), ("nregs", 2),
                           ("nconsts", 2), ("entry", 2)),
                   filler=((2, 0xA5),), entry_bias=0, legacy=False),
               key_taps=(2,)),
    FormatSpec(arm_seed=23,
               header=HeaderLayout(
                   fields=(("nparams", 1), ("flags", 1), ("nregs", 2),
                           ("nconsts", 2), ("entry", 2)),
                   filler=((1, 0x3C),), entry_bias=0, legacy=False),
               key_taps=(1,)),
)

_CASES = [(seed, sparse, ratio, variant)
          for seed in (1, 2, 3, 4, 5)
          for sparse in (1, 2, 3, 5)
          for ratio in (0.0, 0.6, 1.0)
          for variant in range(len(FORMATS))]


def _condition_holds(cond: str, value: int, bk: int) -> bool:
    """Evaluate one emitted condition against an opcode number.

    The emitted conditions are a closed grammar -- equality/range tests over
    ``op``, optional affine ``+/-`` modulo disguises, ``_bk == K``, and their
    negations, joined by ``or`` -- so evaluating them with only ``op`` and
    ``_bk`` in scope is exact, and it is the *emitted text* being evaluated
    rather than a re-derivation of it.
    """
    return bool(eval(cond, {"__builtins__": {}}, {"op": value, "_bk": bk}))


def _opmap(seed, sparse, ratio):
    fused = [(r.first, r.second) for r in FUSION_RULES][: (seed % 4)]
    rng = rngmod.make_domains(bytes([seed]) * 16).get("opcodes")
    return OpcodeMap.shuffled(rng, alias_ratio=ratio, sparse=sparse,
                              fused=fused)


def _emit(opmap, dispatcher, fmt, family="register"):
    trace = []
    text = runtime.interpreter_source(opmap, NAMES, family, dispatcher, fmt,
                                      trace=trace)
    bk = None
    if dispatcher == "bucket":
        m = re.search(r"local \w+ = \(op \* (\d+)\) % (\d+)", text)
        assert m, "bucket dispatch emitted no bucket computation"
        mult, buckets = int(m.group(1)), int(m.group(2))
        bk = (lambda v, _m=mult, _b=buckets: (v * _m) % _b)
    return text, trace, bk


def matches(trace, value, bucket=None):
    """Every arm whose comparisons accept ``value``, in emission order.

    The first element is what actually runs, because ``if``/``elseif`` means
    first match wins; the rest is what the shape should never produce.
    """
    bk = 0 if bucket is None else bucket(value)
    return [numbers for numbers, path in trace
            if all(_condition_holds(cond, value, bk) for cond in path)]


@pytest.mark.parametrize("dispatcher", list(runtime.DISPATCHERS))
@pytest.mark.parametrize("seed,sparse,ratio,variant", _CASES)
def test_every_assigned_number_reaches_its_own_arm(dispatcher, seed, sparse,
                                                   ratio, variant):
    """No opcode this build can emit may fall through its own dispatcher.

    ``sparse`` spaces the numbering out and ``ratio`` gives opcodes extra
    numbers; both are the conditions that break a value-partitioned shape, which
    is why they are crossed with the shapes here instead of sampled.
    """
    opmap = _opmap(seed, sparse, ratio)
    fmt = FORMATS[variant]
    _text, trace, bk = _emit(opmap, dispatcher, fmt)
    assert trace, f"{dispatcher} emitted no arms at all"
    for number in sorted(opmap.to_op):
        found = matches(trace, number, bk)
        assert found, (
            f"{dispatcher}/{fmt.target_mode}/seed {seed}/sparse {sparse}: "
            f"opcode {number} ({opmap.to_op[number]}) reaches no arm, so any "
            f"payload that uses it dies in the fallthrough guard")
        assert number in found[0], (
            f"{dispatcher}: opcode {number} is routed to an arm accepting "
            f"{sorted(found[0])}")


@pytest.mark.parametrize("dispatcher", list(runtime.DISPATCHERS))
@pytest.mark.parametrize("seed", (1, 2, 3, 7, 11))
def test_no_number_is_claimed_by_two_arms(dispatcher, seed):
    """An arm that shadows another is a wrong answer that never reports itself.

    Two arms matching one opcode number means whichever was emitted first wins,
    and if those two arms are different opcodes then a valid payload silently
    computes something else -- strictly worse than the crash the guard gives.
    """
    opmap = _opmap(seed, 2, 1.0)
    _text, trace, bk = _emit(opmap, dispatcher, FormatSpec(pad=1))
    for number in range(1, 256):
        found = matches(trace, number, bk)
        if not found:
            continue
        assert all(number in nums for nums in found), (
            f"{dispatcher}: {number} is accepted by an arm that does not name "
            f"it ({sorted(found[0])})")
        owners = {opmap.to_op[n] for nums in found for n in nums if n in opmap.to_op}
        assert len(owners) <= 1, (
            f"{dispatcher}: opcode {number} matches arms for {sorted(owners)}; "
            f"the first would win and the second would be dead code")


def test_dispatch_conditions_are_not_all_plain_opcode_equality():
    opmap = _opmap(4, 3, 0.6)
    fmt = FormatSpec(op_bytes=2, arm_seed=0x12345)
    text, trace, _bk = _emit(opmap, "nested_if", fmt)
    assert trace
    assert "bit32.bxor" in text or "bit32.band" in text
    assert "_vr" in text


def test_the_guard_still_rejects_unassigned_numbers():
    """A number this build never assigns must reach nothing.

    That is the fallthrough's job: it turns a corrupted payload into a crash
    instead of a different program.
    """
    opmap = _opmap(3, 1, 0.0)
    for dispatcher in runtime.DISPATCHERS:
        _text, trace, bk = _emit(opmap, dispatcher, FormatSpec())
        hits = [n for n in range(1, 256)
                if n not in opmap.to_op and matches(trace, n, bk)]
        assert not hits, (
            f"{dispatcher}: {len(hits)} unassigned numbers reach an arm, e.g. "
            f"{hits[:6]} -- the guard would run a handler instead of refusing")


# ---------------------------------------------------------------------------
# R2: the predicate tap -- dispatch keys folded with a payload header byte
# ---------------------------------------------------------------------------

def _tapped_chain():
    return FormatSpec(dispatch_shape="chain", dispatch_salt=0x4B, arm_seed=9,
                      header=HeaderLayout(
                          fields=(("nparams", 1), ("flags", 1), ("nregs", 2),
                                  ("nconsts", 2), ("entry", 2)),
                          filler=((2, 0xA5),), entry_bias=0, legacy=False),
                      key_taps=(2,))


def test_the_tapped_ladder_reads_the_payload_and_rekeys_the_arms():
    """The chain's scramble gains a term the interpreter text does not carry.

    ``_pt`` is read once from the header filler, and every ladder constant is
    the numbering folded with salt *and* the tap value -- so the constants in
    the text must not equal the salt-only image, while still covering every
    assigned number exactly once.
    """
    fmt = _tapped_chain()
    opmap = _opmap(5, 1, 0.0)
    text, trace, _bk = _emit(opmap, "woven", fmt)
    assert re.search(r"local \w+ = _bd\(_kS, 3\)", text), (
        "the tap read is missing or at the wrong offset")
    m = re.search(r"local (\w+) = bit32\.band\(bit32\.bxor\(op, (\d+), (\w+)\), (\d+)\)",
                  text)
    assert m, "the scramble did not fold the payload term in"
    assert m.group(2) == "75" and m.group(4) == "255"
    pt_name = m.group(3)
    assert pt_name != "op"
    keys = [int(k) for k in re.findall(r"%s == (\d+)" % re.escape(m.group(1)),
                                       text)]
    salt, mask, pt = 0x4B, 255, fmt.key_tap_value()
    assert pt == 0xA5
    want = {(n ^ salt ^ pt) & mask for n in opmap.to_op}
    assert set(keys) == want, "ladder constants are not the tapped image"
    assert {(n ^ salt) & mask for n in opmap.to_op} != want, (
        "the tap value collapsed to nothing")


def test_the_tapped_bank_key_expression_folds_the_payload_term():
    fmt = FormatSpec(arm_seed=23,
                     header=HeaderLayout(
                         fields=(("nparams", 1), ("flags", 1), ("nregs", 2),
                                 ("nconsts", 2), ("entry", 2)),
                         filler=((1, 0x3C),), entry_bias=0, legacy=False),
                     key_taps=(1,))
    opmap = _opmap(4, 1, 0.0)
    text, _trace, _bk = _emit(opmap, "woven", fmt)
    assert re.search(r"local \w+ = _bd\(_kS, 2\)", text), "no tap read"
    assert re.search(r"bit32\.bxor\(bit32\.bxor\(op, \d+\), \w+\)", text), (
        "the bank key did not fold the payload term in")


@pytest.mark.skipif("not find_toolchain().can_execute")
def test_a_tapped_build_executes_like_its_source():
    """Force every drawn format to carry a tap, then run the artifact.

    The tap changes the dispatch keying of whichever shape the group drew,
    so executing the build is the check that the encoder, the ladder and the
    bank all agree with the payload about what the header byte is.
    """
    import couxobf.vm.format as F
    import couxobf.vm.wiring as W
    from dataclasses import replace

    src = ("local function acc(n)\n"
           "  local t = 0\n"
           "  for i = 1, n do\n"
           "    if i % 3 == 0 then t = t + i * 2 else t = t + i end\n"
           "  end\n"
           "  return t\n"
           "end\n"
           "print(acc(60), acc(7))\n")

    orig_draw = F.draw

    def forced(rng, prefs=None, **kw):
        spec = orig_draw(rng, prefs, **kw)
        if spec.key_taps:
            return spec
        header = spec.header
        if header.legacy:
            # A legacy header carries no filler byte, and this test is about
            # the tap's wiring, not which header the stream happens to draw.
            # Swap the same fields in as a non-legacy layout so a filler slot
            # -- and therefore a tap -- can exist.
            header = HeaderLayout(fields=header.fields, filler=header.filler,
                                  entry_bias=header.entry_bias, legacy=False)
        _p, filler_at, _t = header._map()
        if not filler_at:
            header = replace(header, filler=((1, 0x5A),))
            _p, filler_at, _t = header._map()
        return replace(spec, header=header,
                       key_taps=(sorted(filler_at)[0],))

    from couxobf.config import Config
    from couxobf.pipeline import build
    from couxobf.toolchain import execute

    F.draw = forced
    W.draw = forced
    try:
        out = build(src, Config(reproducible_seed=29,
                                min_virtualize_body_nodes=1,
                                max_output_growth=0),
                    name="tap.luau", verify=True)
    finally:
        F.draw = orig_draw
        W.draw = orig_draw
    assert out.stats.virtualized >= 1
    tapped = [g for g in out.stats.vm_groups if (g.get("format") or {}).get("key_taps")]
    assert tapped, "no drawn group carried a tap under the forced draw"
    # The artifact's key math names the payload term, not just the salt.
    # (Minified output drops spaces and ``bit32`` arrives as a captured,
    # renamed local, so both are wildcards here.)
    assert (re.search(r"\w+\.bxor\(op,\s*\d+,\s*\w+\)", out.source)
            or re.search(r"\w+\.bxor\(\w+\.bxor\(op,\s*\d+\),\s*\w+\)",
                         out.source)), "no tapped key expression in the artifact"
    tc = find_toolchain()
    want = execute(tc, src, "want.luau", timeout=30)
    got = execute(tc, out.source, "got.luau", timeout=30)
    assert got.returncode == 0, got.stderr[:300]
    assert got.stdout == want.stdout, (got.stdout, want.stdout)


def test_key_tap_preference_follows_opaque_predicates():
    """R12 wired the knob: `opaque_predicates` is what the tap listens to."""
    from couxobf.config import Config
    from couxobf.vm.format import FormatPrefs

    assert FormatPrefs.from_config(Config()).allow_key_taps is True
    assert (FormatPrefs.from_config(Config(opaque_predicates=False))
            .allow_key_taps is False)


def test_a_draw_never_taps_when_the_preference_is_off():
    """The chance is still spent (the stream stays put), the draw is not."""
    from couxobf.rng import Rng
    from couxobf.vm.format import FormatPrefs, draw

    on = FormatPrefs(allow_key_taps=True)
    off = FormatPrefs(allow_key_taps=False)
    tapped_on = 0
    for seed in range(40):
        key = bytes([(seed * 7 + i) & 0xFF for i in range(16)])
        if draw(Rng(key), on).key_taps:
            tapped_on += 1
        assert not draw(Rng(key), off).key_taps, seed
    assert tapped_on, "forty draws produced no tap at all; knob untestable"


def test_opaque_predicates_off_keeps_the_payload_term_out_of_the_artifact():
    """With the predicate off the forced-tap draw must stay honored-less.

    The forced draw below injects a tap into any spec the knob allowed; with
    ``opaque_predicates=False`` it must inject nothing, and the artifact's key
    math must carry no payload term -- neither the ladder's third operand nor
    the bank's nested one.
    """
    import couxobf.vm.format as F
    import couxobf.vm.wiring as W
    from dataclasses import replace

    src = ("local function acc(n)\n"
           "  local t = 0\n"
           "  for i = 1, n do\n"
           "    if i % 3 == 0 then t = t + i * 2 else t = t + i end\n"
           "  end\n"
           "  return t\n"
           "end\n"
           "print(acc(60), acc(7))\n")

    orig_draw = F.draw

    def forced(rng, prefs=None, **kw):
        spec = orig_draw(rng, prefs, **kw)
        if spec.key_taps or spec.header.legacy:
            return spec
        if prefs is None or not prefs.allow_key_taps:
            return spec           # the knob is off: honor it, do not inject
        _p, filler_at, _t = spec.header._map()
        if not filler_at:
            spec = replace(spec, header=replace(spec.header,
                                                filler=((1, 0x5A),)))
            _p, filler_at, _t = spec.header._map()
        return replace(spec, key_taps=(sorted(filler_at)[0],))

    from couxobf.config import Config
    from couxobf.pipeline import build

    F.draw = forced
    W.draw = forced
    try:
        out = build(src, Config(reproducible_seed=29, opaque_predicates=False,
                                min_virtualize_body_nodes=1,
                                max_output_growth=0),
                    name="untapped.luau", verify=True)
    finally:
        F.draw = orig_draw
        W.draw = orig_draw
    assert out.stats.virtualized >= 1
    assert not [t for g in out.stats.vm_groups
                for t in [(g.get("format") or {}).get("key_taps")]
                if t], "a tap slipped through the knob"
    assert not re.search(r"\w+\.bxor\(op,\s*\d+,\s*\w+\)", out.source)
    assert not re.search(r"\w+\.bxor\(\w+\.bxor\(op,\s*\d+\),\s*\w+\)",
                         out.source)

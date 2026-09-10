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
from couxobf.vm import runtime
from couxobf.vm.format import FUSION_RULES, FormatSpec
from couxobf.vm.isa import OpcodeMap

#: Interpreter locals, fixed here so a failure names the shape it came from.
NAMES = {
    "code": "_kS", "exec": "_kX", "enter": "_kGo", "call": "_kAp",
    "getfenv": "_kGe", "acc": "_kAc", "stack": "_kSt", "sp": "_kSp",
    "append": "_kapp", "iter": "_kiter", "iterpack": "_kiterpack",
    "itercheck": "_kitercheck", "pc": "_kPc", "regs": "_kR",
    "consts": "_kK", "env": "_kE", "edges": "_kEG",
}

#: The layouts worth crossing with the shapes: the historical one, a padded
#: two-byte opcode, and wide registers with relative jumps.
FORMATS = (
    FormatSpec(),
    FormatSpec(op_bytes=2, pad=2),
    FormatSpec(reg_bytes=2, wide_bytes=3, reg_mask=0x5A, target_mode="rel"),
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

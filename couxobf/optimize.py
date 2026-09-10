"""Optimization passes over the IR.

This is the stage the pipeline calls for between lowering and transformation.
Its job here is not to make the program fast -- it is to remove the noise that
the lowering inevitably produces, so the later transformation passes have
something clean to work on and the output is not padded with obvious dead
weight. Over-obfuscation is a stated non-goal: a bigger artifact is not a
stronger one.

The governing constraint is that **an optimization must never change what the
program does.** Every pass below is conservative in a specific, documented way,
because the interesting failures are all cases where Luau and Python disagree:

* Luau has no integer subtype and every number is a double.  Folding is done in
  ``float`` and rejected outright unless the result is finite, so overflow,
  infinities and NaN are left to the runtime rather than approximated.
* Luau coerces strings in arithmetic: ``"10" + 1`` is ``11`` and ``-"5"`` is
  ``-5``.  Folding therefore refuses to touch any operand that is not a number,
  because replicating the coercion rules is exactly where a subtle divergence
  would hide.
* ``..`` stringifies numbers, so ``1 .. 2`` is ``"12"``.  CONCAT is not folded.
* ``a / 0`` is ``inf`` and ``a % 0`` is NaN rather than an error, and a negative
  base with a fractional exponent is NaN rather than complex.  All are excluded
  by the finite-result rule.

Dataflow is intra-block only.  That is weaker than it could be and deliberately
so: a cross-block constant propagation would need the whole CFG to agree, and
the payoff is not worth the risk at this stage.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .ir import (
    MULTIRET,
    OP,
    FuncIR,
    IRModule,
    Instr,
    Kon,
    LoweringError,
    Reg,
    compute_liveness,
    def_use,
    reachable_blocks,
)

# Arithmetic that is safe to fold when both operands are known numbers and the
# result is finite.  DELIBERATELY excludes CONCAT (Luau stringifies numbers),
# LEN (strings only), the comparisons (low value here, and they would need the
# full equality/ordering rules including mixed types), and every instruction
# with a side effect.
FOLDABLE_BIN = {
    "+": OP.ADD,
    "-": OP.SUB,
    "*": OP.MUL,
    "/": OP.DIV,
    "//": OP.IDIV,
    "%": OP.MOD,
    "^": OP.POW,
}
_BIN_BY_OP = {v: k for k, v in FOLDABLE_BIN.items()}

#: Instructions with no observable effect other than writing their destination,
#: so a dead destination makes the whole instruction removable.
REMOVABLE_OPS = frozenset({
    OP.MOV, OP.LOADK, OP.NOP,
    OP.ADD, OP.SUB, OP.MUL, OP.DIV, OP.IDIV, OP.MOD, OP.POW,
    OP.UNM, OP.NOT, OP.LEN,
    OP.EQ, OP.NE, OP.LT, OP.LE, OP.GT, OP.GE,
    OP.NEWTABLE,
})


class OptimizationError(Exception):
    pass


@dataclass
class Stats:
    """What each pass did -- reported so a build can be checked for sanity."""

    folded: int = 0
    copy_rewrites: int = 0
    dead_removed: int = 0
    unreachable_removed: int = 0
    nops_removed: int = 0
    per_proto: Dict[int, Dict[str, int]] = field(default_factory=dict)

    def record(self, proto_id: int, **counts: int) -> None:
        bucket = self.per_proto.setdefault(proto_id, {})
        for key, value in counts.items():
            bucket[key] = bucket.get(key, 0) + value

    @property
    def total_removed(self) -> int:
        return self.dead_removed + self.unreachable_removed + self.nops_removed


#: Instructions whose register uses are explicit operands rather than implicit
#: contiguous ranges.  Copy propagation is deliberately limited to these because
#: CALL, RETURN, loop control and SETLIST encode base-register layouts as part of
#: their semantics.
_COPY_PROP_SAFE = frozenset({
    OP.MOV, OP.ADD, OP.SUB, OP.MUL, OP.DIV, OP.IDIV, OP.MOD, OP.POW,
    OP.UNM, OP.NOT, OP.LEN, OP.CONCAT,
    OP.EQ, OP.NE, OP.LT, OP.LE, OP.GT, OP.GE,
    OP.GETTABLE, OP.SETTABLE,
})


def _is_number(value: Any) -> bool:
    """True for a Luau number constant.

    ``bool`` is excluded explicitly: Python treats ``True`` as ``1``, but a
    Luau boolean is not a number and ``true + 1`` is an error, not ``2``.
    """
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _fold_bin(op: str, left: float, right: float) -> Optional[float]:
    """Evaluate a binary numeric op, or return None to decline.

    Declining is always safe; being wrong never is.  Anything non-finite is
    declined so that overflow and the infinities stay the runtime's business.
    """
    try:
        if op == "+":
            result = left + right
        elif op == "-":
            result = left - right
        elif op == "*":
            result = left * right
        elif op == "/":
            if right == 0.0:
                return None
            result = left / right
        elif op == "//":
            if right == 0.0:
                return None
            result = left // right
        elif op == "%":
            if right == 0.0:
                return None
            result = left % right
        elif op == "^":
            if left < 0.0 and right != math.floor(right):
                # Python would produce a complex number; Luau produces NaN.
                # Neither belongs in a folded constant.
                return None
            result = math.pow(left, right)
        else:  # pragma: no cover - guarded by the caller
            return None
    except (OverflowError, ValueError, ZeroDivisionError):
        return None
    if not math.isfinite(result):
        return None
    return float(result)


def _fold_unary(op: str, value: float) -> Optional[float]:
    if op == "-":
        result = -value
        # -0.0 folded from 0.0 is a real change in observable behaviour, so a
        # zero result is declined rather than risk picking the wrong sign.
        if result == 0.0:
            return None
        return result if math.isfinite(result) else None
    if op == "not":
        return None  # NOT applies to any value, not just numbers
    return None


def fold_constants(proto: FuncIR, stats: Stats) -> int:
    """Replace arithmetic on known constants with the computed constant.

    Constantness is tracked per block by forward scan: a register holds a known
    constant from the ``LOADK`` that wrote it until anything else writes it.
    Ranges written by calls, ``SETLIST`` and the loop instructions are cleared
    wholesale, because tracking those precisely is not worth the risk.
    """
    folded = 0
    for block in proto.blocks:
        known: Dict[int, Any] = {}
        for ins in list(block.instrs):
            defs, uses = def_use(ins)

            op = ins.op
            if op in _BIN_BY_OP and len(ins.args) == 3:
                left = known.get(_idx(ins.args[1]))
                right = known.get(_idx(ins.args[2]))
                if (_is_number(left) and _is_number(right)
                        and isinstance(ins.args[0], Reg)):
                    value = _fold_bin(_BIN_BY_OP[op], float(left), float(right))
                    if value is not None:
                        konst = proto.add_const(value)
                        ins.op = OP.LOADK
                        ins.args = (ins.args[0], konst)
                        folded += 1
                        stats.record(proto.proto_id, folded=1)
                        defs, uses = def_use(ins)

            elif op == OP.UNM and len(ins.args) == 2:
                value = known.get(_idx(ins.args[1]))
                if (_is_number(value) and isinstance(ins.args[0], Reg)):
                    result = _fold_unary("-", float(value))
                    if result is not None:
                        konst = proto.add_const(result)
                        ins.op = OP.LOADK
                        ins.args = (ins.args[0], konst)
                        folded += 1
                        stats.record(proto.proto_id, folded=1)
                        defs, uses = def_use(ins)

            if ins.op == OP.LOADK and isinstance(ins.args[0], Reg):
                known[ins.args[0].index] = proto.consts[ins.args[1].index]
            else:
                for d in defs:
                    known.pop(d, None)
                # Anything that writes a range of registers (calls, SETLIST,
                # loop control) invalidates more than def_use can promise, so
                # drop everything to stay on the safe side.
                if ins.op not in (OP.MOV, OP.LOADK, OP.NOP) and ins.op not in _BIN_BY_OP \
                        and ins.op not in (OP.UNM, OP.NOT, OP.LEN,
                                           OP.EQ, OP.NE, OP.LT, OP.LE, OP.GT, OP.GE):
                    known.clear()
    stats.folded += folded
    return folded


def _idx(operand: Any) -> Optional[int]:
    return operand.index if isinstance(operand, Reg) else None


def _resolve_alias(alias: Dict[int, int], reg: int) -> int:
    seen = set()
    cur = reg
    while cur in alias and cur not in seen:
        seen.add(cur)
        cur = alias[cur]
    return cur


def _rewrite_arg(arg: Any, alias: Dict[int, int]) -> Tuple[Any, bool]:
    if not isinstance(arg, Reg):
        return arg, False
    resolved = _resolve_alias(alias, arg.index)
    if resolved == arg.index:
        return arg, False
    return Reg(resolved), True


def propagate_register_copies(proto: FuncIR, stats: Stats) -> int:
    """Forward copy propagation inside each basic block.

    This is an anti-bloat pass rather than a clever deobfuscation trick: many
    source-level and lowering transformations introduce temporary ``MOV`` chains.
    Rewriting later arithmetic/table uses to the original register lets constant
    folding and dead-store removal clean them up.  The pass is intra-block and
    skips instructions whose operands describe implicit register ranges, so it
    cannot disturb Luau call/return or loop-frame layouts.
    """
    escaped = _escaped_registers(proto)
    rewrites = 0
    for block in proto.blocks:
        alias: Dict[int, int] = {}
        for ins in block.instrs:
            op = ins.op
            defs, _uses = def_use(ins)
            if op in _COPY_PROP_SAFE:
                args = list(ins.args)
                start = 0 if op == OP.SETTABLE else 1
                for i in range(start, len(args)):
                    new, changed = _rewrite_arg(args[i], alias)
                    if changed:
                        args[i] = new
                        rewrites += 1
                        stats.record(proto.proto_id, copy_rewrites=1)
                ins.args = tuple(args)
                defs, _uses = def_use(ins)

            # Any write kills aliases for that destination and aliases that read
            # that destination.  Captured registers are never made aliases: a
            # closure must keep observing the real upvalue cell.
            for d in defs:
                alias.pop(d, None)
            if defs:
                alias = {dst: src for dst, src in alias.items()
                         if src not in defs}

            if op == OP.MOV and len(ins.args) == 2:
                dst, src = ins.args
                if isinstance(dst, Reg) and isinstance(src, Reg) and dst.index not in escaped:
                    resolved = _resolve_alias(alias, src.index)
                    if resolved != dst.index:
                        alias[dst.index] = resolved

            # Conservatively forget aliases across instructions that can call
            # arbitrary Luau or write register ranges.
            if op not in _COPY_PROP_SAFE and op not in (OP.LOADK, OP.GETGLOBAL, OP.GETUPVAL, OP.NOP):
                alias.clear()
    stats.copy_rewrites += rewrites
    return rewrites


def _escaped_registers(proto: FuncIR) -> Set[int]:
    """Registers a closure in this prototype captures.

    Liveness alone is not enough here.  A closure that escapes keeps the
    register it captured alive *past the end of the control flow graph* -- the
    write may be the last thing the function does and still be read later, from
    outside.  Treating those registers as permanently live is what stops a
    dead-store pass from deleting ``v = 2`` in::

        local v = 1
        local function a() local function b() return function() return v end end end
        print(a()()())   -- 1
        v = 2
        print(a()()())   -- 2, and only if that store survives
    """
    escaped: Set[int] = set()
    for block in proto.blocks:
        for ins in block.instrs:
            if ins.op != OP.CLOSURE or len(ins.args) < 2:
                continue
            for desc in getattr(ins.args[1], "upvalues", ()):
                if desc.from_local and desc.index is not None:
                    escaped.add(desc.index)
    return escaped


def eliminate_dead_stores(proto: FuncIR, stats: Stats) -> int:
    """Drop pure instructions whose destination is never read.

    Walks each block backward from its ``live_out``, which ``compute_liveness``
    must have populated.  Only instructions in :data:`REMOVABLE_OPS` are
    candidates; anything with a side effect stays no matter how dead it looks,
    and nothing writing a register a closure captured is ever removed.
    """
    escaped = _escaped_registers(proto)
    removed = 0
    for block in proto.blocks:
        live = set(block.live_out) | escaped
        keep: List[Instr] = []
        for ins in reversed(block.instrs):
            defs, uses = def_use(ins)
            if (ins.op in REMOVABLE_OPS and defs and not (defs & live)
                    and not (defs & escaped)):
                removed += 1
                stats.record(proto.proto_id, dead_removed=1)
                # the instruction is gone, so its operands stop being live here
                live -= defs
                live |= uses
                continue
            keep.append(ins)
            live = (live - defs) | uses
        keep.reverse()
        block.instrs = keep
    stats.dead_removed += removed
    return removed


#: Terminators whose operands name a target block, and which operand index
#: holds it.  Renumbering blocks means rewriting every one of these.
_JUMP_TARGET = {
    OP.JMP: 0,
    OP.JMPFALSE: 1,
    OP.JMPTRUE: 1,
    OP.FORPREP: 1,
    OP.FORINPREP: 1,
    OP.FORLOOP: 1,
    OP.FORIN: 1,
}


def remove_unreachable_blocks(proto: FuncIR, stats: Stats) -> int:
    """Drop blocks nothing can reach, then renumber.

    The lowering leaves unreachable blocks behind when a label is placed but
    never targeted.  Removing them is not just filtering the list: block ids
    *are* list positions (``compute_liveness`` reads ``proto.blocks[succ]``),
    so every remaining block is renumbered and every jump operand that names a
    block is rewritten to match.
    """
    reach = reachable_blocks(proto)
    removed = len(proto.blocks) - len(reach)
    if removed <= 0:
        return 0

    kept = [b for b in proto.blocks if b.id in reach]
    remap = {b.id: i for i, b in enumerate(kept)}

    for block in kept:
        term = block.terminator
        if term is not None and term.op in _JUMP_TARGET:
            slot = _JUMP_TARGET[term.op]
            target = term.args[slot]
            if target not in remap:  # pragma: no cover - unreachable target
                raise OptimizationError(
                    f"{term.op} in block {block.id} targets removed block {target}")
            args = list(term.args)
            args[slot] = remap[target]
            term.args = tuple(args)
        block.succ = [remap[s] for s in block.succ if s in remap]
        block.pred = [remap[p] for p in block.pred if p in remap]
        block.id = remap[block.id]

    proto.blocks = kept
    if proto.entry not in remap:  # pragma: no cover - entry is always reachable
        raise OptimizationError("the entry block was unreachable")
    proto.entry = remap[proto.entry]

    stats.record(proto.proto_id, unreachable_removed=removed)
    stats.unreachable_removed += removed
    return removed


def remove_nops(proto: FuncIR, stats: Stats) -> int:
    """Drop NOPs and self-moves."""
    removed = 0
    for block in proto.blocks:
        keep = []
        for ins in block.instrs:
            if ins.op == OP.NOP:
                removed += 1
                stats.record(proto.proto_id, nops_removed=1)
                continue
            if (ins.op == OP.MOV and len(ins.args) == 2
                    and _idx(ins.args[0]) is not None
                    and _idx(ins.args[0]) == _idx(ins.args[1])):
                removed += 1
                stats.record(proto.proto_id, nops_removed=1)
                continue
            keep.append(ins)
        block.instrs = keep
    stats.nops_removed += removed
    return removed


def optimize_proto(proto: FuncIR, stats: Optional[Stats] = None,
                   passes: int = 2) -> Stats:
    """Run the passes over one prototype until nothing changes.

    Bounded at ``passes`` iterations: folding exposes dead stores which expose
    more folding, but the sequence has to terminate.
    """
    stats = stats if stats is not None else Stats()
    for _ in range(max(1, passes)):
        before = (stats.folded, stats.copy_rewrites, stats.dead_removed,
                  stats.unreachable_removed, stats.nops_removed)
        remove_unreachable_blocks(proto, stats)
        remove_nops(proto, stats)
        propagate_register_copies(proto, stats)
        compute_liveness(proto)
        fold_constants(proto, stats)
        compute_liveness(proto)
        eliminate_dead_stores(proto, stats)
        after = (stats.folded, stats.copy_rewrites, stats.dead_removed,
                 stats.unreachable_removed, stats.nops_removed)
        if after == before:
            break
    compute_liveness(proto)
    return stats


def optimize_module(module: IRModule, passes: int = 2) -> Stats:
    """Optimize every prototype.  Returns what was done, for the build report."""
    stats = Stats()
    for proto in module.walk():
        optimize_proto(proto, stats, passes=passes)
    return stats

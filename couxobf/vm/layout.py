"""Block layout permutation for encoded prototypes.

The interpreter executes bytecode linearly, so the order the encoder lays
blocks out in is the order control flows through them -- except at jumps.  Two
builds of the same function that differ only in block order produce different
byte offsets for every instruction and different jump operands, which means a
liftable disassembly of one does not line up with the other.

Two things make this safe rather than merely plausible.

Fall-through is closed first.  Measured across the conformance corpus, 1575
blocks end without a terminator and rely on running into the next block; every
one of them has exactly one successor.  When a permutation moves such a block
away from its successor, an explicit ``JMP`` is inserted so the edge survives.
The encoder only inserts one where the layout actually breaks the edge, so an
unpermuted build emits exactly the bytes it did before -- verified, all 1575
fall-through blocks are adjacent to their successor in the default layout.

Block ids are not touched.  Other passes index ``proto.blocks`` positionally,
on the assumption that a block's id is its position in the list, so shuffling
that list would quietly break them.  The permutation is expressed as an *order*
handed to the encoder, which resolves targets by id from the same offsets map
it always used.  Nothing outside the encoder sees the change.
"""

from __future__ import annotations

from typing import Any, List, Optional, Sequence

from ..ir import OP, FuncIR
from ..rng import Rng

__all__ = ["JUMP_ARG", "NO_FALLTHROUGH_OPS", "CONDITIONAL_OPS",
           "fallthrough", "permuted_order", "closes_fallthrough"]


#: Which argument of each jumping terminator names its target block, in the
#: IR's own numbering.  This is the same table ``optimize`` uses to renumber
#: jump operands when it removes blocks; it is *not* the index of the target
#: among the encoded wide operands, which is a different numbering and lives in
#: the integrity checker.
JUMP_ARG = {OP.JMP: 0, OP.JMPFALSE: 1, OP.JMPTRUE: 1, OP.FORPREP: 1,
             OP.FORINPREP: 1, OP.FORLOOP: 1, OP.FORIN: 1}


#: Last-instruction opcodes that always transfer control somewhere else, so the
#: block never runs into its neighbour.
NO_FALLTHROUGH_OPS = frozenset({
    OP.JMP, OP.TAILCALL, OP.RETURN, OP.RETURN0, OP.RETURNMULTI,
    OP.FORPREP, OP.FORINPREP,
})

#: Last-instruction opcodes that transfer on a condition and otherwise continue
#: into the next block.
CONDITIONAL_OPS = frozenset({OP.JMPFALSE, OP.JMPTRUE, OP.FORLOOP, OP.FORIN})


def fallthrough(block: Any) -> Optional[int]:
    """The block this one runs into when it does not jump, or ``None``.

    Classified by the last instruction's opcode, because ``Block.terminator``
    is not a control-flow predicate -- it is literally ``instrs[-1]``, so it
    reports ``NOT`` and ``GE`` as "terminators" and ``None`` only for an empty
    block.  A first version of this read it as a predicate and concluded that a
    block ending in ``GE`` transfers control, which left the block falling off
    into unrelated code.  The payload walk caught it, on 16 of 40 permutations.
    """
    if not block.succ:
        return None
    last = block.instrs[-1] if block.instrs else None
    op = last.op if last is not None else None
    if op in NO_FALLTHROUGH_OPS:
        return None
    if op in CONDITIONAL_OPS:
        target = last.args[JUMP_ARG[op]]
        rest = [s for s in block.succ if s != target]
        return rest[0] if len(rest) == 1 else None
    # an ordinary instruction: the block simply continues
    return block.succ[0] if len(block.succ) == 1 else None


def closes_fallthrough(proto: FuncIR, order: Sequence[int]) -> int:
    """How many explicit jumps this layout needs.

    A block runs into whatever the layout puts next unless it transfers control
    itself.  That is only where it should go if the two happen to be adjacent,
    so a permutation that separates them has to make the edge explicit.

    This used to test ``block.terminator is not None`` and skip the block, on
    the assumption that a terminator transfers control.  ``Block.terminator``
    is literally ``instrs[-1]``, so that skipped every non-empty block and
    counted only the empty ones: 8 where the encoder was inserting 45.
    """
    by_id = {b.id: b for b in proto.blocks}
    count = 0
    for i, block_id in enumerate(order):
        block = by_id[block_id]
        falls_into = fallthrough(block)
        if falls_into is None:
            continue
        following = order[i + 1] if i + 1 < len(order) else None
        if falls_into != following:
            count += 1
    return count


def permuted_order(proto: FuncIR, rng: Optional[Rng]) -> List[int]:
    """A shuffled emission order for one prototype's blocks.

    The entry block is placed first.  Leaving it wherever the shuffle dropped it
    would be legal -- the header records the entry offset -- but it would make
    every build start by jumping, and a jump at the entry point is a giveaway
    that costs nothing to avoid.
    """
    ids = [b.id for b in proto.blocks]
    if rng is None or len(ids) < 2:
        return ids
    order = [ids[i] for i in rng.permutation(len(ids))]
    if order[0] != proto.entry:
        order.remove(proto.entry)
        order.insert(0, proto.entry)
    return order

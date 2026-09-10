"""Encode IR prototypes into VM bytecode.

One prototype becomes one byte string plus a small descriptor.  The descriptor
holds what cannot be bytes -- the constant list, the parameter count, the
register count -- and the byte string holds the instructions.

Everything about *how an instruction is laid out* comes from the build's
:class:`~couxobf.vm.format.FormatSpec`: field widths, field order, padding,
operand masks, how a jump target is represented and how the header is packed.
The encoder does not know the historical layout any better than it knows any
other one -- it asks the spec where each operand goes, which is the only thing
that can keep an interpreter generated from the same spec in step with the
bytes it is reading.  Passing no spec at all means "the historical layout", so
every call site written before formats existed still produces identical bytes.

Two details worth stating, because both are places a silent bug would live:

*Jump targets are byte offsets, not block ids.*  The IR names blocks by id; the
bytecode names positions, because instructions are variable length.  The
translation happens here, once, and the interpreter never sees a block id.

*Signed operands are biased, not two's-complemented.*  ``nres`` and ``tail``
use ``-1`` to mean "absent" and ``MULTIRET`` is also ``-1``.  They are encoded
as ``value + 1`` so ``-1`` becomes ``0`` and every encoded operand stays
non-negative.  The interpreter subtracts the same bias.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from ..ir import MULTIRET, OP, FuncIR, Instr, Kon, Reg
from .format import (FUSABLE, FormatSpec, FusionRule, LEGACY_SPEC)
from .layout import CONDITIONAL_OPS, JUMP_ARG, NO_FALLTHROUGH_OPS, fallthrough
from .isa import (
    MAX_REGISTERS,
    MAX_WIDE,
    IR_ARITY,
    OP_GETTABLEK,
    OP_SETTABLEK,
    SUPPORTED,
    UNSUPPORTED_REASON,
    FORMATS,
    OpcodeMap,
    operand_size,
    vm_opcode,
)

#: Added to signed operands so -1 encodes as 0.
BIAS = 1

#: Bytecode header: nparams, flags, nregs, nconsts, entry offset.
HEADER = struct.Struct("<BBHHH")

#: Offsets in the wire format are 0-based, but the interpreter indexes the
#: bytecode with ``string.byte``, which is 1-based.  Every offset handed to the
#: runtime -- the entry point here, and each jump target as its handler reads it
#: -- crosses that boundary and must gain one.  Getting this wrong does not
#: crash at the boundary; it starts the interpreter one byte early, on the last
#: byte of the header and hits the dispatcher's fallthrough.  That fallthrough
#: now raises the same neutral message as every other failure (see
#: ``couxobf.runtime.constpool_runtime.FAILURE_MESSAGE``), so it no longer
#: names the opcode -- which costs a little debuggability and buys the property
#: that an out-of-range opcode is not distinguishable from any other invalid
#: state.  A build that mis-sets this still fails loudly; it just does not say
#: why.
LUA_INDEX_BIAS = 1

FLAG_VARARG = 1

#: Instructions that may be swapped when the format asks for reordering (#33).
#:
#: Single definition, register-only sources, no side effects and no memory
#: write: for that class of instruction the only ordering constraint is
#: def/use, so any pair that does not touch the same register can be swapped
#: without changing what the block computes.  Everything else -- SETTABLE,
#: SETGLOBAL, CALL, SELF, SETLIST, the loop forms -- is left exactly where the
#: IR put it, because "the IR's order is obviously wrong here" is not a
#: judgement this pass is equipped to make.
_REORDER_SAFE = frozenset({
    OP.MOV, OP.LOADK, OP.GETGLOBAL, OP.NEWTABLE,
    OP.ADD, OP.SUB, OP.MUL, OP.DIV, OP.IDIV, OP.MOD, OP.POW,
    OP.UNM, OP.NOT, OP.LEN, OP.CONCAT,
    OP.EQ, OP.NE, OP.LT, OP.LE, OP.GT, OP.GE,
    OP.GETTABLE, OP_GETTABLEK,
})


class EncodingError(Exception):
    pass


@dataclass
class EncodedProto:
    """Everything the interpreter needs to run one prototype."""

    proto_id: int
    name: Optional[str]
    code: bytes
    nparams: int
    nregs: int
    is_vararg: bool
    entry: int
    #: Constant values, in the order the bytecode indexes them.
    consts: List[Any]
    #: Byte offset of every instruction, in emission order.  Used by
    #: :mod:`couxobf.integrity.payload` to check a decoded stream against the
    #: boundaries the encoder actually laid down.
    starts: Tuple[int, ...] = ()

    #: Jump targets, as absolute offsets, in the order the edges were assigned
    #: an index.  Non-empty only when the format represents targets indirectly
    #: (``target_mode == "edges"``), which is what lets the instruction stream
    #: carry an edge *index* instead of a position (#18).
    edges: Tuple[int, ...] = ()
    #: The format this prototype was encoded with, kept so the descriptor and
    #: the interpreter can be generated from the same object that produced the
    #: bytes rather than from a summary of it.
    fmt: FormatSpec = LEGACY_SPEC
    #: Instructions emitted, after fusion.  Reported, not used.
    instructions: int = 0
    #: How many of those were fused pairs.
    fused: int = 0
    #: How many operand bytes were padding.
    pad_bytes: int = 0

    @property
    def lua_entry(self) -> int:
        """``entry`` as :func:`string.byte` wants it: 0-based + 1.

        The wire format numbers positions from zero; ``string.byte`` does not.
        Keeping the conversion on the object is what stops a caller from
        remembering to do it -- see the runtime's entry-point bug in
        ``tests/test_vm.py``'s docstring.
        """
        return self.entry + LUA_INDEX_BIAS



def can_virtualize(proto: FuncIR, fmt: Optional[FormatSpec] = None,
                   upvalues_ok: bool = False) -> Tuple[bool, str]:
    """Whether this prototype can run in the VM, and why not if it cannot.

    The boundary is about *reachability*: the VM frame is an ordinary table, so
    anything that must be visible to real Luau closures -- upvalues and the
    closures that capture them -- cannot live in it.  Refusing those is the
    honest option; approximating them is how a VM ends up subtly wrong.
    Varargs crossed this line in R5: the entry point stashes the caller's
    packed arguments in the frame, which is all a VARARG instruction ever
    needed -- nothing outside the call can observe them.  Upvalue *reads and
    writes* cross it here when ``upvalues_ok`` is set: the stub replaces the
    function and hands the interpreter accessor closures closing over the same
    expression the native reconstruction uses, so the frame never holds the
    shared state -- it holds live doors to it.  One boundary does not move
    even then: an upvalue whose home prototype is itself virtualized has its
    storage inside a frame no closure can see, so the selector refuses such a
    prototype (the pipeline enforces that; this function cannot see the
    module).

    ``fmt`` adds the size constraints that belong to a *format*: a jump target
    has to fit in the field that carries it, and an absolute target has to fit
    in the widest field, which is why the check runs here rather than as an
    exception at encode time.  A prototype that does not fit is left native
    with a reason, and the reason shows up in the report.
    """
    if proto.proto_id == 0:
        return False, "main chunk bootstraps the runtime"
    if proto.num_regs > MAX_REGISTERS:
        return False, f"{proto.num_regs} registers exceeds the VM's {MAX_REGISTERS}"
    if proto.children:
        return False, "creates closures"
    if proto.upvalues and not upvalues_ok:
        return False, "captures upvalues"
    if proto.upvalues:
        # Each upvalue index rides the wire's wide field.  In practice a
        # function captures a handful, but a prototype that captures more
        # than the field can count must be refused before encoding, not
        # crash inside it.
        for i in range(len(proto.upvalues)):
            if fmt is not None and i > fmt.max_wide(("w", "up")):
                return False, f"upvalue {i} does not fit the wire format"
    if proto.num_params > 255:
        return False, "too many parameters to encode"
    if _uses_coroutines(proto):
        return False, ("calls coroutine.* ; a yield across a VM frame cannot be "
                       "resumed by the interpreter")

    for block in proto.blocks:
        for ins in block.instrs:
            if ins.op not in SUPPORTED:
                reason = UNSUPPORTED_REASON.get(ins.op, "no VM handler")
                return False, f"{ins.op}: {reason}"
            vmop = vm_opcode(ins.op, ins.args)
            spec = FORMATS[vmop]
            # Checked against the IR's arity, not the VM's: they differ where
            # the encoder drops operands (NEWTABLE's allocation hints).
            expected = IR_ARITY.get(ins.op)
            if expected is not None and len(ins.args) != expected:
                return False, (f"{ins.op}: operand count {len(ins.args)}, "
                               f"expected {expected}")
            for pos in spec.regs:
                operand = ins.args[pos]
                if not isinstance(operand, Reg):
                    return False, f"{vmop}: operand {pos} is not a register"
                if operand.index >= MAX_REGISTERS:
                    return False, f"{vmop}: register {operand.index} out of range"

    if fmt is not None:
        limit = fmt.max_wide(("w", "target"))
        est = _estimate_size(proto, fmt)
        if est >= limit:
            return False, (f"{est} bytes of bytecode does not fit the format's "
                           f"{limit}-byte addressing")
    return True, ""


#: Names whose presence means the prototype may yield across the VM frame.
_COROUTINE_GLOBAL = "coroutine"


def _uses_coroutines(proto: FuncIR) -> bool:
    """Whether this prototype touches ``coroutine.*``.

    A virtualized function that yields would have to hand its whole interpreter
    frame to the coroutine scheduler, and the frame is a plain Luau table read
    by a plain Luau function -- there is nothing for the scheduler to resume.
    Refusing is the correct answer and the only safe one; the surrounding
    function still works, it just stays native.  (#58 asks for coroutine
    coverage; the honest coverage for the VM is that coroutine-using code is
    left alone and *tested* to still behave.)
    """
    for value in proto.consts:
        if isinstance(value, (bytes, bytearray)):
            if _COROUTINE_GLOBAL.encode() == bytes(value):
                return True
        elif isinstance(value, str) and value == _COROUTINE_GLOBAL:
            return True
    return False


def _estimate_size(proto: FuncIR, fmt: FormatSpec) -> int:
    total = fmt.header_size
    for block in proto.blocks:
        for ins in block.instrs:
            total += fmt.size(vm_opcode(ins.op, ins.args))
    # Fall-through repair adds a jump per block that needs one; over-estimating
    # by one instruction per block is fine for a "will it fit" check.
    total += len(proto.blocks) * fmt.size(OP.JMP)
    return total


def _reg_index(operand: Any, op: str) -> int:
    if not isinstance(operand, Reg):
        raise EncodingError(f"{op}: expected a register, got {operand!r}")
    return operand.index


def _wide(value: int, op: str, field: str, limit: int = MAX_WIDE) -> int:
    if value < 0 or value > limit:
        raise EncodingError(f"{op}: {field} {value} does not fit in the field")
    return value


def _biased(value: int, op: str, field: str, limit: int = MAX_WIDE) -> int:
    return _wide(value + BIAS, op, field, limit)


_JUMP_ARG = JUMP_ARG
_NO_FALLTHROUGH_OPS = NO_FALLTHROUGH_OPS
_CONDITIONAL_OPS = CONDITIONAL_OPS
_fallthrough = fallthrough


def _layout(proto: FuncIR,
            order: Optional[Sequence[int]],
            fmt: Optional[FormatSpec] = None) -> List[Tuple[Any, List[Instr]]]:
    """The blocks in emission order, each with the instructions to emit.

    Execution is linear between jumps, so a block runs into whatever the layout
    puts next.  In the IR's own order that is always where it should go, so
    nothing is added and the bytes are exactly what they were before this
    existed.  Under a permutation it may not be, and then the edge has to
    become an explicit ``JMP``.

    Both fall-through shapes need this, not just the terminator-less one.  A
    conditional jump moved to the end of the layout falls through past the last
    byte of the blob, which the interpreter reads as an opcode it does not
    know; the first version of this only handled the terminator-less case and
    was caught by the payload walk on the fifth permutation tried.
    """
    by_id = {b.id: b for b in proto.blocks}
    ids = list(order) if order is not None else [b.id for b in proto.blocks]
    if sorted(ids) != sorted(by_id):
        raise EncodingError(
            f"prototype {proto.proto_id}: layout order {ids} does not cover "
            f"exactly the blocks {sorted(by_id)}")

    blocks = [by_id[i] for i in ids]
    out: List[Tuple[Any, List[Instr]]] = []
    for i, block in enumerate(blocks):
        instrs = list(block.instrs)
        if fmt is not None and fmt.reorder:
            instrs = _reorder(instrs, fmt)
        following = blocks[i + 1].id if i + 1 < len(blocks) else None
        falls_into = _fallthrough(block)
        if falls_into is not None and falls_into != following:
            instrs.append(Instr(OP.JMP, (falls_into,)))
        out.append((block, instrs))
    return out


def _uses_defs(ins: Instr) -> Tuple[Set[int], Set[int]]:
    """The register indices one safe instruction reads and writes.

    Every opcode in :data:`_REORDER_SAFE` has the same shape -- one destination
    register, then a mix of register and constant sources -- which is what makes
    a generic rule legitimate here rather than lazy.  A new safe opcode with a
    different shape would have to say so, and
    ``test_reorder_safe_ops_share_one_shape`` is the test that notices when it
    does not.
    """
    uses = {arg.index for arg in ins.args[1:] if isinstance(arg, Reg)}
    return uses, {ins.args[0].index}


def _reorder(instrs: List[Instr], fmt: FormatSpec,
             rng: Any = None, chance: float = 0.5) -> List[Instr]:
    """Swap adjacent independent instructions where the format allows it (#33).

    A single forward pass with a swap test, not a scheduler.  A scheduler would
    find more freedom, and would also be a new piece of dataflow logic whose
    bugs are silent -- the whole reason this pass is written as "may these two
    instructions trade places, yes or no" is that the answer to that question is
    checkable by inspection, and the two instructions' registers are the only
    thing that matters.
    """
    out: List[Instr] = list(instrs)
    i = 0
    while i + 1 < len(out):
        x, y = out[i], out[i + 1]
        if x.op in _REORDER_SAFE and y.op in _REORDER_SAFE:
            x_use, x_def = _uses_defs(x)
            y_use, y_def = _uses_defs(y)
            independent = not ((x_def & y_use) or (y_def & x_use)
                               or (x_def & y_def))
            if independent and (rng is None or rng.chance(chance)):
                out[i], out[i + 1] = y, x
                i += 2
                continue
        i += 1
    return out


def _fusion_plan(instrs: List[Instr], rules: Sequence[FusionRule],
                 rng: Any, chance: float = 0.35) -> List[Any]:
    """Group instructions into units: a lone ``Instr`` or a ``(rule, a, b)``.

    Fusing is *only* about where the bytes sit and which handler consumes them.
    The two halves keep their order, nothing is reordered across the pair, and
    a pair is only formed between two instructions the format is willing to
    describe (#6).
    """
    by_pair = {r.name: r for r in rules}
    if not by_pair:
        return list(instrs)
    out: List[Any] = []
    i = 0
    while i < len(instrs):
        fused = None
        if i + 1 < len(instrs):
            a, b = instrs[i], instrs[i + 1]
            # The *VM* opcode, not the IR one: ``GETTABLE`` with a constant key is
            # encoded (and sized) as ``GETTABLEK``, and pairing on the IR name
            # gave a rule whose half-sizes were one byte short of the operands
            # the pair actually carried -- a payload that wrote past its own
            # instruction.
            oa, ob = vm_opcode(a.op, a.args), vm_opcode(b.op, b.args)
            if (oa in FUSABLE and ob in FUSABLE):
                key = "FUSE_%s_%s" % (oa, ob)
                rule = by_pair.get(key)
                if rule is not None and (rng is None or rng.chance(chance)):
                    fused = (rule, a, b)
        if fused is not None:
            out.append(fused)
            i += 2
        else:
            out.append(instrs[i])
            i += 1
    return out


def _field_values(ins: Instr, op: str, fmt: FormatSpec, nconsts: int,
                  target_of, edges: Optional[List[int]] = None
                  ) -> Dict[Tuple[Any, ...], int]:
    """This instruction's operand values, keyed by format field.

    Values are *semantic*: a register index, a constant slot, a count.  Masks,
    biases and the target representation are applied by :meth:`FormatSpec.store`
    at write time, so this function is the only place that has to know the IR's
    operand order, and it is the only thing that had to survive the move from a
    hand-written per-opcode byte layout to a generated one.
    """
    a = ins.args
    limit = fmt.max_wide(("w", "x"))
    values: Dict[Tuple[Any, ...], int] = {}

    def r(pos: int) -> int:
        return _reg_index(a[pos], op)

    def k(pos: int, field: str) -> int:
        value = a[pos]
        # Strict on purpose.  Reg and Kon both carry `.index`, so duck-typing
        # here would encode a register key as a constant index and produce a
        # stream that decodes cleanly into the wrong program.
        if not isinstance(value, Kon):
            raise EncodingError(
                f"{op}: {field} must be a constant, got {type(value).__name__}")
        index = value.index
        if index < 0 or index >= nconsts:
            raise EncodingError(f"{op}: constant index {index} out of range")
        return index

    def tgt(op_name: str, block_id: int) -> None:
        values[("w", "target")] = target_of(block_id, op_name)

    if op == OP.MOV:
        values[("r", 0)], values[("r", 1)] = r(0), r(1)
    elif op == OP.LOADK:
        values[("r", 0)], values[("w", "konst")] = r(0), k(1, "konst")
    elif op == OP.GETGLOBAL:
        values[("r", 0)], values[("w", "name")] = r(0), k(1, "name")
    elif op == OP.SETGLOBAL:
        values[("w", "name")], values[("r", 1)] = k(0, "name"), r(1)
    elif op == OP.GETTABLE:
        values[("r", 0)], values[("r", 1)], values[("r", 2)] = r(0), r(1), r(2)
    elif op == OP_GETTABLEK:
        values[("r", 0)], values[("r", 1)] = r(0), r(1)
        values[("w", "key")] = k(2, "key")
    elif op == OP.SETTABLE:
        values[("r", 0)], values[("r", 1)], values[("r", 2)] = r(0), r(1), r(2)
    elif op == OP_SETTABLEK:
        values[("r", 0)], values[("r", 2)] = r(0), r(2)
        values[("w", "key")] = k(1, "key")
    elif op == OP.NEWTABLE:
        values[("r", 0)] = r(0)
    elif op in (OP.ADD, OP.SUB, OP.MUL, OP.DIV, OP.IDIV, OP.MOD, OP.POW,
                OP.CONCAT, OP.EQ, OP.NE, OP.LT, OP.LE, OP.GT, OP.GE):
        values[("r", 0)], values[("r", 1)], values[("r", 2)] = r(0), r(1), r(2)
    elif op in (OP.UNM, OP.NOT, OP.LEN):
        values[("r", 0)], values[("r", 1)] = r(0), r(1)
    elif op == OP.CALL:
        values[("r", 0)] = r(0)
        values[("w", "argc")] = _wide(int(a[1]), op, "argc", limit)
        values[("w", "nres")] = _biased(int(a[2]), op, "nres", limit)
        values[("w", "tail")] = _biased(int(a[3]), op, "tail", limit)
    elif op == OP.VARARG:
        values[("r", 0)] = r(0)
        values[("w", "count")] = _biased(int(a[1]), op, "count", limit)
    # ``up`` is an index into the accessor list the stub built for this
    # prototype -- an unsigned immediate, no bias.  The operand is an ``Up``,
    # not an int, so the index is spelled out.
    elif op == OP.GETUPVAL:
        values[("r", 0)] = r(0)
        values[("w", "up")] = _wide(a[1].index, op, "up", limit)
    elif op == OP.SETUPVAL:
        values[("r", 1)] = r(1)
        values[("w", "up")] = _wide(a[0].index, op, "up", limit)
    elif op == OP.TAILCALL:
        values[("r", 0)] = r(0)
        values[("w", "argc")] = _wide(int(a[1]), op, "argc", limit)
        values[("w", "tail")] = _biased(int(a[2]), op, "tail", limit)
    elif op == OP.RETURN:
        values[("r", 0)] = r(0)
        values[("w", "count")] = _wide(int(a[1]), op, "count", limit)
    elif op == OP.RETURN0:
        pass
    elif op == OP.RETURNMULTI:
        values[("r", 0)] = r(0)
        values[("w", "count")] = _wide(int(a[1]), op, "count", limit)
        values[("w", "pack")] = _wide(int(a[2]), op, "pack", limit)
    elif op == OP.EXPAND:
        values[("r", 0)] = r(0)
        values[("w", "pack")] = _wide(int(a[1]), op, "pack", limit)
        values[("w", "count")] = _wide(int(a[2]), op, "count", limit)
    elif op == OP.SETLIST:
        values[("r", 0)] = r(0)
        values[("w", "count")] = _wide(int(a[1]), op, "count", limit)
        values[("w", "start")] = _wide(int(a[2]), op, "start", limit)
    elif op == OP.SETLISTMULTI:
        values[("r", 0)] = r(0)
        # a register index in a wide slot: raw (zero-based) here, biased by the
        # reader, exactly like RETURNMULTI/EXPAND
        values[("w", "pack")] = _wide(int(a[1]), op, "pack", limit)
    elif op == OP.SELF:
        values[("r", 0)], values[("r", 1)] = r(0), r(1)
        values[("w", "name")] = k(2, "name")
    elif op == OP.JMP:
        tgt(op, int(a[0]))
    elif op in (OP.JMPFALSE, OP.JMPTRUE):
        values[("r", 0)] = r(0)
        tgt(op, int(a[1]))
    elif op in (OP.FORPREP, OP.FORLOOP):
        values[("r", 0)] = r(0)
        tgt(op, int(a[1]))
    elif op == OP.FORINPREP:
        values[("r", 0)] = r(0)
        tgt(op, int(a[1]))
        resolved = int(a[2]) if len(a) > 2 else 0
        values[("w", "resolved")] = _wide(resolved, op, "resolved", limit)
    elif op == OP.FORIN:
        values[("r", 0)] = r(0)
        tgt(op, int(a[1]))
        nvars = int(a[2]) if len(a) > 2 else 2
        values[("w", "nvars")] = _wide(nvars, op, "nvars", limit)
    elif op == OP.ITERPREP:
        values[("r", 0)] = r(0)
        packed = int(a[1]) if len(a) > 1 else 0
        values[("w", "packed")] = _wide(packed, op, "packed", limit)
    else:  # pragma: no cover - can_virtualize rejects anything unsupported
        raise EncodingError(f"{op} has no encoder")
    return values


def _instruction_size(ins: Instr, fmt: Optional[FormatSpec] = None) -> int:
    op = vm_opcode(ins.op, ins.args)
    return operand_size(op, fmt)


def required_ops(proto: FuncIR, fmt: Optional[FormatSpec] = None, *,
                 permuted_blocks: bool = False) -> Optional[Set[str]]:
    """The VM opcodes one prototype needs, or None if it cannot be answered here.

    This is the input to per-group instruction sets: a group that only runs three
    numeric helpers should not carry 43 arms.  It is deliberately a *superset* of
    what the encoder will emit, because the safe direction to be wrong in is
    "one arm too many" -- an op missing from the map is a build failure, an extra
    one is a few dead bytes.

    So anything the encoder may add on its own is included without trying to
    predict it: both halves of every fusion rule the format understands (the
    choice to fuse a pair is the encoder's, made per block with the build's
    randomness), and a ``JMP`` whenever block layout can be permuted, because
    :func:`_layout` inserts explicit jumps where a fall-through stopped being the
    right edge.  Return values the opcode mapping cannot name -- an IR instruction
    that is not in the VM's set, or one whose ``vm_opcode`` depends on more than
    the IR -- also collapse to None, which the caller reads as "no subset".
    """
    spec = fmt if fmt is not None else LEGACY_SPEC
    ops: Set[str] = set()
    for block in proto.blocks:
        for ins in block.instrs:
            if ins.op not in SUPPORTED:
                return None
            try:
                expected = IR_ARITY.get(ins.op)
                if expected is not None and len(ins.args) != expected:
                    return None
                ops.add(vm_opcode(ins.op, ins.args))
            except (KeyError, IndexError, TypeError):
                return None
    if permuted_blocks:
        ops.add(OP.JMP)
    for rule in spec.fused:
        ops.add(rule.first)
        ops.add(rule.second)
    return ops


def encode_proto(proto: FuncIR, opmap: OpcodeMap,
                 order: Optional[Sequence[int]] = None,
                 fmt: Optional[FormatSpec] = None,
                 rng: Any = None,
                 alias_chance: float = 0.0,
                 upvalues_ok: bool = False) -> EncodedProto:
    """Encode one prototype.  Raises if it cannot be virtualized.

    ``order`` is the block emission order, as a sequence of block ids.  It
    defaults to the IR's own order, which leaves the output byte-identical to
    an unpermuted build; see :mod:`couxobf.vm.layout`.

    ``fmt`` is the instruction format, ``None`` meaning the historical layout.
    ``rng`` powers the optional passes the format can ask for -- in-block
    reordering, padding, filler bytes -- and the choice of alias opcode numbers.
    Leaving ``rng`` out is how a test encodes a prototype deterministically
    against a chosen format.
    """
    spec = fmt if fmt is not None else LEGACY_SPEC
    ok, reason = can_virtualize(proto, spec, upvalues_ok=upvalues_ok)
    if not ok:
        raise EncodingError(f"prototype {proto.proto_id} is not virtualizable: "
                            f"{reason}")

    consts: List[Any] = list(proto.consts)
    # Reordering is applied while the block's instruction list is being laid
    # out, before offsets exist: doing it afterwards would move bytes without
    # moving the jump targets that were already resolved against them.
    layout = _layout(proto, order, spec if spec.reorder else None)
    units_by_block = [
        (block, _fusion_plan(instrs, spec.fused, rng) if spec.fused else instrs)
        for block, instrs in layout
    ]

    # First pass: lay blocks out and record where each one starts, so jump
    # operands (which name block ids in the IR) can become byte offsets.
    offsets: Dict[int, int] = {}
    starts: List[int] = []
    pc = spec.header_size
    for block, units in units_by_block:
        offsets[block.id] = pc
        for unit in units:
            # Recorded for the integrity check: a payload validator can only
            # rediscover instruction boundaries by decoding, and decoding from
            # a wrong offset sometimes succeeds by luck.  Carrying the real
            # boundaries turns that check from probabilistic into exact.
            starts.append(pc)
            pc += _unit_size(unit, spec)

    def target(block_id: int, op: str) -> int:
        if block_id not in offsets:
            raise EncodingError(f"{op}: targets unknown block {block_id}")
        return offsets[block_id]

    # In ``edges`` mode the jump operands name entries in this table instead of
    # positions in the stream, and the table travels with the descriptor.
    edges: List[int] = []
    edge_index: Dict[int, int] = {}

    out = bytearray()
    out += spec.header.pack({
        "nparams": proto.num_params,
        "flags": FLAG_VARARG if proto.is_vararg else 0,
        "nregs": proto.num_regs,
        "nconsts": len(consts),
        "entry": offsets[proto.entry],
    })

    for block, units in units_by_block:
        for unit in units:
            out += _encode_unit(unit, opmap, spec, target, len(consts), len(out),
                                edges, edge_index, rng, alias_chance)

    n_fused = sum(1 for _b, units in units_by_block for u in units
                  if isinstance(u, tuple))
    n_units = sum(len(units) for _b, units in units_by_block)
    return EncodedProto(
        proto_id=proto.proto_id,
        name=proto.name,
        code=bytes(out),
        nparams=proto.num_params,
        nregs=proto.num_regs,
        is_vararg=proto.is_vararg,
        entry=offsets[proto.entry],
        consts=consts,
        starts=tuple(starts),
        edges=tuple(edges),
        fmt=spec,
        instructions=n_units,
        fused=n_fused,
        pad_bytes=n_units * spec.pad,
    )


def _unit_size(unit: Any, fmt: FormatSpec) -> int:
    """How many bytes one unit occupies.

    Always derived from the instructions themselves rather than from the fusion
    rule: the rule names the *pair*, and a pair whose halves resolve to wider
    opcodes than it says is exactly the mismatch that used to write operands
    past the end of the unit.
    """
    if isinstance(unit, tuple):
        rule, a, b = unit
        size = fmt.fused_pair_size(vm_opcode(a.op, a.args),
                                   vm_opcode(b.op, b.args))
        if size != fmt.fused_size(rule):  # pragma: no cover - defensive
            raise EncodingError(
                "%s's halves need %d bytes, the rule allows %d"
                % (rule.name, size, fmt.fused_size(rule)))
        return size
    return fmt.size(vm_opcode(unit.op, unit.args))


def _unit_halves(unit: Any, fmt: FormatSpec, nconsts: int, target,
                 rng: Any) -> Tuple[int, List[Tuple[Dict[Any, int], Dict[Any, int]]]]:
    """This unit's size, and its one or two operand halves.

    Each half is ``(values, offsets)``: what the operands mean, and where the
    format puts them.  A plain instruction is one half; a fused pair is two, the
    second based where the first ends, which is what keeps a fused handler from
    needing operand offsets of its own.
    """
    if isinstance(unit, tuple):
        rule, a, b = unit
        oa = vm_opcode(a.op, a.args)
        ob = vm_opcode(b.op, b.args)
        va = _field_values(a, oa, fmt, nconsts, target, None)
        vb = _field_values(b, ob, fmt, nconsts, target, None)
        shift = fmt.size(oa) - fmt.op_bytes
        ob_offsets = {k: v + shift for k, v in fmt.offsets(ob).items()}
        return (_unit_size(unit, fmt),
                [(va, fmt.offsets(oa)), (vb, ob_offsets)])
    op = vm_opcode(unit.op, unit.args)
    values = _field_values(unit, op, fmt, nconsts, target, None)
    return fmt.size(op), [(values, fmt.offsets(op))]


def _encode_unit(unit: Any, opmap: OpcodeMap, fmt: FormatSpec, target,
                 nconsts: int, instr_start: int, edges: Optional[List[int]],
                 edge_index: Optional[Dict[int, int]], rng: Any,
                 alias_chance: float) -> bytes:
    """Encode one instruction, or one fused pair, as bytes.

    A fused pair is a single instruction whose operand region is the first
    half's region followed by the second half's, under one opcode number that
    only this build assigns.  Nothing about either half changes -- both operands
    keep their offsets relative to their own half -- so the handler for a pair
    is the two ordinary handlers run back to back, and the risk this pass adds
    is layout risk rather than semantic risk.

    Masking happens last, once every operand has its final value, because the
    order matters: a relative offset is computed from real positions and then
    disguised.  Masking a value that had already been wrapped into its field
    would decode to something else entirely.
    """
    fused = isinstance(unit, tuple)
    size, halves = _unit_halves(unit, fmt, nconsts, target, rng)
    body = bytearray(size)

    if fused:
        number = _fused_number(opmap, unit[0])
    else:
        number = _pick_number(opmap, vm_opcode(unit.op, unit.args), rng,
                              alias_chance)
    # The stream carries the cipher's image of the number, never the number the
    # dispatcher compares against.  One write site, one read site (`_ro` in the
    # generated reader, `opcode_at` in the validator), both derived from the same
    # FormatSpec -- so this cannot disagree with the interpreter the way two
    # hand-written halves of a format always eventually do.
    number = fmt.encode_op(number, instr_start + 1)
    for i in range(fmt.op_bytes):
        body[i] = (number >> (8 * i)) & 0xFF
    if fmt.pad:
        # Padding exists to break "operands start immediately after the opcode";
        # filling it with nothing would leave a run of zero bytes that says the
        # same thing as the constant-width encoding did.
        for values, offsets in halves:
            base = min(offsets.values()) - fmt.pad if offsets else fmt.op_bytes
            for i in range(fmt.pad):
                body[base + i] = rng.byte() if rng is not None else 0

    for values, offsets in halves:
        missing = [k for k in offsets if k not in values]
        if missing:
            # Silent zeros here would produce a stream that decodes cleanly into
            # the wrong program, which is the one failure mode a format-driven
            # encoder must not be able to have.
            raise EncodingError("%s: no operand value for %r"
                                % (getattr(unit, "op", "fused"), sorted(missing)))
        if fmt.target_mode == "edges" and edges is not None \
                and ("w", "target") in values:
            values[("w", "target")] = _edge_index(values[("w", "target")],
                                                  edges, edge_index)
        for key, at in offsets.items():
            value = values.get(key, 0)
            stored = fmt.store(key, value,
                               is_target=(key == ("w", "target")),
                               instr_start=instr_start, instr_size=size,
                               target=value)
            width = fmt.width(key)
            for i in range(width):
                body[at + i] = (stored >> (8 * i)) & 0xFF
    if len(body) != size:  # pragma: no cover - defensive
        raise EncodingError(f"unit encoded to {len(body)} bytes, expected {size}")
    return bytes(body)


def _edge_index(abs_target: int, edges: List[int],
                edge_index: Optional[Dict[int, int]]) -> int:
    """Register one jump target in the edge table and return its index.

    The table is emitted next to the payload but not inside it, so an
    instruction's control-flow destination is a small ordinal whose meaning only
    exists in a second structure (#18).  Two jumps to the same block share an
    entry, which is a real saving and also denies the analyst a one-to-one
    mapping from edge index to site.
    """
    if edge_index is None:
        return abs_target
    hit = edge_index.get(abs_target)
    if hit is not None:
        return hit
    index = len(edges)
    edges.append(abs_target)
    edge_index[abs_target] = index
    return index


def _pick_number(opmap: OpcodeMap, op: str, rng: Any, alias_chance: float) -> int:
    """Choose one of the numbers this build assigns to ``op``.

    Using an alias for *some* occurrences, rather than never, is what makes the
    alias set more than dead code in the dispatch chain: an analyst who maps
    number to handler has to find every number that reaches the same handler,
    and a build that only ever used the primary would let them stop at the
    first one.
    """
    if rng is None or alias_chance <= 0:
        return opmap.byte(op)
    numbers = opmap.numbers(op)
    if len(numbers) == 1 or not rng.chance(alias_chance):
        return numbers[0]
    return numbers[rng.randbelow(len(numbers))]


def _fused_number(opmap: OpcodeMap, rule: FusionRule) -> int:
    for number, pair in (opmap.fused or {}).items():
        if pair[0] == rule.first and pair[1] == rule.second:
            return number
    raise EncodingError(f"{rule.name} has no opcode in this build's map")


def decode_header(code: bytes, fmt: Optional[FormatSpec] = None
                  ) -> Tuple[int, int, int, int, int]:
    """Read a header back -- used by tests to check the format round-trips."""
    if fmt is None:
        nparams, flags, nregs, nconsts, entry = HEADER.unpack_from(code, 0)
        return nparams, flags, nregs, nconsts, entry
    h = fmt.header.parse(code)
    return (h["nparams"], h["flags"], h["nregs"], h["nconsts"], h["entry"])

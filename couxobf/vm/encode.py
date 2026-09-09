"""Encode IR prototypes into VM bytecode.

One prototype becomes one byte string plus a small descriptor.  The descriptor
holds what cannot be bytes -- the constant list, the parameter count, the
register count -- and the byte string holds the instructions.

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
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..ir import MULTIRET, OP, FuncIR, Instr, Kon, Reg
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

    @property
    def lua_entry(self) -> int:
        """The entry point as a ``string.byte`` index, ready for the runtime."""
        return self.entry + LUA_INDEX_BIAS


def can_virtualize(proto: FuncIR) -> Tuple[bool, str]:
    """Whether this prototype can run in the VM, and why not if it cannot.

    The boundary is about *reachability*: the VM frame is an ordinary table, so
    anything that must be visible to real Luau closures -- upvalues, varargs,
    nested closures -- cannot live in it.  Refusing those is the honest option;
    approximating them is how a VM ends up subtly wrong.
    """
    if proto.proto_id == 0:
        return False, "main chunk bootstraps the runtime"
    if proto.is_vararg:
        return False, "varargs need the caller's frame"
    if proto.num_regs > MAX_REGISTERS:
        return False, f"{proto.num_regs} registers exceeds the VM's {MAX_REGISTERS}"
    if proto.children:
        return False, "creates closures"
    if proto.upvalues:
        return False, "captures upvalues"
    if proto.num_params > 255:
        return False, "too many parameters to encode"

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
    return True, ""


def _reg_index(operand: Any, op: str) -> int:
    if not isinstance(operand, Reg):
        raise EncodingError(f"{op}: expected a register, got {operand!r}")
    return operand.index


def _wide(value: int, op: str, field: str) -> int:
    if value < 0 or value > MAX_WIDE:
        raise EncodingError(f"{op}: {field} {value} does not fit in two bytes")
    return value


def _biased(value: int, op: str, field: str) -> int:
    return _wide(value + BIAS, op, field)


_JUMP_ARG = JUMP_ARG
_NO_FALLTHROUGH_OPS = NO_FALLTHROUGH_OPS
_CONDITIONAL_OPS = CONDITIONAL_OPS
_fallthrough = fallthrough


def _layout(proto: FuncIR,
            order: Optional[Sequence[int]]) -> List[Tuple[Any, List[Instr]]]:
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
        following = blocks[i + 1].id if i + 1 < len(blocks) else None
        falls_into = _fallthrough(block)
        if falls_into is not None and falls_into != following:
            instrs.append(Instr(OP.JMP, (falls_into,)))
        out.append((block, instrs))
    return out


def encode_proto(proto: FuncIR, opmap: OpcodeMap,
                 order: Optional[Sequence[int]] = None) -> EncodedProto:
    """Encode one prototype.  Raises if it cannot be virtualized.

    ``order`` is the block emission order, as a sequence of block ids.  It
    defaults to the IR's own order, which leaves the output byte-identical to
    an unpermuted build; see :mod:`couxobf.vm.layout`.
    """
    ok, reason = can_virtualize(proto)
    if not ok:
        raise EncodingError(f"prototype {proto.proto_id} is not virtualizable: {reason}")

    consts: List[Any] = list(proto.consts)
    layout = _layout(proto, order)

    # First pass: lay blocks out and record where each one starts, so jump
    # operands (which name block ids in the IR) can become byte offsets.
    offsets: Dict[int, int] = {}
    starts: List[int] = []
    pc = HEADER.size
    for block, instrs in layout:
        offsets[block.id] = pc
        for ins in instrs:
            # Recorded for the integrity check: a payload validator can only
            # rediscover instruction boundaries by decoding, and decoding from
            # a wrong offset sometimes succeeds by luck.  Carrying the real
            # boundaries turns that check from probabilistic into exact.
            starts.append(pc)
            pc += _instruction_size(ins)

    def target(block_id: int, op: str) -> int:
        if block_id not in offsets:
            raise EncodingError(f"{op}: targets unknown block {block_id}")
        return offsets[block_id]

    out = bytearray()
    out += HEADER.pack(
        proto.num_params,
        FLAG_VARARG if proto.is_vararg else 0,
        proto.num_regs,
        len(consts),
        offsets[proto.entry],
    )

    for block, instrs in layout:
        for ins in instrs:
            out += _encode_instruction(ins, opmap, target, len(consts))

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
    )


def _instruction_size(ins: Instr) -> int:
    return operand_size(vm_opcode(ins.op, ins.args))


def _encode_instruction(ins: Instr, opmap: OpcodeMap, target, nconsts: int) -> bytes:
    """Encode one instruction.  Dispatch mirrors ir.py's operand order.

    ``op`` below is the *VM* opcode, which differs from the IR opcode only for
    ``SETTABLE`` (register key vs. constant key).
    """
    op = vm_opcode(ins.op, ins.args)
    a = ins.args
    body = bytearray([opmap.byte(op)])

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

    if op == OP.MOV:
        body += bytes([r(0), r(1)])
    elif op == OP.LOADK:
        body += bytes([r(0)]) + struct.pack("<H", k(1, "konst"))
    elif op == OP.GETGLOBAL:
        body += bytes([r(0)]) + struct.pack("<H", k(1, "name"))
    elif op == OP.SETGLOBAL:
        body += struct.pack("<H", k(0, "name")) + bytes([r(1)])
    elif op == OP.GETTABLE:
        body += bytes([r(0), r(1), r(2)])
    elif op == OP_GETTABLEK:
        body += bytes([r(0), r(1)]) + struct.pack("<H", k(2, "key"))
    elif op == OP.SETTABLE:
        body += bytes([r(0), r(1), r(2)])
    elif op == OP_SETTABLEK:
        body += bytes([r(0), r(2)]) + struct.pack("<H", k(1, "key"))
    elif op == OP.NEWTABLE:
        body += bytes([r(0)])
    elif op in (OP.ADD, OP.SUB, OP.MUL, OP.DIV, OP.IDIV, OP.MOD, OP.POW,
                OP.CONCAT, OP.EQ, OP.NE, OP.LT, OP.LE, OP.GT, OP.GE):
        body += bytes([r(0), r(1), r(2)])
    elif op in (OP.UNM, OP.NOT, OP.LEN):
        body += bytes([r(0), r(1)])
    elif op == OP.CALL:
        base, argc, nres, tail = r(0), int(a[1]), int(a[2]), int(a[3])
        body += bytes([base]) + struct.pack(
            "<HHH", _wide(argc, op, "argc"), _biased(nres, op, "nres"),
            _biased(tail, op, "tail"))
    elif op == OP.TAILCALL:
        base, argc, tail = r(0), int(a[1]), int(a[2])
        body += bytes([base]) + struct.pack(
            "<HH", _wide(argc, op, "argc"), _biased(tail, op, "tail"))
    elif op == OP.RETURN:
        body += bytes([r(0)]) + struct.pack("<H", _wide(int(a[1]), op, "count"))
    elif op == OP.RETURN0:
        pass
    elif op == OP.RETURNMULTI:
        body += bytes([r(0)]) + struct.pack(
            "<HH", _wide(int(a[1]), op, "count"), _wide(int(a[2]), op, "pack"))
    elif op == OP.EXPAND:
        body += bytes([r(0)]) + struct.pack(
            "<HH", _wide(int(a[1]), op, "pack"), _wide(int(a[2]), op, "count"))
    elif op == OP.SETLIST:
        body += bytes([r(0)]) + struct.pack(
            "<HH", _wide(int(a[1]), op, "count"), _wide(int(a[2]), op, "start"))
    elif op == OP.SETLISTMULTI:
        body += bytes([r(0)]) + struct.pack("<H", _wide(int(a[1]), op, "pack"))
    elif op == OP.SELF:
        body += bytes([r(0), r(1)]) + struct.pack("<H", k(2, "name"))
    elif op == OP.JMP:
        body += struct.pack("<H", target(int(a[0]), op))
    elif op in (OP.JMPFALSE, OP.JMPTRUE):
        body += bytes([r(0)]) + struct.pack("<H", target(int(a[1]), op))
    elif op in (OP.FORPREP, OP.FORLOOP):
        body += bytes([r(0)]) + struct.pack("<H", target(int(a[1]), op))
    elif op == OP.FORINPREP:
        resolved = int(a[2]) if len(a) > 2 else 0
        body += bytes([r(0)]) + struct.pack(
            "<HH", target(int(a[1]), op), _wide(resolved, op, "resolved"))
    elif op == OP.FORIN:
        nvars = int(a[2]) if len(a) > 2 else 2
        body += bytes([r(0)]) + struct.pack(
            "<HH", target(int(a[1]), op), _wide(nvars, op, "nvars"))
    elif op == OP.ITERPREP:
        packed = int(a[1]) if len(a) > 1 else 0
        body += bytes([r(0)]) + struct.pack("<H", _wide(packed, op, "packed"))
    else:  # pragma: no cover - can_virtualize rejects anything unsupported
        raise EncodingError(f"{op} has no encoder")

    expected = _instruction_size(ins)
    if len(body) != expected:  # pragma: no cover - defensive
        raise EncodingError(f"{op} encoded to {len(body)} bytes, expected {expected}")
    return bytes(body)


def decode_header(code: bytes) -> Tuple[int, int, int, int, int]:
    """Read a header back -- used by tests to check the format round-trips."""
    nparams, flags, nregs, nconsts, entry = HEADER.unpack_from(code, 0)
    return nparams, flags, nregs, nconsts, entry

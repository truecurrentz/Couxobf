"""The virtual instruction set.

This is the ISA the protection VM executes.  It is deliberately close to the
IR -- one VM opcode per IR opcode, same operand order -- because every
difference is a place the encoder and the interpreter can disagree, and those
bugs are silent.

What makes it *virtual* rather than just a rename:

*The opcode numbers are permuted per build.*  ``ADD`` is not the same byte in
two builds, so a handler located in one build is not found by number in the
next.

*Operands are raw bytes, not Luau syntax.*  The program becomes data.  A reader
gets a byte string and a dispatcher, not a function they can skim.

*The program counter is a byte offset into that string*, so there is no
instruction array to dump -- the bytes are decoded one instruction at a time as
the dispatcher reaches them.

The permutation is a real cost to an analyst and it is also honest about its
limits: it defeats *number*-based matching, not structural matching. Someone
who identifies the add handler by what it does has it regardless of its number.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

from ..ir import OP, Reg
from ..rng import Rng

#: Registers are one byte, so a virtualized prototype is capped at 256.  The
#: reconstructor's table-backed register file has no such limit; this is a VM
#: limit and prototypes over it simply are not virtualized.
MAX_REGISTERS = 256

#: Everything else -- constant indices, jump targets -- is two bytes, little
#: endian.  Jump targets are byte offsets, not instruction numbers, because
#: instructions are variable length.
WIDE_BYTES = 2
MAX_WIDE = 0xFFFF


@dataclass(frozen=True)
class OperandSpec:
    """The shape of one instruction's operands.

    ``regs`` is the number of single-byte register operands, in order.
    ``wides`` is the number of two-byte operands after them.  Anything an
    instruction needs beyond that does not belong in this ISA.
    """

    regs: Tuple[int, ...] = ()
    wides: Tuple[str, ...] = ()

    @property
    def size(self) -> int:
        return 1 + len(self.regs) + WIDE_BYTES * len(self.wides)


# Instruction formats.  Operand order matches the IR exactly; see ir.py for
# what each means.  Comments record the non-obvious ones.
#: VM opcodes for the IR's constant-key table forms.  Not IR opcodes -- nothing
#: in the IR emits them; the encoder picks between the pair by looking at
#: whether the key operand is a Kon or a Reg.
OP_SETTABLEK = "SETTABLEK"
OP_GETTABLEK = "GETTABLEK"

FORMATS: Dict[str, OperandSpec] = {
    OP.MOV:          OperandSpec(regs=(0, 1)),
    OP.LOADK:        OperandSpec(regs=(0,), wides=("konst",)),
    OP.GETGLOBAL:    OperandSpec(regs=(0,), wides=("name",)),
    OP.SETGLOBAL:    OperandSpec(wides=("name",), regs=(1,)),
    OP.GETTABLE:     OperandSpec(regs=(0, 1, 2)),       # key is a register
    OP_GETTABLEK:    OperandSpec(regs=(0, 1), wides=("key",)),  # key is a konst
    # IR SETTABLE has two shapes and the VM gives them two opcodes, because
    # `t.k = v` lowers the key to a constant and `t[k] = v` lowers it to a
    # register.  One opcode with a variable-width key would make instruction
    # size depend on an operand -- which is exactly how a decoder loses sync
    # and starts reading operands as opcodes.
    OP.SETTABLE:     OperandSpec(regs=(0, 1, 2)),       # obj, key reg, value
    OP_SETTABLEK:    OperandSpec(regs=(0, 2), wides=("key",)),  # key is a konst
    OP.NEWTABLE:     OperandSpec(regs=(0,)),
    OP.ADD:          OperandSpec(regs=(0, 1, 2)),
    OP.SUB:          OperandSpec(regs=(0, 1, 2)),
    OP.MUL:          OperandSpec(regs=(0, 1, 2)),
    OP.DIV:          OperandSpec(regs=(0, 1, 2)),
    OP.IDIV:         OperandSpec(regs=(0, 1, 2)),
    OP.MOD:          OperandSpec(regs=(0, 1, 2)),
    OP.POW:          OperandSpec(regs=(0, 1, 2)),
    OP.UNM:          OperandSpec(regs=(0, 1)),
    OP.NOT:          OperandSpec(regs=(0, 1)),
    OP.LEN:          OperandSpec(regs=(0, 1)),
    OP.CONCAT:       OperandSpec(regs=(0, 1, 2)),
    OP.EQ:           OperandSpec(regs=(0, 1, 2)),
    OP.NE:           OperandSpec(regs=(0, 1, 2)),
    OP.LT:           OperandSpec(regs=(0, 1, 2)),
    OP.LE:           OperandSpec(regs=(0, 1, 2)),
    OP.GT:           OperandSpec(regs=(0, 1, 2)),
    OP.GE:           OperandSpec(regs=(0, 1, 2)),
    # CALL base, argc, nres, tail: argc/nres/tail are wide so MULTIRET (-1)
    # survives; it is encoded as a bias, see encode.py.
    OP.CALL:         OperandSpec(regs=(0,), wides=("argc", "nres", "tail")),
    OP.TAILCALL:     OperandSpec(regs=(0,), wides=("argc", "tail")),
    OP.RETURN:       OperandSpec(regs=(0,), wides=("count",)),
    OP.RETURN0:      OperandSpec(),
    OP.RETURNMULTI:  OperandSpec(regs=(0,), wides=("count", "pack")),
    OP.EXPAND:       OperandSpec(regs=(0,), wides=("pack", "count")),
    OP.SETLIST:      OperandSpec(regs=(0,), wides=("count", "start")),
    OP.SETLISTMULTI: OperandSpec(regs=(0,), wides=("pack",)),
    OP.SELF:         OperandSpec(regs=(0, 1), wides=("name",)),
    OP.JMP:          OperandSpec(wides=("target",)),
    OP.JMPFALSE:     OperandSpec(regs=(0,), wides=("target",)),
    OP.JMPTRUE:      OperandSpec(regs=(0,), wides=("target",)),
    OP.FORPREP:      OperandSpec(regs=(0,), wides=("target",)),
    OP.FORLOOP:      OperandSpec(regs=(0,), wides=("target",)),
    OP.FORINPREP:    OperandSpec(regs=(0,), wides=("target", "resolved")),
    OP.FORIN:        OperandSpec(regs=(0,), wides=("target", "nvars")),
    OP.ITERPREP:     OperandSpec(regs=(0,), wides=("packed",)),
}

#: Opcodes the interpreter implements.  A prototype using anything else is not
#: virtualized -- see ``couxobf.vm.encode.can_virtualize``.
SUPPORTED = frozenset(FORMATS)

#: Opcodes that cannot be virtualized at all, and why.  These are not "not yet"
#: in the sense of an oversight: each one needs VM state to be reachable from
#: ordinary Luau closures, which is a different and harder design.
UNSUPPORTED_REASON = {
    OP.CLOSURE: "creates a closure; its upvalues would have to point into VM state",
    OP.GETUPVAL: "reads an upvalue; the VM frame is not a Luau closure",
    OP.SETUPVAL: "writes an upvalue; the VM frame is not a Luau closure",
    OP.VARARG: "varargs need the caller's frame, which the VM does not model",
    OP.NOP: "removed by the optimizer before encoding",
    OP.LABEL: "resolved away during lowering",
}


@dataclass
class OpcodeMap:
    """A per-build assignment of opcode numbers.

    ``encode`` and ``decode`` both go through this, so a build cannot get out of
    sync with itself.  Numbers start at 1 because ``string.byte`` returns nil
    past the end of the string, and a stray 0 would read as a valid opcode.
    """

    to_byte: Dict[str, int]
    to_op: Dict[int, str]

    @classmethod
    def identity(cls) -> "OpcodeMap":
        ops = sorted(SUPPORTED)
        return cls(to_byte={op: i + 1 for i, op in enumerate(ops)},
                   to_op={i + 1: op for i, op in enumerate(ops)})

    @classmethod
    def shuffled(cls, rng: Rng) -> "OpcodeMap":
        # sorted, not list(SUPPORTED): iterating a set of strings follows
        # PYTHONHASHSEED, so an unsorted base would make "same seed, same
        # output" false across processes.
        ops = sorted(SUPPORTED)
        order = [ops[j] for j in rng.permutation(len(ops))]
        return cls(to_byte={op: i + 1 for i, op in enumerate(order)},
                   to_op={i + 1: op for i, op in enumerate(order)})

    def byte(self, op: str) -> int:
        try:
            return self.to_byte[op]
        except KeyError:
            raise KeyError(f"{op} is not in this build's opcode map") from None

    def size(self) -> int:
        return len(self.to_byte)


def operand_size(op: str) -> int:
    """Encoded length in bytes of one instruction of this opcode."""
    spec = FORMATS[op]
    return 1 + len(spec.regs) + WIDE_BYTES * len(spec.wides)


def layout() -> List[Tuple[str, int]]:
    """Opcode name and encoded width, for the build report."""
    return sorted((op, operand_size(op)) for op in SUPPORTED)


def vm_opcode(op: str, args) -> str:
    """The VM opcode one IR instruction encodes to.

    Only the two table accesses split, and only on whether the key is a
    constant.  Everything else is one to one, which is the property that keeps
    the encoder and the interpreter from drifting apart.
    """
    if op == OP.SETTABLE and not isinstance(args[1], Reg):
        return OP_SETTABLEK
    if op == OP.GETTABLE and not isinstance(args[2], Reg):
        return OP_GETTABLEK
    return op


#: How many operands each *IR* instruction carries, measured over the whole
#: test corpus -- every supported opcode turned out to have exactly one arity,
#: so this is a table rather than a range.
#:
#: It usually equals the VM's own operand count, but not always: ``NEWTABLE``
#: carries ``narr``/``nrec`` allocation hints that the VM drops, because it
#: builds an empty table and lets ``SETLIST`` fill it.  Validating against the
#: IR arity is what catches an encoder written against a shape the IR does not
#: actually produce -- which is how NEWTABLE and GETTABLE were being silently
#: refused for 294 prototypes.
IR_ARITY: Dict[str, int] = {
    OP.RETURN0: 0,
    OP.JMP: 1,
    OP.FORLOOP: 2, OP.FORPREP: 2, OP.GETGLOBAL: 2, OP.ITERPREP: 2,
    OP.JMPFALSE: 2, OP.JMPTRUE: 2, OP.LEN: 2, OP.LOADK: 2, OP.MOV: 2,
    OP.NOT: 2, OP.RETURN: 2, OP.SETGLOBAL: 2, OP.SETLISTMULTI: 2, OP.UNM: 2,
    OP.ADD: 3, OP.CONCAT: 3, OP.DIV: 3, OP.EQ: 3, OP.EXPAND: 3, OP.FORIN: 3,
    OP.FORINPREP: 3, OP.GE: 3, OP.GETTABLE: 3, OP.GT: 3, OP.IDIV: 3, OP.LE: 3,
    OP.LT: 3, OP.MOD: 3, OP.MUL: 3, OP.NE: 3, OP.NEWTABLE: 3, OP.POW: 3,
    OP.RETURNMULTI: 3, OP.SELF: 3, OP.SETLIST: 3, OP.SETTABLE: 3, OP.SUB: 3,
    OP.TAILCALL: 3,
    OP.CALL: 4,
}

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
from typing import Any, Dict, List, Optional, Sequence, Tuple

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

    ``regs`` lists the register operands by *IR argument position*, so
    ``SETTABLEK``'s ``regs=(0, 2)`` says "arguments 0 and 2 are registers" and
    argument 1 is not.  ``wides`` names the wide operands that follow them, in
    wire order.  ``wide_first`` records the handful of instructions whose wide
    operand precedes its register operand -- ``SETGLOBAL`` -- and matters because
    the format's geometry is derived from this order rather than from a
    hand-written byte layout.  ``reg_wide`` names wide slots that carry a
    *register index* instead of an immediate, which is how a multi-value pack
    register fits in a two-byte field.
    """

    regs: Tuple[int, ...] = ()
    wides: Tuple[str, ...] = ()
    wide_first: bool = False

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
    # IR order is (konst, register) and the historical wire order follows it, so
    # the wide comes first -- which is why ``FORMATS`` carries the order instead
    # of the encoder keeping a per-opcode exception.
    OP.SETGLOBAL:    OperandSpec(regs=(1,), wides=("name",), wide_first=True),
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
    # VARARG base, count: count is biased exactly like CALL's nres, because
    # it carries the same MULTIRET (-1) meaning -- "every vararg the caller
    # sent, packed into one register" -- and the same field cannot go
    # negative.  The entry point stashes the caller's packed arguments in the
    # frame, so the handler is a slice, not a reconstruction.
    OP.VARARG:       OperandSpec(regs=(0,), wides=("count",)),
    # GETUPVAL d, u / SETUPVAL u, a: ``u`` indexes the frame's accessor list
    # (getter/setter closures the stub builds over the *native* variable the
    # upvalue names), so it rides a wide slot like JMP's target -- it is an
    # immediate, not a register.
    OP.GETUPVAL:     OperandSpec(regs=(0,), wides=("up",), wide_first=True),
    OP.SETUPVAL:     OperandSpec(regs=(1,), wides=("up",), wide_first=True),
    OP.TAILCALL:     OperandSpec(regs=(0,), wides=("argc", "tail")),
    OP.RETURN:       OperandSpec(regs=(0,), wides=("count",)),
    OP.RETURN0:      OperandSpec(),
    OP.RETURNMULTI:  OperandSpec(regs=(0,), wides=("count", "pack")),
    OP.EXPAND:       OperandSpec(regs=(0,), wides=("pack", "count")),
    OP.SETLIST:      OperandSpec(regs=(0,), wides=("count", "start")),
    # ``pack`` is a register index that travels in a wide slot: the IR keeps the
    # multi-value pack as a plain int, so it needs two bytes but keeps register
    # semantics (see ``REGISTER_IN_WIDE``).
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
    # CLOSURE d, proto: the child prototype's id rides a wide slot like a jump
    # target -- it is an immediate, not a register.  The interpreter turns it
    # into a row key and builds the child's entry stub; see runtime._body.
    # The distinction that matters is the one ``can_virtualize`` draws: a child
    # that *captures* cannot be built this way at all, because the closure
    # would have to close over a register that lives in the parent's frame.
    OP.CLOSURE:      OperandSpec(regs=(0,), wides=("proto",)),
}

#: Wide fields that carry a *register index* rather than an immediate.
#:
#: ``pack`` exists because the IR records a multi-value pack as a plain int in a
#: register slot, where a register field would have to be a ``Reg``: it needs two
#: bytes for the size of the field but keeps register semantics -- the register
#: mask, the one-based bias, and ``MAX_REGISTERS`` as its bound.  Reading one is
#: therefore ``_rp`` and not ``_rk``: same slot, different disguise, because #15
#: is about which slot a register index may legally hold and not about how many
#: bytes it travelled in.  ``tail`` and ``nresults`` are deliberately absent: both
#: are biased *counts* (-1 means "absent"), and the helper that consumes them
#: does its own one-based arithmetic.
REGISTER_IN_WIDE = frozenset({"pack"})

#: Opcodes the interpreter implements.  A prototype using anything else is not
#: virtualized -- see ``couxobf.vm.encode.can_virtualize``.
SUPPORTED = frozenset(FORMATS)

#: Opcodes that cannot be virtualized at all, and why.  These are not "not yet"
#: in the sense of an oversight: each one needs VM state to be reachable from
#: ordinary Luau closures, which is a different and harder design.  (Upvalue
#: reads and writes crossed this line in R5: the stub hands the interpreter
#: accessor closures over the native storage, which is what GETUPVAL and
#: SETUPVAL call -- see runtime.py.)
UNSUPPORTED_REASON = {
    # Reached only when the prototype is refused for another reason -- since
    # R5's third increment CLOSURE is in ``FORMATS``, and the refusal for a
    # child that captures is ``can_virtualize``'s own message.
    OP.CLOSURE: ("creates a closure; a capturing one would have to point into "
                 "VM state"),
    OP.NOP: "removed by the optimizer before encoding",
    OP.LABEL: "resolved away during lowering",
}


@dataclass
class OpcodeMap:
    """A per-build assignment of opcode numbers.

    ``encode`` and ``decode`` both go through this, so a build cannot get out of
    sync with itself.  Numbers start at 1 because ``string.byte`` returns nil
    past the end of the string, and a stray 0 would read as a valid opcode.

    Two optional secondaries make the *count* of opcodes a build-time variable
    rather than a constant of the tool (points #71 and #14):

    ``aliases``
        Extra numbers for an opcode that already has one.  They are not decoys
        in the "dead code" sense -- an encoded instruction may really use one --
        but a number that appears in the dispatch chain and rarely or never in
        the stream is exactly the noise the point asks for.
    ``fused``
        Numbers assigned to fused super-instructions (see
        :mod:`couxobf.vm.format`).  Each one is a real handler for a pair of
        instructions, which is what grows the opcode count without padding the
        artifact with unreachable code.
    """

    to_byte: Dict[str, int]
    to_op: Dict[int, str]
    aliases: Dict[str, Tuple[int, ...]] = None  # type: ignore[assignment]
    fused: Dict[int, Tuple[str, str]] = None    # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.aliases is None:
            self.aliases = {}
        if self.fused is None:
            self.fused = {}

    @classmethod
    def identity(cls, ops: Optional[Sequence[str]] = None) -> "OpcodeMap":
        """Dense numbering in name order, over all of the ISA or over a subset.

        The subset form exists so a group that only ever runs three numeric
        helpers has three handlers, with or without randomization -- the arm
        count is a property of the code, not of this switch.
        """
        ops = sorted(SUPPORTED if ops is None else set(ops))
        return cls(to_byte={op: i + 1 for i, op in enumerate(ops)},
                   to_op={i + 1: op for i, op in enumerate(ops)})

    @classmethod
    def shuffled(cls, rng: Rng, *, alias_ratio: float = 0.0,
                 fused: Sequence[Tuple[str, str]] = (),
                 sparse: int = 1,
                 ops: Optional[Sequence[str]] = None) -> "OpcodeMap":
        """A permutation, optionally with alias numbers and super-ops.

        ``alias_ratio`` is the chance that an opcode gets a second (or third)
        number; ``sparse`` spaces the numbering out.  Both change *how many
        opcode bytes the dispatcher has to consider*, which is the quantity the
        design asks to randomize -- a fixed 47 is a fingerprint even when the
        numbers themselves move.

        ``ops`` restricts the map to the operations one group's prototypes use.
        Anything outside it has no number and no handler, which is a *build
        failure* rather than a wrong answer: ``byte()`` raises, and the
        validator's walk refuses an unassigned number.  Callers therefore
        over-approximate the requirement (see
        :func:`couxobf.vm.encode.required_ops`) instead of under-approximating
        it, and an over-approximation only costs a few dead arms.
        """
        # sorted, not a set of strings: iterating a set follows PYTHONHASHSEED,
        # so an unsorted base would make "same seed, same output" false across
        # processes.
        ops = sorted(SUPPORTED if ops is None else set(ops))
        order = [ops[j] for j in rng.permutation(len(ops))]
        # A one-byte opcode field holds 1..255, and 0 is reserved because
        # `string.byte` returns nil past the end of the payload -- so the number
        # space, not the number of knobs, is the hard budget every group shares.
        # Spacing the numbering out (``sparse``) and adding aliases are both ways
        # of spending it, and when it runs out the answer is to stop spending,
        # not to hand out 256 and let it wrap to zero.
        cap = 256
        to_byte: Dict[str, int] = {}
        to_op: Dict[int, str] = {}
        state = {"next": 1}

        def claim(step: int) -> Optional[int]:
            """The next free number, spaced by ``step``, or None when full.

            Spacing is a preference rather than a rule: if the gap would run past
            the cap, the number below it is still usable, and a build that ran out
            quietly would encode opcode 0.
            """
            at = state["next"]
            while at < cap and at in to_op:
                at += 1
            if at >= cap:
                if step <= 1:
                    return None
                return claim(1)
            state["next"] = at + step
            return at

        for op in order:
            # `order` is the drawn permutation of `ops`; a fused rule whose
            # halves are not in the subset would name an unassigned opcode, so
            # the halves are pulled in here rather than filtered out -- the
            # encoder is allowed to emit the pair for exactly those two ops.
            number = claim(max(1, sparse))
            if number is None:  # pragma: no cover - 47 opcodes cannot fill 255
                raise ValueError("no opcode numbers left for %s" % op)
            to_byte[op] = number
            to_op[number] = op
        aliases: Dict[str, Tuple[int, ...]] = {}
        if alias_ratio > 0:
            for op in order:
                extra: List[int] = []
                while rng.chance(alias_ratio) and len(extra) < 3:
                    number = claim(max(1, sparse))
                    if number is None:
                        break
                    extra.append(number)
                    to_op[number] = op
                if extra:
                    aliases[op] = tuple(extra)
        fused_map: Dict[int, Tuple[str, str]] = {}
        for pair in fused:
            number = claim(max(1, sparse))
            if number is None:
                # No room for another arm.  Dropping the rule here is only half
                # the answer -- the caller has to drop it from the *format* too,
                # which is what ``allocated_fused`` is for.
                break
            to_op[number] = FUSED_PREFIX + "%s,%s" % pair
            fused_map[number] = pair
        return cls(to_byte=to_byte, to_op=to_op, aliases=aliases,
                   fused=fused_map)

    def byte(self, op: str) -> int:
        try:
            return self.to_byte[op]
        except KeyError:
            raise KeyError(f"{op} is not in this build's opcode map") from None

    def numbers(self, op: str) -> Tuple[int, ...]:
        """Every number this build will accept for ``op``.

        The encoder uses ``byte(op)`` unless it deliberately draws an alias;
        the dispatcher generator needs the whole set, because a stream that
        *may* contain an alias has to be able to execute it.
        """
        primary = self.to_byte[op]
        return (primary,) + tuple(self.aliases.get(op, ()))

    def size(self) -> int:
        return len(self.to_byte)

    def opcode_count(self) -> int:
        """How many numbers the dispatch chain branches on, aliases included."""
        return len(self.to_op)


#: Marks a fused super-instruction inside ``to_op``, which keys on strings.
FUSED_PREFIX = "@"


def operand_size(op: str, fmt: Any = None) -> int:
    """Encoded length in bytes of one instruction of this opcode.

    With no format this is the historical layout -- one opcode byte, one byte
    per register operand, two per wide operand -- which is what every call site
    that has not been given a :class:`~couxobf.vm.format.FormatSpec` expects.
    """
    if fmt is None:
        spec = FORMATS[op]
        return 1 + len(spec.regs) + WIDE_BYTES * len(spec.wides)
    return fmt.size(op)


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
    OP.VARARG: 2,
    OP.GETUPVAL: 2,
    OP.SETUPVAL: 2,
}

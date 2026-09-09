"""Per-build, per-group VM instruction formats.

One build used to have exactly one instruction encoding: an opcode byte, then
one byte per register operand, then two little-endian bytes per wide operand,
in a fixed order, with a fixed eight-byte header.  A devirtualizer written
against that shape generalizes to every artifact this tool has ever produced,
which is the single largest gap between the design and the implementation.

This module is what closes it.  A :class:`FormatSpec` describes one concrete
encoding -- field widths, field order, padding, operand masks, jump-target
representation, header layout -- and a build draws one *per VM group*, so two
functions in the same artifact can be encoded differently.  The encoder and the
interpreter both derive their work from the same spec, so they cannot disagree
about a layout, which is the failure mode that makes format polymorphism
dangerous rather than merely attractive.

What is randomized, and which point in the design list each knob answers:

``reg_bytes`` / ``wide_bytes`` / ``op_bytes``
    #72 instruction width, #73 operand width.  A two-byte register field and a
    three-byte wide field make every instruction a different length than the
    obvious one.
``pad``
    #72 again: dead bytes between the opcode and the operands, so "opcode then
    operands, tightly packed" is not a property the analyst can assume.
``wides_first``
    #74 operand ordering.
``reg_mask`` / ``wide_mask``
    #4 operand encoding.  Each operand class carries its own additive mask, so
    the bytes in the stream are not the numbers they decode to, and a register
    operand no longer reads as a small integer.
``target_mode``
    #7 relative addressing (``rel``), #8/#10-ish state separation, #18 control
    flow kept out of the instruction stream entirely (``edges``), and a biased
    absolute form (``biased``) which is #46/#70 for the program counter.
``header``
    #70 no permanent ABI: field order, filler and the entry bias move per
    group, so "the eighth byte is the high byte of the entry point" is not
    true across builds.
``allow`` (fused pairs)
    #6 micro-ops fused back together, which also changes the opcode count.

Defaults reproduce the historical layout exactly, so a build that asks for no
operand randomization emits byte-identical output to the build that existed
before this file did.  That is not nostalgia: it is what makes the new pass
auditable, because "nothing changed" has to be a measurable outcome rather than
a hope.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field, replace
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..ir import OP
from ..rng import Rng
from .isa import FORMATS, REGISTER_IN_WIDE, WIDE_BYTES, OP_GETTABLEK

#: Jump-target representations.  ``abs`` is the historical one.
TARGET_MODES = ("abs", "biased", "rel", "edges")

#: Semantic names of the wide fields that carry a jump target, per opcode.
TARGET_FIELD: Dict[str, str] = {
    OP.JMP: "target",
    OP.JMPFALSE: "target",
    OP.JMPTRUE: "target",
    OP.FORPREP: "target",
    OP.FORLOOP: "target",
    OP.FORINPREP: "target",
    OP.FORIN: "target",
}

#: Opcodes that carry a *register index* inside a wide field, so the register
#: mask has to reach them too.  ``tail`` is a register slot holding packed
#: call arguments; ``count``/``start``/``argc`` are plain counts.
WIDE_REG_FIELD = {
    OP.CALL: ("tail",),
    OP.TAILCALL: ("tail",),
}

#: A field key: ``("r", i)`` is the i-th register operand of the instruction,
#: ``("w", name)`` is the named wide operand.  Everything downstream -- the
#: encoder, the interpreter generator, the integrity walk -- names operands
#: this way, so no component has to know where a field sits on the wire.
FieldKey = Tuple[Any, ...]


@dataclass(frozen=True)
class HeaderLayout:
    """The eight bytes at the head of every payload, with room to move.

    ``fields`` is the ordered ``(name, size)`` list; ``filler`` records the
    single bytes inserted between them and the values they hold, so a reader
    can skip them without guessing.  ``entry_bias`` is subtracted from the
    stored entry offset, which is what makes the header's own layout part of
    the per-build format rather than a constant.
    """

    fields: Tuple[Tuple[str, int], ...] = (
        ("nparams", 1), ("flags", 1), ("nregs", 2), ("nconsts", 2),
        ("entry", 2))
    filler: Tuple[Tuple[int, int], ...] = ()
    entry_bias: int = 0
    #: Struct used for the packed legacy form, when there is one.
    legacy: bool = True

    def _map(self):
        """(field positions, filler byte positions), computed together.

        A filler entry is recorded by the *field index* it precedes, which is how
        it stays meaningful when the fields are reordered; turning it into a byte
        offset here -- once, in one place -- is what lets the packer, the reader
        and the interpreter's entry-point expression agree on where everything
        is.  Deriving the offsets three ways and hoping they match is exactly how
        a payload came to be written with a filler byte only the writer knew about.
        """
        filled = dict(self.filler)
        out: Dict[str, Tuple[int, int]] = {}
        filler_at: Dict[int, int] = {}
        at = 0
        for i, (fname, fsize) in enumerate(self.fields):
            if i in filled:
                filler_at[at] = filled[i]
                at += 1
            out[fname] = (at, fsize)
            at += fsize
        if len(self.fields) in filled:
            filler_at[at] = filled[len(self.fields)]
            at += 1
        return out, filler_at, at

    @property
    def size(self) -> int:
        return self._map()[2]

    def positions(self) -> Dict[str, Tuple[int, int]]:
        """Where each field lives, and how wide it is."""
        return self._map()[0]

    def offset(self, name: str) -> int:
        return self.positions()[name][0]

    def width(self, name: str) -> int:
        return self.positions()[name][1]

    def pack(self, values: Dict[str, int]) -> bytes:
        if self.legacy:
            return struct.pack("<BBHHH", values["nparams"], values["flags"],
                               values["nregs"], values["nconsts"],
                               values["entry"] + self.entry_bias)
        positions, filler_at, _total = self._map()
        out = bytearray(self.size)
        for at, value in filler_at.items():
            out[at] = value
        for fname, (at, fsize) in positions.items():
            v = values[fname]
            if fname == "entry":
                v += self.entry_bias
            out[at:at + fsize] = int(v).to_bytes(fsize, "little")
        if len(out) != self.size:  # pragma: no cover - defensive
            raise ValueError("header layout produced the wrong size")
        return bytes(out)

    def parse(self, code: bytes) -> Dict[str, int]:
        if self.legacy:
            nparams, flags, nregs, nconsts, entry = struct.Struct(
                "<BBHHH").unpack_from(code, 0)
            return {"nparams": nparams, "flags": flags, "nregs": nregs,
                    "nconsts": nconsts, "entry": entry - self.entry_bias}
        out: Dict[str, int] = {}
        for fname, (at, fsize) in self.positions().items():
            out[fname] = int.from_bytes(code[at:at + fsize], "little")
        out["entry"] -= self.entry_bias
        return out


#: The layout every build emitted before formats existed.
DEFAULT_HEADER = HeaderLayout()


@dataclass(frozen=True)
class FusionRule:
    """One pair of instructions that may be encoded as a single super-op."""

    first: str
    second: str

    @property
    def name(self) -> str:
        return "FUSE_%s_%s" % (self.first, self.second)


#: Instructions that may participate in a fused pair.
#:
#: Deliberately excludes every opcode that can end a block or call out to
#: arbitrary Luau code: a fused handler executes both halves after all of its
#: operand reads, so a jump inside the first half would skip the second, and a
#: call in the first half could raise with the second half never running --
#: which is exactly the observable difference that makes an "equivalent"
#: transformation not equivalent.
FUSABLE = frozenset({
    OP.MOV, OP.LOADK, OP.GETGLOBAL, OP.NEWTABLE,
    OP.ADD, OP.SUB, OP.MUL, OP.DIV, OP.IDIV, OP.MOD, OP.POW,
    OP.UNM, OP.NOT, OP.LEN,
    OP.EQ, OP.NE, OP.LT, OP.LE, OP.GT, OP.GE,
    OP.CONCAT, OP.GETTABLE, OP_GETTABLEK, OP.SELF, OP.EXPAND,
})

#: The pairs offered to the build, in preference order.  Kept short on purpose:
#: every pair is another arm in the dispatch chain, and #63 says a bigger
#: artifact is not automatically a stronger one.
FUSION_RULES: Tuple[FusionRule, ...] = tuple(
    FusionRule(a, b)
    for a, b in (
        (OP.LOADK, OP.ADD), (OP.LOADK, OP.SUB), (OP.LOADK, OP.MUL),
        (OP.LOADK, OP.CONCAT), (OP.LOADK, OP.EQ), (OP.LOADK, OP.LT),
        (OP.LOADK, OP.GETTABLE), (OP.MOV, OP.ADD), (OP.MOV, OP.LT),
        (OP.GETGLOBAL, OP.LOADK), (OP.MOV, OP.MOV), (OP.MOV, OP.NOT),
        (OP.LOADK, OP.LOADK), (OP.UNM, OP.ADD), (OP.LEN, OP.ADD),
        (OP.MOV, OP.GETTABLE), (OP.LOADK, OP.NEWTABLE),
    )
)


@dataclass(frozen=True)
class FormatSpec:
    """One concrete instruction encoding.

    Constructed by :func:`draw` for a real build and by hand in tests.  The
    defaults are the historical format, so ``FormatSpec()`` is a valid way to
    say "no format polymorphism".
    """

    op_bytes: int = 1
    reg_bytes: int = 1
    wide_bytes: int = WIDE_BYTES
    #: Dead bytes between the opcode and the first operand.
    pad: int = 0
    #: Emit the wide operands before the register operands.
    wides_first: bool = False
    #: Additive masks, applied mod the field width.  #4.
    reg_mask: int = 0
    wide_mask: int = 0
    #: How a jump target is represented.  #7, #18.
    target_mode: str = "abs"
    #: Per-group bias added to every stored jump target (``biased`` mode).
    target_bias: int = 0
    header: HeaderLayout = DEFAULT_HEADER
    #: Fused pairs this format understands, as ``FusionRule``s.  #6.
    fused: Tuple[FusionRule, ...] = ()
    #: Whether the encoder may reorder independent instructions in a block.  #33.
    reorder: bool = False
    #: The group index, written into the payload header so the descriptor never
    #: carries a plaintext copy of which interpreter owns it.
    group: int = 0

    # -- field geometry ---------------------------------------------------
    def fields(self, op: str) -> Tuple[FieldKey, ...]:
        """This instruction's operand fields, in wire order.

        Keys are ``(kind, position_or_name)`` and mirror
        :func:`couxobf.vm.encode._field_values`, the encoder's side of the same
        contract: registers are keyed by IR argument position, wides by the name
        ``FORMATS`` gives them.  A key the encoder does not supply is an error
        rather than a zero, which is what turns a typo in this table into a build
        failure instead of a payload that decodes into the wrong program.
        """
        spec = FORMATS[op]
        regs: List[FieldKey] = [("r", i) for i in spec.regs]
        wides: List[FieldKey] = [("w", name) for name in spec.wides]
        out = (wides + regs) if (self.wides_first or spec.wide_first) \
            else (regs + wides)
        return tuple(out)

    @staticmethod
    def reg_in_wide(key: FieldKey) -> bool:
        """Whether a wide slot carries a register index (read as ``_rp``)."""
        return key[0] == "w" and key[1] in REGISTER_IN_WIDE

    def width(self, key: FieldKey) -> int:
        return self.reg_bytes if (key[0] == "r") else self.wide_bytes

    def mask(self, key: FieldKey) -> int:
        """The additive disguise for one field.

        A register index parked in a wide slot (``REGISTER_IN_WIDE``) is still a
        register: it is bounded by ``isa.MAX_REGISTERS`` and permuted by
        ``reg_mask``, because #15 is about which *slot* a register index may
        legally hold, not about how many bytes it travelled in.
        """
        if key[0] == "r" or (key[0] == "w" and key[1] in REGISTER_IN_WIDE):
            return self.reg_mask
        return self.wide_mask

    def modulo(self, key: FieldKey) -> int:
        return 1 << (8 * self.width(key))

    def offsets(self, op: str) -> Dict[FieldKey, int]:
        """Byte offset of each operand, measured from the start of the body."""
        base = self.op_bytes + self.pad
        out: Dict[FieldKey, int] = {}
        for key in self.fields(op):
            out[key] = base
            base += self.width(key)
        return out

    def body_size(self, op: str) -> int:
        """Bytes occupied by the operands, including the padding."""
        return (self.pad + sum(self.width(k) for k in self.fields(op)))

    def size(self, op: str) -> int:
        return self.op_bytes + self.body_size(op)

    def fused_size(self, rule: FusionRule) -> int:
        """A fused instruction is one opcode field followed by both bodies."""
        return (self.size(rule.first) - self.op_bytes
                + self.size(rule.second) - self.op_bytes + self.op_bytes)

    def fused_pair_size(self, first: str, second: str) -> int:
        """Size of a pair whose halves are known to be these two opcodes."""
        return (self.size(first) - self.op_bytes
                + self.size(second) - self.op_bytes + self.op_bytes)

    def fused_offsets(self, rule: FusionRule) -> Tuple[Dict[FieldKey, int],
                                                        Dict[FieldKey, int]]:
        """Where each half's operands live inside the fused instruction.

        The second half is laid out as if it began where the first one ends, so
        its relative offsets are unchanged -- only the base moves.  That is what
        lets the generator reuse one reader for both halves.
        """
        first = self.offsets(rule.first)
        shift = self.size(rule.first) - self.op_bytes
        second = {k: v + shift for k, v in self.offsets(rule.second).items()}
        return first, second

    def max_wide(self, key: FieldKey) -> int:
        """Largest value the field can carry.

        A relative target gets half the range, because it is signed: the
        encoder wraps a negative delta into the top half of the field, so a
        program that needs more than ``mod // 2`` bytes of reach simply does not
        fit this format and is not virtualized by it.
        """
        mod = self.modulo(key)
        if key[0] == "w" and key[1] not in REGISTER_IN_WIDE \
                and self.target_mode == "rel":
            return mod // 2 - 1
        return mod - 1

    # -- operand value <-> stored value ----------------------------------
    def store(self, key: FieldKey, value: int,
              *, is_target: bool = False, instr_start: int = 0,
              instr_size: int = 0, target: int = 0) -> int:
        """The integer to write into one field.

        ``value`` is the semantic operand (a register index, a constant slot, a
        count).  Jump targets go through ``target_mode`` first, then the mask,
        then the field's modulus -- in that order, because a masked *relative*
        offset has to be wrapped before it is disguised, not after.
        """
        v = value
        if is_target:
            v = self.encode_target(target, instr_start, instr_size, value)
        return (v + self.mask(key)) % self.modulo(key)

    def encode_target(self, target: int, instr_start: int, instr_size: int,
                      value: int) -> int:
        if self.target_mode == "abs":
            return target
        if self.target_mode == "biased":
            return target + self.target_bias
        if self.target_mode == "rel":
            # Signed relative to the *end* of the instruction, which is where
            # the program counter already is when the handler applies it.
            return target - (instr_start + instr_size)
        if self.target_mode == "edges":
            # `value` is the edge index; the table holds the real offsets.
            return value
        raise ValueError(f"unknown target mode {self.target_mode!r}")

    def decode_target_expr(self, raw: str) -> str:
        """Luau text: from a decoded field value to a jump offset (0-based)."""
        if self.target_mode == "abs":
            return raw
        if self.target_mode == "biased":
            return "%s - %d" % (raw, self.target_bias)
        raise AssertionError("rel and edges are handled by the caller")

    # -- header helpers ---------------------------------------------------
    @property
    def header_size(self) -> int:
        return self.header.size

    def lua_string(self, key: FieldKey) -> str:
        """The ``string.byte`` bias for one field.

        ``string.byte`` is 1-based while the wire format is 0-based, so every
        read adds one.  The register file is one-based as well, which is the
        other half of the ``+ 1``.
        """
        return " + 1"

    def summary(self) -> Dict[str, Any]:
        return {
            "group": self.group,
            "op_bytes": self.op_bytes,
            "reg_bytes": self.reg_bytes,
            "wide_bytes": self.wide_bytes,
            "pad": self.pad,
            "wides_first": self.wides_first,
            "reg_mask": self.reg_mask,
            "wide_mask": self.wide_mask,
            "target_mode": self.target_mode,
            "target_bias": self.target_bias,
            "header": {
                "order": [n for n, _ in self.header.fields],
                "size": self.header.size,
                "filler": list(self.header.filler),
                "entry_bias": self.header.entry_bias,
            },
            "fused": [r.name for r in self.fused],
            "reorder": self.reorder,
        }


# -- the reader half: Luau source for one build's field readers --------------

def reader_source(fmt: FormatSpec, code_var: str,
                  edge_var: str = "EG") -> List[str]:
    """Local functions that turn a byte position into an operand value.

    Emitted as functions rather than inlined expressions for two reasons.  The
    first is size: ``LOADK``, ``GETTABLEK`` and ``SELF`` all read a masked
    wide field, and spelling the arithmetic out at every site would add hundreds
    of bytes of noise per handler.  The second is the point of #25: a shared
    reader is one place a deobfuscator can anchor on, so the reader is generated
    from this build's parameters and nothing else, and two builds of the same
    source do not share its text.

    Register reads return the *one-based* index, because every consumer wants
    that and adding it here rather than at each use site is one less place for
    the two conventions to be confused.
    """
    lines: List[str] = []
    if fmt.reg_bytes == 1:
        lines.append(f"local function _r8(a) return _bd({code_var}, a) end")
    else:
        lines.append(f"local function _r8(a) return _bd({code_var}, a) + "
                     f"_bd({code_var}, a + 1) * 256 end")
    lines.append("local function _rr(a) return (_r8(a) - %d) %% %d + 1 end"
                 % (fmt.reg_mask, 1 << (8 * fmt.reg_bytes)))
    if fmt.wide_bytes == 2:
        lines.append("local function _rw(a) return _bd(%s, a) + _bd(%s, a + 1) "
                     "* 256 end" % (code_var, code_var))
    elif fmt.wide_bytes == 3:
        lines.append("local function _rw(a) return _bd(%s, a) + _bd(%s, a + 1) "
                     "* 256 + _bd(%s, a + 2) * 65536 end"
                     % (code_var, code_var, code_var))
    else:  # pragma: no cover - draw() only produces 2 and 3
        lines.append("local function _rw(a) return _bd(%s, a) end" % code_var)
    lines.append("local function _rk(a) return (_rw(a) - %d) %% %d end"
                 % (fmt.wide_mask, 1 << (8 * fmt.wide_bytes)))
    # Register index in a wide slot: the wide field's *size* and the register
    # field's mask and one-based bias, so the handler can use it as an index
    # exactly as if it had been a byte-wide ``r`` field.
    lines.append("local function _rp(a) return (_rw(a) - %d) %% %d + 1 end"
                 % (fmt.reg_mask, 1 << (8 * fmt.wide_bytes)))
    if fmt.target_mode == "rel":
        # Two's-complement-free signed decoding: the modulus is a power of two,
        # so the high bit says "negative" and subtracting the modulus once is
        # exact for every value a real offset can take.
        mod = 1 << (8 * fmt.wide_bytes)
        lines.append("local function _rt(a) local v = _rk(a) if v >= %d then "
                     "v = v - %d end return v end" % (mod // 2, mod))
    elif fmt.target_mode == "edges":
        # Targets live in their own authenticated region, four bytes per edge,
        # and the instruction carries only the *ordinal* -- so the field is read
        # like any other wide (same mask, same width) and the result indexes the
        # table.  Reading the table at the field's byte position instead would
        # decode a jump to wherever the operand happened to sit, which is a
        # desync the build-time check cannot see because it walks the same payload
        # from the ordinal side.  Costs one indirection per jump and buys the
        # property that a lift of the instruction stream alone does not reveal
        # where control goes (#18).
        lines.append(
            "local function _rt(a) local q = 1 + _rk(a) * 4 return "
            "_bd(%s, q) + _bd(%s, q + 1) * 256 + _bd(%s, q + 2) * 65536 "
            "+ _bd(%s, q + 3) * 16777216 end"
            % ((edge_var,) * 4))
    else:
        bias = fmt.target_bias if fmt.target_mode == "biased" else 0
        if bias:
            lines.append("local function _rt(a) local v = _rk(a) - %d "
                         "if v < 0 then v = v + %d end return v end"
                         % (bias, 1 << (8 * fmt.wide_bytes)))
        else:
            lines.append("local function _rt(a) return _rk(a) end")
    return lines


def read_reg(fmt: FormatSpec, off: int) -> str:
    """Luau text reading a register field at ``pc + off`` (one-based index)."""
    at = "pc" if off == 0 else "pc + %d" % off
    return "_rr(%s)" % at


def read_wide(fmt: FormatSpec, off: int) -> str:
    at = "pc" if off == 0 else "pc + %d" % off
    return "_rk(%s)" % at


def read_target(fmt: FormatSpec, off: int) -> str:
    at = "pc" if off == 0 else "pc + %d" % off
    return "_rt(%s)" % at


# -- drawing a format -------------------------------------------------------

def random_header(rng: Rng) -> HeaderLayout:
    """A header with the fields moved around and optionally padded."""
    names = [("nparams", 1), ("flags", 1), ("nregs", 2), ("nconsts", 2),
             ("entry", 2)]
    order = rng.shuffled(names)
    if not rng.chance(0.5):
        # Leave the legacy packing in place: it is the smaller and faster
        # option, and a build that always reorders is a signature of its own.
        return DEFAULT_HEADER
    filler: List[Tuple[int, int]] = []
    if rng.chance(0.35):
        at = rng.randbelow(len(order) + 1)
        filler.append((at, rng.byte()))
    return HeaderLayout(fields=tuple(order), filler=tuple(filler),
                        entry_bias=rng.randint(0, 255) if rng.chance(0.5) else 0,
                        legacy=False)


@dataclass(frozen=True)
class FormatPrefs:
    """Which knobs a build is allowed to turn, and how hard.

    One knob per randomized property, because they do not cost the same.  Two-byte
    registers add a byte per operand and buy a layout a generic decoder misreads;
    a 25% chance of a padded instruction adds one or two bytes and buys very
    little on its own; relative jumps cost nothing at runtime and are the reason a
    lifted stream does not show absolute offsets.  A UI that exposes "formats:
    low / high" cannot say that, so the knobs stay separate and :attr:`variety`
    scales how often each one is spent.
    """

    variety: int = 1
    allow_op_widen: bool = True
    allow_reg_widen: bool = True
    allow_wide_widen: bool = True
    allow_pad: bool = True
    allow_operand_swap: bool = True
    allow_reg_mask: bool = True
    allow_wide_mask: bool = True
    allow_biased: bool = True
    allow_relative: bool = True
    allow_edges: bool = False
    allow_renumbered_header: bool = True
    allow_instruction_reorder: bool = True
    #: Probability a given knob is spent, per unit of `variety`.  The defaults are
    #: the measured middle ground: enough divergence that two builds are not the
    #: same shape, not so much that the artifact grows for its own sake.
    weight: float = 0.5

    @classmethod
    def from_config(cls, config: Any) -> "FormatPrefs":
        """Read the knobs off a :class:`~couxobf.config.Config`.

        Kept as one function rather than a dozen conditionals at the call site so
        that "which config field turns which knob" has exactly one answer, and a
        field that stops being read shows up as an unused attribute here instead of
        as a silently inert option in the UI.
        """
        # Read as attributes, not through getattr with a name and a default: the
        # docstring above promises that a field which stops being read shows up
        # here as an unused attribute, and a string literal in a getattr call is
        # how four of these fields ended up claiming to be wired while nothing
        # could grep for them.
        enabled = bool(config.operand_randomization)
        variety = int(config.instruction_formats) if enabled else 0
        pc = bool(config.pc_protection)
        return cls(
            variety=variety,
            allow_op_widen=variety >= 1,
            allow_reg_widen=variety >= 1 and bool(config.register_randomization),
            allow_wide_widen=variety >= 1,
            allow_pad=variety >= 2,
            allow_operand_swap=variety >= 1,
            allow_reg_mask=bool(config.register_randomization),
            allow_wide_mask=variety >= 1,
            allow_biased=pc,
            allow_relative=pc,
            allow_edges=bool(config.edge_indirection),
            allow_renumbered_header=variety >= 1,
            allow_instruction_reorder=bool(config.control_flow_level >= 1)
            and variety >= 1,
            weight={0: 0.0, 1: 0.5, 2: 0.8, 3: 1.0}[max(0, min(3, variety))],
        )


def draw(rng: Optional[Rng], prefs: Optional[FormatPrefs] = None, *,
         fusion_rules: Sequence[FusionRule] = (),
         group: int = 0) -> FormatSpec:
    """Draw one format for one VM group.

    ``prefs.variety`` is 0 for "the historical format, always" -- what the compact
    profile wants -- and 2 spends every available knob.  In between, each knob is
    spent with a probability, so the option is a dial rather than a switch.  The
    design's #63 warning applies to polymorphism as much as to output size: a
    build that randomizes everything pays for it in bytes, and the *quality* of
    the diversity does not improve linearly with how many knobs are on.
    """
    prefs = prefs or FormatPrefs()
    if prefs.variety <= 0 or rng is None:
        return FormatSpec(group=group, fused=tuple(fusion_rules))

    def on(allowed: bool, prob: float = 1.0) -> bool:
        return bool(allowed) and rng.chance(min(1.0, prob * prefs.weight))

    op_bytes = 2 if on(prefs.allow_op_widen, 0.4) else 1
    reg_bytes = 2 if on(prefs.allow_reg_widen, 0.5) else 1
    wide_bytes = 3 if on(prefs.allow_wide_widen, 0.4) else 2
    pad = rng.randint(1, 2) if on(prefs.allow_pad, 0.5) else 0
    wides_first = on(prefs.allow_operand_swap, 0.6)
    reg_mod = 1 << (8 * reg_bytes)
    wide_mod = 1 << (8 * wide_bytes)
    # A mask of 0 means "no mask", so masks are drawn from the non-zero range
    # and the *absence* of one is a deliberate outcome rather than a fallback.
    reg_mask = rng.randint(1, reg_mod - 1) if on(prefs.allow_reg_mask, 0.8) else 0
    wide_mask = (rng.randint(1, wide_mod - 1)
                 if on(prefs.allow_wide_mask, 0.8) else 0)
    modes = ["abs"]
    if prefs.allow_biased:
        modes.append("biased")
    if prefs.allow_relative:
        modes.append("rel")
    if prefs.allow_edges:
        modes.append("edges")
    mode = "abs"
    if len(modes) > 1 and on(True, 0.7):
        mode = rng.choice([m for m in modes if m != "abs"] or ["abs"])
    bias = rng.randint(1, wide_mod - 1) if mode == "biased" else 0
    chosen: Tuple[FusionRule, ...] = ()
    if fusion_rules:
        # A random subset, not the whole menu.  Which pairs a build fuses is
        # then part of the format, and two builds at the same level do not share
        # it; the cap keeps the dispatch chain from growing into the "bigger is
        # stronger" trap (#63).
        wanted = rng.randint(1 if prefs.variety >= 2 else 0, len(fusion_rules))
        if wanted:
            chosen = tuple(rng.sample(list(fusion_rules), wanted))
    return FormatSpec(
        op_bytes=op_bytes,
        reg_bytes=reg_bytes,
        wide_bytes=wide_bytes,
        pad=pad,
        wides_first=wides_first,
        reg_mask=reg_mask,
        wide_mask=wide_mask,
        target_mode=mode,
        target_bias=bias,
        header=(random_header(rng) if on(prefs.allow_renumbered_header, 0.6)
                else DEFAULT_HEADER),
        fused=tuple(chosen),
        reorder=on(prefs.allow_instruction_reorder, 0.6),
        group=group,
    )


def legacy_spec() -> FormatSpec:
    """The format every artifact had before this module existed."""
    return FormatSpec()


#: The one instance of the above, so "no format" is a shared immutable value
#: rather than something every call site allocates.
LEGACY_SPEC = legacy_spec()


def describe(formats: Iterable[FormatSpec]) -> List[Dict[str, Any]]:
    """Per-group format summaries, for the build report and the UI."""
    return [f.summary() for f in formats]

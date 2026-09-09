"""The VM interpreter, as generated Luau.

One function, a byte string, and a dispatch chain.  The program counter is an
offset into the string and each instruction is decoded as the dispatcher
reaches it -- there is no decoded instruction array to dump, which is the point
of keeping the bytecode as bytes rather than as data structures.

The handler bodies mirror :mod:`couxobf.lower_back` instruction for
instruction.  That is not laziness: the reconstructor's semantics are pinned by
the differential test suite, so copying them is how the VM inherits that
verification instead of having to rediscover it.  Where a handler deviates it
says so, and says what was measured.

Opcode numbers are inlined from the build's :class:`~couxobf.vm.isa.OpcodeMap`
and operand geometry from its :class:`~couxobf.vm.format.FormatSpec`, so
neither the dispatch chain nor the layout of a single instruction is the same
twice.  Both are generated rather than transcribed, which is the only defence
against the failure that matters here: an encoder and an interpreter that
disagree about an offset produce a program that runs and computes the wrong
thing.  Neither of them knows a byte offset directly -- both ask the spec.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..ir import OP
from .families import Family, family as _family, substitute
from .format import FormatSpec, FusionRule, LEGACY_SPEC, reader_source
from .isa import (FUSED_PREFIX, REGISTER_IN_WIDE, OP_GETTABLEK, OP_SETTABLEK,
                   OpcodeMap)

#: Per-opcode names for the register operands, in the order ``FORMATS[op].regs``
#: lists them -- which is the IR argument position, not a count, so
#: ``SETTABLEK`` with ``regs=(0, 2)`` gets two names and not three.
REG_VARS: Dict[str, Tuple[str, ...]] = {
    OP.MOV: ("a", "s"),
    OP.LOADK: ("a",),
    OP.GETGLOBAL: ("a",),
    OP.SETGLOBAL: ("v",),
    OP.GETTABLE: ("a", "o", "k"),
    OP_GETTABLEK: ("a", "o"),
    OP.SETTABLE: ("o", "k", "v"),
    OP_SETTABLEK: ("o", "v"),
    OP.NEWTABLE: ("a",),
    OP.ADD: ("a", "x", "y"), OP.SUB: ("a", "x", "y"), OP.MUL: ("a", "x", "y"),
    OP.DIV: ("a", "x", "y"), OP.IDIV: ("a", "x", "y"), OP.MOD: ("a", "x", "y"),
    OP.POW: ("a", "x", "y"), OP.CONCAT: ("a", "x", "y"),
    OP.EQ: ("a", "x", "y"), OP.NE: ("a", "x", "y"), OP.LT: ("a", "x", "y"),
    OP.LE: ("a", "x", "y"), OP.GT: ("a", "x", "y"), OP.GE: ("a", "x", "y"),
    OP.UNM: ("a", "x"), OP.NOT: ("a", "x"), OP.LEN: ("a", "x"),
    OP.CALL: ("base",),
    OP.TAILCALL: ("base",),
    OP.RETURN: ("base",),
    OP.RETURN0: (),
    OP.RETURNMULTI: ("base",),
    OP.EXPAND: ("dst",),
    OP.SETLIST: ("tbl",),
    OP.SETLISTMULTI: ("tbl",),
    OP.SELF: ("a", "o"),
    OP.JMP: (),
    OP.JMPFALSE: ("a",), OP.JMPTRUE: ("a",),
    OP.FORPREP: ("base",), OP.FORLOOP: ("base",),
    OP.FORINPREP: ("base",), OP.FORIN: ("base",),
    OP.ITERPREP: ("base",),
}

#: Instructions whose handler always transfers control, so the pc it leaves
#: behind is never read.  ``RETURN`` and ``TAILCALL`` are absent on purpose: they
#: advance before returning, which is what a future return-value epilogue needs.
_NO_ADVANCE = frozenset({OP.JMP, OP.RETURN0})

#: Names for the wide operands, per opcode.  Anything not listed here keeps the
#: name ``FORMATS`` gives the field, which is already a fine local name.
WIDE_VARS: Dict[str, Dict[str, str]] = {
    OP_GETTABLEK: {"key": "k"},
    # SETGLOBAL's constant operand is called ``name`` in FORMATS and ``k`` here,
    # because the body it feeds is ``E[K[k + 1]] = R[v]``.  The name mismatch is
    # invisible to Luau -- an undeclared local reads as nil -- which is why
    # ``test_every_handler_body_uses_only_declared_names`` exists.
    OP.SETGLOBAL: {"name": "k"},
    OP_SETTABLEK: {"key": "k"},
    OP.LOADK: {"konst": "k"},
    OP.GETGLOBAL: {"name": "k"},
    OP.SELF: {"name": "k"},
    OP.RETURNMULTI: {"pack": "t"},
    OP.SETLISTMULTI: {"pack": "pk"},
    OP.EXPAND: {"pack": "t"},
}

_ARITH = {OP.ADD: "+", OP.SUB: "-", OP.MUL: "*", OP.DIV: "/", OP.IDIV: "//",
          OP.MOD: "%", OP.POW: "^", OP.CONCAT: ".."}
_CMP = {OP.EQ: "==", OP.NE: "~=", OP.LT: "<", OP.LE: "<=", OP.GT: ">",
        OP.GE: ">="}


def _pos(off: int) -> str:
    """Luau text for "this many bytes past the operand region's start"."""
    return "pc" if not off else "pc + %d" % off


class OperandView:
    """Where one instruction's operands live, and what to call them.

    Small enough to be obvious and shared by three consumers -- the read lines,
    the body, and the fused-pair generator -- so that no two of them can agree
    on a layout by accident.
    """

    __slots__ = ("fmt", "op", "shift")

    def __init__(self, fmt: FormatSpec, op: str, shift: int = 0) -> None:
        self.fmt = fmt
        self.op = op
        self.shift = shift

    def names(self) -> Dict[Tuple[Any, ...], str]:
        reg_names = REG_VARS.get(self.op, ())
        wide_names = WIDE_VARS.get(self.op, {})
        out: Dict[Tuple[Any, ...], str] = {}
        seen_reg = 0
        for key in self.fmt.fields(self.op):
            if key[0] == "r":
                out[key] = (reg_names[seen_reg] if seen_reg < len(reg_names)
                            else "r%d" % seen_reg)
                seen_reg += 1
            else:
                out[key] = wide_names.get(key[1], key[1])
        return out

    def offsets(self) -> Dict[Tuple[Any, ...], int]:
        """Positions relative to ``pc`` as the handler sees it.

        ``pc`` has already moved past the opcode field, so every unit-relative
        offset is short by one opcode width by the time it is used.  Doing the
        subtraction here means the handler bodies never mention a byte position
        and the encoder can keep talking about positions from the start of the
        instruction, which is what it needs in order to write them.
        """
        back = self.fmt.op_bytes
        return {k: v + self.shift - back
                for k, v in self.fmt.offsets(self.op).items()}

    def reads(self) -> List[str]:
        """The operand reads, in wire order, all before ``pc`` moves."""
        names = self.names()
        lines: List[str] = []
        for key, at in sorted(self.offsets().items(), key=lambda kv: kv[1]):
            var = names[key]
            pos = _pos(at)
            if key[0] == "r":
                lines.append(f"local {var} = _rr({pos})")
            elif self.fmt.reg_in_wide(key):
                # register semantics, wide storage -- see ``isa.REGISTER_IN_WIDE``
                lines.append(f"local {var} = _rp({pos})")
            elif key == ("w", "target"):
                lines.append(_target_read(self.fmt, pos))
            else:
                lines.append(f"local {var} = _rk({pos})")
        return lines


def _target_read(fmt: FormatSpec, pos: str) -> str:
    """Decode a jump target into ``tgt``, as Luau text."""
    return f"local tgt = _rt({pos})"


def _target_jump(fmt: FormatSpec, travel: int = 0) -> str:
    """How a handler transfers control, once ``tgt`` is decoded.

    A relative delta is measured from the *next* instruction, so the arm has to
    be standing there when it applies it.  Handlers that advance ``pc`` before
    doing their work already are; ``travel`` carries the distance for the ones
    that do not -- the unconditional ``JMP`` arm, which never advances because
    nothing reads the pc it leaves behind.  Without it a jump lands inside the
    instruction that follows its target's block header: the encoder, the payload
    and the integrity walk all agree with each other, so only the running program
    ever notices, and what it notices is a wrong answer or an "invalid state" a
    few instructions later.

    Every other mode yields an absolute position and gains the one-based index
    ``string.byte`` wants, so ``travel`` is irrelevant there.
    """
    if fmt.target_mode == "rel":
        return "pc = pc + tgt" if not travel else "pc = pc + %d + tgt" % travel
    return "pc = tgt + 1"


def _body(op: str, fam: Family, n: Dict[str, str], fmt: FormatSpec,
          travel: int = 0) -> List[str]:
    """What one opcode *does*, given its operands in locals.

    Every branch here reads only names -- never offsets -- because the layout is
    the format's business.  That is the invariant that makes two-byte registers
    and three-byte wides a configuration rather than a rewrite.  ``travel`` is how
    far ``pc`` still has to move to reach the next instruction while this body
    runs; see :func:`_target_jump`.
    """
    jump = _target_jump(fmt, travel)

    if op == OP.MOV:
        return fam.store("R[a]", "R[s]")
    if op == OP.LOADK:
        return fam.store("R[a]", "K[k + 1]")
    if op == OP.GETGLOBAL:
        # E is the calling function's environment, resolved per call -- see
        # interpreter_source for why it cannot be captured once at load.
        return fam.store("R[a]", "E[K[k + 1]]")
    if op == OP.SETGLOBAL:
        return ["E[K[k + 1]] = R[v]"]
    if op == OP.GETTABLE:
        return fam.store("R[a]", "R[o][R[k]]")
    if op == OP_GETTABLEK:
        return fam.store("R[a]", "R[o][K[k + 1]]")
    if op == OP.SETTABLE:
        return ["R[o][R[k]] = R[v]"]
    if op == OP_SETTABLEK:
        return ["R[o][K[k + 1]] = R[v]"]
    if op == OP.NEWTABLE:
        return fam.store("R[a]", "{}")
    if op in _ARITH:
        return fam.binary("R[a]", "R[x]", "R[y]", _ARITH[op])
    if op in _CMP:
        return fam.binary("R[a]", "R[x]", "R[y]", _CMP[op])
    if op == OP.UNM:
        return substitute(fam.unary("R[a]", lambda e: "-" + e), "R[x]")
    if op == OP.NOT:
        return substitute(fam.unary("R[a]", lambda e: "not " + e), "R[x]")
    if op == OP.LEN:
        return substitute(fam.unary("R[a]", lambda e: "#" + e), "R[x]")
    if op == OP.CALL:
        # nres and tail arrive biased by one so -1 encodes as 0
        return [
            "local res = _pack(" + n["call"] + "(R, base, argc, tail))",
            "if nres < 0 then",
            "  R[base] = res",
            "else",
            "  for i = 1, nres do",
        ] + ["    " + line for line in fam.store("R[base + i - 1]", "res[i]")] + \
            ["  end", "end"]
    if op == OP.TAILCALL:
        return ["return " + n["call"] + "(R, base, argc, tail)"]
    if op == OP.RETURN:
        return ["return _unpack(R, base, base + count - 1)"]
    if op == OP.RETURN0:
        return ["return"]
    if op == OP.RETURNMULTI:
        # explicit values first, then the spliced multi-ret -- the count is
        # part of the instruction and dropping it loses the prefix.  They go
        # into one table: `return unpack(a), unpack(b)` truncates the first
        # call to a single value, which would silently drop all but head[1].
        return ["local src = R[t]",
                "local out = {}",
                "local m = count",
                "for i = 0, count - 1 do",
                "  out[i + 1] = R[base + i]",
                "end",
                "for i = 1, src.n do",
                "  m += 1",
                "  out[m] = src[i]",
                "end",
                "if m == 0 then",
                "  return",
                "end",
                "return _unpack(out, 1, m)"]
    if op == OP.EXPAND:
        return ["local src = R[t]",
                # assigns nils past src.n, matching a multi-assign that fills
                # missing values with nil
                "for i = 1, count do",
                "  R[dst + i - 1] = src[i]",
                "end"]
    if op == OP.SETLIST:
        return ["local t = R[tbl]",
                # absolute indices: appending at #t + 1 would drop explicit nils
                "for i = 1, count do",
                "  t[start + i - 1] = R[tbl + i]",
                "end"]
    if op == OP.SETLISTMULTI:
        return [n["append"] + "(R[tbl], R[pk])"]
    if op == OP.SELF:
        # R(base+1) = obj; R(base) = obj[key]
        return ["local obj = R[o]",
                "R[a + 1] = obj",
                "R[a] = obj[K[k + 1]]"]
    if op == OP.JMP:
        return [jump]
    if op in (OP.JMPFALSE, OP.JMPTRUE):
        # the branch test is inverted between the two, and only in the body:
        # the operand reads, the target and the advance are identical
        test = "not R[a]" if op == OP.JMPFALSE else "R[a]"
        return [f"local c = {test}",
                "if c then",
                "  " + jump,
                "end"]
    if op == OP.FORPREP:
        # step the counter back once, then jump to FORLOOP which steps forward
        # and tests -- the same split the reconstructor emits
        return ["R[base] = R[base] - R[base + 2]", jump]
    if op == OP.FORLOOP:
        return ["local i = R[base] + R[base + 2]",
                "R[base] = i",
                "local lim, step = R[base + 1], R[base + 2]",
                "if (step > 0 and i <= lim) or (step < 0 and i >= lim) then",
                "  R[base + 3] = i",
                "  " + jump,
                "end"]
    if op == OP.FORINPREP:
        # validated once at loop entry, the way Luau does it; skipped when
        # ITERPREP resolved the iterator so a bad __iter result surfaces as a
        # call failure
        return ["if resolved == 0 then",
                "  R[base] = " + n["itercheck"] + "(R[base])",
                "end",
                jump]
    if op == OP.FORIN:
        # one call, all its results -- calling the iterator a second time to
        # fetch the extras would be observably wrong for any stateful iterator
        return ["local f, s, c = R[base], R[base + 1], R[base + 2]",
                "local res = _pack(f(s, c))",
                "if res[1] ~= nil then",
                "  for i = 0, nvars - 1 do",
                "    R[base + 3 + i] = res[i + 1]",
                "  end",
                "  R[base + 2] = res[1]",
                "  " + jump,
                "end"]
    if op == OP.ITERPREP:
        return ["local h = packed == 1 and " + n["iterpack"] + " or "
                + n["iter"],
                "R[base], R[base + 1], R[base + 2] = h(R[base])"]
    raise ValueError(f"{op} has no handler")


def _fix_bias(op: str, fmt: FormatSpec, view: OperandView) -> List[str]:
    """Adjust the two operands that are biased rather than raw.

    ``nres`` and ``tail`` carry ``+1`` so that ``-1`` ("absent") survives a
    field that cannot go negative; ``tail`` additionally names a register slot,
    which only matters because the register file is one-based.
    """
    out: List[str] = []
    if op == OP.CALL:
        out.append("nres = nres - 1")
        out.append("tail = tail - 1")
    elif op == OP.TAILCALL:
        out.append("tail = tail - 1")
    return out


def _handler(op: str, n: Dict[str, str], fam: Optional[Family] = None,
             fmt: Optional[FormatSpec] = None, view: Optional[OperandView] = None
             ) -> List[str]:
    """The Luau body of one opcode handler.

    The dispatcher has already stepped past the opcode field, so operand reads
    start at ``pc`` and every handler advances ``pc`` by its own width before
    doing its work.  A handler that jumps only has to overwrite ``pc``
    afterwards.

    ``fam`` is the operand discipline -- see :mod:`couxobf.vm.families`.  Every
    value-producing handler routes its result through the family rather than
    assigning to the register file directly, which is what makes the four
    interpreters actually differ instead of being the same code with different
    local names.
    """
    if fam is None:
        fam = _family("register", n)
    spec = fmt if fmt is not None else LEGACY_SPEC
    v = view if view is not None else OperandView(spec, op)
    advance = spec.body_size(op)
    out = v.reads()
    travel = advance
    if advance and op not in _NO_ADVANCE:
        # Advancing before doing the work is what lets every format -- padded,
        # reordered, wide-register -- share one rule.  A handler that always
        # transfers control does not need it, and the suite pins that so the
        # dispatcher cannot inherit a stale pc.
        out.append("pc = pc + %d" % advance)
        travel = 0
    return out + _fix_bias(op, spec, v) + _body(op, fam, n, spec, travel)


def _fused_handler(rule: FusionRule, n: Dict[str, str], fam: Family,
                   fmt: FormatSpec) -> List[str]:
    """Both halves of a fused pair, run in order under one opcode (#6).

    Each half keeps its own reads and its own body, in ``do`` blocks so their
    locals cannot collide -- ``SETLIST`` and ``FORIN`` both name a loop variable
    ``i``, and one merged scope would make the second half read the first
    half's.  The advance covers both halves at once.

    Nothing about either half's work changes: they execute in the order the
    encoder saw them, after all of their operands were read, which is the same
    order and the same read discipline the ordinary handlers use.  Fusing a
    pair that could jump or call out is refused in
    :mod:`couxobf.vm.format`, precisely so that "the halves run in order" is
    enough to be equivalent.
    """
    shift = fmt.size(rule.first) - fmt.op_bytes
    lines: List[str] = []
    for op, base in ((rule.first, 0), (rule.second, shift)):
        view = OperandView(fmt, op, base)
        lines.append("do")
        lines += ["  " + ln for ln in view.reads()]
        lines += ["  " + ln for ln in _fix_bias(op, fmt, view)]
        lines += ["  " + ln for ln in _body(op, fam, n, fmt)]
        lines.append("end")
    # One advance for the whole unit, after both halves have read their
    # operands: the halves cannot jump or return (see ``FUSABLE``), so nothing
    # in them observes `pc`, and putting the advance last keeps it from having
    # to be split between two scopes.
    lines.append(_fix_advance(fmt, rule))
    return lines


def _fix_advance(fmt: FormatSpec, rule: FusionRule) -> str:
    return "pc = pc + %d" % (fmt.fused_size(rule) - fmt.op_bytes)


# -- dispatch ----------------------------------------------------------------

class _Entry:
    """One dispatch arm: an opcode or a fused pair, and the numbers it accepts."""

    __slots__ = ("op", "numbers", "pair")

    def __init__(self, op: str, numbers: Tuple[int, ...],
                 pair: Optional[FusionRule] = None) -> None:
        self.op = op
        self.numbers = numbers
        self.pair = pair

    @property
    def key(self) -> int:
        return self.numbers[0]

    def condition(self, fmt: FormatSpec, var: str = "op") -> str:
        if len(self.numbers) == 1:
            return f"{var} == {self.numbers[0]}"
        # An aliased opcode tests as a disjunction rather than being emitted
        # twice: two arms with the same body would be boilerplate an automated
        # deobfuscator folds, and folding it would tell them where the alias set
        # is.
        return "(" + " or ".join("%s == %d" % (var, x) for x in self.numbers) + ")"

    def body(self, n: Dict[str, str], fam: Family, fmt: FormatSpec) -> List[str]:
        if self.pair is not None:
            return _fused_handler(self.pair, n, fam, fmt)
        return _handler(self.op, n, fam, fmt)

def _arm_key(entry: "_Entry", seed: int) -> int:
    """A permutation of the arms, mixed enough to be one.

    The first version sorted on ``(number * K + seed)``, which is wrong twice
    over: adding a small seed to a hash of consecutive integers barely changes
    the order at all, and when it does, the result is a rotation of one fixed
    sequence -- recognizable structure, which is the opposite of the point.  So
    the seed goes in before the multiply and the value gets an avalanche pass
    after it: two builds whose maps agree and whose seeds differ emit different
    chains, and neither order is a shifted copy of the other.
    """
    h = (((entry.numbers[0] if entry.numbers else 0) + seed) * 2654435761) & 0xFFFFFFFF
    h ^= h >> 15
    h = (h * 2246822519) & 0xFFFFFFFF
    h ^= h >> 13
    return h

def dispatch_entries(opmap: OpcodeMap, fmt: Optional[FormatSpec] = None
                     ) -> List[_Entry]:
    """Every arm this build's dispatcher needs, in dispatch order.

    Ordered by opcode number, so the chain is a function of the map and nothing
    else: two builds whose maps agree emit chains that agree, which is what
    makes "the dispatcher is generated, not transcribed" checkable.
    """
    entries: List[_Entry] = []
    for op in sorted(opmap.to_byte, key=lambda o: opmap.to_byte[o]):
        entries.append(_Entry(op, opmap.numbers(op)))
    for number, pair in sorted((opmap.fused or {}).items()):
        entries.append(_Entry(FUSED_PREFIX + "%s,%s" % pair, (number,),
                              pair=FusionRule(pair[0], pair[1])))
    # `arm_seed` permutes the order the arms are tested in.  It is a hash of the
    # numbers, not a shuffle with a random generator: the emitted chain stays a
    # pure function of (map, format), so two builds whose maps agree emit chains
    # that agree -- which is what keeps the dispatch tests checking the generator
    # instead of checking a second implementation of it.
    seed = getattr(fmt, "arm_seed", 0) if fmt is not None else 0
    if seed:
        entries = sorted(entries, key=lambda e: (_arm_key(e, seed), e.numbers[0]))

    return entries


def _emit_chain(lines: List[str], indent: str, entries: Sequence[_Entry],
                n: Dict[str, str], fam: Family, fmt: FormatSpec,
                path: Tuple[str, ...] = (),
                trace: Optional[List[Tuple[Tuple[int, ...], Tuple[str, ...]]]] = None
                ) -> None:
    """A linear ``if/elseif`` chain over this build's entries.

    ``trace`` is recorded, not derived: every arm that goes out appends the
    numbers it accepts and the full chain of comparisons that reach it, which is
    what lets :mod:`tests.test_vm_dispatch` check the emitted routing instead of a
    second implementation of it.  ``path`` is the enclosing decisions -- the
    subtree pivots of the decision tree, the bucket of the two-level shape.
    """
    first = True
    for entry in entries:
        cond = entry.condition(fmt)
        lines.append(f"{indent}{'if' if first else 'elseif'} {cond} then")
        first = False
        if trace is not None:
            trace.append((tuple(entry.numbers), path + (cond,)))
        for body_line in entry.body(n, fam, fmt):
            lines.append(f"{indent}  {body_line}")
    lines.append(f"{indent}else")
    lines.append(f'{indent}  error("invalid state")')
    lines.append(f"{indent}end")


def _tree_pairs(entries: Sequence[_Entry]) -> List[Tuple[int, _Entry]]:
    """One ``(number, entry)`` per number this build dispatches on.

    The tree must split *numbers*, not entries: an opcode with aliases owns
    several numbers that are nowhere near each other, and a partition of the
    entries would leave ``op == 87`` sitting in the subtree the pivot says can
    only hold small numbers.  That is a misroute, and a misroute in a dispatch
    tree is not a wrong answer -- it is the "invalid state" fallthrough on a
    perfectly valid payload.
    """
    pairs: List[Tuple[int, _Entry]] = []
    for entry in entries:
        for number in entry.numbers:
            pairs.append((number, entry))
    pairs.sort(key=lambda p: p[0])
    return pairs


#: Numbers per leaf before the tree stops splitting.  Small leaves are cheap to
#: compare, and a tree that bottoms out at one number per leaf is only a binary
#: search for the reader, not for the CPU.
_LEAF = 4


def _emit_tree(lines: List[str], indent: str, entries: Sequence[_Entry],
               n: Dict[str, str], fam: Family, fmt: FormatSpec,
               path: Tuple[str, ...] = (),
               trace: Optional[List[Tuple[Tuple[int, ...], Tuple[str, ...]]]] = None
               ) -> None:
    """A binary search over the opcode numbers, leaves guarded.

    The leaves still test for equality, and every arm only ever mentions numbers
    that fall inside the range its subtree covers -- see :func:`_tree_pairs` for
    why that is the whole correctness argument.  An unassigned opcode is still
    possible, so each leaf keeps its ``else error(...)`` guard.
    """
    _emit_tree_range(lines, indent, _tree_pairs(entries), n, fam, fmt, path,
                     trace)


def _emit_tree_range(lines: List[str], indent: str,
                     pairs: Sequence[Tuple[int, _Entry]], n: Dict[str, str],
                     fam: Family, fmt: FormatSpec,
                     path: Tuple[str, ...] = (),
                     trace: Optional[List[Tuple[Tuple[int, ...],
                                                Tuple[str, ...]]]] = None
                     ) -> None:
    if len(pairs) <= _LEAF:
        groups: List[Tuple[_Entry, List[int]]] = []
        index: Dict[int, int] = {}
        for number, entry in pairs:
            slot = index.get(id(entry))
            if slot is None:
                index[id(entry)] = len(groups)
                groups.append((entry, [number]))
            else:
                groups[slot][1].append(number)
        first = True
        for entry, numbers in groups:
            cond = ("op == %d" % numbers[0] if len(numbers) == 1 else
                    "(" + " or ".join("op == %d" % x for x in numbers) + ")")
            lines.append(f"{indent}{'if' if first else 'elseif'} {cond} then")
            first = False
            if trace is not None:
                trace.append((tuple(numbers), path + (cond,)))
            for body_line in entry.body(n, fam, fmt):
                lines.append(f"{indent}  {body_line}")
        lines.append(f"{indent}else")
        lines.append(f'{indent}  error("invalid state")')
        lines.append(f"{indent}end")
        return
    # Split by index, not by a pivot value chosen from the middle entry: taking
    # the median number and putting it in the low half keeps two elements from
    # ever shrinking, which recursed 995 frames deep the first time it was tried.
    cut = len(pairs) // 2
    mid = pairs[cut - 1][0]
    pivot = "op <= %d" % mid
    lines.append(f"{indent}if {pivot} then")
    _emit_tree_range(lines, indent + "  ", pairs[:cut], n, fam, fmt,
                     path + (pivot,), trace)
    lines.append(f"{indent}else")
    _emit_tree_range(lines, indent + "  ", pairs[cut:], n, fam, fmt,
                     path + ("not (%s)" % pivot,), trace)
    lines.append(f"{indent}end")


def _emit_bucket(lines: List[str], entries: Sequence[_Entry],
                 n: Dict[str, str], fam: Family, fmt: FormatSpec,
                 buckets: int, multiplier: int,
                 trace: Optional[List[Tuple[Tuple[int, ...], Tuple[str, ...]]]] = None
                 ) -> None:
    """Two levels: a computed bucket, then a short chain inside it.

    ``(op * multiplier) % buckets`` rather than a plain ``op % buckets`` so the
    grouping is not the obvious one and differs per build.  Multiplication by
    an odd number is a bijection on the residues that matter here, so the
    buckets stay a partition either way -- which is the property that makes
    this correct rather than merely different.

    An entry with alias numbers joins *every* bucket its numbers land in, and
    inside a bucket it only names the numbers that landed there: the chains are
    mutually exclusive, so an arm that reached only one bucket would reject a
    stream that legitimately used another, and an arm that listed all of them
    would advertise the whole alias set from every bucket it appears in.
    """
    groups: Dict[int, List[_Entry]] = {}
    for entry in entries:
        for number in entry.numbers:
            groups.setdefault((number * multiplier) % buckets, []).append(entry)
    lines.append(f"    local _bk = (op * {multiplier}) % {buckets}")
    path: Tuple[str, ...] = ()
    first = True
    for key in sorted(groups):
        lines.append(f"    {'if' if first else 'elseif'} _bk == {key} then")
        first = False
        here = [number for number, _e in _tree_pairs(entries)
                if (number * multiplier) % buckets == key]
        members = set(here)
        scoped: List[_Entry] = []
        seen: set = set()
        for entry in groups[key]:
            if id(entry) in seen:
                continue
            seen.add(id(entry))
            numbers = tuple(sorted(set(entry.numbers) & members))
            if numbers:
                scoped.append(_Entry(entry.op, numbers, entry.pair))
        _emit_chain(lines, "      ", scoped, n, fam, fmt,
                    path + ("_bk == %d" % key,), trace)
    lines.append("    else")
    lines.append('      error("invalid state")')
    lines.append("    end")


def _emit_state_transition(lines: List[str], entries: Sequence[_Entry],
                           n: Dict[str, str], fam: Family, fmt: FormatSpec,
                           trace: Optional[List[Tuple[Tuple[int, ...], Tuple[str, ...]]]] = None
                           ) -> None:
    """An inner dispatcher per instruction, driven by a transient state.

    The outer VM still advances one bytecode instruction at a time.  This shape
    deliberately separates opcode decoding from handler execution one step more:
    the decoded opcode becomes a short-lived state, and a second dispatcher
    consumes that state.  It is heavier than the direct chain and is therefore a
    polymorphic option, not the only interpreter shape.
    """
    seed = dispatch_seed(entries)
    state_name = "_ds%d" % (seed % 997)
    lines.append(f"    local {state_name} = op")
    lines.append("    while true do")
    first = True
    for entry in entries:
        cond = entry.condition(fmt, state_name)
        lines.append(f"      {'if' if first else 'elseif'} {cond} then")
        first = False
        if trace is not None:
            trace.append((tuple(entry.numbers), (entry.condition(fmt),)))
        body_lines = entry.body(n, fam, fmt)
        for body_line in body_lines:
            lines.append(f"        {body_line}")
        if not any(line.lstrip().startswith("return") for line in body_lines):
            lines.append("        break")
    lines.append("      else")
    lines.append('        error("invalid state")')
    lines.append("      end")
    lines.append("    end")


#: Dispatch shapes this can emit.  NESTED_IF is the flat chain every build used
#: to have; the others are genuinely different control structures, not the same
#: chain with different spacing.
DISPATCHERS = ("nested_if", "decision_tree", "bucket", "state_transition")


def dispatch_seed(entries: Sequence[_Entry]) -> int:
    """A per-build number derived from the dispatch table's shape."""
    total = 0
    for i, entry in enumerate(entries):
        for number in entry.numbers:
            total += number * (i + 1)
    return total


def _emit_dispatch(lines: List[str], entries: Sequence[_Entry],
                   n: Dict[str, str], fam: Family, dispatcher: str,
                   fmt: FormatSpec,
                   trace: Optional[List[Tuple[Tuple[int, ...],
                                              Tuple[str, ...]]]] = None
                   ) -> None:
    if dispatcher == "decision_tree":
        _emit_tree(lines, "    ", entries, n, fam, fmt, (), trace)
    elif dispatcher == "bucket":
        # derived from the opcode map, so it varies per build without needing
        # another randomness stream threaded down here
        seed = dispatch_seed(entries)
        buckets = 4 + seed % 5                       # 4..8 buckets
        multiplier = 1 + 2 * ((seed // 5) % 17)      # odd, 1..33
        _emit_bucket(lines, entries, n, fam, fmt, buckets, multiplier, trace)
    elif dispatcher == "state_transition":
        _emit_state_transition(lines, entries, n, fam, fmt, trace)
    elif dispatcher == "nested_if":
        _emit_chain(lines, "    ", entries, n, fam, fmt, (), trace)
    else:
        raise ValueError(f"unknown dispatcher {dispatcher!r}; "
                         f"expected one of {DISPATCHERS}")


#: The interpreter's local that holds a prototype's control-flow edge table.
#: Renamed per build along with ``pc``/``R``/``K``/``E`` -- see
#: :func:`_rename_core_tokens` -- so the readers below never have to be told
#: which name to use, and a fixed ``EG`` never reaches the artifact.
EDGE_LOCAL = "EG"


def reader_lines(fmt: FormatSpec, code_var: str, edge_var: str = EDGE_LOCAL
                 ) -> List[str]:
    """The field readers this build's handlers call.

    A thin wrapper over :func:`~couxobf.vm.format.reader_source` that keeps the
    ``_bd`` byte fetch beside the readers that use it.  Two builds of the same
    source share no line of it, because every width, mask and mode it encodes
    came out of that build's own randomness.
    """
    return list(reader_source(fmt, code_var, edge_var))


def interpreter_source(opmap: OpcodeMap, names: Dict[str, str],
                       vm_family: str = "register",
                       dispatcher: str = "nested_if",
                       fmt: Optional[FormatSpec] = None,
                       trace: Optional[List[Tuple[Tuple[int, ...],
                                                  Tuple[str, ...]]]] = None,
                       entry_guard: Sequence[str] = (),
                       opaque_predicates: bool = True
                       ) -> str:
    """The interpreter, with this build's opcode numbers *and layout* inlined.

    ``names`` supplies the local names so the interpreter is not recognisable by
    shape alone: ``code``, ``exec``, ``enter``, ``call``, ``getfenv``, ``acc``,
    ``stack``, ``sp``, ``append``, ``iter``, ``iterpack``, ``itercheck``.

    ``vm_family`` selects the operand discipline and ``fmt`` the instruction
    format.  Without a format the historical layout is used, which is what makes
    "no format polymorphism" a supported configuration rather than a fallback
    someone forgot to remove.
    """
    spec = fmt if fmt is not None else LEGACY_SPEC
    n = names
    fam = _family(vm_family, names)
    code = n["code"]
    header = spec.header
    entry_at = header.offset("entry")
    entry_w = header.width("entry")
    nparams_at = header.offset("nparams")
    # Little-endian at the field's own width, read through the layout -- the same
    # three consumers (encoder, interpreter, build-time validator) then share one
    # convention instead of each assuming the header is eight bytes long.
    raw = _le_read("_bd(%s, %%d)" % code, entry_at, entry_w)
    nparams_expr = _le_read("_bd(p.code, %d)", nparams_at,
                             header.width("nparams"))
    entry_expr = "%s + 1" % raw
    if spec.header.entry_bias:
        # The bias wraps inside the field, so a large entry offset and a bias
        # cannot push the stored value out of the slot it lives in.
        entry_expr = "(%s - %d) %% %d + 1" % (raw, spec.header.entry_bias,
                                              1 << (8 * entry_w))
    opaque_line = ([
        # A short opaque branch whose truth depends on the bytecode and the
        # decoded opcode for this execution, not on a repetitive algebraic
        # identity.  It doubles as a cheap tamper tripwire: a bad pc/op image
        # reaches the same neutral error as every other invalid VM state.
        f"    if not ((op == op) and (pc >= 1) and (#{n['code']} >= pc)) then error(\"invalid state\") end",
    ] if opaque_predicates else [])

    lines: List[str] = [
        "local _bd = string.byte",
        "local _unpack = table.unpack",
        "local _pack = table.pack",
        # getfenv is held in a local rather than looked up as a global, because
        # a virtualised function that has had setfenv applied to it no longer
        # sees the real globals -- including getfenv itself.  Measured: calling
        # it through the swapped env fails with "attempt to call a nil value".
        f"local {n['getfenv']} = getfenv",
        f"local {n['call']} = function(R, base, argc, tail)",
        "  local f = R[base]",
        "  if tail >= 0 then",
        "    local t = R[tail + 1]",
        "    local args = {}",
        "    for i = 1, argc do",
        "      args[i] = R[base + i]",
        "    end",
        "    local m = argc",
        "    for i = 1, t.n do",
        "      m += 1",
        "      args[m] = t[i]",
        "    end",
        "    return f(_unpack(args, 1, m))",
        "  end",
        "  if argc == 0 then",
        "    return f()",
        "  end",
        "  return f(_unpack(R, base + 1, base + argc))",
        "end",
        # E arrives as an argument.  Resolving it here instead would give this
        # function's environment, not the virtualised function's, and a
        # setfenv'd build would silently read and write the real globals.
        f"local function {n['exec']}(p, R, E)",
        f"  local {n['code']} = p.code",
        "  local K = p.consts",
    ]
    if spec.target_mode == "edges":
        # The edge table is its own pooled, authenticated blob, so a jump's
        # destination is not in the instruction stream at all (#18) while still
        # being inside something the pool's MAC covers -- which is what keeps
        # this distinct from putting targets in the plaintext descriptor.
        lines.append("  local %s = p.edges" % EDGE_LOCAL)
    lines += ["  " + ln for ln in reader_lines(spec, code, EDGE_LOCAL)]
    lines += [
        # The entry point comes out of the payload header, which is inside the
        # authenticated blob, rather than from the descriptor table beside it.
        # The two used to agree by construction and nothing checked that they
        # still agreed: editing the plaintext `entry` in the emitted source
        # moved the program counter into the middle of the bytecode without
        # touching the MAC. Measured on a one-prototype build, entry values
        # 13/17/21 of 59 scanned ran to completion with exit code 0 and
        # silently wrong output.
        f"  local pc = {entry_expr}",
    ] + ["  " + decl for decl in fam.state] + [
        "  while true do",
        # The selector comes from the generated reader, not from a `byte(code, pc)`
        # written here: the stream carries the format's image of the number, so
        # the decode has to happen somewhere shared with every other field read
        # (`_ro`, alongside `_rr`/`_rk`/`_rp`) rather than in the one place that
        # also happens to be the anchor a matcher looks for first.
        "    local op = _ro(pc)",
        *opaque_line,
        f"    pc = pc + {spec.op_bytes}",
    ]

    _emit_dispatch(lines, dispatch_entries(opmap, spec), n, fam, dispatcher,
                   spec, trace)
    lines += [
        "  end",
        "end",
        f"local function {n['enter']}(p, E, ...)",
        # The environment guard, when this build has one: checking on entry is
        # what catches a runner that swaps the dump surfaces while the artifact
        # is already running.  Before the frame is built, so a refused call never
        # touches the payload at all.
        *[f"  {line}" for line in entry_guard],
        "  local R = {}",
        "  local args = _pack(...)",
        # same reason as the entry point: nparams is a header field, and which
        # one is a property of this build's layout
        "  for i = 1, %s do" % nparams_expr,
        "    R[i] = args[i]",
        "  end",
        f"  return {n['exec']}(p, R, E)",
        "end",
    ]
    return _rename_core_tokens("\n".join(lines) + "\n", names)


#: The interpreter's working names, as written in the templates above.
_CORE_TOKENS = (("pc", "pc"), ("R", "regs"), ("K", "consts"), ("E", "env"),
                ("EG", "edges"))


def _le_read(read: str, at: int, width: int) -> str:
    """Little-endian assembly of ``width`` reads starting at ``at`` (1-based).

    ``read`` is a format string taking the position, so the same helper builds a
    header field read and any other multi-byte fetch from the payload.
    """
    parts = [(read % (at + 1 + i)) if width > 1 else (read % (at + 1))
             for i in range(width)]
    if width == 1:
        return parts[0]
    return " + ".join(p if i == 0 else "%s * %d" % (p, 256 ** i)
                      for i, p in enumerate(parts))


def _rename_core_tokens(text: str, names: Dict[str, str]) -> str:
    """Swap the interpreter's ``pc``/``R``/``K``/``E`` for this build's names.

    Done as a pass over the finished text rather than at each of the ~350 use
    sites, because those sites embed the tokens inside expressions like
    ``_rk(pc + 1)`` and editing them individually is how a build ends up
    half-renamed and still correct-looking.

    Safe because none of the four appears inside a string literal in the
    generated source -- measured, not assumed.  A caller that does not supply a
    replacement keeps the literal token, so older name dictionaries still work.
    """
    import re as _re

    for token, key in _CORE_TOKENS:
        replacement = names.get(key)
        if not replacement:
            continue
        text = _re.sub(r"(?<![\w])" + _re.escape(token) + r"(?![\w])",
                       replacement, text)
    return text

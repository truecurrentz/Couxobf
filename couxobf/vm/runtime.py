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
    OP.VARARG: ("base",),
    OP.GETUPVAL: ("a",),
    OP.SETUPVAL: ("v",),
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
    # R5's third increment: the register the new closure lands in, and the
    # child prototype's id as a wide immediate.
    OP.CLOSURE: ("a",),
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
    OP.CLOSURE: {"proto": "pid"},
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
        from .isa import FORMATS
        reg_order = {pos: idx for idx, pos in enumerate(FORMATS[self.op].regs)}
        for key in self.fmt.fields(self.op):
            if key[0] == "r":
                reg_index = reg_order.get(key[1], 0)
                out[key] = (reg_names[reg_index] if reg_index < len(reg_names)
                            else "r%d" % reg_index)
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

    def reads(self, code_var: Optional[str] = None) -> List[str]:
        """The operand reads, in wire order, all before ``pc`` moves.

        ``code_var`` enables the format's inline-read mode: the field
        arithmetic is spelled at the read site instead of calling the
        generated readers, trading artifact bytes for the function-call
        cost on the interpreter's hottest path.  Jump targets stay a reader
        call either way (see ``_rt_source`` for why).
        """
        from .format import inline_read
        inline = bool(getattr(self.fmt, "inline_reads", False)) and code_var
        names = self.names()
        lines: List[str] = []
        for key, at in sorted(self.offsets().items(), key=lambda kv: kv[1]):
            var = names[key]
            pos = _pos(at)
            if key == ("w", "target"):
                lines.append(_target_read(self.fmt, pos))
            elif inline:
                kind = "r" if key[0] == "r" else (
                    "p" if self.fmt.reg_in_wide(key) else "w")
                lines.append("local %s = %s"
                             % (var, inline_read(self.fmt, kind, code_var, pos)))
            elif key[0] == "r":
                lines.append(f"local {var} = _rr({pos})")
            elif self.fmt.reg_in_wide(key):
                # register semantics, wide storage -- see ``isa.REGISTER_IN_WIDE``
                lines.append(f"local {var} = _rp({pos})")
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
          travel: int = 0, variant: int = 0, row_mask: int = 0) -> List[str]:
    """What one opcode *does*, given its operands in locals.

    Every branch here reads only names -- never offsets -- because the layout is
    the format's business.  That is the invariant that makes two-byte registers
    and three-byte wides a configuration rather than a rewrite.  ``travel`` is how
    far ``pc`` still has to move to reach the next instruction while this body
    runs; see :func:`_target_jump`.
    """
    jump = _target_jump(fmt, travel)

    if op == OP.MOV:
        if variant % 3 == 1:
            return ["local _mv = R[s]", *fam.store("R[a]", "_mv")]
        if variant % 3 == 2:
            return ["do local _mv = R[s]" , *["  " + ln for ln in fam.store("R[a]", "_mv")], "end"]
        return fam.store("R[a]", "R[s]")
    if op == OP.LOADK:
        if variant % 3 == 1:
            return ["local _kv = K[k + 1]", *fam.store("R[a]", "_kv")]
        if variant % 3 == 2:
            return ["do local _kv = K[k + 1]", *["  " + ln for ln in fam.store("R[a]", "_kv")], "end"]
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
    if op == OP.CLOSURE:
        # R5's third increment: hand out the child's entry stub, which the
        # prelude built once per prototype and keyed by descriptor row.  It is
        # a lookup rather than a closure being built here, for two reasons:
        # the stub has to be the same function value every time -- Luau's own
        # compiler hoists a closure that captures nothing, so `f == f` holds
        # across iterations of a loop that declares one -- and a child that
        # captured anything was never eligible, so there are no accessors to
        # build.
        #
        # The key is the prototype id masked with the plan's own mask, the one
        # the descriptor table is keyed by; the mask travels as a literal
        # rather than as a table, so the artifact carries no map from
        # prototype to interpreter.
        # Every name here is read tolerantly, and for one reason: a caller may
        # hand in a partial name table (the tests do, to pin the names a
        # failure should report), and the arm is generated for every opcode in
        # the map whether or not this build will ever run it.  An undeclared
        # name is a nil global in Luau, which is harmless for a table this arm
        # only ever looks up a key in -- and a KeyError at *build* time is not
        # harmless at all.
        stubs = n.get("stubs") or "stubs"
        caps = n.get("caps") or "caps"
        snaps = n.get("snaps") or "snaps"
        rows = n.get("rows") or "rows"
        uvs = n.get("uvs") or "uvs"
        getter = n.get("getfenv") or "getfenv"
        setter = n.get("setfenv") or "setfenv"
        enter = n.get("enter") or "enter"
        key = "bit32.bxor(pid, %d)" % (int(row_mask) & 0xffffffff)
        # R5's fourth increment: a child that *captures* has no stub in the
        # table, because the accessors it needs close over this frame -- the
        # parent's register slots, or the parent's own accessor list for an
        # upvalue the parent relays.  Nothing outside the running interpreter
        # can name those, so the stub is built here, at the closure site, and
        # it is built fresh: Luau gives a capturing closure a new identity per
        # evaluation, unlike the hoisted, non-capturing case above.
        return [
            # ``and`` because either table may be absent: a build with no
            # capturing child emits no descriptor table at all, and an
            # undeclared name in Luau is a nil global rather than a syntax
            # error -- which is the friendliest possible failure to debug and
            # the least friendly to leave in a shipped artifact.
            "local _zc = %s and %s[%s]" % (caps, caps, key),
            "if not _zc then",
        ] + ["  " + _l for _l in fam.store("R[a]", "%s[%s]" % (stubs, key))] + [
            "else",
            "  local _zu = {}",
            "  for _zi = 1, #_zc do",
            "    local _zd = _zc[_zi]",
            "    if _zd > 0 then",
            # A plain local of the parent's: live, not a copy.  Both closures
            # close over the frame, so a write by either side is seen by the
            # other -- which is what the native path's accessors do over the
            # owner's register.  Registers captured by a closure are pinned at
            # lowering time (``_FuncBuilder.captured``), so the slot is never
            # handed to a sibling after the block that owns it closes.
            # One-based, like every other register the frame holds: the entry
            # point lays the parameters down at R[1..n], so register 0 of the
            # prototype is never a slot anything reads.
            "      local _zs = _zd",
            "      _zu[_zi * 2 - 1] = function() return R[_zs] end",
            "      _zu[_zi * 2] = function(_zv) R[_zs] = _zv end",
            "    else",
            # An upvalue of the parent's: relay its accessor pair rather than
            # re-deriving it, so a chain of captures ends at the same closures
            # the native site built, whatever depth it started at.
            "      local _zu2 = -_zd - 1",
            "      _zu[_zi * 2 - 1] = R.%s[_zu2 * 2 + 1]" % uvs,
            "      _zu[_zi * 2] = R.%s[_zu2 * 2 + 2]" % uvs,
            "    end",
            "  end",
            # A loop variable is fresh per iteration in Luau, so a closure
            # declared in the body captures *that* iteration's value.  The
            # frame slot keeps moving, so the accessor closes over a cell
            # holding a snapshot taken now instead.
            "  local _zn = %s and %s[%s]" % (snaps, snaps, key),
            "  if _zn then",
            "    for _zj = 1, #_zn do",
            "      local _zk = _zn[_zj]",
            "      local _zcell = { R[_zc[_zk + 1]] }",
            "      _zu[_zk * 2 + 1] = function() return _zcell[1] end",
            "      _zu[_zk * 2 + 2] = function(_zv) _zcell[1] = _zv end",
            "    end",
            "  end",
            # setfenv, not getfenv: this closure is born inside the
            # interpreter, so its inherited environment is the interpreter's
            # and not the parent's.  E is the environment the parent's frame
            # was entered with, which is the one a child of it should see.
        ] + ["  " + _l for _l in fam.store(
            "R[a]", "%s(function(...) return %s(%s[%s], %s(1), _zu, ...) end, E)"
            % (setter, enter, rows, key, getter))] + [
            "end",
        ]
    if op in _ARITH:
        sym = _ARITH[op]
        if variant % 3 == 1:
            return ["local _ax, _ay = R[x], R[y]",
                    *fam.store("R[a]", f"_ax {sym} _ay")]
        if variant % 3 == 2:
            return [f"local _ar = (function(_x, _y) return _x {sym} _y end)(R[x], R[y])",
                    *fam.store("R[a]", "_ar")]
        return fam.binary("R[a]", "R[x]", "R[y]", sym)
    if op in _CMP:
        sym = _CMP[op]
        if variant % 3 == 1:
            return ["local _cx, _cy = R[x], R[y]",
                    *fam.store("R[a]", f"_cx {sym} _cy")]
        if variant % 3 == 2:
            return [f"local _cr = (function(_x, _y) return _x {sym} _y end)(R[x], R[y])",
                    *fam.store("R[a]", "_cr")]
        return fam.binary("R[a]", "R[x]", "R[y]", sym)
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
    if op == OP.VARARG:
        # count arrives biased like nres, so -1 ("every vararg, packed") is 0
        # on the wire and `< 0` here after the bias is removed.  The pack the
        # entry point stashed holds every argument the caller sent; the named
        # parameters are its first slots, so the varargs start just past the
        # count it recorded.  Reading past `.n` yields nil, which is exactly
        # what a short vararg list must produce.
        va = "R." + n["vpack"]
        np = "va." + n["vnp"]
        return [
            "local va = " + va,
            "if count < 0 then",
            "  local t = {}",
            "  local m = 0",
            "  for i = " + np + " + 1, va.n do",
            "    m += 1",
            "    t[m] = va[i]",
            "  end",
            "  t.n = m",
            "  R[base] = t",
            "else",
            "  for i = 1, count do",
        ] + ["    " + line for line in fam.store("R[base + i - 1]", "va[" + np + " + i]")] + \
            ["  end", "end"]
    if op in (OP.GETUPVAL, OP.SETUPVAL):
        # The frame holds no upvalue state: it holds the accessor list the
        # stub built -- one getter/setter pair per upvalue, each a real Luau
        # closure over the native variable the upvalue names.  Calling them
        # is what keeps reads and writes live and consistent with any native
        # sibling sharing the variable.  ``up`` is zero-based on the wire, so
        # the one-based pairs sit at 2*up+1 and 2*up+2.  A prototype with no
        # upvalues never encodes either opcode, so the entry point's ``false``
        # placeholder is never indexed.
        uv = "R." + n["uvs"]
        if op == OP.GETUPVAL:
            return fam.store("R[a]", "(%s[up * 2 + 1])()" % uv)
        return ["(%s[up * 2 + 2])(R[v])" % uv]
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
    """Adjust the operands that are biased rather than raw.

    ``nres``, ``tail`` and VARARG's ``count`` carry ``+1`` so that ``-1``
    ("absent" / "all of them") survives a field that cannot go negative;
    ``tail`` additionally names a register slot, which only matters because
    the register file is one-based.
    """
    out: List[str] = []
    if op == OP.CALL:
        out.append("nres = nres - 1")
        out.append("tail = tail - 1")
    elif op == OP.TAILCALL:
        out.append("tail = tail - 1")
    elif op == OP.VARARG:
        out.append("count = count - 1")
    return out


def _handler(op: str, n: Dict[str, str], fam: Optional[Family] = None,
             fmt: Optional[FormatSpec] = None, view: Optional[OperandView] = None,
             variant: int = 0, row_mask: int = 0
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
        fam = _family("woven", n)
    spec = fmt if fmt is not None else LEGACY_SPEC
    v = view if view is not None else OperandView(spec, op)
    advance = spec.body_size(op)
    out = v.reads(code_var=n.get("code"))
    travel = advance
    if advance and op not in _NO_ADVANCE:
        # Advancing before doing the work is what lets every format -- padded,
        # reordered, wide-register -- share one rule.  A handler that always
        # transfers control does not need it, and the suite pins that so the
        # dispatcher cannot inherit a stale pc.
        out.append("pc = pc + %d" % advance)
        travel = 0
    return out + _fix_bias(op, spec, v) + _body(op, fam, n, spec, travel,
                                                variant, row_mask)


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
        lines += ["  " + ln for ln in view.reads(code_var=n.get("code"))]
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
    """One dispatch arm: an opcode or a fused pair, and the numbers it accepts.

    ``variant`` is the alias implementation path.  Alias numbers are real
    numbers the encoder may emit; giving each one a separate implementation path
    avoids the old "N conditions, one identical handler" shape that a static
    normalizer can collapse immediately.
    """

    #: ``row_mask`` is how a CLOSURE arm finds the child's descriptor row: the
    #: prototype id in the instruction, masked with the plan's own mask.  It is
    #: a build constant rather than a table, so the artifact carries no map
    #: from prototype to interpreter.
    __slots__ = ("op", "numbers", "pair", "variant", "row_mask")

    def __init__(self, op: str, numbers: Tuple[int, ...],
                 pair: Optional[FusionRule] = None,
                 variant: int = 0, row_mask: int = 0) -> None:
        self.op = op
        self.numbers = numbers
        self.pair = pair
        self.variant = variant
        self.row_mask = int(row_mask) & 0xffffffff

    @property
    def key(self) -> int:
        return self.numbers[0]

    def condition(self, fmt: FormatSpec, var: str = "op", roll: str = "_vr") -> str:
        def one(number: int) -> str:
            seed = (getattr(fmt, "arm_seed", 0) ^ ((number + 0x9E37) << 7)
                    ^ (self.variant * 0x45D9F3B)) & 0xffffffff
            mod = 1 << (8 * max(1, int(getattr(fmt, "op_bytes", 1))))
            mask = mod - 1
            salt = ((seed ^ (seed >> 11) ^ (seed << 5)) & mask)
            salt2 = (((seed >> 3) ^ (seed << 9) ^ 0xA5A5) & mask)
            mode = seed & 3
            if mode == 1:
                return "bit32.band(bit32.bxor(%s, %d, %s), %d) == bit32.band(bit32.bxor(%d, %d, %s), %d)" % (
                    var, salt, roll, mask, number, salt, roll, mask)
            if mode == 2:
                return "bit32.band((%s + bit32.band(%s, %d) + %d), %d) == bit32.band((%d + bit32.band(%s, %d) + %d), %d)" % (
                    var, roll, mask, salt, mask, number, roll, mask, salt, mask)
            if mode == 3:
                return "bit32.band(bit32.bxor((%s + %d), %s, %d), %d) == bit32.band(bit32.bxor((%d + %d), %s, %d), %d)" % (
                    var, salt, roll, salt2, mask, number, salt, roll, salt2, mask)
            return "bit32.band(bit32.bxor(%s, %d), %d) == %d" % (
                var, salt, mask, (number ^ salt) & mask)

        if len(self.numbers) == 1:
            return one(self.numbers[0])
        # An aliased opcode tests as a disjunction rather than being emitted
        # twice: two arms with the same body would be boilerplate an automated
        # deobfuscator folds, and folding it would tell them where the alias set
        # is.
        return "(" + " or ".join(one(x) for x in self.numbers) + ")"

    def body(self, n: Dict[str, str], fam: Family, fmt: FormatSpec) -> List[str]:
        if self.pair is not None:
            return _fused_handler(self.pair, n, fam, fmt)
        return _handler(self.op, n, fam, fmt, variant=self.variant,
                        row_mask=self.row_mask)

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

def dispatch_entries(opmap: OpcodeMap, fmt: Optional[FormatSpec] = None,
                     row_mask: int = 0) -> List[_Entry]:
    """Every arm this build's dispatcher needs, in dispatch order.

    Ordered by opcode number, so the chain is a function of the map and nothing
    else: two builds whose maps agree emit chains that agree, which is what
    makes "the dispatcher is generated, not transcribed" checkable.
    """
    entries: List[_Entry] = []
    for op in sorted(opmap.to_byte, key=lambda o: opmap.to_byte[o]):
        for variant, number in enumerate(opmap.numbers(op)):
            entries.append(_Entry(op, (number,), variant=variant,
                                  row_mask=row_mask))
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


def _vm_fail(fmt: FormatSpec, site: int) -> str:
    seed = (getattr(fmt, "arm_seed", 0) ^ (site * 0x9E3779B1)) & 0xffffffff
    return "\"%08x\"" % seed


def _plain_cond(numbers: Tuple[int, ...]) -> str:
    if len(numbers) == 1:
        return "op == %d" % numbers[0]
    return "(" + " or ".join("op == %d" % x for x in numbers) + ")"



def _dispatch_key_seed(entries: Sequence[_Entry], fmt: FormatSpec) -> int:
    return (dispatch_seed(entries) ^ getattr(fmt, "arm_seed", 0) ^ 0xA3C59AC3) & 0xffffffff


def _dispatch_key_number(number: int, seed: int, fmt: FormatSpec) -> int:
    mask = (1 << (8 * max(1, int(getattr(fmt, "op_bytes", 1))))) - 1
    salt = ((seed ^ (seed >> 9) ^ (seed << 7)) & mask)
    pt = fmt.key_tap_value() if getattr(fmt, "key_taps", ()) else 0
    return ((number ^ salt ^ pt) + ((seed >> 16) & mask)) & mask


def _dispatch_key_expr(var: str, seed: int, fmt: FormatSpec) -> str:
    mask = (1 << (8 * max(1, int(getattr(fmt, "op_bytes", 1))))) - 1
    salt = ((seed ^ (seed >> 9) ^ (seed << 7)) & mask)
    bias = (seed >> 16) & mask
    if getattr(fmt, "key_taps", ()):
        # The tapped shape folds the payload-read term in at runtime; see
        # the chain ladder for why the text alone must not decode.
        return ("bit32.band(bit32.bxor(bit32.bxor(%s, %d), _pt) + %d, %d)"
                % (var, salt, bias, mask))
    return "bit32.band(bit32.bxor(%s, %d) + %d, %d)" % (var, salt, bias, mask)



def _local_ident(seed: int, tag: int) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    x = (seed ^ (tag * 0x9E3779B1) ^ 0xA5A5A5A5) & 0xffffffff
    chars = ["_"]
    for _ in range(7):
        x ^= (x << 13) & 0xffffffff
        x ^= x >> 17
        x ^= (x << 5) & 0xffffffff
        chars.append(alphabet[x % len(alphabet)])
    return "".join(chars)


def _handler_line(line: str, ret_name: str) -> List[str]:
    stripped = line.lstrip()
    prefix = line[:len(line) - len(stripped)]
    if stripped == "return":
        return [f"{prefix}{ret_name} = _pack()", f"{prefix}return true"]
    if stripped.startswith("return "):
        return [f"{prefix}{ret_name} = _pack({stripped[7:]})", f"{prefix}return true"]
    return [line]


def _emit_handler_bank(lines: List[str], entries: Sequence[_Entry],
                       n: Dict[str, str], fam: Family, fmt: FormatSpec,
                       trace: Optional[List[Tuple[Tuple[int, ...], Tuple[str, ...]]]] = None
                       ) -> Tuple[str, str, str, int]:
    seed = _dispatch_key_seed(entries, fmt)
    table_name = _local_ident(seed, 1)
    call_name = _local_ident(seed, 2)
    ret_name = _local_ident(seed, 4)
    bucket_count = 2 << (seed & 1)  # two or four tables, build-specific.
    lines.append(f"  local {table_name} = {{}}")
    lines.append(f"  local {ret_name} = nil")
    for bucket in range(1, bucket_count + 1):
        lines.append(f"  {table_name}[{bucket}] = {{}}")
    for idx, entry in enumerate(entries, 1):
        func_name = _local_ident(seed, 16 + idx)
        lines.append(f"  local function {func_name}()")
        for body_line in entry.body(n, fam, fmt):
            for emitted in _handler_line(body_line, ret_name):
                lines.append(f"    {emitted}")
        lines.append("  end")
        for number in entry.numbers:
            key = _dispatch_key_number(number, seed, fmt)
            bucket = ((key + (seed & 0xff)) % bucket_count) + 1
            lines.append(f"  {table_name}[{bucket}][{key}] = {func_name}")
        if trace is not None:
            trace.append((tuple(entry.numbers), (_plain_cond(tuple(entry.numbers)),)))
    return table_name, call_name, ret_name, bucket_count


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
        cond = entry.condition(fmt, roll="_vr")
        lines.append(f"{indent}{'if' if first else 'elseif'} {cond} then")
        first = False
        if trace is not None:
            trace.append((tuple(entry.numbers), path + (_plain_cond(tuple(entry.numbers)),)))
        for body_line in entry.body(n, fam, fmt):
            lines.append(f"{indent}  {body_line}")
    lines.append(f"{indent}else")
    lines.append(f"{indent}  error({_vm_fail(fmt, 1)})")
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


#: The single production dispatcher.
DISPATCHERS = ("woven",)


def dispatch_seed(entries: Sequence[_Entry]) -> int:
    """A per-build number derived from the dispatch table's shape."""
    total = 0
    for i, entry in enumerate(entries):
        for number in entry.numbers:
            total += number * (i + 1)
    return total


def _emit_chain_ladder(lines: List[str], entries: Sequence[_Entry],
                       n: Dict[str, str], fam: Family, fmt: FormatSpec,
                       trace: Optional[List[Tuple[Tuple[int, ...],
                                                  Tuple[str, ...]]]] = None
                       ) -> None:
    """The ``chain`` dispatch shape: handler bodies inlined in an if ladder.

    One scramble per instruction -- ``band(bxor(op, salt), mask)`` -- and then
    plain integer comparisons, one per arm, in this build's drawn order.  No
    closure call, no bucket table, no pack-of-results protocol on return:
    a RETURN arm's ``return ...`` leaves the interpreter directly, which is
    several times cheaper per instruction than the bank shape on hot loops.

    The scramble is the protection half: ``bxor`` with the format's salt is a
    bijection over the opcode field, so distinct numbers always map to
    distinct keys, an unassigned number can never collide with a real arm,
    and the keys in the ladder are a per-build image of the numbering rather
    than the numbering itself.
    """
    mask = (1 << (8 * max(1, fmt.op_bytes))) - 1
    salt = getattr(fmt, "dispatch_salt", 0) & mask
    # R2's tap: when the format taps a header filler byte, the scramble
    # gains a term the interpreter's text does not carry.  ``_pt`` is read
    # from the payload once per call, so the ladder's constants are an image
    # of the numbering under a salt the (encrypted) payload holds -- lifting
    # the interpreter alone no longer decodes the arms.  ``bxor`` stays
    # bijective in ``op`` either way, so an unassigned number still cannot
    # collide with a real arm.
    tapped = bool(getattr(fmt, "key_taps", ()))
    pt = fmt.key_tap_value() if tapped else 0
    dk = _local_ident((getattr(fmt, "arm_seed", 0) ^ salt ^ 0xC417), 7)
    if tapped:
        lines.append("    local %s = bit32.band(bit32.bxor(op, %d, _pt), %d)"
                     % (dk, salt, mask))
    else:
        lines.append("    local %s = bit32.band(bit32.bxor(op, %d), %d)"
                     % (dk, salt, mask))
    first = True
    for entry in entries:
        number = entry.numbers[0]
        key = (number ^ salt ^ pt) & mask
        cond = "%s == %d" % (dk, key)
        lines.append("    %s %s then" % ("if" if first else "elseif", cond))
        first = False
        if trace is not None:
            # Routing truth is recorded as the plain number the arm accepts:
            # the scramble is bijective, so "which value reaches which arm"
            # is the same fact stated without it, and the harness evaluates
            # these conditions with only ``op`` in scope.
            trace.append((tuple(entry.numbers),
                          (_plain_cond(tuple(entry.numbers)),)))
        for body_line in entry.body(n, fam, fmt):
            lines.append("      " + body_line)
    lines.append("    else")
    lines.append("      error(%s)" % _vm_fail(fmt, 1))
    lines.append("    end")


def _emit_dispatch(lines: List[str], entries: Sequence[_Entry],
                   n: Dict[str, str], fam: Family, dispatcher: str,
                   fmt: FormatSpec,
                   trace: Optional[List[Tuple[Tuple[int, ...],
                                              Tuple[str, ...]]]] = None,
                   table_name: str = "", call_name: str = "",
                   ret_name: str = "", bucket_count: int = 1
                   ) -> None:
    seed = _dispatch_key_seed(entries, fmt)
    if not table_name:
        table_name = _local_ident(seed, 1)
    if not call_name:
        call_name = _local_ident(seed, 2)
    if not ret_name:
        ret_name = _local_ident(seed, 4)
    key_name = _local_ident(seed, 3)
    lines.append(f"    local {key_name} = {_dispatch_key_expr('op', seed, fmt)}")
    if bucket_count > 1:
        lines.append(f"    local {call_name} = {table_name}[(({key_name} + {seed & 0xff}) % {bucket_count}) + 1][{key_name}]")
    else:
        lines.append(f"    local {call_name} = {table_name}[{key_name}]")
    lines.append(f"    if {call_name} == nil then error({_vm_fail(fmt, 1)}) end")
    lines.append(f"    if {call_name}() then return _unpack({ret_name}, 1, {ret_name}.n) end")


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
                       opaque_predicates: bool = True,
                       row_mask: int = 0
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
    nparams_expr = _le_read("_bd(_ec, %d)", nparams_at,
                             header.width("nparams"))
    entry_expr = "%s + 1" % raw
    if spec.header.entry_bias:
        # The bias wraps inside the field, so a large entry offset and a bias
        # cannot push the stored value out of the slot it lives in.
        entry_expr = "(%s - %d) %% %d + 1" % (raw, spec.header.entry_bias,
                                              1 << (8 * entry_w))
    loop_guard: List[str] = []
    if entry_guard:
        gseed = (getattr(spec, "arm_seed", 0) ^ len(opmap.to_op) ^ 0x6D2B79F5) & 0xffff
        gmask = 3 + (gseed & 3)
        loop_guard.append("if bit32.band(bit32.bxor(pc, op, %d), %d) == 0 then" % (gseed, gmask))
        loop_guard += ["  " + line for line in entry_guard]
        loop_guard.append("end")

    # The loop's tripwire: a pc driven off the payload reaches the same
    # neutral error as every other invalid VM state.  The payload's length is
    # hoisted to a local -- computing `#code` per instruction made the
    # tripwire cost several percent of a hot loop for nothing, because the
    # length cannot change while the loop runs.
    code_len = _local_ident((getattr(spec, "arm_seed", 0) ^ 0x1E4F), 9)
    opaque_line = ([
        f"    if {code_len} < pc or pc < 1 then error({_vm_fail(spec, 5)}) end",
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
        # setfenv for the same reason, and for one more: R5's fourth increment
        # builds a capturing child's entry stub *inside* the interpreter, whose
        # environment is not the virtualised parent's.  Held in a local so a
        # swapped environment cannot take it away from the build.
        f"local {n.get('setfenv') or 'setfenv'} = setfenv",
        f"local {n['call']} = function(R, base, argc, tail)",
        "  local f = R[base]",
        "  if tail >= 0 then",
        "    local t = R[tail + 1]",
        "    if t ~= nil then",
        "      local args = {}",
        "      for i = 1, argc do",
        "        args[i] = R[base + i]",
        "      end",
        "      local m = argc",
        "      for i = 1, t.n do",
        "        m += 1",
        "        args[m] = t[i]",
        "      end",
        "      return f(_unpack(args, 1, m))",
        "    end",
        "  end",
        "  if argc == 0 then",
        "    return f()",
        "  end",
        "  return f(_unpack(R, base + 1, base + argc))",
        "end",
        # E arrives as an argument.  Resolving it here instead would give this
        # function's environment, not the virtualised function's, and a
        # setfenv'd build would silently read and write the real globals.
        # Forward-declared, not merely declared later: ``exec``'s body holds
        # every handler, and R5's third increment gives one of them -- CLOSURE
        # -- reason to call ``enter``.  A local declared *after* ``exec`` would
        # read as a global there, which in Luau is nil, so the closure would be
        # created and then fail on the first call.  Declaring the name first
        # and assigning it afterwards makes it an upvalue of every arm.
        f"local {n['enter']}",
        f"local function {n['exec']}(p, R, E, _ec)",
        f"  local {n['code']} = _ec or p.code",
        f"  if type({n['code']}) == \"function\" then {n['code']} = {n['code']}() end",
        "  local K = p.consts",
        "  if type(K) == \"function\" then K = K() end",
    ]
    if spec.target_mode == "edges":
        # The edge table is its own pooled, authenticated blob, so a jump's
        # destination is not in the instruction stream at all (#18) while still
        # being inside something the pool's MAC covers -- which is what keeps
        # this distinct from putting targets in the plaintext descriptor.
        lines.append("  local %s = p.edges" % EDGE_LOCAL)
        lines.append("  if type(%s) == \"function\" then %s = %s() end" % (EDGE_LOCAL, EDGE_LOCAL, EDGE_LOCAL))
    lines += ["  " + ln for ln in reader_lines(spec, code, EDGE_LOCAL)]
    lines += [
        f"  local {code_len} = #{n['code']}",
        # The entry point comes out of the payload header, which is inside the
        # authenticated blob, rather than from the descriptor table beside it.
        f"  local pc = {entry_expr}",
    ] + ["  " + decl for decl in fam.state]
    tap_read = spec.key_tap_read(code)
    if tap_read:
        # The dispatch key's payload term, read once per call.  Placed with
        # the frame locals rather than in the loop: it cannot change while
        # the payload runs, and recomputing it per instruction would charge
        # the hot path for a constant.
        lines.append("  local _pt = %s" % tap_read)
    entries = dispatch_entries(opmap, spec, row_mask=row_mask)
    shape = getattr(spec, "dispatch_shape", "bank")
    if shape == "chain":
        # No bank: the arms' bodies go into the ladder below, so nothing here
        # declares the closure table or its pack-of-results protocol.
        handler_table = handler_call = handler_ret = ""
        handler_buckets = 1
    else:
        handler_table, handler_call, handler_ret, handler_buckets = _emit_handler_bank(lines, entries, n, fam, spec, trace)
    lines += [
        "  while true do",
        # The selector comes from the generated reader, not from a `byte(code, pc)`
        # written here: the stream carries the format's image of the number, so
        # the decode has to happen somewhere shared with every other field read
        # (`_ro`, alongside `_rr`/`_rk`/`_rp`) rather than in the one place that
        # also happens to be the anchor a matcher looks for first.
        "    local op = _ro(pc)",
        *opaque_line,
        "    local _vr = bit32.bxor(op, bit32.band(pc, 65535))",
        f"    pc = pc + {spec.op_bytes}",
        *["    " + line for line in loop_guard],
    ]

    if shape == "chain":
        _emit_chain_ladder(lines, entries, n, fam, spec, trace)
    else:
        _emit_dispatch(lines, entries, n, fam, dispatcher,
                       spec, trace, handler_table, handler_call, handler_ret, handler_buckets)
    lines += [
        "  end",
        "end",
        f"{n['enter']} = function(p, E, _uv, ...)",
        # The environment guard rides the dispatch loop (see ``loop_guard``),
        # masked like any other opaque check, rather than sitting at the head
        # of this function: an entry point that opens with the check is a
        # signature for it, and the loop already re-checks often enough that a
        # mid-run swap is caught within a handful of instructions.
        "  local _ec = p.code",
        "  if type(_ec) == \"function\" then _ec = _ec() end",
        "  local R = {}",
        "  local args = _pack(...)",
        # same reason as the entry point: nparams is a header field, and which
        # one is a property of this build's layout
        "  for i = 1, %s do" % nparams_expr,
        "    R[i] = args[i]",
        "  end",
        # R5: the vararg tail rides the frame.  A VARARG instruction is then a
        # slice of this pack -- nothing outside the call can observe it, which
        # is why varargs could join the VM.  The named-parameter count travels
        # as a field of the pack itself, because `args` is fresh per call and
        # nothing that reads it looks past `.n`.
        "  args.%s = %s" % (n["vnp"], nparams_expr),
        "  R.%s = args" % n["vpack"],
        # R5's second increment: upvalues ride the frame too -- but not as
        # state.  ``_uv`` is the accessor list the stub built for this
        # prototype (getter/setter closures over the native variable), or
        # ``false`` when the prototype captures nothing.  GETUPVAL and
        # SETUPVAL call through it; the frame itself never holds a captured
        # value, so nothing outside the call can observe a copy.
        "  R.%s = _uv" % n["uvs"],
        f"  return {n['exec']}(p, R, E, _ec)",
        "end",
    ]
    return _rename_core_tokens("\n".join(lines) + "\n", names)


#: The interpreter's working names, as written in the templates above.
_CORE_TOKENS = (("pc", "pc"), ("R", "regs"), ("K", "consts"), ("E", "env"),
                ("EG", "edges"), ("_ro", "ro"), ("_r8", "r8"),
                ("_rr", "rr"), ("_rw", "rw"), ("_rk", "rk"),
                ("_rp", "rp"), ("_rt", "rt"), ("_pt", "pt"))


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

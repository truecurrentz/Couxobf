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

Opcode numbers are inlined from the build's :class:`OpcodeMap`, so the dispatch
chain differs between builds.  The chain is generated, never transcribed.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from ..ir import OP
from .families import Family, family as _family, substitute
from .isa import OP_GETTABLEK, OP_SETTABLEK, OpcodeMap


def _handler(op: str, n: Dict[str, str],
             fam: Optional[Family] = None) -> List[str]:
    """The Luau body of one opcode handler.

    The dispatcher has already stepped past the opcode byte, so operand reads
    start at ``pc`` and every handler advances ``pc`` by its own operand width
    before doing its work.  A handler that jumps only has to overwrite ``pc``
    afterwards.

    ``fam`` is the operand discipline -- see :mod:`couxobf.vm.families`.  Every
    value-producing handler routes its result through the family rather than
    assigning to the register file directly, which is what makes the four
    interpreters actually differ instead of being the same code with different
    local names.
    """
    if fam is None:
        fam = _family("register", n)
    code = n["code"]
    b = lambda at: f"_byte({code}, {at})"
    w = lambda at: f"(_byte({code}, {at}) + _byte({code}, {at} + 1) * 256)"
    reg = lambda at: f"({b(at)} + 1)"  # register file is one-based

    if op == OP.MOV:
        return [f"local a, s = {reg('pc')}, {reg('pc + 1')}",
                "pc = pc + 2"] + fam.store("R[a]", "R[s]")
    if op == OP.LOADK:
        # the constant index is read before pc moves: these expressions embed
        # the literal text "pc + 1", so advancing first would read past the
        # instruction.  Every handler keeps its reads ahead of its advance.
        return [f"local a = {reg('pc')}",
                f"local k = {w('pc + 1')}",
                "pc = pc + 3"] + fam.store("R[a]", "K[k + 1]")
    if op == OP.GETGLOBAL:
        # E is the calling function's environment, resolved per call -- see
        # interpreter_source for why it cannot be captured once at load.
        return [f"local a = {reg('pc')}",
                f"local k = {w('pc + 1')}",
                "pc = pc + 3"] + fam.store("R[a]", "E[K[k + 1]]")
    if op == OP.SETGLOBAL:
        return [f"local k = {w('pc')}",
                f"local v = {reg('pc + 2')}",
                "pc = pc + 3",
                "E[K[k + 1]] = R[v]"]
    if op == OP.GETTABLE:
        # computed key: `t[k]`
        return [f"local a, o, k = {reg('pc')}, {reg('pc + 1')}, {reg('pc + 2')}",
                "pc = pc + 3"] + fam.store("R[a]", "R[o][R[k]]")
    if op == OP_GETTABLEK:
        # literal key: `t.k`, so the key is a pool constant
        return [f"local a, o = {reg('pc')}, {reg('pc + 1')}",
                f"local k = {w('pc + 2')}",
                "pc = pc + 4"] + fam.store("R[a]", "R[o][K[k + 1]]")
    if op == OP.SETTABLE:
        # computed key: `t[k] = v`
        return [f"local o, k, v = {reg('pc')}, {reg('pc + 1')}, {reg('pc + 2')}",
                "pc = pc + 3",
                "R[o][R[k]] = R[v]"]
    if op == OP_SETTABLEK:
        # literal key: `t.k = v`, so the key is a pool constant
        return [f"local o, v = {reg('pc')}, {reg('pc + 1')}",
                f"local k = {w('pc + 2')}",
                "pc = pc + 4",
                "R[o][K[k + 1]] = R[v]"]
    if op == OP.NEWTABLE:
        return [f"local a = {reg('pc')}",
                "pc = pc + 1"] + fam.store("R[a]", "{}")
    if op in (OP.ADD, OP.SUB, OP.MUL, OP.DIV, OP.IDIV, OP.MOD, OP.POW, OP.CONCAT):
        symbol = {OP.ADD: "+", OP.SUB: "-", OP.MUL: "*", OP.DIV: "/",
                  OP.IDIV: "//", OP.MOD: "%", OP.POW: "^", OP.CONCAT: ".."}[op]
        return [f"local a, x, y = {reg('pc')}, {reg('pc + 1')}, {reg('pc + 2')}",
                "pc = pc + 3"] + fam.binary("R[a]", "R[x]", "R[y]", symbol)
    if op in (OP.EQ, OP.NE, OP.LT, OP.LE, OP.GT, OP.GE):
        symbol = {OP.EQ: "==", OP.NE: "~=", OP.LT: "<", OP.LE: "<=",
                  OP.GT: ">", OP.GE: ">="}[op]
        return [f"local a, x, y = {reg('pc')}, {reg('pc + 1')}, {reg('pc + 2')}",
                "pc = pc + 3"] + fam.binary("R[a]", "R[x]", "R[y]", symbol)
    if op == OP.UNM:
        return [f"local a, x = {reg('pc')}, {reg('pc + 1')}", "pc = pc + 2"] + \
            substitute(fam.unary("R[a]", lambda e: "-" + e), "R[x]")
    if op == OP.NOT:
        return [f"local a, x = {reg('pc')}, {reg('pc + 1')}", "pc = pc + 2"] + \
            substitute(fam.unary("R[a]", lambda e: "not " + e), "R[x]")
    if op == OP.LEN:
        return [f"local a, x = {reg('pc')}, {reg('pc + 1')}", "pc = pc + 2"] + \
            substitute(fam.unary("R[a]", lambda e: "#" + e), "R[x]")
    if op == OP.CALL:
        # nres and tail arrive biased by one so -1 encodes as 0
        return [f"local base = {reg('pc')}",
                f"local argc = {w('pc + 1')}",
                f"local nres = {w('pc + 3')} - 1",
                f"local tail = {w('pc + 5')} - 1",
                "pc = pc + 7",
                f"local res = _pack({n['call']}(R, base, argc, tail))",
                "if nres < 0 then",
                "  R[base] = res",
                "else",
                "  for i = 1, nres do"] + \
            ["    " + line for line in fam.store("R[base + i - 1]", "res[i]")] + \
            ["  end", "end"]
    if op == OP.TAILCALL:
        return [f"local base = {reg('pc')}",
                f"local argc = {w('pc + 1')}",
                f"local tail = {w('pc + 3')} - 1",
                "pc = pc + 5",
                f"return {n['call']}(R, base, argc, tail)"]
    if op == OP.RETURN:
        return [f"local base = {reg('pc')}",
                f"local count = {w('pc + 1')}",
                "pc = pc + 3",
                "return _unpack(R, base, base + count - 1)"]
    if op == OP.RETURN0:
        return ["return"]
    if op == OP.RETURNMULTI:
        # explicit values first, then the spliced multi-ret -- the count is
        # part of the instruction and dropping it loses the prefix.  They go
        # into one table: `return unpack(a), unpack(b)` truncates the first
        # call to a single value, which would silently drop all but head[1].
        return [f"local base = {reg('pc')}",
                f"local count = {w('pc + 1')}",
                f"local t = {reg('pc + 3')}",
                "pc = pc + 5",
                "local src = R[t]",
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
        return [f"local dst = {reg('pc')}",
                f"local t = {reg('pc + 1')}",
                f"local count = {w('pc + 3')}",
                "pc = pc + 5",
                "local src = R[t]",
                # assigns nils past src.n, matching a multi-assign that fills
                # missing values with nil
                "for i = 1, count do",
                "  R[dst + i - 1] = src[i]",
                "end"]
    if op == OP.SETLIST:
        return [f"local tbl = {reg('pc')}",
                f"local count = {w('pc + 1')}",
                f"local start = {w('pc + 3')}",
                "pc = pc + 5",
                "local t = R[tbl]",
                # absolute indices: appending at #t + 1 would drop explicit nils
                "for i = 1, count do",
                "  t[start + i - 1] = R[tbl + i]",
                "end"]
    if op == OP.SETLISTMULTI:
        return [f"local tbl = {reg('pc')}",
                f"local pk = {reg('pc + 1')}",
                "pc = pc + 3",
                f"{n['append']}(R[tbl], R[pk])"]
    if op == OP.SELF:
        # R(base+1) = obj; R(base) = obj[key]
        return [f"local a, o = {reg('pc')}, {reg('pc + 1')}",
                f"local k = {w('pc + 2')}",
                "pc = pc + 4",
                "local obj = R[o]",
                "R[a + 1] = obj",
                "R[a] = obj[K[k + 1]]"]
    if op == OP.JMP:
        return [f"pc = {w('pc')} + 1"]
    if op in (OP.JMPFALSE, OP.JMPTRUE):
        cond = f"R[{reg('pc')}]"
        if op == OP.JMPFALSE:
            cond = f"not {cond}"
        return [f"local c = {cond}",
                f"local tgt = {w('pc + 1')}",
                "pc = pc + 3",
                "if c then",
                "  pc = tgt + 1",
                "end"]
    if op == OP.FORPREP:
        # step the counter back once, then jump to FORLOOP which steps forward
        # and tests -- the same split the reconstructor emits
        return [f"local base = {reg('pc')}",
                f"local tgt = {w('pc + 1')}",
                "pc = pc + 3",
                "R[base] = R[base] - R[base + 2]",
                "pc = tgt + 1"]
    if op == OP.FORLOOP:
        return [f"local base = {reg('pc')}",
                f"local tgt = {w('pc + 1')}",
                "pc = pc + 3",
                "local i = R[base] + R[base + 2]",
                "R[base] = i",
                "local lim, step = R[base + 1], R[base + 2]",
                "if (step > 0 and i <= lim) or (step < 0 and i >= lim) then",
                "  R[base + 3] = i",
                "  pc = tgt + 1",
                "end"]
    if op == OP.FORINPREP:
        # validated once at loop entry, the way Luau does it; skipped when
        # ITERPREP resolved the iterator so a bad __iter result surfaces as a
        # call failure
        return [f"local base = {reg('pc')}",
                f"local tgt = {w('pc + 1')}",
                f"local resolved = {w('pc + 3')}",
                "pc = pc + 5",
                "if resolved == 0 then",
                f"  R[base] = {n['itercheck']}(R[base])",
                "end",
                "pc = tgt + 1"]
    if op == OP.FORIN:
        # one call, all its results -- calling the iterator a second time to
        # fetch the extras would be observably wrong for any stateful iterator
        return [f"local base = {reg('pc')}",
                f"local tgt = {w('pc + 1')}",
                f"local nvars = {w('pc + 3')}",
                "pc = pc + 5",
                "local f, s, c = R[base], R[base + 1], R[base + 2]",
                "local res = _pack(f(s, c))",
                "if res[1] ~= nil then",
                "  for i = 0, nvars - 1 do",
                "    R[base + 3 + i] = res[i + 1]",
                "  end",
                "  R[base + 2] = res[1]",
                "  pc = tgt + 1",
                "end"]
    if op == OP.ITERPREP:
        return [f"local base = {reg('pc')}",
                f"local packed = {w('pc + 1')}",
                "pc = pc + 3",
                f"local h = packed == 1 and {n['iterpack']} or {n['iter']}",
                "R[base], R[base + 1], R[base + 2] = h(R[base])"]
    raise ValueError(f"{op} has no handler")


def interpreter_source(opmap: OpcodeMap, names: Dict[str, str],
                       vm_family: str = "register") -> str:
    """The interpreter, with this build's opcode numbers inlined.

    ``names`` supplies the local names so the interpreter is not recognisable
    by shape alone: ``code``, ``exec``, ``enter``, ``call``, ``getfenv``,
    ``acc``, ``stack``, ``sp``, ``append``, ``iter``, ``iterpack``,
    ``itercheck``.

    ``vm_family`` selects the operand discipline.  Same bytecode, same
    semantics, different machinery -- see :mod:`couxobf.vm.families`.
    """
    n = names
    fam = _family(vm_family, names)
    lines: List[str] = [
        "local _byte = string.byte",
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
        "  local pc = p.entry",
    ] + ["  " + decl for decl in fam.state] + [
        "  while true do",
        f"    local op = _byte({n['code']}, pc)",
        "    pc = pc + 1",
    ]

    first = True
    for op in sorted(opmap.to_byte, key=lambda o: opmap.to_byte[o]):
        number = opmap.to_byte[op]
        lines.append(f"    {'if' if first else 'elseif'} op == {number} then")
        first = False
        for body_line in _handler(op, n, fam):
            lines.append(f"      {body_line}")
    lines += [
        "    else",
        '      error("unknown opcode " .. tostring(op))',
        "    end",
        "  end",
        "end",
        f"local function {n['enter']}(p, E, ...)",
        "  local R = {}",
        "  local args = _pack(...)",
        "  for i = 1, p.nparams do",
        "    R[i] = args[i]",
        "  end",
        f"  return {n['exec']}(p, R, E)",
        "end",
    ]
    return "\n".join(lines) + "\n"

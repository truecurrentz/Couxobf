"""couxobf's intermediate representation.

A register-machine IR with an explicit CFG.  Every transformation after this
point works on IR, never on source text, so the obfuscator cannot be fooled by
surface syntax and cannot accidentally produce invalid Luau.

Shape
-----
* three-address-ish instructions over a virtual register file (unbounded
  registers; allocation happens later),
* one constant pool per prototype,
* explicit upvalue descriptors,
* a control-flow graph with block ids, predecessor/successor lists, and
  per-instruction side-effect and liveness information.

Lowering follows Luau's documented semantics closely enough that the VM
lowering can be checked instruction by instruction:

* ``for`` loops use the ``FORPREP``/``FORLOOP`` pair with Lua's "pre-decrement
  then jump past the body" arrangement, so integer-loop edge cases (empty
  ranges, negative steps, huge limits) behave identically;
* ``repeat ... until`` evaluates its condition inside the body's scope, which
  is why body locals are visible to it;
* ``and``/``or`` short-circuit through conditional jumps rather than a
  boolean-producing instruction, so a right operand with side effects runs
  exactly as often as it does in the original;
* multi-value calls are explicit (``MULTIRET``), so ``local a, b = f()`` and
  ``local a = f()`` are distinguishable and truncation is preserved.

What this IR deliberately does *not* do
---------------------------------------
It does not model Luau's gradual type system beyond passing annotations
through as opaque text, and it does not attempt to prove anything about
metatables.  Every transformation in the pipeline is therefore required to be
sound under arbitrary ``__index``/``__newindex``/``__add`` metamethods.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

from . import ast_nodes as A
from .lexer import unescape_text

MULTIRET = -1


# --------------------------------------------------------------------------
# operands
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Reg:
    index: int

    # Offset arithmetic keeps call/return/vararg register ranges readable:
    # ``base + i`` is the i-th slot of a multi-register run.
    def __add__(self, other: int) -> "Reg":
        return Reg(self.index + other)

    def __sub__(self, other: int) -> "Reg":
        return Reg(self.index - other)

    def __str__(self) -> str:  # pragma: no cover - debug output
        return f"R{self.index}"


@dataclass(frozen=True)
class Kon:
    """Index into the prototype's constant pool."""

    index: int

    def __str__(self) -> str:  # pragma: no cover
        return f"K{self.index}"


@dataclass(frozen=True)
class Up:
    """Index into the prototype's upvalue table."""

    index: int

    def __str__(self) -> str:  # pragma: no cover
        return f"U{self.index}"


Operand = Union[Reg, Kon, Up]


@dataclass(frozen=True)
class UpvalueDesc:
    """How a prototype reaches one of its upvalues.

    ``from_local`` means the value lives in a register of the immediately
    enclosing prototype at creation time (Lua's OPEN upvalue); otherwise it is
    reached through an upvalue of the enclosing prototype.
    """

    from_local: bool
    index: int
    name: str


# --------------------------------------------------------------------------
# instructions
# --------------------------------------------------------------------------
class OP:
    NOP = "NOP"
    MOV = "MOV"                     # d, a
    LOADK = "LOADK"                 # d, k
    GETGLOBAL = "GETGLOBAL"         # d, k(name)
    SETGLOBAL = "SETGLOBAL"         # k(name), a
    GETUPVAL = "GETUPVAL"           # d, u
    SETUPVAL = "SETUPVAL"           # u, a
    SELF = "SELF"                   # base, a, k   -> R(base)=a[k], R(base+1)=a
    GETTABLE = "GETTABLE"           # d, a, b
    SETTABLE = "SETTABLE"           # a, b, c
    NEWTABLE = "NEWTABLE"           # d, narr, nrec
    SETLIST = "SETLIST"             # base, count, start
    SETLISTMULTI = "SETLISTMULTI"   # base, packreg
    ADD = "ADD"                     # d, a, b
    SUB = "SUB"
    MUL = "MUL"
    DIV = "DIV"
    IDIV = "IDIV"
    MOD = "MOD"
    POW = "POW"
    UNM = "UNM"                     # d, a
    NOT = "NOT"                     # d, a
    LEN = "LEN"                     # d, a
    CONCAT = "CONCAT"               # d, a, b
    EQ = "EQ"                       # d, a, b   (boolean)
    NE = "NE"
    LT = "LT"
    LE = "LE"
    GT = "GT"
    GE = "GE"
    JMP = "JMP"                     # target
    JMPFALSE = "JMPFALSE"           # a, target
    JMPTRUE = "JMPTRUE"             # a, target
    # Multi-value convention: a call or vararg with nres == MULTIRET stores
    # ``table.pack`` of its results *back into its own base register*.  A
    # trailing multi-valued argument is recorded in the call's ``tail`` slot so
    # the emitter can splice those values in as the final arguments, and
    # ``EXPAND`` distributes a packed multi into consecutive registers.
    CALL = "CALL"                   # base, argc, nres, tail
    TAILCALL = "TAILCALL"           # base, argc, tail
    RETURN = "RETURN"               # base, n
    RETURN0 = "RETURN0"
    RETURNMULTI = "RETURNMULTI"     # base, n, packreg
    EXPAND = "EXPAND"               # dst, packreg, count
    CLOSURE = "CLOSURE"             # d, proto
    VARARG = "VARARG"               # base, n
    FORPREP = "FORPREP"             # base, target
    FORLOOP = "FORLOOP"             # base, target
    # Luau's generalized iteration: `for x in v do` where v is a single value
    # uses v directly when it is callable, otherwise calls v's __iter to obtain
    # the (iterator, state, control) triple.
    ITERPREP = "ITERPREP"           # base
    FORINPREP = "FORINPREP"         # base, target
    FORIN = "FORIN"                 # base, target, nvars
    LABEL = "LABEL"                 # marker, never executes


#: Instructions that cannot raise, cannot invoke a metamethod, and cannot
#: observe or change program state.  Only these may be deleted when their
#: result is dead or reordered freely -- Luau arithmetic goes through
#: metamethods, so almost nothing else qualifies.
PURE_OPS = frozenset({OP.MOV, OP.LOADK, OP.NOP})

#: Instructions with no destination and no observable effect other than
#: writing a value that may itself be dead.
#: Instructions that always transfer control themselves.  Every one of these
#: sets the program counter (or leaves the function), so an emitter must not
#: also append a fall-through -- doing so silently breaks loop back-edges.
TERMINATORS = frozenset({OP.JMP, OP.JMPFALSE, OP.JMPTRUE, OP.TAILCALL,
                         OP.RETURN, OP.RETURN0, OP.RETURNMULTI,
                         OP.FORPREP, OP.FORINPREP, OP.FORLOOP, OP.FORIN})


@dataclass
class Instr:
    op: str
    args: Tuple[Any, ...] = ()
    line: int = 0
    #: set by the lowerer: the AST node this instruction came from
    origin: Any = None

    def dest(self) -> Optional[Reg]:
        """The register this instruction defines, if any."""
        if self.op in (OP.MOV, OP.LOADK, OP.GETGLOBAL, OP.GETUPVAL, OP.GETTABLE,
                       OP.ADD, OP.SUB, OP.MUL, OP.DIV, OP.IDIV, OP.MOD, OP.POW,
                       OP.UNM, OP.NOT, OP.LEN, OP.CONCAT, OP.EQ, OP.NE, OP.LT,
                       OP.LE, OP.GT, OP.GE, OP.NEWTABLE, OP.CLOSURE):
            return self.args[0] if isinstance(self.args[0], Reg) else None
        if self.op in (OP.CALL, OP.VARARG, OP.SELF):
            return self.args[0] if isinstance(self.args[0], Reg) else None
        return None

    def uses(self) -> List[Operand]:
        """Operands this instruction reads.  Excludes its own destination."""
        d = self.dest()
        out: List[Operand] = []
        for i, a in enumerate(self.args):
            if not isinstance(a, (Reg, Kon, Up)):
                continue
            if i == 0 and d is not None and a is d and self.op not in (
                    OP.CALL, OP.VARARG, OP.SELF):
                continue
            out.append(a)
        return out

    def __str__(self) -> str:  # pragma: no cover - debug output
        return f"{self.op} " + ", ".join(str(a) for a in self.args)


@dataclass
class Label:
    id: int


# --------------------------------------------------------------------------
# CFG
# --------------------------------------------------------------------------
@dataclass
class Block:
    id: int
    instrs: List[Instr] = field(default_factory=list)
    succ: List[int] = field(default_factory=list)
    pred: List[int] = field(default_factory=list)
    #: block-local live-out set, filled by compute_liveness
    live_out: Set[int] = field(default_factory=set)
    live_in: Set[int] = field(default_factory=set)

    @property
    def terminator(self) -> Optional[Instr]:
        return self.instrs[-1] if self.instrs else None

    def __str__(self) -> str:  # pragma: no cover
        return f"B{self.id}({len(self.instrs)}i -> {self.succ})"


@dataclass
class FuncIR:
    proto_id: int
    name: Optional[str]
    node: Any                       # A.Func, or None for the main chunk
    num_params: int = 0
    is_vararg: bool = False
    num_regs: int = 0
    consts: List[Any] = field(default_factory=list)
    upvalues: List[UpvalueDesc] = field(default_factory=list)
    children: List["FuncIR"] = field(default_factory=list)
    blocks: List[Block] = field(default_factory=list)
    entry: int = 0
    is_method: bool = False
    method_name: Optional[str] = None
    #: facts the classifier uses to decide the virtualization level
    node_count: int = 0
    call_count: int = 0
    closure_count: int = 0
    loop_count: int = 0
    branch_count: int = 0
    #: registers holding a value that is fresh on each loop iteration: the
    #: loop variable itself, and any local declared inside a loop body.  A
    #: closure capturing one of these must see the value from the iteration it
    #: was created in, not whatever the register holds later.
    per_iteration: Set[int] = field(default_factory=set)
    #: filled in by the classifier / lowering
    virtualization: int = 0
    vm_family: Optional[str] = None

    # -- constants -------------------------------------------------------
    def add_const(self, value: Any) -> Kon:
        for i, v in enumerate(self.consts):
            if type(v) is type(value) and v == value:
                return Kon(i)
        self.consts.append(value)
        return Kon(len(self.consts) - 1)

    def add_name(self, name: str) -> Kon:
        return self.add_const(name.encode("utf-8", "surrogatepass"))

    # -- blocks ----------------------------------------------------------
    def renumber(self) -> None:
        self.entry = self.blocks[0].id if self.blocks else 0

    def all_instrs(self) -> Iterable[Instr]:
        for b in self.blocks:
            yield from b.instrs

    def walk_children(self) -> Iterable["FuncIR"]:
        yield self
        for c in self.children:
            yield from c.walk_children()


@dataclass
class IRModule:
    main: FuncIR
    protos: List[FuncIR] = field(default_factory=list)

    def walk(self) -> Iterable[FuncIR]:
        return self.main.walk_children()


# ==========================================================================
# lowering
# ==========================================================================
_BINARY_OPS = {
    "+": OP.ADD, "-": OP.SUB, "*": OP.MUL, "/": OP.DIV, "//": OP.IDIV,
    "%": OP.MOD, "^": OP.POW, "..": OP.CONCAT,
    "==": OP.EQ, "~=": OP.NE, "<": OP.LT, "<=": OP.LE, ">": OP.GT, ">=": OP.GE,
}


class LoweringError(Exception):
    pass


def _lid(target: Any) -> int:
    """A jump target is a Label while lowering and an int afterwards."""
    return target.id if isinstance(target, Label) else int(target)


@dataclass
class _Local:
    reg: int
    name: str


class _FuncBuilder:
    def __init__(self, lowerer: "Lowerer", proto: FuncIR,
                 parent: Optional["_FuncBuilder"] = None) -> None:
        self.l = lowerer
        self.proto = proto
        self.parent = parent
        self.code: List[Union[Instr, Tuple[Label, Instr]]] = []
        #: scope stack of {name: _Local}
        self.scopes: List[Dict[str, _Local]] = [{}]
        self.base = 0
        self.max_regs = 0
        self.loop_depth = 0
        #: registers of locals some closure captured.  A captured local stays
        #: reachable through the closure after its block closes, so its
        #: register must never be handed out again.
        self.captured: Set[int] = set()
        self.loop_stack: List[Tuple[Label, Label]] = []  # (continue, break)
        self.next_label = 0
        self.reg_names: Dict[int, str] = {}

    # -- emission --------------------------------------------------------
    def emit(self, op: str, *args: Any, line: int = 0, origin: Any = None) -> Instr:
        ins = Instr(op, tuple(args), line, origin)
        self.code.append(ins)
        return ins

    def label(self) -> Label:
        self.next_label += 1
        lbl = Label(self.next_label)
        self.code.append((lbl, Instr(OP.LABEL, (lbl.id,))))
        return lbl

    def place(self, lbl: Label) -> None:
        self.code.append((lbl, Instr(OP.LABEL, (lbl.id,))))

    def new_reg(self) -> Reg:
        """Allocate a scratch register.

        Scratch registers are never recycled *within* a statement -- a value
        may still be referenced by a pending store -- but the whole scratch
        range is reclaimed when the statement ends (see ``Lowerer._stmt``).
        """
        idx = self.proto.num_regs
        self.proto.num_regs += 1
        self.max_regs = max(self.max_regs, self.proto.num_regs)
        return Reg(idx)

    def new_regs(self, n: int) -> List[Reg]:
        return [self.new_reg() for _ in range(n)]

    def alloc_local(self, name: str) -> Reg:
        idx = self.proto.num_regs
        self.proto.num_regs += 1
        self.scopes[-1][name] = _Local(idx, name)
        self.base = self.proto.num_regs
        self.max_regs = max(self.max_regs, self.proto.num_regs)
        self.reg_names[idx] = name
        return Reg(idx)

    def push_scope(self) -> None:
        self.scopes.append({})

    def pop_scope(self) -> None:
        self.scopes.pop()
        self.base = self._min_base()

    def _min_base(self) -> int:
        high = 0
        for scope in self.scopes:
            for loc in scope.values():
                high = max(high, loc.reg + 1)
        for reg in self.captured:
            high = max(high, reg + 1)
        return high

    def lookup(self, name: str) -> Optional[_Local]:
        for scope in reversed(self.scopes):
            loc = scope.get(name)
            if loc is not None:
                return loc
        return None

    # -- upvalues --------------------------------------------------------
    def upvalue_for(self, name: str) -> Optional[Up]:
        """Bind ``name`` from an enclosing prototype as an upvalue of *this* one.

        ``chain[d]`` is the enclosing builder at distance ``d + 1`` (so
        ``chain[0]`` is the immediate parent).  If the variable is a local of
        ``chain[D]``, then every builder between it and this one needs a relay
        slot, because an upvalue can only reach one prototype level at a time.
        """
        chain: List[_FuncBuilder] = []
        cur = self.parent
        while cur is not None:
            chain.append(cur)
            cur = cur.parent

        src_depth = -1
        src_local: Optional[_Local] = None
        src_upval = -1
        for d, fb in enumerate(chain):
            loc = fb.lookup(name)
            if loc is not None:
                src_depth, src_local = d, loc
                # pin the register: the closure outlives the block that
                # declared the local, and the reconstruction resolves the
                # upvalue by that register's name.
                fb.captured.add(loc.reg)
                break
            for i, desc in enumerate(fb.proto.upvalues):
                if desc.name == name:
                    src_depth, src_upval = d, i
                    break
            if src_depth >= 0:
                break
        if src_depth < 0:
            return None

        from_local = src_local is not None
        index = src_local.reg if src_local is not None else src_upval

        # thread relay slots from the prototype just inside the source down to
        # the immediate parent
        for d in range(src_depth - 1, -1, -1):
            index = chain[d]._add_upvalue(
                UpvalueDesc(from_local=from_local, index=index, name=name))
            from_local = False

        return Up(self._add_upvalue(
            UpvalueDesc(from_local=from_local, index=index, name=name)))

    def _add_upvalue(self, desc: UpvalueDesc) -> int:
        """Add (or find) an upvalue descriptor; returns its index."""
        for i, d in enumerate(self.proto.upvalues):
            if (d.name == desc.name and d.from_local == desc.from_local
                    and d.index == desc.index):
                return i
        self.proto.upvalues.append(desc)
        return len(self.proto.upvalues) - 1

    # -- operand for a name ---------------------------------------------
    def read_name(self, name: str, dst: Reg, line: int) -> None:
        loc = self.lookup(name)
        if loc is not None:
            self.emit(OP.MOV, dst, Reg(loc.reg), line=line)
            return
        if self.parent is not None:
            up = self.upvalue_for(name)
            if up is not None:
                self.emit(OP.GETUPVAL, dst, up, line=line)
                return
        self.emit(OP.GETGLOBAL, dst, self.proto.add_name(name), line=line)

    def write_name(self, name: str, src: Reg, line: int) -> None:
        loc = self.lookup(name)
        if loc is not None:
            self.emit(OP.MOV, Reg(loc.reg), src, line=line)
            return
        if self.parent is not None:
            up = self.upvalue_for(name)
            if up is not None:
                self.emit(OP.SETUPVAL, up, src, line=line)
                return
        self.emit(OP.SETGLOBAL, self.proto.add_name(name), src, line=line)


class Lowerer:
    def __init__(self) -> None:
        self.protos: List[FuncIR] = []

    # -- entry -----------------------------------------------------------
    def lower(self, root: A.Block) -> IRModule:
        main = FuncIR(proto_id=0, name="<main>", node=None, is_vararg=True)
        self.protos.append(main)
        fb = _FuncBuilder(self, main)
        fb.base = 0
        self._block(fb, root)
        fb.emit(OP.RETURN0, line=0)
        main.num_regs = fb.max_regs
        main.blocks = self._build_cfg(fb)
        main.node_count = self._count(root)
        for proto in self.protos:
            compute_liveness(proto)
        return IRModule(main=main, protos=self.protos)

    def _count(self, node: Any) -> int:
        return len(list(A.walk(node))) if hasattr(A, "walk") else 1

    # -- CFG construction ------------------------------------------------
    def _build_cfg(self, fb: _FuncBuilder) -> List[Block]:
        """Split the linear stream into basic blocks and link the edges."""
        items = fb.code
        label_at: Dict[int, int] = {}
        # pass 1: which positions start a block
        starts: Set[int] = {0}
        for i, it in enumerate(items):
            ins = it[1] if isinstance(it, tuple) else it
            if isinstance(it, tuple):
                starts.add(i)
                label_at[it[0].id] = None  # filled below
            if ins.op in (OP.JMP, OP.JMPFALSE, OP.JMPTRUE):
                starts.add(i + 1)
            elif ins.op in (OP.RETURN, OP.RETURN0, OP.RETURNMULTI, OP.TAILCALL):
                starts.add(i + 1)

        # map label id -> block index
        block_index: List[int] = []
        cur = -1
        for i, it in enumerate(items):
            if i in starts:
                cur += 1
            block_index.append(cur)
        for i, it in enumerate(items):
            if isinstance(it, tuple):
                label_at[it[0].id] = block_index[i]

        nblocks = cur + 1
        blocks = [Block(id=i) for i in range(nblocks)]
        for i, it in enumerate(items):
            if isinstance(it, tuple):
                continue
            blocks[block_index[i]].instrs.append(it)
        # A label maps to the block that starts at its position.  This table
        # is the only place jump targets are resolved; blocks that turn out
        # empty simply fall through via their successor edge.
        self._resolve_edges(blocks, {k: v for k, v in label_at.items()
                                     if v is not None})
        return blocks

    def _resolve_edges(self, blocks: List[Block], label_at: Dict[int, int]) -> None:
        for b in blocks:
            b.instrs = [i for i in b.instrs if i.op != OP.LABEL]

        def resolve(lbl_id: int) -> int:
            if lbl_id not in label_at:
                raise LoweringError(f"jump to unplaced label {lbl_id}")
            return label_at[lbl_id]

        for b in blocks:
            term = b.instrs[-1] if b.instrs else None
            fallthrough = b.id + 1 if b.id + 1 < len(blocks) else None
            if term is None:
                if fallthrough is not None:
                    b.succ.append(fallthrough)
                continue
            op = term.op
            if op in (OP.RETURN, OP.RETURN0, OP.RETURNMULTI, OP.TAILCALL):
                continue
            if op == OP.JMP:
                tgt = resolve(_lid(term.args[0]))
                term.args = (tgt,)
                b.succ.append(tgt)
            elif op in (OP.JMPFALSE, OP.JMPTRUE):
                tgt = resolve(_lid(term.args[1]))
                term.args = (term.args[0], tgt)
                if fallthrough is not None:
                    b.succ.append(fallthrough)
                b.succ.append(tgt)
            elif op in (OP.FORPREP, OP.FORINPREP):
                tgt = resolve(_lid(term.args[1]))
                # preserve any trailing operands -- FORINPREP carries a flag
                # saying whether ITERPREP already resolved the iterator
                term.args = (term.args[0], tgt) + tuple(term.args[2:])
                b.succ.append(tgt)
            elif op in (OP.FORLOOP, OP.FORIN):
                tgt = resolve(_lid(term.args[1]))
                # FORIN carries the loop-variable count in args[2]; rebuilding
                # the operand tuple without it silently truncates every generic
                # for to two variables, because both def_use and the
                # reconstructor treat a missing count as 2.
                term.args = (term.args[0], tgt) + tuple(term.args[2:])
                if fallthrough is not None:
                    b.succ.append(fallthrough)
                b.succ.append(tgt)
            else:
                if fallthrough is not None:
                    b.succ.append(fallthrough)

        # predecessors
        for b in blocks:
            for s in b.succ:
                if b.id not in blocks[s].pred:
                    blocks[s].pred.append(b.id)

    # -- blocks & statements --------------------------------------------
    def _block(self, fb: _FuncBuilder, block: A.Block,
               is_repeat_body: bool = False) -> None:
        fb.push_scope()
        for stmt in block.body:
            self._stmt(fb, stmt)
        if not is_repeat_body:
            fb.pop_scope()

    def _stmt(self, fb: _FuncBuilder, s: Any) -> None:
        line = getattr(s, "line", 0)
        if isinstance(s, A.ExprStat):
            self._expr_stmt(fb, s)
        elif isinstance(s, A.Local):
            self._local(fb, s)
        elif isinstance(s, A.Assign):
            self._assign(fb, s)
        elif isinstance(s, A.Compound):
            self._compound(fb, s)
        elif isinstance(s, A.LocalFunc):
            r = fb.alloc_local(s.name.name)
            self._function(fb, s.fn, dst=r, name=s.name.name, line=line)
        elif isinstance(s, A.FuncStat):
            self._funcstat(fb, s)
        elif isinstance(s, A.Return):
            self._return(fb, s)
        elif isinstance(s, A.If):
            self._if(fb, s)
        elif isinstance(s, A.While):
            self._while(fb, s)
        elif isinstance(s, A.Repeat):
            self._repeat(fb, s)
        elif isinstance(s, A.NumFor):
            self._numfor(fb, s)
        elif isinstance(s, A.GenFor):
            self._genfor(fb, s)
        elif isinstance(s, A.Do):
            self._block(fb, s.body)
        elif isinstance(s, A.Break):
            if not fb.loop_stack:
                raise LoweringError("break outside a loop")
            fb.emit(OP.JMP, fb.loop_stack[-1][1], line=line, origin=s)
        elif isinstance(s, A.Continue):
            if not fb.loop_stack:
                raise LoweringError("continue outside a loop")
            fb.emit(OP.JMP, fb.loop_stack[-1][0], line=line, origin=s)
        elif isinstance(s, A.Declare):
            # type declarations carry no runtime behaviour
            pass
        else:
            raise LoweringError(f"cannot lower statement {type(s).__name__}")
        # Reclaim every scratch register; ``base`` still covers the locals
        # that are in scope at this point.
        fb.proto.num_regs = fb.base

    # -- individual statements ------------------------------------------
    def _expr_stmt(self, fb: _FuncBuilder, s: A.ExprStat) -> None:
        e = s.expr
        if isinstance(e, A.Call) or isinstance(e, A.MethodCall):
            base = fb.new_reg()
            self._call(fb, e, base, nres=0, line=s.line)
        else:
            raise LoweringError(f"statement expression of type {type(e).__name__} "
                                "is not callable")

    def _call(self, fb: _FuncBuilder, e: Any, base: Reg, nres: int,
              line: int) -> None:
        """Emit a call with R(base)=callee and ``nres`` results wanted.

        ``nres == MULTIRET`` packs the results into R(base).  A trailing
        multi-valued argument is evaluated into its own register and recorded
        as ``tail``; the emitter splices it as the final arguments, which is
        what ``f(g())`` requires.
        """
        if isinstance(e, A.MethodCall):
            obj = fb.new_reg()
            self._expr(fb, e.obj, obj)
            key = fb.proto.add_const(e.method.encode("utf-8", "surrogatepass"))
            fb.emit(OP.SELF, base, obj, key, line=line, origin=e)
            argstart = 2
        else:
            self._expr(fb, e.fn, base)
            argstart = 1
        args = e.args
        # Reserve the argument slots *before* evaluating anything: for a method
        # call the first one holds `self` (written by SELF), and evaluating the
        # arguments first would let their temporaries land in those slots.
        for _ in range(argstart - 1 + len(args)):
            fb.new_reg()
        for i, arg in enumerate(args):
            if i == len(args) - 1 and _is_multiret(arg):
                self._expr(fb, arg, base + argstart + i, want=MULTIRET)
                tail = (base + argstart + i).index
                # fixed arguments are those *before* the tail; the tail's own
                # slot is spliced, not counted.
                fb.emit(OP.CALL, base, argstart - 1 + i, nres, tail,
                        line=line, origin=e)
                fb.proto.call_count += 1
                return
            self._expr(fb, arg, base + argstart + i)
        fb.emit(OP.CALL, base, argstart + len(args) - 1, nres, -1,
                line=line, origin=e)
        fb.proto.call_count += 1

    def _local(self, fb: _FuncBuilder, s: A.Local) -> None:
        names = [n.name for n in s.names]
        exprs = s.values
        if exprs and _is_multiret(exprs[-1]):
            # Values are evaluated before any name is declared, so that
            # `local x = x` still reads the outer x.
            tmps: List[Reg] = []
            for e in exprs[:-1]:
                t = fb.new_reg()
                self._expr(fb, e, t)
                tmps.append(t)
            pack = fb.new_reg()
            self._expr(fb, exprs[-1], pack, want=MULTIRET)
            locs = [fb.alloc_local(name) for name in names]
            for i, r in enumerate(locs):
                if i < len(tmps):
                    fb.emit(OP.MOV, r, tmps[i], line=s.line, origin=s)
            extra = len(locs) - len(tmps)
            if extra > 0:
                fb.emit(OP.EXPAND, locs[len(tmps)], pack.index, extra,
                        line=s.line, origin=s)
            return
        for i, name in enumerate(names):
            r = fb.alloc_local(name)
            if i < len(exprs):
                self._expr(fb, exprs[i], r)
            else:
                fb.emit(OP.LOADK, r, fb.proto.add_const(None), line=s.line)

    def _assign(self, fb: _FuncBuilder, s: A.Assign) -> None:
        targets = s.targets
        values = s.values
        nil_k = fb.proto.add_const(None)
        multiret_tail = bool(values) and _is_multiret(values[-1])
        pack = None
        tmps: List[Reg] = []
        if multiret_tail:
            for e in values[:-1]:
                t = fb.new_reg()
                self._expr(fb, e, t)
                tmps.append(t)
            pack = fb.new_reg()
            self._expr(fb, values[-1], pack, want=MULTIRET)
        else:
            for e in values:
                t = fb.new_reg()
                self._expr(fb, e, t)
                tmps.append(t)
        prepared = [self._prepare_target(fb, t, s.line) for t in targets]
        extra = len(targets) - len(tmps) if multiret_tail else 0
        scratch = None
        if extra > 0:
            # EXPAND needs consecutive destinations, and the real targets may
            # be table slots, so distribute into scratch registers first.
            scratch = fb.new_reg()
            for _ in range(extra - 1):
                fb.new_reg()
            fb.emit(OP.EXPAND, scratch, pack.index, extra, line=s.line,
                    origin=s)
        for i, store in enumerate(prepared):
            if i < len(tmps):
                store(tmps[i])
            elif scratch is not None and i - len(tmps) < extra:
                store(scratch + (i - len(tmps)))
            else:
                t = fb.new_reg()
                fb.emit(OP.LOADK, t, nil_k, line=s.line)
                store(t)

    def _prepare_target(self, fb: _FuncBuilder, t: Any, line: int):
        """Evaluate the target's container, return a ``store(value)`` closure."""
        if isinstance(t, A.Name):
            def store(v: Reg, _t=t) -> None:
                self._write_name_preserving(fb, _t.name, v, line)
            return store
        if isinstance(t, (A.Index, A.Field)):
            obj = fb.new_reg()
            self._expr(fb, t.obj, obj)
            if isinstance(t, A.Field):
                key = fb.proto.add_const(t.name.encode("utf-8", "surrogatepass"))
            else:
                kreg = fb.new_reg()
                self._expr(fb, t.key, kreg)
                key = kreg
            def store(v: Reg, _o=obj, _k=key) -> None:
                fb.emit(OP.SETTABLE, _o, _k, v, line=line)
            return store
        raise LoweringError(f"cannot assign to {type(t).__name__}")

    def _write_name_preserving(self, fb: _FuncBuilder, name: str, src: Reg,
                               line: int) -> None:
        loc = fb.lookup(name)
        if loc is not None:
            fb.emit(OP.MOV, Reg(loc.reg), src, line=line)
            return
        if fb.parent is not None:
            up = fb.upvalue_for(name)
            if up is not None:
                fb.emit(OP.SETUPVAL, up, src, line=line)
                return
        fb.emit(OP.SETGLOBAL, fb.proto.add_name(name), src, line=line)

    def _compound(self, fb: _FuncBuilder, s: A.Compound) -> None:
        op = _BINARY_OPS[s.op.rstrip("=")]
        cur = fb.new_reg()
        if isinstance(s.target, A.Name):
            self._read_name(fb, s.target.name, cur, s.line)

            def store(v: Reg) -> None:
                self._write_name_preserving(fb, s.target.name, v, s.line)
        else:
            holder = self._prepare_target(fb, s.target, s.line)
            self._read_table(fb, s.target, cur, s.line)

            def store(v: Reg, _h=holder) -> None:
                _h(v)
        rhs = fb.new_reg()
        self._expr(fb, s.value, rhs)
        out = fb.new_reg()
        fb.emit(op, out, cur, rhs, line=s.line, origin=s)
        store(out)

    def _read_table(self, fb: _FuncBuilder, t: Any, dst: Reg, line: int) -> None:
        obj = fb.new_reg()
        self._expr(fb, t.obj, obj)
        if isinstance(t, A.Field):
            key = fb.proto.add_const(t.name.encode("utf-8", "surrogatepass"))
        else:
            key = fb.new_reg()
            self._expr(fb, t.key, key)
        fb.emit(OP.GETTABLE, dst, obj, key, line=line, origin=t)

    def _funcstat(self, fb: _FuncBuilder, s: A.FuncStat) -> None:
        tmp = fb.new_reg()
        # The parser already materialised the implicit `self` parameter for
        # `function t:m()`, so nothing to insert here (inserting again would
        # give the prototype an extra unused parameter and shift the rest).
        self._function(fb, s.fn, dst=tmp, name=None, line=s.line)
        store = self._prepare_target(fb, s.target, s.line)
        store(tmp)

    def _function(self, fb: _FuncBuilder, fn: A.Func, dst: Reg,
                  name: Optional[str], line: int) -> None:
        # A trailing `Param(name=None)` is the vararg marker, not a parameter:
        # counting it would give the prototype an extra named parameter and
        # shift every vararg by one.
        named = [p for p in fn.params if p.name is not None]
        proto = FuncIR(
            proto_id=len(self.protos), name=name, node=fn,
            num_params=len(named),
            is_vararg=len(named) != len(fn.params),
            is_method=getattr(fn, "_is_method", False),
        )
        self.protos.append(proto)
        fb.proto.children.append(proto)
        sub = _FuncBuilder(self, proto, parent=fb)
        for p in named:
            sub.alloc_local(p.name)
        sub.base = proto.num_regs
        self._block(sub, fn.body)
        sub.emit(OP.RETURN0, line=0)
        proto.num_regs = sub.max_regs
        proto.blocks = self._build_cfg(sub)
        proto.node_count = self._count(fn.body)
        fb.emit(OP.CLOSURE, dst, proto, line=line, origin=fn)
        fb.proto.closure_count += 1

    def _return(self, fb: _FuncBuilder, s: A.Return) -> None:
        vals = s.values
        if not vals:
            fb.emit(OP.RETURN0, line=s.line, origin=s)
            return
        if len(vals) == 1 and _is_multiret(vals[0]):
            e = vals[0]
            base = fb.new_reg()
            if isinstance(e, (A.Call, A.MethodCall)):
                self._call(fb, e, base, nres=MULTIRET, line=s.line)
                # a call in return position is a tail call
                for ins in reversed(fb.code):
                    if not isinstance(ins, tuple) and ins.op == OP.CALL:
                        ins.op = OP.TAILCALL
                        ins.args = (ins.args[0], ins.args[1], ins.args[3])
                        break
                return
            self._expr(fb, e, base, want=MULTIRET)   # `return ...`
            fb.emit(OP.RETURNMULTI, base, 0, base.index, line=s.line, origin=s)
            return
        n = len(vals)
        base = fb.new_reg()
        for _ in range(n - 1):
            fb.new_reg()
        if _is_multiret(vals[-1]):
            for i, v in enumerate(vals[:-1]):
                self._expr(fb, v, base + i)
            pack = base + (n - 1)
            self._expr(fb, vals[-1], pack, want=MULTIRET)
            fb.emit(OP.RETURNMULTI, base, n - 1, pack.index, line=s.line,
                    origin=s)
            return
        for i, v in enumerate(vals):
            self._expr(fb, v, base + i)
        fb.emit(OP.RETURN, base, n, line=s.line, origin=s)

    # -- control flow ----------------------------------------------------
    def _if(self, fb: _FuncBuilder, s: A.If) -> None:
        fb.proto.branch_count += 1
        end = fb.label()
        for cond, body in s.arms:
            nxt = fb.label()
            r = fb.new_reg()
            self._expr(fb, cond, r)
            fb.emit(OP.JMPFALSE, r, nxt, line=s.line, origin=s)
            self._block(fb, body)
            fb.emit(OP.JMP, end, line=s.line)
            fb.place(nxt)
        if s.otherwise is not None:
            self._block(fb, s.otherwise)
        fb.place(end)

    def _while(self, fb: _FuncBuilder, s: A.While) -> None:
        fb.proto.loop_count += 1
        fb.proto.branch_count += 1
        head = fb.label()
        tail = fb.label()      # continue target: re-test the condition
        end = fb.label()       # break target
        fb.place(head)
        r = fb.new_reg()
        self._expr(fb, s.cond, r)
        fb.emit(OP.JMPFALSE, r, end, line=s.line, origin=s)
        fb.loop_stack.append((tail, end))
        fb.loop_depth += 1
        self._block(fb, s.body)
        fb.loop_depth -= 1
        fb.loop_stack.pop()
        fb.place(tail)
        fb.emit(OP.JMP, head, line=s.line)
        fb.place(end)

    def _repeat(self, fb: _FuncBuilder, s: A.Repeat) -> None:
        fb.proto.loop_count += 1
        fb.proto.branch_count += 1
        head = fb.label()
        # body locals stay visible to the until-condition
        cont = fb.label()
        end = fb.label()
        fb.place(head)
        fb.push_scope()
        fb.loop_stack.append((cont, end))
        fb.loop_depth += 1
        for stmt in s.body.body:
            self._stmt(fb, stmt)
        fb.loop_depth -= 1
        fb.loop_stack.pop()
        fb.place(cont)
        r = fb.new_reg()
        self._expr(fb, s.cond, r)
        # `until cond` exits when cond is true, so the loop-back edge is taken
        # while it is *false*.
        fb.emit(OP.JMPFALSE, r, head, line=s.line, origin=s)
        fb.pop_scope()
        fb.place(end)

    def _numfor(self, fb: _FuncBuilder, s: A.NumFor) -> None:
        fb.proto.loop_count += 1
        # Reserve init/limit/step up front.  Evaluating the bounds first would
        # let their temporaries occupy base+1 and base+2 and silently overwrite
        # the limit -- which is how `for i = 10, 1, -4` lost an iteration.
        base = fb.new_reg()
        fb.new_reg()
        fb.new_reg()
        self._expr(fb, s.start, base)
        self._expr(fb, s.stop, base + 1)
        if s.step is not None:
            self._expr(fb, s.step, base + 2)
        else:
            fb.emit(OP.LOADK, base + 2, fb.proto.add_const(1), line=s.line)
        for off in (0, 1, 2):
            self._coerce_number(fb, base + off, s.line)
        fb.loop_depth += 1
        var = fb.alloc_local(s.var.name)
        fb.proto.per_iteration.add(base.index + 3)
        if var.index != base.index + 3:  # pragma: no cover - safety net
            fb.proto.num_regs = base.index + 4
            fb.scopes[-1][s.var.name] = _Local(base.index + 3, s.var.name)
            fb.base = base.index + 4
        loop = fb.label()
        end = fb.label()
        fb.emit(OP.FORPREP, base, loop, line=s.line, origin=s)
        body = fb.label()
        fb.place(body)
        fb.loop_stack.append((loop, end))
        self._block(fb, s.body)
        fb.loop_depth -= 1
        fb.loop_stack.pop()
        fb.place(loop)
        fb.emit(OP.FORLOOP, base, body, line=s.line, origin=s)
        fb.place(end)

    def _genfor(self, fb: _FuncBuilder, s: A.GenFor) -> None:
        fb.proto.loop_count += 1
        base = fb.new_reg()
        fb.new_reg()
        fb.new_reg()
        # `for k, v in f(x) do` binds three control values (iterator, state,
        # control) from the *multi-value* result of the first expression.
        iters = list(s.iters)
        resolved = False
        if len(iters) == 1:
            # Luau decides *at runtime* whether this is a classic (iterator,
            # state, control) triple or generalized iteration, based on how many
            # values the expression actually produces: exactly one value is
            # treated as the iterable (callable, __iter, or a plain table via
            # next), two or more are the classic triple.  A statically visible
            # single value can be resolved straight away; a call has to be
            # packed so the count survives to runtime.
            if _is_multiret(iters[0]):
                self._expr(fb, iters[0], base, want=MULTIRET)
                fb.emit(OP.ITERPREP, base, 1, line=s.line, origin=s)
            else:
                self._expr(fb, iters[0], base)
                fb.emit(OP.ITERPREP, base, 0, line=s.line, origin=s)
            resolved = True
        elif len(iters) < 3 and _is_multiret(iters[-1]):
            self._expr(fb, iters[-1], base, want=3)
            for i, e in enumerate(iters[:-1]):
                raise LoweringError("generic for: only the last iterator "
                                    "expression may be a call")
        else:
            while len(iters) < 3:
                iters.append(A.Nil())
            for i, e in enumerate(iters[:3]):
                self._expr(fb, e, base + i)
        # loop variables must sit immediately after the three control values
        need = base.index + 3 + len(s.vars)
        if fb.proto.num_regs < need:
            fb.proto.num_regs = need
        fb.loop_depth += 1
        for i, v in enumerate(s.vars):
            fb.scopes[-1][v.name] = _Local(base.index + 3 + i, v.name)
            fb.proto.per_iteration.add(base.index + 3 + i)
        fb.base = need
        loop = fb.label()
        end = fb.label()
        # `resolved` means ITERPREP has already turned the first control value
        # into an iterator; re-validating it would change which error the user
        # sees when a __iter metamethod hands back something uncallable.
        fb.emit(OP.FORINPREP, base, loop, 1 if resolved else 0,
                line=s.line, origin=s)
        body = fb.label()
        fb.place(body)
        fb.loop_stack.append((loop, end))
        self._block(fb, s.body)
        fb.loop_depth -= 1
        fb.loop_stack.pop()
        fb.place(loop)
        fb.emit(OP.FORIN, base, body, len(s.vars), line=s.line, origin=s)
        fb.place(end)

    def _read_name(self, fb: _FuncBuilder, name: str, dst: Reg, line: int) -> None:
        fb.read_name(name, dst, line)

    def _coerce_number(self, fb: _FuncBuilder, reg: Reg, line: int) -> None:
        """Force a register through tonumber, in place.

        Luau's numeric ``for`` accepts anything ``tonumber`` can read, so
        ``for i = "10", "1", "-2"`` is valid and runs five iterations.  Without
        this the control registers keep their strings and the first comparison
        raises instead.
        """
        fn = fb.new_reg()
        fb.emit(OP.GETGLOBAL, fn, fb.proto.add_name("tonumber"), line=line)
        fb.emit(OP.MOV, fn + 1, reg, line=line)
        fb.emit(OP.CALL, fn, 1, 1, -1, line=line)
        fb.emit(OP.MOV, reg, fn, line=line)

    # -- expressions -----------------------------------------------------
    def _expr(self, fb: _FuncBuilder, e: Any, dst: Reg,
              want: int = 1) -> Reg:
        line = getattr(e, "line", 0)
        if isinstance(e, A.Number):
            fb.emit(OP.LOADK, dst, fb.proto.add_const(e.value), line=line)
        elif isinstance(e, A.Str):
            fb.emit(OP.LOADK, dst, fb.proto.add_const(e.raw), line=line)
        elif isinstance(e, A.Bool):
            fb.emit(OP.LOADK, dst, fb.proto.add_const(e.value), line=line)
        elif isinstance(e, A.Nil):
            fb.emit(OP.LOADK, dst, fb.proto.add_const(None), line=line)
        elif isinstance(e, A.Vararg):
            fb.emit(OP.VARARG, dst, want, line=line, origin=e)
        elif isinstance(e, A.Name):
            self._read_name(fb, e.name, dst, line)
        elif isinstance(e, A.Group):
            # parentheses truncate to one value
            self._expr(fb, e.expr, dst, want=1)
        elif isinstance(e, A.Cast):
            self._expr(fb, e.expr, dst, want=1)
        elif isinstance(e, A.Un):
            op = {"-": OP.UNM, "not": OP.NOT, "#": OP.LEN}.get(e.op)
            if op is None:
                raise LoweringError(f"unsupported unary operator {e.op!r}")
            r = fb.new_reg()
            self._expr(fb, e.operand, r)
            fb.emit(op, dst, r, line=line, origin=e)
        elif isinstance(e, A.Bin):
            self._bin(fb, e, dst, line)
        elif isinstance(e, A.Index):
            obj = fb.new_reg()
            self._expr(fb, e.obj, obj)
            key = fb.new_reg()
            self._expr(fb, e.key, key)
            fb.emit(OP.GETTABLE, dst, obj, key, line=line, origin=e)
        elif isinstance(e, A.Field):
            obj = fb.new_reg()
            self._expr(fb, e.obj, obj)
            k = fb.proto.add_const(e.name.encode("utf-8", "surrogatepass"))
            fb.emit(OP.GETTABLE, dst, obj, k, line=line, origin=e)
        elif isinstance(e, A.Table):
            self._table(fb, e, dst, line)
        elif isinstance(e, (A.Call, A.MethodCall)):
            self._call(fb, e, dst, nres=want, line=line)
        elif isinstance(e, A.IfExpr):
            self._ifexpr(fb, e, dst, line)
        elif isinstance(e, A.Interp):
            self._interp(fb, e, dst, line)
        elif isinstance(e, A.Func):
            self._function(fb, e, dst=dst, name=None, line=line)
        else:
            raise LoweringError(f"cannot lower expression {type(e).__name__}")
        return dst

    def _bin(self, fb: _FuncBuilder, e: A.Bin, dst: Reg, line: int) -> None:
        if e.op in ("and", "or"):
            self._expr(fb, e.left, dst)
            end = fb.label()
            fb.emit(OP.JMPFALSE if e.op == "and" else OP.JMPTRUE, dst, end,
                    line=line, origin=e)
            self._expr(fb, e.right, dst)
            fb.place(end)
            return
        op = _BINARY_OPS.get(e.op)
        if op is None:
            raise LoweringError(f"unsupported binary operator {e.op!r}")
        lhs = fb.new_reg()
        self._expr(fb, e.left, lhs)
        rhs = fb.new_reg()
        self._expr(fb, e.right, rhs)
        fb.emit(op, dst, lhs, rhs, line=line, origin=e)

    def _ifexpr(self, fb: _FuncBuilder, e: A.IfExpr, dst: Reg, line: int) -> None:
        fb.proto.branch_count += 1
        else_lbl = fb.label()
        end = fb.label()
        r = fb.new_reg()
        self._expr(fb, e.cond, r)
        fb.emit(OP.JMPFALSE, r, else_lbl, line=line, origin=e)
        self._expr(fb, e.then, dst)
        fb.emit(OP.JMP, end, line=line)
        fb.place(else_lbl)
        self._expr(fb, e.otherwise, dst)
        fb.place(end)

    def _table(self, fb: _FuncBuilder, e: A.Table, dst: Reg, line: int) -> None:
        narr = sum(1 for it in e.items if it.kind == "array")
        nrec = len(e.items) - narr
        fb.emit(OP.NEWTABLE, dst, fb.proto.add_const(narr),
                fb.proto.add_const(nrec), line=line, origin=e)
        array_run: List[Reg] = []
        array_next = 1

        def flush() -> None:
            nonlocal array_next
            if not array_run:
                return
            # SETLIST expects consecutive registers after the table
            for i, r in enumerate(array_run):
                if r.index != dst.index + 1 + i:
                    fb.emit(OP.MOV, dst + 1 + i, r, line=line)
            # The start index is carried explicitly.  Appending with `#t + 1`
            # would silently drop an explicit nil element and shift everything
            # after it, which changes what ipairs sees.
            fb.emit(OP.SETLIST, dst, len(array_run), array_next, line=line,
                    origin=e)
            array_next += len(array_run)
            array_run.clear()

        for idx, item in enumerate(e.items):
            if item.kind == "array":
                if idx == len(e.items) - 1 and _is_multiret(item.value):
                    # `{a, f()}`: the trailing call contributes *all* its
                    # values, not just the first.
                    flush()
                    pack = fb.new_reg()
                    self._expr(fb, item.value, pack, want=MULTIRET)
                    fb.emit(OP.SETLISTMULTI, dst, pack.index, line=line,
                            origin=e)
                    continue
                r = fb.new_reg()
                self._expr(fb, item.value, r)
                array_run.append(r)
                continue
            flush()
            # TableItem.kind is "array" | "field" (name = key) | "key"
            # ([expr] = value), matching what the parser produces.
            if item.kind == "field":
                k = fb.proto.add_const(
                    (item.key_name or "").encode("utf-8", "surrogatepass"))
            elif item.kind == "key":
                k = fb.new_reg()
                self._expr(fb, item.key_expr, k)
            else:
                raise LoweringError(f"unexpected table item kind {item.kind!r}")
            v = fb.new_reg()
            self._expr(fb, item.value, v)
            fb.emit(OP.SETTABLE, dst, k, v, line=line, origin=e)
        flush()

    def _interp(self, fb: _FuncBuilder, e: A.Interp, dst: Reg, line: int) -> None:
        parts: List[Reg] = []
        for p in e.parts:
            r = fb.new_reg()
            if isinstance(p, str):
                # literal chunks of an interpolated string still carry their
                # escape sequences at this point
                fb.emit(OP.LOADK, r, fb.proto.add_const(unescape_text(p)),
                        line=line)
            else:
                self._expr(fb, p, r)
                # Luau's `..` only accepts strings and numbers, so coercing an
                # interpolated value with `.. ""` breaks on booleans and nil.
                # Interpolated string literals convert with tostring, which
                # also honours __tostring.
                fn = fb.new_reg()
                fb.emit(OP.GETGLOBAL, fn, fb.proto.add_name("tostring"),
                        line=line)
                fb.emit(OP.MOV, fn + 1, r, line=line)
                fb.emit(OP.CALL, fn, 1, 1, -1, line=line)
                fb.emit(OP.MOV, r, fn, line=line)
            parts.append(r)
        if not parts:
            fb.emit(OP.LOADK, dst, fb.proto.add_const(b""), line=line)
            return
        acc = parts[0]
        for r in parts[1:]:
            out = fb.new_reg()
            fb.emit(OP.CONCAT, out, acc, r, line=line, origin=e)
            acc = out
        if acc.index != dst.index:
            fb.emit(OP.MOV, dst, acc, line=line)


def _is_multiret(e: Any) -> bool:
    """Does this expression expand to an unknown number of values?"""
    if isinstance(e, A.Vararg):
        return True
    if isinstance(e, (A.Call, A.MethodCall)):
        return True
    if isinstance(e, A.Group):
        return False
    return False


# --------------------------------------------------------------------------
# analysis
# --------------------------------------------------------------------------
def def_use(ins: Instr) -> Tuple[Set[int], Set[int]]:
    """Registers an instruction kills and reads, including implicit ranges.

    Several instructions address registers *relative to a base* rather than
    listing them: ``SETLIST`` reads ``base+1..base+count``, ``CALL`` reads the
    callee and its argument run, ``RETURN`` reads a run, ``FORLOOP`` reads and
    writes the four-slot control block, and so on.  Treating those as operand-
    free makes the sources look dead, which is precisely how a register
    allocator ends up handing the same physical register to two live values.
    """
    a = ins.args
    op = ins.op
    defs: Set[int] = set()
    uses: Set[int] = set()

    def ri(x: Any) -> Optional[int]:
        return x.index if isinstance(x, Reg) else None

    def use_all(idx_from: int) -> None:
        for x in a[idx_from:]:
            r = ri(x)
            if r is not None:
                uses.add(r)

    def run(base: int, n: int) -> Set[int]:
        return {base + i for i in range(max(0, n))}

    if op in (OP.MOV, OP.LOADK, OP.GETGLOBAL, OP.GETUPVAL, OP.GETTABLE,
              OP.ADD, OP.SUB, OP.MUL, OP.DIV, OP.IDIV, OP.MOD, OP.POW,
              OP.UNM, OP.NOT, OP.LEN, OP.CONCAT, OP.EQ, OP.NE, OP.LT, OP.LE,
              OP.GT, OP.GE, OP.NEWTABLE):
        d = ri(a[0])
        if d is not None:
            defs.add(d)
        use_all(1)
    elif op == OP.CLOSURE:
        d = ri(a[0])
        if d is not None:
            defs.add(d)
        # A closure reads the registers it captures, but they are not operands:
        # args[1] is the child prototype.  Every capture chain bottoms out at a
        # `from_local` descriptor in the prototype that owns the register, so
        # recording those indices here is enough to keep liveness honest -- a
        # dead-store pass would otherwise delete the store a closure depends on.
        child = a[1] if len(a) > 1 else None
        for desc in getattr(child, "upvalues", ()):
            if desc.from_local and desc.index is not None:
                uses.add(desc.index)
    elif op in (OP.SETTABLE,):
        use_all(0)
    elif op in (OP.SETGLOBAL, OP.SETUPVAL):
        r = ri(a[1])
        if r is not None:
            uses.add(r)
    elif op == OP.SELF:
        b = ri(a[0])
        if b is not None:
            defs.update(run(b, 2))
        r = ri(a[1])
        if r is not None:
            uses.add(r)
    elif op == OP.SETLIST:
        b = ri(a[0])
        if b is not None:
            uses.add(b)
            uses |= run(b + 1, int(a[1]))
    elif op == OP.SETLISTMULTI:
        for x in a[:2]:
            r = ri(x)
            if r is not None:
                uses.add(r)
    elif op == OP.CALL:
        b, argc, nres, tail = ri(a[0]), int(a[1]), int(a[2]), int(a[3])
        if b is not None:
            uses.add(b)
            uses |= run(b + 1, argc)
            if nres == MULTIRET:
                defs.add(b)
            elif nres > 0:
                defs |= run(b, nres)
        if tail >= 0:
            uses.add(tail)
    elif op == OP.TAILCALL:
        b, argc, tail = ri(a[0]), int(a[1]), int(a[2])
        if b is not None:
            uses.add(b)
            uses |= run(b + 1, argc)
        if tail >= 0:
            uses.add(tail)
    elif op == OP.RETURN:
        b = ri(a[0])
        if b is not None:
            uses |= run(b, int(a[1]))
    elif op == OP.RETURNMULTI:
        b, n, pack = ri(a[0]), int(a[1]), int(a[2])
        if b is not None:
            uses |= run(b, n)
        uses.add(pack)
    elif op == OP.VARARG:
        b, n = ri(a[0]), int(a[1])
        if b is not None:
            if n == MULTIRET:
                defs.add(b)
            elif n > 0:
                defs |= run(b, n)
    elif op == OP.EXPAND:
        d, pack, n = ri(a[0]), int(a[1]), int(a[2])
        uses.add(pack)
        if d is not None:
            defs |= run(d, n)
    elif op == OP.FORPREP:
        b = ri(a[0])
        if b is not None:
            uses |= run(b, 3)
            defs.add(b)
    elif op == OP.FORLOOP:
        b = ri(a[0])
        if b is not None:
            uses |= run(b, 3)
            defs.add(b)
            defs.add(b + 3)
    elif op == OP.FORINPREP:
        b = ri(a[0])
        if b is not None:
            uses |= run(b, 3)
    elif op == OP.ITERPREP:
        b = ri(a[0])
        if b is not None:
            uses.add(b)
            defs |= run(b, 3)
    elif op == OP.FORIN:
        b = ri(a[0])
        nvars = int(a[2]) if len(a) > 2 else 2
        if b is not None:
            uses |= run(b, 3)
            defs.add(b + 2)
            defs |= run(b + 3, nvars)
    elif op == OP.NOP:
        pass
    else:  # pragma: no cover - defensive
        use_all(0)
    return defs, uses


def compute_liveness(proto: FuncIR) -> None:
    """Standard backward liveness over virtual registers."""
    for b in proto.blocks:
        b.live_in = set()
        b.live_out = set()

    changed = True
    while changed:
        changed = False
        for b in reversed(proto.blocks):
            out: Set[int] = set()
            for s in b.succ:
                out |= proto.blocks[s].live_in
            if out != b.live_out:
                b.live_out = out
                changed = True
            work = set(out)
            for ins in reversed(b.instrs):
                d, u = def_use(ins)
                work -= d
                work |= u
            if work != b.live_in:
                b.live_in = work
                changed = True


def side_effect_free(ins: Instr) -> bool:
    return ins.op in PURE_OPS


def reachable_blocks(proto: FuncIR) -> Set[int]:
    seen: Set[int] = set()
    stack = [proto.entry]
    while stack:
        b = stack.pop()
        if b in seen:
            continue
        seen.add(b)
        stack.extend(proto.blocks[b].succ)
    return seen


def postorder(proto: FuncIR) -> List[int]:
    """Reverse postorder, the usual order for dataflow and for emission."""
    order: List[int] = []
    seen: Set[int] = set()

    def visit(b: int) -> None:
        if b in seen:
            return
        seen.add(b)
        for s in proto.blocks[b].succ:
            visit(s)
        order.append(b)

    visit(proto.entry)
    order.reverse()
    return order

"""Reconstruct executable Luau from the IR.

Three purposes, in increasing order of importance:

1. **It is the semantic oracle for lowering.**  Round-tripping source through
   the IR and diffing the result against the original, executed by a real Luau
   VM, is the only way to be confident the lowering preserves semantics.  A
   hand-written Python interpreter would just be a second implementation with
   its own bugs; real Luau is the authority.
2. **It is the control-flow flattening transform.**  The emitted dispatcher
   ``while`` loop *is* a flattened CFG -- the same shape the obfuscator uses,
   just without the encoding.
3. **It is the scaffold for mixed execution.**  A function can run as
   reconstructed source while its callees run in the VM, or vice versa.

The register file is a table
----------------------------
Each prototype gets one table, ``_kR<pid>``, indexed by register number.  The
obvious alternative -- one Luau local per register -- is a dead end: Luau caps a
function at 200 locals, and a straightforward lowering of a large chunk
routinely needs more.  Register allocation could bring the count down, but it
cannot be done soundly with a single virtual-to-physical map, because the
lowerer recycles virtual registers across statements and so the *same* virtual
register participates in several different loop-control groups at different
program points; keeping ``base..base+3`` adjacent for all of them requires live
range splitting.  A table sidesteps the whole problem, costs one table index per
operand, and matches how the VM holds its registers anyway.

The dispatcher
--------------
Each basic block becomes one arm of an ``if/elseif`` chain over a program
counter inside ``while true do``.  Block successors become assignments to the
counter, so the CFG's edges are explicit in the output rather than implicit in
the syntax tree.  ``return`` leaves the function directly, so no exit-block
plumbing is needed.

Loop instructions keep Lua's exact semantics rather than being turned back into
``for`` statements, because the CFG has already lost the loop's syntactic shape:

* ``FORPREP`` pre-decrements the counter by the step and jumps to the
  ``FORLOOP`` block -- that pre-decrement is what makes the first test correct;
* ``FORLOOP`` increments, tests against the step's sign, copies the counter
  into the visible loop variable, and jumps back;
* ``FORIN`` calls the iterator with (state, control), stops when the first
  result is nil, otherwise advances the control variable.

Multiple returns
----------------
A call or vararg asked for ``MULTIRET`` packs its results with ``table.pack``
into its own base register.  A trailing multi-valued argument is spliced into
the outer call with ``table.unpack(t, 1, t.n)``, ``EXPAND`` distributes a packed
multi across consecutive registers, and ``RETURNMULTI`` splices one at the end
of a return list.  This is what makes ``f(g())``, ``local a, b = f()`` and
``return a, f()`` all behave as they do in the original.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from . import ast_nodes as A
from .config import VirtualizationLevel
from .ir import (MULTIRET, TERMINATORS, FuncIR, IRModule, Instr, Kon, OP, Reg,
                 Up)

#: Prefix for synthesized identifiers.  Reserved in the name generator so a
#: user identifier can never collide with one.
PREFIX = "_k"

HELPER_PACK = "_kpack"
HELPER_UNPACK = "_kunpk"
HELPER_APPEND = "_kapp"
#: local holding the writable global environment (see `_global_expr`)
ENV_NAME = "_kE"
HELPER_ITER = "_kiter"
HELPER_ITERPACK = "_kiterpack"
HELPER_ITERCHECK = "_kitercheck"

HELPERS_SRC = f"""
local function {HELPER_PACK}(...)
  return table.pack(...)
end
local function {HELPER_UNPACK}(t, i)
  return table.unpack(t, i, t.n)
end
local function {HELPER_ITER}(v)
  -- Luau's generalized iteration.  The order matters: __iter wins over
  -- callability, and whatever __iter hands back is used *unchecked*, so an
  -- uncallable result fails later with "attempt to call a X value" exactly as
  -- it does under Luau.
  local mt = getmetatable(v)
  local m = mt and mt.__iter
  if m then
    return m(v)
  end
  if type(v) == "function" then
    return v
  end
  if mt and mt.__call then
    return v
  end
  if type(v) == "table" then
    return next, v, nil
  end
  -- Match Luau's own wording: user code routinely inspects this message with
  -- pcall, so a different string changes observable behaviour.
  error("attempt to iterate over a " .. type(v) .. " value")
end
local function {HELPER_ITERPACK}(t)
  -- Luau picks between the classic (iterator, state, control) triple and
  -- generalized iteration by how many values the iterator expression actually
  -- produced: exactly one means the value is the iterable itself.
  if t.n == 1 then
    return {HELPER_ITER}(t[1])
  end
  return t[1], t[2], t[3]
end
local function {HELPER_ITERCHECK}(f)
  -- The classic (iterator, state, control) form still needs the iterator to be
  -- callable, and Luau reports that with its own wording rather than the
  -- generic "attempt to call" a later call would produce.
  local ty = type(f)
  if ty == "function" then
    return f
  end
  -- "callable" includes a __call metamethod, and a table or userdata may be
  -- callable through one that getmetatable does not expose directly, so those
  -- are left to the call itself.  Only the plainly non-callable types are
  -- reported here, with Luau's own wording.
  if ty == "table" or ty == "userdata" or ty == "thread" then
    return f
  end
  error("attempt to iterate over a " .. ty .. " value")
end
local function {HELPER_APPEND}(dst, t)
  local n = #dst
  for i = 1, t.n do
    n += 1
    dst[n] = t[i]
  end
end
"""


class ReconstructionError(Exception):
    pass


def regs_name(proto_id: int) -> str:
    return f"{PREFIX}R{proto_id}"


def pc_name(proto_id: int) -> str:
    return f"{PREFIX}C{proto_id}"


def param_name(proto_id: int, i: int) -> str:
    return f"{PREFIX}P{proto_id}_{i}"


def _name(n: str) -> A.Name:
    return A.Name(name=n)


def _local_name(n: str) -> A.LocalName:
    return A.LocalName(name=n)


def _num(v: Any) -> A.Number:
    return A.Number(value=v, is_float=isinstance(v, float))


def _const_expr(value: Any) -> A.Expr:
    if value is None:
        return A.Nil()
    if isinstance(value, bool):
        return A.Bool(value=value)
    if isinstance(value, (int, float)):
        return _num(value)
    if isinstance(value, (bytes, bytearray)):
        return A.Str(raw=bytes(value))
    if isinstance(value, str):
        return A.Str(raw=value.encode("utf-8", "surrogatepass"))
    raise ReconstructionError(f"cannot emit constant {value!r}")


class Reconstructor:
    def __init__(self, pool: Any = None, accessor: Optional[str] = None,
                 vm: Any = None, bank: Any = None,
                 bank_accessor: Optional[str] = None) -> None:
        """``pool`` is a :class:`~couxobf.constpool.ConstantPool`.

        When one is supplied, no literal reaches the output: every constant is
        interned into the pool and read back through ``accessor`` at runtime.
        Without a pool the reconstructor emits literals inline, which keeps the
        plain path simple and diffable.

        ``vm`` is an optional :class:`~couxobf.vm.wiring.VMPlan`.  Prototypes it
        selects are encoded to bytecode and replaced by a closure that enters
        the interpreter; everything else is reconstructed natively as usual.
        """
        self.parents: Dict[int, Optional[FuncIR]] = {}
        self.by_id: Dict[int, FuncIR] = {}
        #: (proto_id, upvalue_index) -> name of the snapshot local a closure
        #: captures instead of the live register
        self.snapshots: Dict[Tuple[int, int], str] = {}
        self.pool = pool
        self.accessor = accessor
        self.vm = vm
        #: proto_id -> EncodedProto, filled in as function_expr runs
        self.vm_encoded: Dict[int, Any] = {}
        #: Optional :class:`~couxobf.strings.bank.StringBank`.  When present,
        #: string *values* loaded by LOADK are resolved through it instead of
        #: the pool.  Only values: table keys, method names and global names
        #: stay in the pool, because turning every ``{foo = 1}`` into a runtime
        #: call costs far more than it hides.
        self.bank = bank
        self.bank_accessor = bank_accessor
        if (pool is None) != (accessor is None):
            raise ReconstructionError("pool and accessor must be given together")

    # -- entry -----------------------------------------------------------
    def reconstruct(self, module: IRModule) -> A.Block:
        self._build_parent_map(module)
        return A.Block(body=self._proto_body(module.main))

    def function_expr(self, proto: FuncIR) -> A.Func:
        if self.vm is not None and self.vm.selects(proto):
            wrapper = self._vm_closure(proto)
            if wrapper is not None:
                return wrapper
        params = [A.Param(name=param_name(proto.proto_id, i))
                  for i in range(proto.num_params)]
        if proto.is_vararg:
            params.append(A.Param(name=None))
        return A.Func(params=params, body=A.Block(body=self._proto_body(proto)))

    def _vm_closure(self, proto: FuncIR) -> Optional[A.Func]:
        """Encode ``proto`` and return the Luau closure that runs it.

        Returns ``None`` if the prototype turns out not to be encodable after
        all, so the caller falls back to native reconstruction rather than
        failing the whole build.  Eligibility was already checked when the plan
        was made; this second check is cheap insurance against the plan and the
        encoder disagreeing.
        """
        from .vm import encode as _encode

        ok, _reason = _encode.can_virtualize(proto)
        if not ok:
            return None
        self.vm_encoded[proto.proto_id] = _encode.encode_proto(
            proto, self.vm.opmap)
        # A vararg parameter list, not the prototype's declared parameters:
        # the descriptor carries the real count and the interpreter distributes
        # the arguments itself.  From the caller's side this is an ordinary
        # Luau function with the same signature.
        #
        # The environment is resolved here, in the closure the caller actually
        # holds, at level 1 -- this function.  Resolving it deeper would return
        # the interpreter's environment instead, and `setfenv` applied to a
        # virtualised function would be ignored.  `_gf` is an upvalue rather
        # than a global lookup, because a swapped environment does not contain
        # getfenv either.
        return A.Func(
            params=[A.Param(name=None)],
            body=A.Block(body=[A.Return(values=[A.Call(
                fn=A.Name(name=self.vm.names["enter"]),
                args=[A.Index(obj=A.Name(name=self.vm.table),
                              key=_num(proto.proto_id)),
                      A.Call(fn=A.Name(name=self.vm.names["getfenv"]),
                             args=[_num(1)]),
                      A.Vararg()])])]))

    def _build_parent_map(self, module: IRModule) -> None:
        def walk(p: FuncIR, par: Optional[FuncIR]) -> None:
            self.parents[p.proto_id] = par
            self.by_id[p.proto_id] = p
            for c in p.children:
                walk(c, p)

        walk(module.main, None)

    # -- addressing ------------------------------------------------------
    def _reg(self, proto: FuncIR, i: int) -> A.Index:
        return A.Index(obj=_name(regs_name(proto.proto_id)), key=_num(i))

    def _upvalue_expr(self, proto: FuncIR, i: int) -> A.Expr:
        """The expression an upvalue resolves to in the enclosing scope.

        Deliberately not a copy: addressing the enclosing prototype's own
        register slot means writes go to the variable the owner still uses.  A
        local copy would silently break ``SETUPVAL``.
        """
        snap = self.snapshots.get((proto.proto_id, i))
        if snap is not None:
            return _name(snap)
        desc = proto.upvalues[i]
        par = self.parents.get(proto.proto_id)
        if par is None:
            raise ReconstructionError(
                f"upvalue {i} of {proto.name} has no enclosing prototype")
        if desc.from_local:
            return self._reg(par, desc.index)
        return self._upvalue_expr(par, desc.index)

    def _upvalue_home(self, proto: FuncIR, i: int) -> Tuple[int, int]:
        """The (prototype, register) an upvalue ultimately reads."""
        desc = proto.upvalues[i]
        par = self.parents[proto.proto_id]
        if desc.from_local:
            return (par.proto_id, desc.index)
        return self._upvalue_home(par, desc.index)

    def _operand(self, proto: FuncIR, op: Any) -> A.Expr:
        if isinstance(op, Reg):
            return self._reg(proto, op.index)
        if isinstance(op, Kon):
            if self.pool is not None:
                return self._pool_ref(proto.consts[op.index])
            return _const_expr(proto.consts[op.index])
        if isinstance(op, Up):
            return self._upvalue_expr(proto, op.index)
        raise ReconstructionError(f"bad operand {op!r}")

    def _bank_or_pool(self, proto: FuncIR, k: Kon) -> A.Expr:
        """A loaded constant: a bank ticket for strings, a pool slot otherwise.

        Each *occurrence* takes a fresh ticket, which is the point -- two uses
        of the same literal resolve independently.  Numbers, booleans and nil
        stay in the pool: fragmenting a double buys nothing.
        """
        value = proto.consts[k.index]
        if isinstance(value, (bytes, bytearray, str)):
            ticket = self.bank.ticket(value)
            return A.Call(fn=_name(self.bank_accessor), args=[_num(ticket)])
        return self._pool_ref(value)

    def _pool_ref(self, value: Any) -> A.Expr:
        """A runtime read of one pooled constant."""
        slot = self.pool.slot(value)
        return A.Call(fn=_name(self.accessor), args=[_num(slot)])

    def _global_expr(self, proto: FuncIR, k: Kon) -> A.Expr:
        """The expression naming a global.

        Always a plain identifier, even when a constant pool is in use.  It is
        tempting to hide the name by reading it through an environment table --
        ``env[pool.get(slot)]`` -- but that is *wrong*: Luau resolves a global
        against the calling function's own environment, so ``setfenv(f, t)``
        changes what ``A`` means inside ``f``.  An environment captured at load
        time ignores that, and the indirection silently breaks ``setfenv``.

        Global names therefore stay visible in the protected output.  That is a
        real limitation and it is recorded in ``docs/SECURITY.md``: the pool
        protects values, not the names a program uses to reach the standard
        library.
        """
        return _name(self._name_const(proto, k))

    def _assign(self, proto: FuncIR, dst: Reg, value: A.Expr) -> A.Assign:
        return A.Assign(targets=[self._reg(proto, dst.index)], values=[value])

    def _splice(self, proto: FuncIR, pack: int) -> A.Expr:
        return A.Call(fn=_name(HELPER_UNPACK), args=[self._reg(proto, pack),
                                                     _num(1)])

    # -- prototype -------------------------------------------------------
    def _proto_body(self, proto: FuncIR) -> List[A.Stmt]:
        pid = proto.proto_id
        stmts: List[A.Stmt] = [
            # A plain table constructor, not table.create: the reconstructed
            # chunk may run after user code has replaced or cleared `table`,
            # and depending on a global here would make the scaffolding fail
            # for reasons that have nothing to do with the program.
            A.Local(names=[_local_name(regs_name(pid))],
                    values=[A.Table(items=[])]),
        ]
        for i in range(proto.num_params):
            stmts.append(A.Assign(targets=[self._reg(proto, i)],
                                  values=[_name(param_name(pid, i))]))
        pc = pc_name(pid)
        stmts.append(A.Local(names=[_local_name(pc)], values=[_num(proto.entry)]))

        arms: List[Tuple[A.Expr, A.Block]] = []
        for b in proto.blocks:
            cond = A.Bin(op="==", left=_name(pc), right=_num(b.id))
            arms.append((cond, A.Block(body=self._block_body(proto, b, pc))))
        stmts.append(A.While(
            cond=A.Bool(value=True),
            body=A.Block(body=[A.If(arms=arms,
                                    otherwise=A.Block(body=[A.Break()]))])))
        return stmts

    def _set_pc(self, pc: str, target: int) -> A.Assign:
        return A.Assign(targets=[_name(pc)], values=[_num(target)])

    def _block_body(self, proto: FuncIR, b, pc: str) -> List[A.Stmt]:
        out: List[A.Stmt] = []
        for ins in b.instrs:
            out.extend(self._instr(proto, ins, b, pc))
        # A block only stops advancing the counter itself when it ends in a
        # terminator; otherwise control falls through and the dispatcher has to
        # be told where.  Forgetting this spins on one arm forever.
        term = b.instrs[-1].op if b.instrs else None
        if term not in TERMINATORS and b.id + 1 < len(proto.blocks):
            out.append(self._set_pc(pc, b.id + 1))
        return out

    # -- instructions ----------------------------------------------------
    def _instr(self, proto: FuncIR, ins: Instr, b, pc: str) -> List[A.Stmt]:
        op = ins.op
        a = ins.args
        g = lambda i: self._operand(proto, a[i])  # noqa: E731
        out: List[A.Stmt] = []

        if op == OP.NOP:
            return out
        if op == OP.LOADK and self.bank is not None:
            return [self._assign(proto, a[0], self._bank_or_pool(proto, a[1]))]
        if op in (OP.MOV, OP.LOADK):
            return [self._assign(proto, a[0], g(1))]
        if op == OP.GETGLOBAL:
            return [self._assign(proto, a[0], self._global_expr(proto, a[1]))]
        if op == OP.SETGLOBAL:
            return [A.Assign(targets=[self._global_expr(proto, a[0])],
                             values=[g(1)])]
        if op == OP.GETUPVAL:
            return [self._assign(proto, a[0], g(1))]
        if op == OP.SETUPVAL:
            return [A.Assign(targets=[self._upvalue_expr(proto, a[0].index)],
                             values=[g(1)])]
        if op == OP.GETTABLE:
            return [self._assign(proto, a[0], A.Index(obj=g(1), key=g(2)))]
        if op == OP.SETTABLE:
            return [A.Assign(targets=[A.Index(obj=g(0), key=g(1))], values=[g(2)])]
        if op == OP.SELF:
            # R(base) = obj[key]; R(base+1) = obj
            return [
                self._assign(proto, a[0] + 1, g(1)),
                self._assign(proto, a[0], A.Index(obj=g(1), key=g(2))),
            ]
        if op == OP.NEWTABLE:
            return [self._assign(proto, a[0], A.Table(items=[]))]
        if op == OP.SETLIST:
            base, count = a[0], int(a[1])
            start = int(a[2]) if len(a) > 2 else 1
            tbl = self._reg(proto, base.index)
            for i in range(count):
                # absolute index, never `#t + 1`: an explicit nil element does
                # not lengthen the table, so appending by length would drop it
                # and shift every later element down by one.
                out.append(A.Assign(
                    targets=[A.Index(obj=tbl, key=_num(start + i))],
                    values=[self._reg(proto, base.index + 1 + i)]))
            return out
        if op == OP.SETLISTMULTI:
            return [A.ExprStat(expr=A.Call(
                fn=_name(HELPER_APPEND),
                args=[self._reg(proto, a[0].index), self._reg(proto, a[1])]))]
        if op in _ARITH:
            return [self._assign(proto, a[0], A.Bin(op=_ARITH[op], left=g(1),
                                                    right=g(2)))]
        if op in _CMP:
            return [self._assign(proto, a[0], A.Bin(op=_CMP[op], left=g(1),
                                                    right=g(2)))]
        if op == OP.UNM:
            return [self._assign(proto, a[0], A.Un(op="-", operand=g(1)))]
        if op == OP.NOT:
            return [self._assign(proto, a[0], A.Un(op="not", operand=g(1)))]
        if op == OP.LEN:
            return [self._assign(proto, a[0], A.Un(op="#", operand=g(1)))]
        if op == OP.CONCAT:
            return [self._assign(proto, a[0], A.Bin(op="..", left=g(1),
                                                    right=g(2)))]
        if op == OP.CLOSURE:
            child = a[1]
            saved = dict(self.snapshots)
            snaps: List[Tuple[str, A.Expr]] = []
            for i in range(len(child.upvalues)):
                home_pid, home_reg = self._upvalue_home(child, i)
                if home_reg in self.by_id[home_pid].per_iteration:
                    # Luau gives every loop iteration its own variable, so a
                    # closure built inside the body captures that iteration's
                    # value.  Reading the shared register later would report
                    # the final one instead, so capture through a local that is
                    # fresh each time this block runs.
                    nm = f"{PREFIX}U{child.proto_id}_{i}"
                    self.snapshots[(child.proto_id, i)] = nm
                    snaps.append((nm, self._reg(self.by_id[home_pid], home_reg)))
            fn = self.function_expr(child)
            self.snapshots = saved
            assign = self._assign(proto, a[0], fn)
            if not snaps:
                return [assign]
            body = [A.Local(names=[_local_name(nm)], values=[expr])
                    for nm, expr in snaps]
            body.append(assign)
            return [A.Do(body=A.Block(body=body))]
        if op == OP.JMP:
            return [self._set_pc(pc, a[0])]
        if op in (OP.JMPFALSE, OP.JMPTRUE):
            cond = g(0)
            if op == OP.JMPFALSE:
                cond = A.Un(op="not", operand=A.Group(expr=cond))
            return [A.If(
                arms=[(cond, A.Block(body=[self._set_pc(pc, a[1])]))],
                otherwise=A.Block(body=[self._set_pc(pc, b.id + 1)]))]
        if op == OP.CALL:
            return self._emit_call(proto, a[0], int(a[1]), int(a[2]), int(a[3]))
        if op == OP.TAILCALL:
            base, argc, tail = a[0], int(a[1]), int(a[2])
            return [A.Return(values=[A.Call(
                fn=self._reg(proto, base.index),
                args=self._call_args(proto, base, argc, tail))])]
        if op == OP.RETURN0:
            return [A.Return(values=[])]
        if op == OP.RETURN:
            base, n = a[0], int(a[1])
            return [A.Return(values=[self._reg(proto, base.index + i)
                                     for i in range(n)])]
        if op == OP.RETURNMULTI:
            base, n, pack = a[0], int(a[1]), int(a[2])
            vals: List[A.Expr] = [self._reg(proto, base.index + i)
                                  for i in range(n)]
            vals.append(self._splice(proto, pack))
            return [A.Return(values=vals)]
        if op == OP.EXPAND:
            dst, pack, count = a[0], int(a[1]), int(a[2])
            return [A.Assign(
                targets=[self._reg(proto, dst.index + i) for i in range(count)],
                values=[self._splice(proto, pack)])]
        if op == OP.VARARG:
            base, n = a[0], int(a[1])
            if n == MULTIRET:
                return [self._assign(proto, base, A.Call(fn=_name(HELPER_PACK),
                                                         args=[A.Vararg()]))]
            targets = [self._reg(proto, base.index + i) for i in range(max(n, 0))]
            if not targets:
                return out
            return [A.Assign(targets=targets, values=[A.Vararg()])]
        if op == OP.FORPREP:
            base, tgt = a[0], a[1]
            i_ = self._reg(proto, base.index)
            step = self._reg(proto, base.index + 2)
            return [A.Assign(targets=[i_],
                             values=[A.Bin(op="-", left=i_, right=step)]),
                    self._set_pc(pc, tgt)]
        if op == OP.FORLOOP:
            base, tgt = a[0], a[1]
            i_ = self._reg(proto, base.index)
            lim = self._reg(proto, base.index + 1)
            step = self._reg(proto, base.index + 2)
            cond = A.Bin(
                op="or",
                left=A.Group(expr=A.Bin(
                    op="and",
                    left=A.Bin(op=">", left=step, right=_num(0)),
                    right=A.Bin(op="<=", left=i_, right=lim))),
                right=A.Group(expr=A.Bin(
                    op="and",
                    left=A.Bin(op="<", left=step, right=_num(0)),
                    right=A.Bin(op=">=", left=i_, right=lim))))
            body = A.Block(body=[
                A.Assign(targets=[self._reg(proto, base.index + 3)],
                         values=[i_]),
                self._set_pc(pc, tgt),
            ])
            return [A.Assign(targets=[i_],
                             values=[A.Bin(op="+", left=i_, right=step)]),
                    A.If(arms=[(cond, body)],
                         otherwise=A.Block(body=[self._set_pc(pc, b.id + 1)]))]
        if op == OP.ITERPREP:
            base = a[0]
            packed = int(a[1]) if len(a) > 1 else 0
            helper = HELPER_ITERPACK if packed else HELPER_ITER
            return [A.Assign(
                targets=[self._reg(proto, base.index + i) for i in range(3)],
                values=[A.Call(fn=_name(helper),
                               args=[self._reg(proto, base.index)])])]
        if op == OP.FORINPREP:
            # validated once, at loop entry, the way Luau does it -- not on
            # every iteration.  Skipped when ITERPREP already resolved the
            # iterator, so a bad __iter result surfaces as a call failure.
            base = a[0]
            resolved = int(a[2]) if len(a) > 2 else 0
            stmts = []
            if not resolved:
                reg = self._reg(proto, base.index)
                stmts.append(A.Assign(
                    targets=[reg],
                    values=[A.Call(fn=_name(HELPER_ITERCHECK), args=[reg])]))
            stmts.append(self._set_pc(pc, a[1]))
            return stmts
        if op == OP.FORIN:
            base, tgt = a[0], a[1]
            nvars = int(a[2]) if len(a) > 2 else 2
            f = self._reg(proto, base.index)
            s = self._reg(proto, base.index + 1)
            c = self._reg(proto, base.index + 2)
            targets = [self._reg(proto, base.index + 3 + i) for i in range(nvars)]
            body = A.Block(body=[A.Assign(targets=[c], values=[targets[0]]),
                                 self._set_pc(pc, tgt)])
            return [A.Assign(targets=targets,
                             values=[A.Call(fn=f, args=[s, c])]),
                    A.If(arms=[(A.Bin(op="~=", left=targets[0], right=A.Nil()),
                                body)],
                         otherwise=A.Block(body=[self._set_pc(pc, b.id + 1)]))]
        raise ReconstructionError(f"cannot reconstruct {op}")

    def _name_const(self, proto: FuncIR, k: Kon) -> str:
        v = proto.consts[k.index]
        if isinstance(v, (bytes, bytearray)):
            return v.decode("utf-8", "surrogatepass")
        return str(v)

    def _call_args(self, proto: FuncIR, base: Reg, argc: int,
                   tail: int) -> List[A.Expr]:
        args: List[A.Expr] = [self._reg(proto, base.index + 1 + i)
                              for i in range(argc)]
        if tail >= 0:
            args.append(self._splice(proto, tail))
        return args

    def _emit_call(self, proto: FuncIR, base: Reg, argc: int, nres: int,
                   tail: int) -> List[A.Stmt]:
        call = A.Call(fn=self._reg(proto, base.index),
                      args=self._call_args(proto, base, argc, tail))
        if nres == 0:
            return [A.ExprStat(expr=call)]
        if nres == MULTIRET:
            return [self._assign(proto, base,
                                 A.Call(fn=_name(HELPER_PACK), args=[call]))]
        return [A.Assign(targets=[self._reg(proto, base.index + i)
                                  for i in range(nres)], values=[call])]


_ARITH = {OP.ADD: "+", OP.SUB: "-", OP.MUL: "*", OP.DIV: "/",
          OP.IDIV: "//", OP.MOD: "%", OP.POW: "^"}
_CMP = {OP.EQ: "==", OP.NE: "~=", OP.LT: "<", OP.LE: "<=",
        OP.GT: ">", OP.GE: ">="}


def reconstruct_protected(module: IRModule,
                          keys: Any,
                          rng: Any,
                          context: bytes,
                          cache_policy: str = "full",
                          cache_bound: int = 64,
                          names: Optional[Dict[str, str]] = None,
                          minify: bool = False,
                          optimize_first: bool = True,
                          vm_level: Any = VirtualizationLevel.HEAVY,
                          vm_rng: Any = None,
                          vm_protos: Any = None,
                          vm_family: Any = "register",
                          string_level: int = 0,
                          string_rng: Any = None,
                          string_cache_policy: str = "none",
                          string_page_size: int = 512) -> str:
    """Lower an IR module to protected, self-contained Luau source.

    Assembles three pieces in the order they must appear: the constant pool
    runtime (which decrypts), the small helper functions, and the reconstructed
    body.  Constants are interned while the body is emitted, so the pool is only
    sealed afterwards -- which is fine, because the accessor name is fixed up
    front and the sealed blob is emitted last as data.

    ``keys`` is a :class:`~couxobf.crypto.kdf.KeyMaterial` and ``rng`` an
    :class:`~couxobf.rng.Rng`; both must come from the build seed so the output
    is reproducible.
    """
    # imported here rather than at module scope: the printer and the parser do
    # not depend on this module, but keeping the edge local means the import
    # order of the package cannot break the plain reconstruction path
    from . import optimize as _optimize
    from . import parser as _parser
    from .constpool import ConstantPool
    from .emit import printer as _printer
    from .runtime.constpool_runtime import ConstantPoolRuntime, default_names

    names = names or default_names()
    if optimize_first:
        # before the pool is built, so folded constants are interned once
        # rather than once per site they were duplicated at
        _optimize.optimize_module(module)
    pool = ConstantPool(keys, rng, context,
                        cache_policy=cache_policy, cache_bound=cache_bound)

    # Selected after optimization, so prototypes the optimizer shrank below the
    # size floor are not virtualized on the strength of code that no longer
    # exists.
    # Virtualization is on by default at the same level ``Config`` defaults to.
    # Pass ``VirtualizationLevel.NONE`` (or the "compact" profile) to get a
    # purely native reconstruction.
    # ``vm_protos`` lets a caller supply an explicit selection -- the pipeline
    # passes the classifier's decision rather than the size-floor heuristic.
    plan = None
    if VirtualizationLevel.parse(vm_level) is not VirtualizationLevel.NONE:
        from .vm import wiring as _wiring
        selected = (set(vm_protos) if vm_protos is not None
                    else _wiring.select_protos(module, vm_level))
        plan = _wiring.make_plan(vm_rng if vm_rng is not None else rng,
                                 selected, family=vm_family)

    # Strings get their own bank at level 2 and above: fragmented, scattered
    # across shuffled pages, and addressed by a per-occurrence ticket rather
    # than interned by value.  The pool interns, so one recovered accessor
    # yields every string; the bank deliberately does not.
    bank = None
    bank_names = None
    if string_level >= 2:
        from .strings.bank import StringBank
        from .runtime.stringbank_runtime import default_names as bank_default_names
        bank = StringBank(keys, string_rng if string_rng is not None else rng,
                          context, page_size=string_page_size)
        bank_names = bank_default_names()

    rec = Reconstructor(pool=pool, accessor=names["get"], vm=plan, bank=bank,
                        bank_accessor=(bank_names["get"] if bank_names else None))
    body = rec.reconstruct(module)

    # The VM's bytecode and constants are interned here, before the pool is
    # sealed below.  Doing it after would hand out slot numbers the encrypted
    # blob does not contain; the pool now refuses that outright, but the order
    # still has to be right.
    vm_src = ""
    if plan is not None and rec.vm_encoded:
        from .integrity import validate_module as _validate_payload
        from .vm import wiring as _wiring
        # Checked before emission, not after: a payload whose entry point or
        # jump targets do not line up with the instruction boundaries the
        # encoder laid down will run and compute the wrong thing, and nothing
        # downstream points back here.  This is the check that catches the
        # encoder bug, as opposed to the MAC, which catches the edit.
        _validate_payload(rec.vm_encoded, plan.opmap)
        pooled = lambda value: "%s(%d)" % (names["get"], pool.slot(value))
        vm_src = _wiring.prelude_source(plan, rec.vm_encoded, pooled, pooled)

    # A program with no constants at all needs no pool: emitting the runtime
    # for an empty blob would just be a decoder that never runs.
    need_pool = len(pool) > 0
    need_bank = bank is not None and len(bank) > 0

    # One crypto module for both, when both exist.  The module is ~8KB; two
    # copies would be two decoders to find and two places to drift.
    crypto_src = ""
    if need_pool and need_bank:
        from .runtime.luau_crypto import crypto_runtime
        crypto_src = ("local %s = (function()\n%s end)()\n" % (
            names["crypto"],
            crypto_runtime({"xor": names["c_xor"], "sha": names["c_sha"],
                            "mac": names["c_mac"], "open": names["c_open"],
                            "seal": names["c_seal"]})))

    pool_src = ""
    if need_pool:
        sealed = pool.seal()
        runtime = ConstantPoolRuntime(names, cache_policy=cache_policy,
                                      cache_bound=cache_bound)
        pool_src = runtime.emit(sealed.key, sealed.nonce, sealed.tag,
                                sealed.ciphertext, sealed.aad,
                                emit_crypto=not crypto_src)

    bank_src = ""
    if need_bank:
        from .runtime.luau_crypto import crypto_runtime
        from .runtime.stringbank_runtime import StringBankRuntime
        # "none" is the default cache policy and the right one: a table of
        # decrypted strings is a single dump that undoes the per-occurrence
        # tickets entirely.
        bn = dict(bank_names)
        if crypto_src:
            # The shared module exports the *pool's* field names, so the bank
            # has to call it by those.  Keeping its own would compile fine and
            # then fail at the first decrypt with "attempt to call a nil
            # value", because the field simply is not there.
            bn["crypto"] = names["crypto"]
            for role in ("c_xor", "c_sha", "c_mac", "c_open", "c_seal"):
                bn[role] = names[role]
        bank_runtime = StringBankRuntime(
            bn, cache_policy=string_cache_policy,
            emit_crypto=not crypto_src)
        bank_src = bank_runtime.emit(
            bank.seal(),
            crypto_runtime({"xor": bn["c_xor"], "sha": bn["c_sha"],
                            "mac": bn["c_mac"], "open": bn["c_open"],
                            "seal": bn["c_seal"]}) if not crypto_src else "")

    crypto_block = _parser.parse(crypto_src, "<crypto>") if crypto_src else None
    pool_block = _parser.parse(pool_src, "<constpool>") if pool_src else None
    bank_block = _parser.parse(bank_src, "<stringbank>") if bank_src else None
    # The helper functions have to be in scope too; a loop or a multi-value
    # call anywhere in the body refers to them.
    helpers = _parser.parse(HELPERS_SRC, "<helpers>")

    # The VM prelude goes after both: the interpreter calls the helpers, and
    # the descriptor table reads the bytecode and the constants back out of the
    # pool at load time, so the accessor has to exist first.  Routing the
    # bytecode through the pool is what makes the payload protected rather than
    # merely encoded -- it is encrypted in the blob like every other constant.
    vm_block = _parser.parse(vm_src, "<vm>") if vm_src else None

    prefix: List[A.Stmt] = []
    for block in (crypto_block, pool_block, bank_block):
        if block is not None:
            prefix += list(block.body)
    vm_stmts = list(vm_block.body) if vm_block is not None else []
    out = A.Block(body=prefix + list(helpers.body) + vm_stmts + list(body.body))
    return _printer.emit(out, minify=minify)

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

#: The helper roles, in emission order.  The names themselves are per-build;
#: these are only the legacy fixed values, kept as a fallback so callers that
#: have not been given a build's names still work.
DEFAULT_HELPERS: Dict[str, str] = {
    "pack": HELPER_PACK,
    "unpack": HELPER_UNPACK,
    "append": HELPER_APPEND,
    "iter": HELPER_ITER,
    "iterpack": HELPER_ITERPACK,
    "itercheck": HELPER_ITERCHECK,
}

#: Roles in the order the helpers are declared.
HELPER_ROLES: Tuple[str, ...] = ("pack", "unpack", "iter", "iterpack",
                                 "itercheck", "append")


def helper_names(rng: Any, used: Optional[Set[str]] = None) -> Dict[str, str]:
    """Per-build names for the six shared helpers.

    These were the constants ``_kpack``, ``_kunpk``, ``_kiter``,
    ``_kiterpack``, ``_kitercheck`` and ``_kapp`` -- identical in every build,
    always declared in the same order at the same place in the prelude.  That
    is a stable signature an automated tool can anchor on before it has
    understood a single instruction.

    ``used`` must be the set of prefixes already handed out this build, so a
    helper name cannot collide with the constant pool's or the string bank's.
    """
    import string as _string

    used = used if used is not None else set()
    out: Dict[str, str] = {}
    for role in HELPER_ROLES:
        while True:
            candidate = "_k" + "".join(
                rng.choice(_string.ascii_letters) for _ in range(4))
            if candidate in used:
                continue
            used.add(candidate)
            out[role] = candidate
            break
    return out

#: Prefixes the reconstruction reserves for its own generated identifiers.  A
#: random prefix must not start with any of these, or it could shadow one of
#: them: the reconstructor emits ``_kR<pid>`` register files, ``_kC<pid>``
#: program counters and ``_kP<pid>_<i>`` parameters.
_RESERVED_PREFIX_CHARS = frozenset("RCP")


def fresh_prefix(rng: Any, used: Optional[Set[str]] = None,
                 body: int = 3) -> str:
    """A per-build name prefix for one emitted runtime.

    These used to be the constants ``_kQ`` and ``_kS``, identical in every
    build.  A fixed prefix appearing a hundred-odd times is a fingerprint an
    automated tool can match on before it has understood anything, so it is
    drawn from the build's own randomness instead.
    """
    import string as _string

    alphabet = _string.ascii_letters
    while True:
        head = rng.choice(alphabet)
        # `_kR`/`_kC`/`_kP` are taken by register files, program counters and
        # parameter names respectively.
        if head in _RESERVED_PREFIX_CHARS:
            continue
        candidate = "_k" + head + "".join(
            rng.choice(alphabet) for _ in range(body))
        if used is None or candidate not in used:
            if used is not None:
                used.add(candidate)
            return candidate

def _fusion_rules(level: Any):
    """Which fused super-instructions this build may emit (#6).

    Level 0 fuses nothing -- the compact profile wants small output and fusion
    buys its diversity a byte at a time.  Higher levels offer more pairs, and
    the build picks a random *subset* of what is offered, so two builds at the
    same level do not agree on which pairs exist.  Capping the subset is what
    keeps the dispatch chain from growing into the "bigger is stronger" trap the
    design warns about (#63): fifteen rules is roughly fifteen extra arms, each
    with both halves' bodies inlined.
    """
    from .vm.format import FUSION_RULES

    try:
        want = int(level)
    except (TypeError, ValueError):
        return ()
    if want <= 0:
        return ()
    return FUSION_RULES


def helpers_src(h: Dict[str, str]) -> str:
    """The shared helper block, with this build's names."""
    return f"""
    local function {h['pack']}(...)
      return table.pack(...)
    end
    local function {h['unpack']}(t, i)
      return table.unpack(t, i, t.n)
    end
    local function {h['iter']}(v)
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
    local function {h['iterpack']}(t)
      -- Luau picks between the classic (iterator, state, control) triple and
      -- generalized iteration by how many values the iterator expression actually
      -- produced: exactly one means the value is the iterable itself.
      if t.n == 1 then
        return {h['iter']}(t[1])
      end
      return t[1], t[2], t[3]
    end
    local function {h['itercheck']}(f)
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
    local function {h['append']}(dst, t)
      local n = #dst
      for i = 1, t.n do
        n += 1
        dst[n] = t[i]
      end
    end
    """


#: Legacy name for callers that have not been updated.
HELPERS_SRC = helpers_src(DEFAULT_HELPERS)



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
                 bank_accessor: Optional[str] = None,
                 helpers: Optional[Dict[str, str]] = None,
                 native_prefix: str = PREFIX,
                 pool_ticket: Optional[Any] = None) -> None:
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
        #: Slot numbers are not passed to the runtime directly.  The pool
        #: accessor receives a per-build ticket and decodes it locally, so a dump
        #: of call-site constants is not an index over the decrypted table.
        self.pool_ticket = pool_ticket or (lambda slot: slot)
        self.vm = vm
        #: The shared helpers' names for this build.  Must match what
        #: ``helpers_src`` declared, or the interpreter calls functions that do
        #: not exist -- which is a runtime error, not a build error.
        self.helpers: Dict[str, str] = dict(helpers or DEFAULT_HELPERS)
        self.native_prefix = native_prefix
        #: proto_id -> EncodedProto, filled in as function_expr runs
        self.vm_encoded: Dict[int, Any] = {}
        #: Randomness for per-prototype layout choices (padding bytes, alias
        #: selection).  The same stream the block permutation uses, because both
        #: are "where do the bytes go" decisions and separating them would only
        #: mean one more stream to audit for accidental reuse.
        self.vm_layout_rng: Any = None
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
        params = [A.Param(name=self._param_name(proto.proto_id, i))
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

        # The plan, not a default: which group owns this prototype decides the
        # opcode map, the instruction format *and* the interpreter that will run
        # it.  Asking those three questions separately is how a build ends up
        # executing bytes encoded for a different machine -- and eligibility has
        # to be judged against the format in play, because a wide operand that
        # fits a three-byte field does not fit a two-byte one.
        group = self.vm.group_for(proto.proto_id)
        fmt = self.vm.fmt_for(proto.proto_id)
        ok, _reason = _encode.can_virtualize(proto, fmt)
        if not ok:
            return None
        order = None
        if self.vm.permute_blocks and self.vm.layout_rng is not None:
            from .vm import layout as _layout
            order = _layout.permuted_order(proto, self.vm.layout_rng)
        self.vm_encoded[proto.proto_id] = _encode.encode_proto(
            proto, self.vm.opmap_for(proto.proto_id), order=order, fmt=fmt,
            rng=self.vm_layout_rng,
            alias_chance=self.vm.alias_chance)
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
        # `enter_for` is this prototype's *group's* entry point, and the row it
        # is handed comes out of the assembled descriptor table.  Naming the
        # interpreter in the closure rather than storing "which VM" in the
        # artifact means a build with three VMs carries no table that says so.
        enter = self.vm.enter_for(proto.proto_id)
        return A.Func(
            params=[A.Param(name=None)],
            body=A.Block(body=[A.Return(values=[A.Call(
                fn=A.Name(name=enter),
                args=[A.Index(obj=A.Name(name=self.vm.rows_table),
                              key=_num(self.vm.row_key(proto.proto_id))),
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
    def _regs_name(self, proto_id: int) -> str:
        return f"{self.native_prefix}r{proto_id}"

    def _pc_name(self, proto_id: int) -> str:
        return f"{self.native_prefix}c{proto_id}"

    def _param_name(self, proto_id: int, i: int) -> str:
        return f"{self.native_prefix}p{proto_id}_{i}"

    def _reg(self, proto: FuncIR, i: int) -> A.Index:
        return A.Index(obj=_name(self._regs_name(proto.proto_id)), key=_num(i))

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
        return A.Call(fn=_name(self.accessor), args=[_num(self.pool_ticket(slot))])

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
        return A.Call(fn=_name(self.helpers["unpack"]), args=[self._reg(proto, pack),
                                                     _num(1)])

    # -- prototype -------------------------------------------------------
    def _proto_body(self, proto: FuncIR) -> List[A.Stmt]:
        pid = proto.proto_id
        stmts: List[A.Stmt] = [
            # A plain table constructor, not table.create: the reconstructed
            # chunk may run after user code has replaced or cleared `table`,
            # and depending on a global here would make the scaffolding fail
            # for reasons that have nothing to do with the program.
            A.Local(names=[_local_name(self._regs_name(pid))],
                    values=[A.Table(items=[])]),
        ]
        for i in range(proto.num_params):
            stmts.append(A.Assign(targets=[self._reg(proto, i)],
                                  values=[_name(self._param_name(pid, i))]))
        pc = self._pc_name(pid)
        stmts.append(A.Local(names=[_local_name(pc)], values=[_num(proto.entry)]))

        # The native flattened driver no longer uses one canonical
        # ``while true; if pc == block`` signature.  The state stays numeric and
        # exact, but the loop is keyed by the liveness of the state and the block
        # tests can carry a build-local additive bias.
        salt = 0
        if self.vm_layout_rng is not None:
            try:
                salt = self.vm_layout_rng.randbelow(257)
            except AttributeError:
                salt = 0
        arms: List[Tuple[A.Expr, A.Block]] = []
        for b in proto.blocks:
            left: A.Expr = _name(pc)
            right: A.Expr = _num(b.id)
            if salt:
                left = A.Bin(op="+", left=left, right=_num(salt))
                right = _num(b.id + salt)
            cond = A.Bin(op="==", left=left, right=right)
            arms.append((cond, A.Block(body=self._block_body(proto, b, pc))))
        stmts.append(A.While(
            cond=_name(pc),
            body=A.Block(body=[A.If(arms=arms,
                                    otherwise=A.Block(body=[
                                        A.Assign(targets=[_name(pc)],
                                                 values=[A.Nil()])]))])))
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
                fn=_name(self.helpers["append"]),
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
                return [self._assign(proto, base, A.Call(fn=_name(self.helpers["pack"]),
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
            helper = (self.helpers["iterpack"] if packed
                      else self.helpers["iter"])
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
                    values=[A.Call(fn=_name(self.helpers["itercheck"]), args=[reg])]))
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
                                 A.Call(fn=_name(self.helpers["pack"]), args=[call]))]
        return [A.Assign(targets=[self._reg(proto, base.index + i)
                                  for i in range(nres)], values=[call])]


_ARITH = {OP.ADD: "+", OP.SUB: "-", OP.MUL: "*", OP.DIV: "/",
          OP.IDIV: "//", OP.MOD: "%", OP.POW: "^"}
_CMP = {OP.EQ: "==", OP.NE: "~=", OP.LT: "<", OP.LE: "<=",
        OP.GT: ">", OP.GE: ">="}


#: Marks a constant-pool context that has been extended with a build fingerprint.
#: Not a secret -- a delimiter, so the extension is unambiguous.
_FINGERPRINT_AAD_TAG = b"\xc1f"


def reconstruct_protected(module: IRModule,
                          keys: Any,
                          rng: Any,
                          context: bytes,
                          cache_policy: str = "full",
                          cache_bound: int = 64,
                          pool_decoys: int = 0,
                          constant_level: int = 0,
                          numeric_level: int = 0,
                          fingerprint: bool = True,
                          metadata_fragmentation: bool = True,
                          names: Optional[Dict[str, str]] = None,
                          minify: bool = False,
                          optimize_first: bool = True,
                          vm_level: Any = VirtualizationLevel.HEAVY,
                          vm_rng: Any = None,
                          vm_protos: Any = None,
                          vm_family: Any = "register",
                          block_permutation: bool = False,
                          opaque_predicates: bool = True,
                          layout_rng: Any = None,
                          dispatcher_family: Any = "mixed",
                          opcode_randomization: bool = True,
                          string_level: int = 0,
                          string_rng: Any = None,
                          string_cache_policy: str = "none",
                          string_page_size: int = 512,
                          vm_variety: int = 1,
                          isa_subset: bool = False,
                          fmt_prefs: Any = None,
                          families: Any = None,
                          dispatchers: Any = None,
                          fusion_level: int = 0,
                          alias_ratio: float = 0.0,
                          alias_chance: float = 0.0,
                          env_guard: int = 0,
                          dump_guard: int = 0,
                          guard_policy: str = "fail",
                          names_out: Optional[Dict[str, Any]] = None) -> str:
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

    prefixes: Set[str] = set()
    # Its own prefix again: the guard's locals are the one part of the artifact
    # whose names a runner is *looking* for, since finding the checker finds what
    # it refuses on.
    from . import guard as _guard
    guard = _guard.make(env_guard, dump_guard, guard_policy,
                        prefix=fresh_prefix(rng, prefixes))
    names = names or default_names(fresh_prefix(rng, prefixes))
    # Drawn from the same `used` set as the pool and bank prefixes, so a helper
    # name cannot collide with either runtime's identifiers.
    helper_map = helper_names(rng, prefixes)
    if names_out is not None:
        # Callers need the names that were actually chosen.  Guessing them from
        # default_names() stopped working the moment the prefix became per-build,
        # and a validator that cannot find the helpers silently checks nothing.
        names_out["pool"] = dict(names)
        names_out["helpers"] = dict(helper_map)
    if optimize_first:
        # before the pool is built, so folded constants are interned once
        # rather than once per site they were duplicated at
        _optimize.optimize_module(module)
    pool = ConstantPool(keys, rng, context,
                        cache_policy=cache_policy, cache_bound=cache_bound,
                        decoys=pool_decoys,
                        constant_level=constant_level,
                        numeric_level=numeric_level)

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
                                 selected, family=vm_family,
                                 permute_blocks=block_permutation,
                                 layout_rng=layout_rng,
                                 dispatcher=dispatcher_family,
                                 randomize_opcodes=opcode_randomization,
                                 variety=vm_variety,
                                 fusion=_fusion_rules(fusion_level),
                                 alias_ratio=alias_ratio,
                                 alias_chance=alias_chance,
                                 fmt_prefs=fmt_prefs,
                                 families=families,
                                 dispatchers=dispatchers,
                                 # One metadata object or three: see
                                 # prelude_source.  Off is the easier read, and
                                 # the config's name for choosing that is
                                 # `metadata_fragmentation`.
                                 fragmented=bool(metadata_fragmentation),
                                 # Per-group instruction sets: the narrowing is
                                 # only answerable with the IR in hand, because
                                 # "which opcodes does this function need" is a
                                 # question about its instructions, not about any
                                 # of the names the config has.
                                 protos_by_id=({q.proto_id: q for q in module.protos}
                                                if isa_subset else None),
                                 isa_subset=bool(isa_subset),
                                 # wiring indexes this positionally as
                                 # (append, iter, iterpack, itercheck); passing
                                 # the dict would hand it the role *keys*.
                                 shared=(helper_map["append"],
                                         helper_map["iter"],
                                         helper_map["iterpack"],
                                         helper_map["itercheck"]))

    if names_out is not None:
        # Asked for, as distinct from produced: with nothing virtualized there is no
        # plan, so nothing gets digested, and the report must not read that as "the
        # user declined".
        names_out["fingerprint_requested"] = 1 if fingerprint else 0
    if plan is not None and fingerprint:
        from .vm.wiring import structural_fingerprint
        digest = structural_fingerprint(plan)
        # Two facts, reported separately.  The digest describes the format
        # decisions this build drew, which exist whether or not a prototype ended
        # up on the interpreter.  Folding them into the pool's AAD is the claim
        # that the pool cannot open under another *running* format -- and a build
        # that virtualized nothing has no running format, so binding there let
        # `--vm-family` change a program with no VM in it.  The digest is still
        # reported, because it is true; it just authenticates nothing.
        bound = bool(plan.protos)
        if bound:
            # The pool is not sealed yet -- interning happens during lowering and
            # sealing at emit -- so the digest can still bind to it.  Tagged so a
            # context that happens to end in eight bytes of its own cannot read as
            # one that was extended here.
            pool.context = context + _FINGERPRINT_AAD_TAG + digest
        if names_out is not None:
            names_out["fingerprint"] = digest.hex()
            names_out["fingerprint_bound"] = 1 if bound else 0
    if plan is not None and names_out is not None:
        # What each VM group in this artifact actually is.  Reported rather than
        # inferred: `--vm-family register` is what the user asked for, and with two
        # groups the second one is a different family, dispatcher and format -- a
        # report that echoed only the config would describe a build that did not
        # happen.
        names_out["vm_plan"] = plan.summary()
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
                          context, page_size=string_page_size,
                          randomized_ids=True)
        # Its own prefix, drawn from the string stream: sharing the constant
        # pool's prefix would make the two runtimes recognisable as a pair.
        bank_names = bank_default_names(
            fresh_prefix(string_rng if string_rng is not None else rng,
                         prefixes))
        if names_out is not None:
            names_out["bank"] = dict(bank_names)

    ticket_rng = rng.fork("pool-ticket") if hasattr(rng, "fork") else rng
    pool_ticket_mask = (ticket_rng.u32() if hasattr(ticket_rng, "u32") else 0x5A17C0DE) & 0xffffffff
    if pool_ticket_mask == 0:
        pool_ticket_mask = 0x5A17C0DE
    pool_ticket = lambda slot: (int(slot) ^ pool_ticket_mask) & 0xffffffff
    rec = Reconstructor(pool=pool, accessor=names["get"], vm=plan, bank=bank,
                        bank_accessor=(bank_names["get"] if bank_names else None),
                        helpers=helper_map,
                        native_prefix=fresh_prefix(rng, prefixes),
                        pool_ticket=pool_ticket)
    rec.vm_layout_rng = layout_rng if layout_rng is not None else vm_rng
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
        # encoder bug, as opposed to the MAC, which catches the edit.  Each
        # group is validated with *its own* map and format, since a single
        # validator built from group 0 would reject every other group.
        for group in plan.groups:
            mine = {pid: enc for pid, enc in rec.vm_encoded.items()
                    if group.describes(pid)}
            if mine:
                _validate_payload(mine, group.opmap, group.fmt)
        pooled = lambda value: "%s(%d)" % (names["get"], pool_ticket(pool.slot(value)))
        vm_src = _wiring.prelude_source(plan, rec.vm_encoded, pooled, pooled,
                                        edges_expr=pooled,
                                        entry_guard=guard.entry_lines(),
                                        opaque_predicates=bool(opaque_predicates))

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

    runtime_guard_check = guard.n("check") if guard.refuses else ""

    pool_src = ""
    if need_pool:
        sealed = pool.seal()
        if names_out is not None:
            # Read here rather than where the pool was built: constants are
            # interned while the bodies are lowered, and the decoys are planted as
            # they go, so any earlier count is a count of a pool that does not
            # exist yet.
            names_out["pool_decoys"] = pool.decoys_planted
        runtime = ConstantPoolRuntime(names, cache_policy=cache_policy,
                                      cache_bound=cache_bound)
        pool_src = runtime.emit(sealed.key, sealed.nonce, sealed.tag,
                                sealed.ciphertext, sealed.aad,
                                emit_crypto=not crypto_src,
                                guard_check=runtime_guard_check,
                                ticket_mask=pool_ticket_mask)

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
                            "seal": bn["c_seal"]}) if not crypto_src else "",
            guard_check=runtime_guard_check)

    crypto_block = _parser.parse(crypto_src, "<crypto>") if crypto_src else None
    pool_block = _parser.parse(pool_src, "<constpool>") if pool_src else None
    bank_block = _parser.parse(bank_src, "<stringbank>") if bank_src else None
    # The helper functions have to be in scope too; a loop or a multi-value
    # call anywhere in the body refers to them.
    helpers = _parser.parse(helpers_src(helper_map), "<helpers>")

    # The VM prelude goes after both: the interpreter calls the helpers, and
    # the descriptor table reads the bytecode and the constants back out of the
    # pool at load time, so the accessor has to exist first.  Routing the
    # bytecode through the pool is what makes the payload protected rather than
    # merely encoded -- it is encrypted in the blob like every other constant.
    # A failure to parse the runtime this module just assembled is a bug in the
    # generator, not in the input, so it is reported as one -- the alternative is
    # a ParseError whose line number points into source nobody wrote.
    vm_block = _parser.parse(vm_src, "<vm>") if vm_src else None

    blocks = [b for b in (crypto_block, pool_block, bank_block, helpers,
                          vm_block) if b is not None]
    captured: Dict[str, str] = {}
    if guard.active and blocks:
        # The capture set is decided *here*, once the emitted scaffolding exists:
        # binding a fixed list would capture functions the runtime never calls
        # (padding) and could miss one it does (a leak).  Whatever the scaffolding
        # reads is what gets a local, and each of those locals replaces every read
        # of the global in the scaffolding only -- the reconstructed user code is
        # left to resolve its globals the way the source did, because `setfenv`
        # has to keep working.
        used = set()
        for block in blocks:
            used.update(_guard.used_globals(block))
        captured = guard.bind(used)
        for block in blocks:
            _guard.rewrite(block, captured)
    guard_block = (_parser.parse(_guard.guard_block(guard), "<guard>")
                   if guard.active else None)
    if names_out is not None:
        # Filled in here rather than where the guard was created, because "what
        # did this build capture" is only knowable once the scaffolding exists.
        names_out["guard"] = guard.summary()
        names_out["guard_capture"] = dict(captured)

    def _guard_stmts() -> List[A.Stmt]:
        if guard_block is None:
            return []
        # The guard no longer emits ``local alias = global`` captures here.  The
        # emitted chunk is wrapped below in a parameterized IIFE whose parameters
        # are exactly these aliases, and whose arguments are the real globals in a
        # build-random order.  That leaves the protected scaffold reading locals
        # after entry while avoiding the stable local-alias prelude that used to
        # identify every build.
        aliases = set(captured.values())
        return [s for s in guard_block.body
                if not (isinstance(s, A.Local)
                        and len(s.names) == 1
                        and s.names[0].name in aliases)]

    component_blocks: Dict[str, List[A.Stmt]] = {
        "guard": _guard_stmts(),
        "crypto": list(crypto_block.body) if crypto_block is not None else [],
        "pool": list(pool_block.body) if pool_block is not None else [],
        "bank": list(bank_block.body) if bank_block is not None else [],
        "helpers": list(helpers.body),
        "vm": list(vm_block.body) if vm_block is not None else [],
    }
    deps: Dict[str, Set[str]] = {k: set() for k, v in component_blocks.items() if v}
    if "pool" in deps and "crypto" in deps:
        deps["pool"].add("crypto")
    if "bank" in deps and "crypto" in deps:
        deps["bank"].add("crypto")
    # When level-2 guard refusal is enabled, pool/string-bank accessors call the
    # same checker as VM entries before materializing plaintext.  That makes the
    # guard a real dependency, not merely a block that happened to be emitted
    # earlier in today's layout.
    if runtime_guard_check:
        for guarded in ("pool", "bank"):
            if guarded in deps and "guard" in deps:
                deps[guarded].add("guard")
    if "vm" in deps:
        for need in ("pool", "helpers", "guard"):
            if need in deps:
                deps["vm"].add(need)
    order: List[str] = []
    pending_components = set(deps)
    while pending_components:
        ready = [k for k in pending_components if deps[k] <= set(order)]
        try:
            rng.shuffle(ready)
        except AttributeError:
            pass
        pick = ready[0]
        order.append(pick)
        pending_components.remove(pick)
    prefix: List[A.Stmt] = []
    for key in order:
        prefix += component_blocks[key]
    if names_out is not None:
        names_out["bootstrap_order"] = list(order) + ["driver"]
    out = A.Block(body=prefix + list(body.body))
    emitted = _printer.emit(out, minify=minify)
    if captured:
        order = list(captured.items())
        # Randomize parameter ordering per build.  The mapping itself is already
        # per-build by name, but position matters for the wrapper shape: two
        # artifacts with the same library set no longer present the same capture
        # sequence to a reader.
        try:
            rng.shuffle(order)
        except AttributeError:
            import random as _random
            _random.shuffle(order)
        params = ", ".join(alias for _global, alias in order)
        args = ", ".join(global_name for global_name, _alias in order)
        sep = "" if minify else "\n"
        emitted = "return(function(%s)%s%s%send)(%s)\n" % (
            params, sep, emitted, sep, args)
    return emitted

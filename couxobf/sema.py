"""Semantic analysis: scopes, symbols, upvalues, arity, and function facts.

Nothing is transformed until this module has answered, for every identifier in
the program:

* is it a local, a parameter, an upvalue, or a global?
* which declaration does it resolve to?
* is it captured by a nested closure?
* does the enclosing function use ``...``?

Luau scoping rules implemented here:

* a local becomes visible in the statement *after* its declaration, so
  ``local x = x`` initialises from the outer ``x``;
* ``local function f`` is visible inside its own body (recursion);
* ``for`` control variables are scoped to the loop body;
* a ``repeat ... until cond`` condition can see locals declared in the body;
* in ``a, b = b, a`` every right-hand side is evaluated before any assignment;
* a statement-level ``function a.b.c()`` is an assignment to a *global*.

The resolver attaches a :class:`Symbol` to every :class:`Name` node as
``node.symbol`` (``None`` means "resolves to a global").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .ast_nodes import (
    Assign, Bin, Block, Bool, Break, Call, Cast, Compound, Continue, Declare, Do,
    Expr, ExprStat, Field, Func, FuncStat, GenFor, Group, If, IfExpr, Index,
    Interp, Local, LocalFunc, LocalName, MethodCall, Name, Nil, NumFor, Number,
    Param, Repeat, Return, Str, Table, TableItem, TypeAlias, Un, Vararg, While,
)

GLOBAL_NAMES = frozenset({
    "_G", "_VERSION", "assert", "bit32", "buffer", "collectgarbage", "coroutine",
    "debug", "error", "gcinfo", "math", "next", "os", "pairs", "ipairs", "pcall",
    "xpcall", "print", "rawequal", "rawget", "rawlen", "rawset", "require",
    "select", "setmetatable", "getmetatable", "string", "table", "task", "tick",
    "time", "tonumber", "tostring", "type", "typeof", "unpack", "utf8", "warn",
    "newproxy", "self",
})

LUAU_GLOBALS_READ_ONLY = GLOBAL_NAMES


@dataclass
class Symbol:
    name: str
    kind: str  # "local" | "param" | "upvalue" | "global"
    scope: "Scope" = field(default_factory=lambda: None)  # type: ignore[assignment]
    index: int = -1
    is_captured: bool = False
    is_assigned: bool = False
    new_name: Optional[str] = None
    decl_line: int = 0
    decl_col: int = 0
    func: Optional["FuncInfo"] = None
    # filled in for upvalues: index into the capturing function's upvalue table
    upvalue_index: int = -1

    @property
    def effective_name(self) -> str:
        return self.new_name if self.new_name is not None else self.name


@dataclass
class Scope:
    parent: Optional["Scope"] = None
    symbols: Dict[str, Symbol] = field(default_factory=dict)
    func: Optional["FuncInfo"] = None
    depth: int = 0
    # repeat/until: locals declared here are visible in the until-condition
    is_repeat_body: bool = False


@dataclass
class FuncInfo:
    node: Func
    scope: Scope
    parent: Optional["FuncInfo"] = None
    params: List[Symbol] = field(default_factory=list)
    locals: List[Symbol] = field(default_factory=list)
    upvalues: List[Symbol] = field(default_factory=list)
    nested: List["FuncInfo"] = field(default_factory=list)
    has_vararg: bool = False
    is_method: bool = False
    method_name: Optional[str] = None
    name: Optional[str] = None  # for named/local functions
    depth: int = 0
    # facts used by the classifier and the VM
    node_count: int = 0
    call_count: int = 0
    closure_count: int = 0
    loop_count: int = 0
    branch_count: int = 0
    metamethod: bool = False
    returns_multi: bool = False
    uses_vararg_in_body: bool = False
    tail_calls: int = 0
    # set when the body was replaced by a VM stub
    virtualized: bool = False
    proto_index: int = -1


@dataclass
class Analysis:
    root: Block
    scopes: List[Scope] = field(default_factory=list)
    functions: List[FuncInfo] = field(default_factory=list)
    symbols: List[Symbol] = field(default_factory=list)
    globals_read: Set[str] = field(default_factory=set)
    globals_written: Set[str] = field(default_factory=set)
    main: Optional[FuncInfo] = None

    def local_symbols(self) -> List[Symbol]:
        return [s for s in self.symbols if s.kind in ("local", "param")]


METAMETHOD_NAMES = frozenset({
    "__add", "__sub", "__mul", "__div", "__idiv", "__mod", "__pow", "__unm",
    "__concat", "__len", "__eq", "__lt", "__le", "__index", "__newindex",
    "__call", "__tostring", "__metatable", "__mode", "__iter", "__name",
    "__type", "__close",
})


class ScopeAnalyzer:
    def __init__(self) -> None:
        self.analysis = Analysis(root=Block())
        self.current: Optional[FuncInfo] = None

    # -- scope plumbing --------------------------------------------------
    def _open_scope(self, func: Optional[FuncInfo] = None) -> Scope:
        parent = self._current_scope()
        scope = Scope(parent=parent, func=func, depth=(parent.depth + 1) if parent else 0)
        self.analysis.scopes.append(scope)
        self._scope_stack.append(scope)
        return scope

    def _close_scope(self) -> None:
        self._scope_stack.pop()

    def _current_scope(self) -> Optional[Scope]:
        return self._scope_stack[-1] if self._scope_stack else None

    def _declare(self, name: str, kind: str, line: int = 0, col: int = 0) -> Symbol:
        scope = self._current_scope()
        sym = Symbol(
            name=name, kind=kind, scope=scope, index=len(scope.symbols),
            decl_line=line, decl_col=col, func=self.current,
        )
        scope.symbols[name] = sym
        self.analysis.symbols.append(sym)
        if kind == "param":
            self.current.params.append(sym)
        else:
            self.current.locals.append(sym)
        return sym

    def _resolve(self, node: Name) -> Optional[Symbol]:
        scope = self._current_scope()
        while scope is not None:
            sym = scope.symbols.get(node.name)
            if sym is not None:
                # mark capture if the declaration lives in another function
                if self.current is not None and sym.func is not self.current:
                    sym.is_captured = True
                    self._link_upvalue(sym)
                return sym
            scope = scope.parent
        return None

    def _link_upvalue(self, sym: Symbol) -> None:
        """Register ``sym`` as an upvalue of every function between here and its home."""
        fn = self.current
        while fn is not None and fn is not sym.func:
            if not any(existing is sym for existing in fn.upvalues):
                fn.upvalues.append(sym)
            # keep walking: a symbol captured two or more levels up must be
            # linked into *every* intervening prototype, not just the first.
            fn = fn.parent
        if sym.upvalue_index < 0 and sym.func is not None:
            sym.upvalue_index = len(sym.func.locals)

    # -- entry -----------------------------------------------------------
    def analyze(self, root: Block) -> Analysis:
        self._scope_stack: List[Scope] = []
        self.analysis.root = root
        main_scope = self._open_scope()
        main = FuncInfo(node=Func(params=[], body=root), scope=main_scope, name="<main>")
        main_scope.func = main
        self.analysis.main = main
        self.analysis.functions.append(main)
        self.current = main
        self.block(root)
        self.current = None
        self._close_scope()
        self._count_facts()
        return self.analysis

    # -- nodes -----------------------------------------------------------
    def block(self, block: Block) -> None:
        for stmt in block.body:
            self.stmt(stmt)

    def stmt(self, node) -> None:
        if isinstance(node, Local):
            # RHS first: `local x = x` must see the outer x.
            for v in node.values:
                self.expr(v)
            node.symbols = [
                self._declare(ln.name, "local", ln.line, ln.col) for ln in node.names
            ]
            return
        if isinstance(node, LocalFunc):
            # Declared in the enclosing scope *before* the body is walked, so a
            # recursive reference inside resolves to this symbol and is marked
            # captured -- exactly how Luau compiles `local function f`.
            sym = self._declare(node.name.name, "local", node.name.line, node.name.col)
            self.function(node.fn, name=node.name.name)
            node.symbol = sym
            return
        if isinstance(node, Assign):
            for v in node.values:
                self.expr(v)
            for t in node.targets:
                self.assign_target(t)
            return
        if isinstance(node, Compound):
            self.expr(node.target)
            self.expr(node.value)
            return
        if isinstance(node, FuncStat):
            fn = self.function(node.fn, name=self._chain_name(node.target),
                               method=node.is_method, method_name=node.method_name)
            self.assign_target(node.target)
            node.funcinfo = fn
            return
        if isinstance(node, ExprStat):
            self.expr(node.expr)
            return
        if isinstance(node, If):
            for cond, body in node.arms:
                self.expr(cond)
                self._open_scope()
                self.block(body)
                self._close_scope()
            if node.otherwise is not None:
                self._open_scope()
                self.block(node.otherwise)
                self._close_scope()
            return
        if isinstance(node, While):
            self.expr(node.cond)
            self._open_scope()
            self.block(node.body)
            self._close_scope()
            return
        if isinstance(node, Do):
            self._open_scope()
            self.block(node.body)
            self._close_scope()
            return
        if isinstance(node, Repeat):
            self._open_scope()
            self.block(node.body)
            # the until-condition sees the body's locals
            self.expr(node.cond)
            self._close_scope()
            return
        if isinstance(node, NumFor):
            self.expr(node.start)
            self.expr(node.stop)
            if node.step is not None:
                self.expr(node.step)
            self._open_scope()
            node.var_sym = self._declare(node.var.name, "local", node.var.line, node.var.col)
            self.block(node.body)
            self._close_scope()
            return
        if isinstance(node, GenFor):
            for e in node.iters:
                self.expr(e)
            self._open_scope()
            node.var_syms = [
                self._declare(v.name, "local", v.line, v.col) for v in node.vars
            ]
            self.block(node.body)
            self._close_scope()
            return
        if isinstance(node, Return):
            for i, v in enumerate(node.values):
                self.expr(v)
                if i == len(node.values) - 1 and isinstance(v, (Call, MethodCall, Vararg)):
                    self.current.returns_multi = True
            return
        if isinstance(node, (Break, Continue, TypeAlias, Declare)):
            return
        raise TypeError(f"unhandled statement {type(node).__name__}")

    def _chain_name(self, target: Expr) -> Optional[str]:
        if isinstance(target, Name):
            return target.name
        if isinstance(target, Field):
            base = self._chain_name(target.obj)
            return f"{base}.{target.name}" if base else None
        return None

    def assign_target(self, target: Expr) -> None:
        if isinstance(target, Name):
            sym = self._resolve(target)
            target.symbol = sym
            if sym is None:
                self.analysis.globals_written.add(target.name)
                target.symbol = None
            else:
                sym.is_assigned = True
            return
        self.expr(target)

    def expr(self, node: Expr) -> None:
        if isinstance(node, Name):
            sym = self._resolve(node)
            node.symbol = sym
            if sym is None:
                self.analysis.globals_read.add(node.name)
            return
        if isinstance(node, (Nil, Bool, Number, Str, Vararg)):
            if isinstance(node, Vararg) and self.current is not None:
                self.current.uses_vararg_in_body = True
            return
        if isinstance(node, Func):
            self.function(node)
            return
        if isinstance(node, Interp):
            for part in node.parts:
                if not isinstance(part, str):
                    self.expr(part)
            return
        if isinstance(node, (Group, Cast)):
            self.expr(node.expr)
            return
        if isinstance(node, (Index, Field)):
            self.expr(node.obj)
            if isinstance(node, Index):
                self.expr(node.key)
            return
        if isinstance(node, Call):
            self.expr(node.fn)
            for a in node.args:
                self.expr(a)
            self.current.call_count += 1
            return
        if isinstance(node, MethodCall):
            self.expr(node.obj)
            for a in node.args:
                self.expr(a)
            self.current.call_count += 1
            return
        if isinstance(node, (Bin, Un)):
            self.expr(node.operand if isinstance(node, Un) else node.left)
            if isinstance(node, Bin):
                self.expr(node.right)
            return
        if isinstance(node, IfExpr):
            self.expr(node.cond)
            self.expr(node.then)
            self.expr(node.otherwise)
            return
        if isinstance(node, Table):
            for item in node.items:
                if item.key_expr is not None:
                    self.expr(item.key_expr)
                self.expr(item.value)
                if item.kind == "field" and item.key_name in METAMETHOD_NAMES:
                    self.current.metamethod = True
            return
        raise TypeError(f"unhandled expression {type(node).__name__}")

    def function(self, node: Func, name: Optional[str] = None, method: bool = False,
                 method_name: Optional[str] = None) -> FuncInfo:
        parent = self.current
        scope = self._open_scope()
        info = FuncInfo(
            node=node, scope=scope, parent=parent, name=name,
            depth=(parent.depth + 1) if parent else 1,
            is_method=method, method_name=method_name,
        )
        scope.func = info
        if parent is not None:
            parent.nested.append(info)
            parent.closure_count += 1
        self.analysis.functions.append(info)
        saved = self.current
        self.current = info
        for p in node.params:
            if p.name is None:
                info.has_vararg = True
                continue
            p.symbol = self._declare(p.name, "param", p.line, p.col)
        self.block(node.body)
        self.current = saved
        self._close_scope()
        return info

    # -- metrics ---------------------------------------------------------
    def _count_facts(self) -> None:
        from .ast_nodes import walk

        for info in self.analysis.functions:
            nodes = 0
            stack = list(info.node.body.body)
            while stack:
                n = stack.pop()
                if isinstance(n, Func):
                    continue  # nested functions are measured separately
                nodes += 1
                if isinstance(n, (While, NumFor, GenFor, Repeat)):
                    info.loop_count += 1
                elif isinstance(n, If):
                    info.branch_count += 1
                from .ast_nodes import walk_shallow

                stack.extend(walk_shallow(n))
            info.node_count = nodes


def analyze(root: Block) -> Analysis:
    return ScopeAnalyzer().analyze(root)

"""Luau source emitter (AST -> text).

Two output styles: readable and minified.  Correctness rules that matter:

* ``Group`` nodes are always re-emitted with parentheses, because ``(f())``
  truncates a multi-return call to a single value.
* Operators are parenthesised from the recorded precedence table, and
  right-associativity of ``..`` and ``^`` is respected.
* String literals are re-emitted with 3-digit decimal escapes for every byte
  outside printable ASCII.  Three digits are mandatory, not cosmetic:
  ``"\\0" .. "5"`` would otherwise lex as the single escape ``\\05``.
* A ``;`` is inserted between two statements when the next one starts with
  ``(``, ``{``, a string or a backtick and the previous one ends with something
  a call suffix could attach to -- Luau rejects that as an ambiguous call.
"""

from __future__ import annotations

from typing import List, Optional

from ..ast_nodes import (
    Assign, Bin, Block, Bool, Break, Call, Cast, Compound, Continue, Declare, Do,
    Expr, ExprStat, Field, Func, FuncStat, GenFor, Group, If, IfExpr, Index,
    Interp, Local, LocalFunc, LocalName, MethodCall, Name, Nil, NumFor, Number,
    Param, Repeat, Return, Str, Table, TableItem, TypeAlias, Un, Vararg, While,
    walk,
)
from ..parser import BINARY_PRIORITY, UNARY_PRIORITY

_WORDISH = lambda c: c.isalnum() or c == "_" or ord(c) > 127

# boundaries where naive concatenation would lex as a different token
_MERGE_PAIRS = {
    "--", "..", "::", "==", "~=", "<=", ">=", "//", "->", "+=", "-=", "*=",
    "/=", "%=", "^=", "..=", "<<", ">>", "//=",
}

_CALL_TAIL = set(")}]'\"`") | set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
_CALL_HEAD = set("({'\"`")


class Writer:
    def __init__(self, minify: bool = False):
        self.parts: List[str] = []
        self.minify = minify
        self.indent = 0
        self._last = ""
        self._last_kind = ""

    def tok(self, text: str, kind: str = "") -> None:
        if text == "":
            return
        if self.parts and (
            self._needs_space(self._last, text[0])
            # `10` followed by `..` would lex as `10.` + `.`, so separate them.
            or (self._last_kind == "num" and text[0] == ".")
        ):
            self.parts.append(" ")
        self.parts.append(text)
        self._last = text[-1]
        self._last_kind = kind

    def raw(self, text: str, kind: str = "") -> None:
        self.parts.append(text)
        self._last = text[-1] if text else self._last
        self._last_kind = kind or self._last_kind

    @staticmethod
    def _needs_space(a: str, b: str) -> bool:
        if _WORDISH(a) and _WORDISH(b):
            return True
        if a + b in _MERGE_PAIRS:
            return True
        if a == "-" and b == "-":
            return True
        if a == "[" and b == "[":
            return True
        if a == "." and b == ".":
            return True
        return False

    def newline(self) -> None:
        if self.minify:
            # Emit nothing, but do NOT touch _last: the token-merge check still
            # has to see the real previous character (`1` + `return` -> `1return`).
            return
        self.parts.append("\n" + "  " * self.indent)
        self._last = "\n"

    def sep(self) -> None:
        if self.minify:
            self._last = " "
            return
        self.parts.append(" ")
        self._last = " "

    def value(self) -> str:
        return "".join(self.parts)


def _lit_str(raw: bytes) -> str:
    out = ['"']
    for b in raw:
        if b == 34:
            out.append('\\"')
        elif b == 92:
            out.append("\\\\")
        elif 32 <= b < 127:
            out.append(chr(b))
        else:
            out.append("\\%03d" % b)
    out.append('"')
    return "".join(out)


def _lit_number(node: Number) -> str:
    if node.is_float:
        v = float(node.value)
        # Luau has no inf/nan literal.  These expressions are exactly equal in
        # Luau's float semantics (IEEE-754 division), so they round-trip.
        if v != v:
            return "(0/0)"
        if v == float("inf"):
            return "(1/0)"
        if v == float("-inf"):
            return "(-1/0)"
        return repr(v)
    return str(int(node.value))


class Printer:
    def __init__(self, minify: bool = False, keep_types: bool = False):
        self.w = Writer(minify)
        self.minify = minify
        self.keep_types = keep_types

    # -- entry ----------------------------------------------------------
    def emit(self, block: Block) -> str:
        self.block(block, top=True)
        text = self.w.value()
        if self.minify:
            return text.strip() + "\n"
        return text.strip("\n") + "\n"

    # -- helpers --------------------------------------------------------
    def _prec(self, node: Expr) -> int:
        if isinstance(node, Bin):
            return BINARY_PRIORITY[node.op][0]
        if isinstance(node, Un):
            return UNARY_PRIORITY
        if isinstance(node, Cast):
            return UNARY_PRIORITY + 1
        return 100

    def expr(self, node: Expr, limit: int = 0) -> None:
        """Emit ``node``, wrapping it in parentheses when needed at ``limit``."""
        if self._prec(node) < limit:
            self.w.tok("(")
            self._expr_raw(node)
            self.w.tok(")")
        else:
            self._expr_raw(node)

    def _expr_raw(self, node: Expr) -> None:
        w = self.w
        if isinstance(node, Nil):
            w.tok("nil")
        elif isinstance(node, Bool):
            w.tok("true" if node.value else "false")
        elif isinstance(node, Number):
            w.tok(_lit_number(node), "num")
        elif isinstance(node, Str):
            w.tok(_lit_str(node.raw))
        elif isinstance(node, Interp):
            w.tok("`")
            for part in node.parts:
                if isinstance(part, str):
                    w.raw(part)
                else:
                    w.raw("{")
                    self.expr(part)
                    w.raw("}")
            w.raw("`")
        elif isinstance(node, Vararg):
            w.tok("...")
        elif isinstance(node, Name):
            w.tok(node.name)
        elif isinstance(node, Group):
            w.tok("(")
            self.expr(node.expr)
            w.tok(")")
        elif isinstance(node, Cast):
            self.expr(node.expr, 100)
            w.tok("::")
            w.tok(node.type_text.strip())
        elif isinstance(node, Index):
            self.expr(node.obj, 100)
            w.tok("[")
            self.expr(node.key)
            w.tok("]")
        elif isinstance(node, Field):
            self.expr(node.obj, 100)
            w.tok(".")
            w.tok(node.name)
        elif isinstance(node, MethodCall):
            self.expr(node.obj, 100)
            w.tok(":")
            w.tok(node.method)
            self.args(node.args)
        elif isinstance(node, Call):
            self.expr(node.fn, 100)
            self.args(node.args)
        elif isinstance(node, Bin):
            lp, rp = BINARY_PRIORITY[node.op]
            self.expr(node.left, lp + 1)
            w.tok(node.op)
            self.expr(node.right, rp + 1)
        elif isinstance(node, Un):
            w.tok(node.op)
            self.expr(node.operand, UNARY_PRIORITY)
        elif isinstance(node, IfExpr):
            w.tok("if")
            self.expr(node.cond)
            w.tok("then")
            self.expr(node.then)
            self._emit_ifexpr_else(node.otherwise)
        elif isinstance(node, Table):
            self.table(node)
        elif isinstance(node, Func):
            self.func(node)
        else:  # pragma: no cover - defensive
            raise TypeError(f"cannot emit expression {type(node).__name__}")

    def _emit_ifexpr_else(self, node: Expr) -> None:
        # `if c then a elseif d then b else e` is stored desugared, so the else
        # branch is simply another if-expression: `else if d then b else e`.
        self.w.tok("else")
        self.expr(node)

    def args(self, args: List[Expr]) -> None:
        w = self.w
        w.tok("(")
        for i, a in enumerate(args):
            if i:
                w.tok(",")
            self.expr(a)
        w.tok(")")

    def table(self, node: Table) -> None:
        w = self.w
        w.tok("{")
        for i, item in enumerate(node.items):
            if i:
                w.tok(",")
            if item.kind == "array":
                self.expr(item.value)
            elif item.kind == "field":
                w.tok(item.key_name or "")
                w.tok("=")
                self.expr(item.value)
            else:
                w.tok("[")
                self.expr(item.key_expr)
                w.tok("]")
                w.tok("=")
                self.expr(item.value)
        w.tok("}")

    def func(self, node: Func) -> None:
        w = self.w
        w.tok("function")
        self.params(node.params)
        if self.keep_types and node.returns:
            w.tok(":")
            w.tok(node.returns.strip())
        self.block(node.body)
        w.tok("end")

    def params(self, params: List[Param]) -> None:
        w = self.w
        w.tok("(")
        for i, p in enumerate(params):
            if i:
                w.tok(",")
            if p.name is None:
                w.tok("...")
            else:
                w.tok(p.name)
            if self.keep_types and p.type_text:
                w.tok(":")
                w.tok(p.type_text.strip())
        w.tok(")")

    def local_name(self, ln: LocalName) -> None:
        self.w.tok(ln.name)
        if self.keep_types and ln.type_text:
            self.w.tok(":")
            self.w.tok(ln.type_text.strip())

    # -- blocks and statements ------------------------------------------
    def block(self, node: Block, top: bool = False) -> None:
        w = self.w
        if not top:
            w.indent += 1
        prev: Optional[str] = None
        for stmt in node.body:
            start = len(w.parts)
            self.stmt(stmt)
            text = "".join(w.parts[start:])
            if prev is not None and prev[-1:] in _CALL_TAIL and text[:1] in _CALL_HEAD:
                # Luau would read this as an ambiguous call.
                w.parts.insert(start, ";")
            prev = text
        if not top:
            w.indent -= 1

    def stmt(self, node) -> None:
        w = self.w
        if isinstance(node, Local):
            w.tok("local")
            for i, ln in enumerate(node.names):
                if i:
                    w.tok(",")
                self.local_name(ln)
                attr = node.attrs[i] if i < len(node.attrs) else None
                if attr:
                    w.tok("<")
                    w.tok(attr)
                    w.tok(">")
            if node.values:
                w.tok("=")
                self.expr_list(node.values)
        elif isinstance(node, LocalFunc):
            w.tok("local")
            w.tok("function")
            w.tok(node.name.name)
            self.params(node.fn.params)
            if self.keep_types and node.fn.returns:
                w.tok(":")
                w.tok(node.fn.returns.strip())
            self.block(node.fn.body)
            w.tok("end")
        elif isinstance(node, Assign):
            for i, t in enumerate(node.targets):
                if i:
                    w.tok(",")
                self.expr(t, 100)
            w.tok("=")
            self.expr_list(node.values)
        elif isinstance(node, Compound):
            self.expr(node.target, 100)
            w.tok(node.op)
            self.expr(node.value)
        elif isinstance(node, FuncStat):
            w.tok("function")
            self.expr(node.target, 100)
            self.params(node.fn.params)
            if self.keep_types and node.fn.returns:
                w.tok(":")
                w.tok(node.fn.returns.strip())
            self.block(node.fn.body)
            w.tok("end")
        elif isinstance(node, ExprStat):
            self.expr(node.expr, 100)
        elif isinstance(node, If):
            for i, (cond, body) in enumerate(node.arms):
                w.tok("if" if i == 0 else "elseif")
                self.expr(cond)
                w.tok("then")
                self.block(body)
            if node.otherwise is not None:
                w.tok("else")
                self.block(node.otherwise)
            w.tok("end")
        elif isinstance(node, While):
            w.tok("while")
            self.expr(node.cond)
            w.tok("do")
            self.block(node.body)
            w.tok("end")
        elif isinstance(node, Repeat):
            w.tok("repeat")
            self.block(node.body)
            w.tok("until")
            self.expr(node.cond)
        elif isinstance(node, NumFor):
            w.tok("for")
            self.local_name(node.var)
            w.tok("=")
            self.expr(node.start)
            w.tok(",")
            self.expr(node.stop)
            if node.step is not None:
                w.tok(",")
                self.expr(node.step)
            w.tok("do")
            self.block(node.body)
            w.tok("end")
        elif isinstance(node, GenFor):
            w.tok("for")
            for i, v in enumerate(node.vars):
                if i:
                    w.tok(",")
                self.local_name(v)
            w.tok("in")
            self.expr_list(node.iters)
            w.tok("do")
            self.block(node.body)
            w.tok("end")
        elif isinstance(node, Do):
            w.tok("do")
            self.block(node.body)
            w.tok("end")
        elif isinstance(node, Break):
            w.tok("break")
        elif isinstance(node, Continue):
            w.tok("continue")
        elif isinstance(node, Return):
            w.tok("return")
            if node.values:
                self.expr_list(node.values)
        elif isinstance(node, TypeAlias):
            if node.exported:
                w.tok("export")
            w.tok("type")
            w.tok(node.name)
            if node.generics:
                w.raw(node.generics)
            w.tok("=")
            w.raw(node.type_text.strip())
        elif isinstance(node, Declare):
            w.raw(node.text.strip())
        else:  # pragma: no cover - defensive
            raise TypeError(f"cannot emit statement {type(node).__name__}")
        w.newline()

    def expr_list(self, values: List[Expr]) -> None:
        for i, v in enumerate(values):
            if i:
                self.w.tok(",")
            self.expr(v)


def emit(block: Block, minify: bool = False, keep_types: bool = False) -> str:
    return Printer(minify=minify, keep_types=keep_types).emit(block)


def count_nodes(block: Block) -> int:
    return sum(1 for _ in walk(block))

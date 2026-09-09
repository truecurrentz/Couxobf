"""Recursive-descent parser for Luau, producing the AST in :mod:`couxobf.ast_nodes`.

The grammar follows Luau's own parser (``Ast/src/Parser.cpp``) on the points
that are observable:

* binary operator precedence is taken verbatim from Luau's
  ``binaryPriority`` table -- ``or`` 1, ``and`` 2, comparisons 3, ``..`` {5,4}
  right-assoc, ``+ -`` 6, ``* / // %`` 7, unary 8, ``^`` {10,9} right-assoc;
* Luau has **no** bitwise binary operators (they are ``bit32`` functions), so
  ``&``/``|`` only ever appear inside type annotations;
* the type assertion ``expr :: Type`` is parsed as ``simpleexp ['::' Type]``,
  i.e. it binds tighter than every binary operator;
* prefix expressions support ``.name``, ``[expr]``, ``:method(args)`` and
  ``args`` suffixes, where ``args`` may be ``( ... )``, a table constructor or
  a string literal;
* Luau has no ``goto``; it does have ``continue``.

Type annotations are consumed by a dedicated mini-parser
(:meth:`Parser.parse_type_text`) purely to locate their extent; the original
source text is stored verbatim.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from .ast_nodes import (
    Assign, Bin, Block, Bool, Break, Call, Cast, Compound, Continue, Declare, Do,
    Expr, ExprStat, Field, Func, FuncStat, GenFor, Group, If, IfExpr, Index,
    Interp, Local, LocalFunc, LocalName, MethodCall, Name, Nil, NumFor, Number,
    Param, Repeat, Return, Str, Table, TableItem, TypeAlias, Un, Vararg, While,
)
from .lexer import KEYWORDS, Token, tokenize

BINARY_PRIORITY = {
    "or": (1, 1),
    "and": (2, 2),
    "<": (3, 3),
    ">": (3, 3),
    "<=": (3, 3),
    ">=": (3, 3),
    "~=": (3, 3),
    "==": (3, 3),
    "..": (5, 4),
    "+": (6, 6),
    "-": (6, 6),
    "*": (7, 7),
    "/": (7, 7),
    "//": (7, 7),
    "%": (7, 7),
    "^": (10, 9),
}
UNARY_PRIORITY = 8

COMPOUND_OPS = frozenset({"+=", "-=", "*=", "/=", "//=", "%=", "^=", "..="})

BLOCK_TERMINATORS = frozenset({"end", "else", "elseif", "until"})


class ParseError(Exception):
    def __init__(self, message: str, token: Token):
        super().__init__(f"{token.line}:{token.col}: {message}")
        self.line = token.line
        self.col = token.col


def _tok_end(tok: Token) -> int:
    return tok.offset + len(tok.text or "")


class Parser:
    def __init__(self, tokens: List[Token], source: str, name: str = "<input>"):
        self.tokens = tokens
        self.src = source
        self.name = name
        self.pos = 0

    # ------------------------------------------------------------------
    # token helpers
    # ------------------------------------------------------------------
    def peek(self, k: int = 0) -> Token:
        i = self.pos + k
        if i >= len(self.tokens):
            return self.tokens[-1]
        return self.tokens[i]

    def advance(self) -> Token:
        tok = self.peek()
        if tok.kind != "EOF":
            self.pos += 1
        return tok

    def at_op(self, *ops: str) -> bool:
        tok = self.peek()
        return tok.kind == "OP" and tok.value in ops

    def at_kw(self, *kws: str) -> bool:
        tok = self.peek()
        return tok.kind == "KEYWORD" and tok.value in kws

    def at_name(self, value: Optional[str] = None) -> bool:
        tok = self.peek()
        return tok.kind == "NAME" and (value is None or tok.value == value)

    def expect_op(self, op: str) -> Token:
        if not self.at_op(op):
            raise ParseError(f"expected '{op}'", self.peek())
        return self.advance()

    def expect_kw(self, kw: str) -> Token:
        if not self.at_kw(kw):
            raise ParseError(f"expected '{kw}'", self.peek())
        return self.advance()

    def expect_name(self, what: str = "name") -> Token:
        if self.peek().kind != "NAME":
            raise ParseError(f"expected {what}", self.peek())
        return self.advance()

    def _slice(self, start_tok: Token) -> str:
        prev = self.tokens[self.pos - 1] if self.pos > 0 else start_tok
        return self.src[start_tok.offset : _tok_end(prev)]

    # ------------------------------------------------------------------
    # entry point
    # ------------------------------------------------------------------
    def parse(self) -> Block:
        block = self.parse_block(top_level=True)
        if self.peek().kind != "EOF":
            raise ParseError(f"unexpected token '{self.peek().value}'", self.peek())
        return block

    def parse_block(self, top_level: bool = False) -> Block:
        start = self.peek()
        body = []
        while True:
            tok = self.peek()
            if tok.kind == "EOF":
                if not top_level:
                    raise ParseError("unexpected end of input inside block", tok)
                break
            if tok.kind == "KEYWORD" and tok.value in BLOCK_TERMINATORS:
                break
            stmt = self.parse_stat()
            if stmt is not None:
                body.append(stmt)
                if isinstance(stmt, Return):
                    # `return` must be the last statement of a block; a trailing
                    # `;` is allowed.
                    while self.at_op(";"):
                        self.advance()
                    break
        return Block(line=start.line, col=start.col, body=body)

    # ------------------------------------------------------------------
    # statements
    # ------------------------------------------------------------------
    def parse_stat(self) -> Optional[object]:
        tok = self.peek()
        if self.at_op(";"):
            self.advance()
            return None
        if tok.kind == "KEYWORD":
            kw = tok.value
            if kw == "if":
                return self.parse_if()
            if kw == "while":
                return self.parse_while()
            if kw == "do":
                self.advance()
                body = self.parse_block()
                self.expect_kw("end")
                return Do(line=tok.line, col=tok.col, body=body)
            if kw == "for":
                return self.parse_for()
            if kw == "repeat":
                self.advance()
                body = self.parse_block()
                self.expect_kw("until")
                cond = self.parse_expr()
                return Repeat(line=tok.line, col=tok.col, body=body, cond=cond)
            if kw == "function":
                return self.parse_function_stat()
            if kw == "local":
                return self.parse_local()
            if kw == "return":
                self.advance()
                values: List[Expr] = []
                if not (
                    self.peek().kind == "EOF"
                    or (self.peek().kind == "KEYWORD" and self.peek().value in BLOCK_TERMINATORS)
                    or self.at_op(";")
                ):
                    values = self.parse_expr_list()
                return Return(line=tok.line, col=tok.col, values=values)
            if kw == "break":
                self.advance()
                return Break(line=tok.line, col=tok.col)
            if kw == "continue":
                self.advance()
                return Continue(line=tok.line, col=tok.col)
        if self.at_name("type") and self._is_type_alias():
            return self.parse_type_alias(exported=False)
        if self.at_name("export") and self.peek(1).kind == "NAME" and self.peek(1).value == "type":
            self.advance()
            return self.parse_type_alias(exported=True)
        if self.at_name("declare"):
            return self.parse_declare()
        return self.parse_expr_stat()

    def _is_type_alias(self) -> bool:
        # `type X = ...` or `type X<T> = ...`
        return (
            self.peek(1).kind == "NAME"
            and (self.peek(2).kind == "OP" and self.peek(2).value in ("=", "<"))
        )

    def parse_type_alias(self, exported: bool) -> TypeAlias:
        tok = self.advance()  # `type`
        name = self.expect_name("type name").value
        generics = None
        if self.at_op("<"):
            generics = self._capture_balanced("<", ">")
        self.expect_op("=")
        start = self.peek()
        self.parse_type_text()
        return TypeAlias(
            line=tok.line, col=tok.col, exported=exported, name=name,
            generics=generics, type_text=self._slice(start),
        )

    def parse_declare(self) -> Declare:
        tok = self.advance()
        start = tok.offset
        if self.at_name("function"):
            self.advance()
            self.expect_name("function name")
            if self.at_op("<"):
                self._capture_balanced("<", ">")
            self._parse_param_list()
            if self.at_op(":"):
                self.advance()
                self.parse_type_text()
        else:
            self.expect_name("declaration name")
            self.expect_op(":")
            self.parse_type_text()
        return Declare(line=tok.line, col=tok.col, text=self.src[start : _tok_end(self.tokens[self.pos - 1])])

    def parse_if(self) -> If:
        tok = self.expect_kw("if")
        arms: List[Tuple[Expr, Block]] = []
        cond = self.parse_expr()
        self.expect_kw("then")
        arms.append((cond, self.parse_block()))
        while self.at_kw("elseif"):
            self.advance()
            c = self.parse_expr()
            self.expect_kw("then")
            arms.append((c, self.parse_block()))
        otherwise = None
        if self.at_kw("else"):
            self.advance()
            otherwise = self.parse_block()
        self.expect_kw("end")
        return If(line=tok.line, col=tok.col, arms=arms, otherwise=otherwise)

    def parse_while(self) -> While:
        tok = self.expect_kw("while")
        cond = self.parse_expr()
        self.expect_kw("do")
        body = self.parse_block()
        self.expect_kw("end")
        return While(line=tok.line, col=tok.col, cond=cond, body=body)

    def parse_for(self) -> object:
        tok = self.expect_kw("for")
        names = [LocalName(name=self.expect_name().value, line=tok.line, col=tok.col)]
        while self.at_op(","):
            self.advance()
            names.append(LocalName(name=self.expect_name().value, line=tok.line, col=tok.col))
        if self.at_op("="):
            if len(names) != 1:
                raise ParseError("numeric for needs exactly one control variable", self.peek())
            self.advance()
            start = self.parse_expr()
            self.expect_op(",")
            stop = self.parse_expr()
            step = None
            if self.at_op(","):
                self.advance()
                step = self.parse_expr()
            self.expect_kw("do")
            body = self.parse_block()
            self.expect_kw("end")
            return NumFor(
                line=tok.line, col=tok.col, var=names[0], start=start, stop=stop,
                step=step, body=body,
            )
        if not self.at_kw("in"):
            raise ParseError("expected '=' or 'in' in for statement", self.peek())
        self.advance()
        iters = self.parse_expr_list()
        self.expect_kw("do")
        body = self.parse_block()
        self.expect_kw("end")
        return GenFor(line=tok.line, col=tok.col, vars=names, iters=iters, body=body)

    def parse_function_stat(self) -> FuncStat:
        tok = self.expect_kw("function")
        base = Name(line=tok.line, col=tok.col, name=self.expect_name("function name").value)
        target: Expr = base
        while self.at_op("."):
            self.advance()
            nm = self.expect_name("field name")
            target = Field(line=nm.line, col=nm.col, obj=target, name=nm.value)
        is_method = False
        method_name = None
        if self.at_op(":"):
            self.advance()
            nm = self.expect_name("method name")
            is_method = True
            method_name = nm.value
            target = Field(line=nm.line, col=nm.col, obj=target, name=nm.value)
        fn = self.parse_function_body(method=is_method)
        return FuncStat(
            line=tok.line, col=tok.col, target=target, fn=fn,
            is_method=is_method, method_name=method_name,
        )

    def parse_local(self) -> object:
        tok = self.expect_kw("local")
        if self.at_kw("function"):
            self.advance()
            nm = self.expect_name("function name")
            fn = self.parse_function_body(method=False)
            return LocalFunc(
                line=tok.line, col=tok.col,
                name=LocalName(name=nm.value, line=nm.line, col=nm.col), fn=fn,
            )
        names: List[LocalName] = []
        attrs: List[Optional[str]] = []
        first = self.expect_name("variable name")
        names.append(LocalName(name=first.value, line=first.line, col=first.col))
        self._parse_name_decor(names, attrs)
        while self.at_op(","):
            self.advance()
            nm = self.expect_name("variable name")
            names.append(LocalName(name=nm.value, line=nm.line, col=nm.col))
            self._parse_name_decor(names, attrs)
        values: List[Expr] = []
        if self.at_op("="):
            self.advance()
            values = self.parse_expr_list()
        return Local(line=tok.line, col=tok.col, names=names, values=values, attrs=attrs)

    def _parse_name_decor(self, names, attrs) -> None:
        """Consume the optional attribute and annotation for the *last* name.

        Both orderings occur in practice (``local x <const>: T`` and
        ``local x: T <const>``), so accept either.
        """
        attrs.append(None)
        for _ in range(2):
            if attrs[-1] is None and self.at_op("<"):
                attrs[-1] = self._parse_attr()
                continue
            if names[-1].type_text is None and self.at_op(":"):
                self.advance()
                names[-1].type_text = self.parse_type_text()
                continue
            break

    def _parse_attr(self) -> Optional[str]:
        if self.at_op("<"):
            self.advance()
            nm = self.expect_name("attribute")
            self.expect_op(">")
            return nm.value
        return None

    def parse_expr_stat(self) -> object:
        tok = self.peek()
        expr = self.parse_suffixed_expr()
        if self.at_op(",") or self.at_op("="):
            targets = [expr]
            while self.at_op(","):
                self.advance()
                targets.append(self.parse_suffixed_expr())
            self.expect_op("=")
            values = self.parse_expr_list()
            return Assign(line=tok.line, col=tok.col, targets=targets, values=values)
        if self.peek().kind == "OP" and self.peek().value in COMPOUND_OPS:
            op = self.advance().value
            value = self.parse_expr()
            return Compound(line=tok.line, col=tok.col, target=expr, op=op, value=value)
        if not isinstance(expr, (Call, MethodCall)):
            raise ParseError("syntax error: expression statement is not a call", tok)
        return ExprStat(line=tok.line, col=tok.col, expr=expr)

    # ------------------------------------------------------------------
    # expressions
    # ------------------------------------------------------------------
    def parse_expr(self, limit: int = 0) -> Expr:
        tok = self.peek()
        if tok.kind == "OP" and tok.value in ("-", "#", "not_op") or (
            tok.kind == "KEYWORD" and tok.value == "not"
        ):
            op = self.advance().value
            operand = self.parse_expr(UNARY_PRIORITY)
            left: Expr = Un(line=tok.line, col=tok.col, op=op, operand=operand)
        else:
            left = self.parse_assertion_expr()
        while True:
            cur = self.peek()
            op = None
            if cur.kind == "OP" and cur.value in BINARY_PRIORITY:
                op = cur.value
            elif cur.kind == "KEYWORD" and cur.value in ("and", "or"):
                op = cur.value
            if op is None:
                break
            lp, rp = BINARY_PRIORITY[op]
            if lp <= limit:
                break
            self.advance()
            right = self.parse_expr(rp)
            left = Bin(line=cur.line, col=cur.col, op=op, left=left, right=right)
        return left

    def parse_assertion_expr(self) -> Expr:
        expr = self.parse_simple_expr()
        if self.at_op("::"):
            tok = self.advance()
            text = self.parse_type_text()
            expr = Cast(line=tok.line, col=tok.col, expr=expr, type_text=text)
        return expr

    def parse_expr_list(self) -> List[Expr]:
        values = [self.parse_expr()]
        while self.at_op(","):
            self.advance()
            values.append(self.parse_expr())
        return values

    def parse_simple_expr(self) -> Expr:
        tok = self.peek()
        if tok.kind == "NUMBER":
            self.advance()
            return Number(
                line=tok.line, col=tok.col, value=tok.value,
                is_float=tok.is_float, text=tok.text,
            )
        if tok.kind == "STRING":
            self.advance()
            return Str(line=tok.line, col=tok.col, raw=tok.value)
        if tok.kind == "INTERP":
            self.advance()
            parts: List[object] = []
            for part in tok.value:
                if isinstance(part, str):
                    parts.append(part)
                else:
                    sub = Parser(tokenize(part[1], self.name), part[1], self.name).parse_expr()
                    parts.append(sub)
            return Interp(line=tok.line, col=tok.col, parts=parts)
        if tok.kind == "KEYWORD":
            if tok.value == "nil":
                self.advance()
                return Nil(line=tok.line, col=tok.col)
            if tok.value == "true":
                self.advance()
                return Bool(line=tok.line, col=tok.col, value=True)
            if tok.value == "false":
                self.advance()
                return Bool(line=tok.line, col=tok.col, value=False)
            if tok.value == "function":
                self.advance()
                return self.parse_function_body(method=False)
            if tok.value == "if":
                return self.parse_if_expr()
        if self.at_op("..."):
            self.advance()
            return Vararg(line=tok.line, col=tok.col)
        if self.at_op("{"):
            return self.parse_table()
        # Luau's `simpleexp` falls through to `prefixexp`, which includes the
        # whole suffix chain (`.name`, `[e]`, `:m(args)`, `args`).
        return self.parse_suffixed_expr()

    def parse_if_expr(self) -> Expr:
        """``if c then a [elseif d then b]* else e`` as an expression.

        Stored as a right-nested chain, which is exactly the desugaring Luau
        uses; folding right (not left) is what keeps every middle branch.
        """
        tok = self.expect_kw("if")
        arms = []
        cond = self.parse_expr()
        self.expect_kw("then")
        arms.append((cond, self.parse_expr()))
        while self.at_kw("elseif"):
            self.advance()
            c = self.parse_expr()
            self.expect_kw("then")
            arms.append((c, self.parse_expr()))
        if not self.at_kw("else"):
            raise ParseError("expected 'else' in if expression", self.peek())
        self.advance()
        node = self.parse_if_expr() if self.at_kw("if") else self.parse_expr()
        for c, t in reversed(arms):
            node = IfExpr(line=tok.line, col=tok.col, cond=c, then=t, otherwise=node)
        return node

    def parse_primary_prefix(self) -> Expr:
        """``prefixexp -> NAME | '(' expr ')'`` -- the chain *seed* only."""
        tok = self.peek()
        if self.at_op("("):
            self.advance()
            inner = self.parse_expr()
            end = self.expect_op(")")
            return Group(line=tok.line, col=tok.col, expr=inner)
        if tok.kind == "NAME":
            self.advance()
            return Name(line=tok.line, col=tok.col, name=tok.value)
        raise ParseError(f"unexpected symbol '{tok.value}'", tok)

    def parse_suffixed_expr(self) -> Expr:
        expr = self.parse_primary_prefix()
        while True:
            tok = self.peek()
            if self.at_op("."):
                self.advance()
                nm = self.expect_name("field name")
                expr = Field(line=nline(tok), col=tok.col, obj=expr, name=nm.value)
            elif self.at_op("["):
                self.advance()
                key = self.parse_expr()
                self.expect_op("]")
                expr = Index(line=tok.line, col=tok.col, obj=expr, key=key)
            elif self.at_op(":"):
                self.advance()
                nm = self.expect_name("method name")
                args = self.parse_call_args()
                expr = MethodCall(line=tok.line, col=tok.col, obj=expr, method=nm.value, args=args)
            elif self.at_op("("):
                args = self.parse_call_args()
                expr = Call(line=tok.line, col=tok.col, fn=expr, args=args)
            elif self.at_op("{"):
                table = self.parse_table()
                expr = Call(line=tok.line, col=tok.col, fn=expr, args=[table])
            elif tok.kind == "STRING":
                self.advance()
                expr = Call(
                    line=tok.line, col=tok.col, fn=expr,
                    args=[Str(line=tok.line, col=tok.col, raw=tok.value)],
                )
            elif tok.kind == "INTERP":
                self.advance()
                parts = []
                for part in tok.value:
                    if isinstance(part, str):
                        parts.append(part)
                    else:
                        parts.append(Parser(tokenize(part[1], self.name), part[1], self.name).parse_expr())
                expr = Call(
                    line=tok.line, col=tok.col, fn=expr,
                    args=[Interp(line=tok.line, col=tok.col, parts=parts)],
                )
            else:
                break
        return expr

    def parse_call_args(self) -> List[Expr]:
        self.expect_op("(")
        args: List[Expr] = []
        if not self.at_op(")"):
            args = self.parse_expr_list()
        self.expect_op(")")
        return args

    def parse_table(self) -> Table:
        tok = self.expect_op("{")
        items: List[TableItem] = []
        while not self.at_op("}"):
            item = self.parse_table_item()
            items.append(item)
            if self.at_op(",") or self.at_op(";"):
                item.sep = self.advance().value
            else:
                if not self.at_op("}"):
                    raise ParseError("expected ',' or '}' in table constructor", self.peek())
                break
        self.expect_op("}")
        return Table(line=tok.line, col=tok.col, items=items)

    def parse_table_item(self) -> TableItem:
        tok = self.peek()
        if self.at_op("["):
            self.advance()
            key = self.parse_expr()
            self.expect_op("]")
            self.expect_op("=")
            value = self.parse_expr()
            return TableItem(kind="key", value=value, key_expr=key, line=tok.line, col=tok.col)
        if tok.kind == "NAME" and self.peek(1).kind == "OP" and self.peek(1).value == "=":
            self.advance()
            self.advance()
            value = self.parse_expr()
            return TableItem(kind="field", value=value, key_name=tok.value, line=tok.line, col=tok.col)
        value = self.parse_expr()
        return TableItem(kind="array", value=value, line=tok.line, col=tok.col)

    # ------------------------------------------------------------------
    # functions
    # ------------------------------------------------------------------
    def parse_function_body(self, method: bool) -> Func:
        tok = self.peek()
        generics = None
        if self.at_op("<"):
            generics = self._capture_balanced("<", ">")
        params = self._parse_param_list(method=method)
        returns = None
        if self.at_op(":"):
            self.advance()
            returns = self.parse_type_text(allow_pack=True)
        body = self.parse_block()
        self.expect_kw("end")
        return Func(line=tok.line, col=tok.col, params=params, body=body, generics=generics, returns=returns)

    def _parse_param_list(self, method: bool = False) -> List[Param]:
        self.expect_op("(")
        params: List[Param] = []
        if method:
            params.append(Param(name="self", line=self.peek().line, col=self.peek().col))
        if not self.at_op(")"):
            while True:
                tok = self.peek()
                if self.at_op("..."):
                    self.advance()
                    p = Param(name=None, line=tok.line, col=tok.col)
                    if self.at_op(":"):
                        self.advance()
                        p.type_text = self.parse_type_text()
                    params.append(p)
                    break
                nm = self.expect_name("parameter name")
                p = Param(name=nm.value, line=nm.line, col=nm.col)
                if self.at_op(":"):
                    self.advance()
                    p.type_text = self.parse_type_text()
                params.append(p)
                if self.at_op(","):
                    self.advance()
                    continue
                break
        self.expect_op(")")
        return params

    # ------------------------------------------------------------------
    # type annotations (verbatim capture)
    # ------------------------------------------------------------------
    def _capture_balanced(self, open_op: str, close_op: str) -> str:
        start = self.peek()
        self.expect_op(open_op)
        depth = 1
        while depth > 0:
            tok = self.peek()
            if tok.kind == "EOF":
                raise ParseError("unbalanced type parameter list", start)
            if tok.kind == "OP" and tok.value == open_op:
                depth += 1
            elif tok.kind == "OP" and tok.value == close_op:
                depth -= 1
            self.advance()
        return self._slice(start)

    def parse_type_text(self, allow_pack: bool = False) -> str:
        start = self.peek()
        self._parse_type(allow_pack=allow_pack)
        return self._slice(start)

    def _parse_type(self, allow_pack: bool = False) -> None:
        if allow_pack and self.at_op("("):
            self.advance()
            if not self.at_op(")"):
                self._parse_type_list()
            self.expect_op(")")
            if not self.at_op("->"):
                return  # bare type pack, e.g. `): (string, buffer)`
        self._parse_type_intersection()
        while self.at_op("|"):
            self.advance()
            self._parse_type_intersection()

    def _parse_type_intersection(self) -> None:
        self._parse_type_unary()
        while self.at_op("&"):
            self.advance()
            self._parse_type_unary()

    def _parse_type_unary(self) -> None:
        if self.at_op("?"):
            self.advance()
            self._parse_type_unary()
            return
        self._parse_type_prim()
        if self.at_op("?"):
            self.advance()

    def _parse_type_prim(self) -> None:
        tok = self.peek()
        if tok.kind == "KEYWORD" and tok.value in ("nil", "true", "false"):
            self.advance()
            return
        if tok.kind in ("STRING", "NUMBER"):
            self.advance()
            return
        if self.at_op("..."):
            self.advance()
            self._parse_type_unary()
            return
        if self.at_name("typeof"):
            self.advance()
            self.expect_op("(")
            self.parse_expr()
            self.expect_op(")")
            return
        if self.at_op("("):
            self.advance()
            if not self.at_op(")"):
                self._parse_type_list()
            self.expect_op(")")
            self.expect_op("->")
            if self.at_op("("):
                save = self.pos
                try:
                    self.advance()
                    if not self.at_op(")"):
                        self._parse_type_list()
                    self.expect_op(")")
                except ParseError:
                    self.pos = save
                    self._parse_type()
            else:
                self._parse_type()
            return
        if self.at_op("{"):
            self._parse_table_type()
            return
        if self.at_op("_"):
            self.advance()
            return
        if tok.kind == "NAME":
            self.advance()
            while self.at_op("."):
                self.advance()
                self.expect_name("qualified type name")
            if self.at_op("<"):
                self.advance()
                if not self.at_op(">"):
                    self._parse_type_list()
                self.expect_op(">")
            if self.at_op("..."):
                self.advance()
            return
        raise ParseError(f"unexpected token '{tok.value}' in type annotation", tok)

    def _parse_type_list(self) -> None:
        self._parse_type()
        while self.at_op(","):
            self.advance()
            if self.at_op("..."):
                self.advance()
                break
            self._parse_type()

    def _parse_table_type(self) -> None:
        self.expect_op("{")
        while not self.at_op("}"):
            if self.peek().kind == "EOF":
                raise ParseError("unfinished table type", self.peek())
            if self.at_op("["):
                self.advance()
                self._parse_type()
                self.expect_op("]")
                self.expect_op(":")
                self._parse_type()
            elif self.peek().kind in ("NAME", "STRING") or (
                self.peek().kind == "KEYWORD" and self.peek().value in ("true", "false", "nil")
            ):
                self.advance()
                if self.at_op("?"):
                    self.advance()
                self.expect_op(":")
                self._parse_type()
            else:
                raise ParseError("unexpected token in table type", self.peek())
            if self.at_op(",") or self.at_op(";"):
                self.advance()
            else:
                break
        self.expect_op("}")


def nline(tok: Token) -> int:  # tiny helper to keep call sites short
    return tok.line


def parse(source: str, name: str = "<input>") -> Block:
    """Lex + parse Luau source into an AST block."""
    return Parser(tokenize(source, name), source, name).parse()

"""The AST produced by :mod:`couxobf.parser`.

Design notes:

* Every node keeps its source position for diagnostics.
* Parenthesised expressions are represented by an explicit :class:`Group`
  node.  This is *not* cosmetic: in Luau ``(f())`` truncates a multi-return
  call to one value, so dropping the parens would change semantics.
* Type annotations and ``::`` casts are captured **verbatim** as source text
  rather than parsed into a type AST.  Rationale: Luau types are erased at
  runtime, so the protector's default is to strip them (release builds); when
  a debug build keeps them it re-emits the exact original text, which is
  lossless and cannot be corrupted by a partial type parser.  Annotations that
  mention ``typeof(name)`` are detected so that the renamer will not rename
  those locals out from under them.
* Nodes are plain dataclasses; :func:`walk` provides a uniform child
  enumeration used by every pass.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Tuple, Union

__all__ = [
    "Node", "Expr", "Stmt", "Block", "Param", "TableItem", "LocalName",
    "Nil", "Bool", "Number", "Str", "Interp", "Vararg", "Name", "Func", "Table",
    "Index", "Field", "Call", "MethodCall", "Bin", "Un", "IfExpr", "Cast", "Group",
    "Local", "LocalFunc", "Assign", "Compound", "FuncStat", "ExprStat", "If",
    "While", "Repeat", "NumFor", "GenFor", "Do", "Break", "Continue", "Return",
    "TypeAlias", "Declare", "walk", "walk_shallow",
]


@dataclass
class Node:
    line: int = 0
    col: int = 0


class Expr(Node):
    """Base class for expressions."""


class Stmt(Node):
    """Base class for statements."""


# --------------------------------------------------------------------------
# expressions
# --------------------------------------------------------------------------
@dataclass
class Nil(Expr):
    pass


@dataclass
class Bool(Expr):
    value: bool = False


@dataclass
class Number(Expr):
    value: Union[int, float] = 0
    is_float: bool = False
    text: str = ""


@dataclass
class Str(Expr):
    raw: bytes = b""


@dataclass
class Interp(Expr):
    """Backtick interpolated string.

    ``parts`` alternates between ``str`` literal chunks (source text, escapes
    intact) and :class:`Expr` interpolation values.
    """

    parts: List[Union[str, Expr]] = field(default_factory=list)


@dataclass
class Vararg(Expr):
    pass


@dataclass
class Name(Expr):
    name: str = ""


@dataclass
class Param:
    name: Optional[str]  # None => `...`
    type_text: Optional[str] = None
    line: int = 0
    col: int = 0


@dataclass
class Block(Node):
    body: List[Stmt] = field(default_factory=list)


@dataclass
class Func(Expr):
    params: List[Param] = field(default_factory=list)
    body: Block = field(default_factory=Block)
    generics: Optional[str] = None
    returns: Optional[str] = None


@dataclass
class TableItem(Node):
    kind: str = "array"  # "array" | "field" | "key"
    value: Expr = field(default_factory=Nil)
    key_name: Optional[str] = None
    key_expr: Optional[Expr] = None
    sep: str = ","


@dataclass
class Table(Expr):
    items: List[TableItem] = field(default_factory=list)


@dataclass
class Index(Expr):
    obj: Expr = field(default_factory=Nil)
    key: Expr = field(default_factory=Nil)


@dataclass
class Field(Expr):
    """``obj.name`` -- kept distinct from :class:`Index` because the key is an
    identifier, which matters for table-key protection decisions."""

    obj: Expr = field(default_factory=Nil)
    name: str = ""


@dataclass
class Call(Expr):
    fn: Expr = field(default_factory=Nil)
    args: List[Expr] = field(default_factory=list)


@dataclass
class MethodCall(Expr):
    """``obj:method(args)`` -- Luau compiles this to NAMECALL."""

    obj: Expr = field(default_factory=Nil)
    method: str = ""
    args: List[Expr] = field(default_factory=list)


@dataclass
class Bin(Expr):
    op: str = ""
    left: Expr = field(default_factory=Nil)
    right: Expr = field(default_factory=Nil)


@dataclass
class Un(Expr):
    op: str = ""
    operand: Expr = field(default_factory=Nil)


@dataclass
class IfExpr(Expr):
    """Luau ``if c then a else b`` as an *expression*."""

    cond: Expr = field(default_factory=Nil)
    then: Expr = field(default_factory=Nil)
    otherwise: Expr = field(default_factory=Nil)


@dataclass
class Cast(Expr):
    expr: Expr = field(default_factory=Nil)
    type_text: str = ""


@dataclass
class Group(Expr):
    expr: Expr = field(default_factory=Nil)


# --------------------------------------------------------------------------
# statements
# --------------------------------------------------------------------------
@dataclass
class LocalName:
    name: str
    type_text: Optional[str] = None
    line: int = 0
    col: int = 0


@dataclass
class Local(Stmt):
    names: List[LocalName] = field(default_factory=list)
    values: List[Expr] = field(default_factory=list)
    attrs: List[Optional[str]] = field(default_factory=list)  # Luau `<const>`/`<close>`


@dataclass
class LocalFunc(Stmt):
    name: LocalName = field(default_factory=lambda: LocalName(""))
    fn: Func = field(default_factory=Func)


@dataclass
class Assign(Stmt):
    targets: List[Expr] = field(default_factory=list)
    values: List[Expr] = field(default_factory=list)


@dataclass
class Compound(Stmt):
    target: Expr = field(default_factory=Nil)
    op: str = "+="
    value: Expr = field(default_factory=Nil)


@dataclass
class FuncStat(Stmt):
    """``function a.b.c:d(...)``.  ``target`` is a Name/Field/Index chain."""

    target: Expr = field(default_factory=Nil)
    fn: Func = field(default_factory=Func)
    is_method: bool = False
    method_name: Optional[str] = None


@dataclass
class ExprStat(Stmt):
    expr: Expr = field(default_factory=Nil)


@dataclass
class If(Stmt):
    arms: List[Tuple[Expr, Block]] = field(default_factory=list)
    otherwise: Optional[Block] = None


@dataclass
class While(Stmt):
    cond: Expr = field(default_factory=Nil)
    body: Block = field(default_factory=Block)


@dataclass
class Repeat(Stmt):
    body: Block = field(default_factory=Block)
    cond: Expr = field(default_factory=Nil)


@dataclass
class NumFor(Stmt):
    var: LocalName = field(default_factory=lambda: LocalName(""))
    start: Expr = field(default_factory=Nil)
    stop: Expr = field(default_factory=Nil)
    step: Optional[Expr] = None
    body: Block = field(default_factory=Block)


@dataclass
class GenFor(Stmt):
    vars: List[LocalName] = field(default_factory=list)
    iters: List[Expr] = field(default_factory=list)
    body: Block = field(default_factory=Block)


@dataclass
class Do(Stmt):
    body: Block = field(default_factory=Block)


@dataclass
class Break(Stmt):
    pass


@dataclass
class Continue(Stmt):
    pass


@dataclass
class Return(Stmt):
    values: List[Expr] = field(default_factory=list)


@dataclass
class TypeAlias(Stmt):
    exported: bool = False
    name: str = ""
    generics: Optional[str] = None
    type_text: str = ""


@dataclass
class Declare(Stmt):
    text: str = ""


# --------------------------------------------------------------------------
# traversal
# --------------------------------------------------------------------------
def _node_children(node: Node) -> Iterator[Tuple[str, object]]:
    """Yield ``(field_name, child)`` for every child node of ``node``."""
    if isinstance(node, Block):
        for i, s in enumerate(node.body):
            yield f"body[{i}]", s
        return
    if isinstance(node, Func):
        for i, p in enumerate(node.params):
            yield f"params[{i}]", p
        yield "body", node.body
        return
    if isinstance(node, Param):
        return
    if isinstance(node, Table):
        for i, item in enumerate(node.items):
            yield f"items[{i}]", item
        return
    if isinstance(node, TableItem):
        if node.key_expr is not None:
            yield "key_expr", node.key_expr
        yield "value", node.value
        return
    if isinstance(node, Interp):
        for i, part in enumerate(node.parts):
            if not isinstance(part, str):
                yield f"parts[{i}]", part
        return
    if isinstance(node, Local):
        for i, v in enumerate(node.values):
            yield f"values[{i}]", v
        return
    if isinstance(node, LocalFunc):
        yield "fn", node.fn
        return
    if isinstance(node, (Assign,)):
        for i, t in enumerate(node.targets):
            yield f"targets[{i}]", t
        for i, v in enumerate(node.values):
            yield f"values[{i}]", v
        return
    if isinstance(node, FuncStat):
        yield "target", node.target
        yield "fn", node.fn
        return
    if isinstance(node, If):
        for i, (c, b) in enumerate(node.arms):
            yield f"arms[{i}].cond", c
            yield f"arms[{i}].body", b
        if node.otherwise is not None:
            yield "otherwise", node.otherwise
        return
    if isinstance(node, (While, Do)):
        yield "body", node.body
        if isinstance(node, While):
            yield "cond", node.cond
        return
    if isinstance(node, Repeat):
        yield "body", node.body
        yield "cond", node.cond
        return
    if isinstance(node, NumFor):
        yield "start", node.start
        yield "stop", node.stop
        if node.step is not None:
            yield "step", node.step
        yield "body", node.body
        return
    if isinstance(node, GenFor):
        for i, e in enumerate(node.iters):
            yield f"iters[{i}]", e
        yield "body", node.body
        return
    if isinstance(node, ExprStat):
        yield "expr", node.expr
        return
    if isinstance(node, Compound):
        yield "target", node.target
        yield "value", node.value
        return
    if isinstance(node, Return):
        for i, v in enumerate(node.values):
            yield f"values[{i}]", v
        return
    if isinstance(node, Index):
        yield "obj", node.obj
        yield "key", node.key
        return
    if isinstance(node, Field):
        yield "obj", node.obj
        return
    if isinstance(node, Call):
        yield "fn", node.fn
        for i, a in enumerate(node.args):
            yield f"args[{i}]", a
        return
    if isinstance(node, MethodCall):
        yield "obj", node.obj
        for i, a in enumerate(node.args):
            yield f"args[{i}]", a
        return
    if isinstance(node, Bin):
        yield "left", node.left
        yield "right", node.right
        return
    if isinstance(node, Un):
        yield "operand", node.operand
        return
    if isinstance(node, IfExpr):
        yield "cond", node.cond
        yield "then", node.then
        yield "otherwise", node.otherwise
        return
    if isinstance(node, (Cast, Group)):
        yield "expr", node.expr
        return
    return


def walk_shallow(node: Node) -> Iterator[Node]:
    for _, child in _node_children(node):
        if isinstance(child, Node):
            yield child
        elif isinstance(child, Param):
            yield child


def walk(node: Node) -> Iterator[Node]:
    """Pre-order traversal including the root."""
    yield node
    for child in list(walk_shallow(node)):
        yield from walk(child)


def child_slots(node: Node) -> List[Tuple[str, Node]]:
    """Mutable ``(slot, child)`` pairs, used by tree rewriters."""
    return [(name, child) for name, child in _node_children(node) if isinstance(child, Node)]

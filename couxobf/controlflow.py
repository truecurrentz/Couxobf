"""Small semantic-preserving control-flow rewrites over the parsed AST.

The open-source obfuscators studied for this project commonly invert branches or
wrap blocks before heavier passes.  This module keeps the useful part and drops
the bloat: only branches that already have both sides are rewritten, so no empty
blocks, fake predicates, or dead arms are introduced.  The condition is still
evaluated exactly once and in the same position.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Any, List

from . import ast_nodes as A


@dataclass
class Stats:
    branch_inversions: int = 0


def invert_branches(root: A.Block, rng: Any = None, *, enabled: bool = True) -> Stats:
    """Randomly invert eligible branches in-place and return counts.

    Eligible means an ``if`` statement with one condition and an ``else`` body,
    or an ``if`` expression.  ``elseif`` ladders are intentionally skipped: a
    sound inversion would have to nest the remaining ladder in the new true arm,
    which makes code larger for little additional protection.
    """
    stats = Stats()
    if not enabled:
        return stats
    rewriter = _Rewriter(rng, stats)
    rewriter.block(root)
    return stats


class _Rewriter:
    def __init__(self, rng: Any, stats: Stats) -> None:
        self.rng = rng
        self.stats = stats

    def _take(self) -> bool:
        if self.rng is None:
            return True
        # A high-but-not-total rate avoids one fixed branch dialect while still
        # making the option observable on normal code.
        return self.rng.chance(0.75) if hasattr(self.rng, "chance") else True

    def block(self, block: A.Block) -> None:
        for stmt in block.body:
            self.stmt(stmt)

    def stmt(self, stmt: A.Stmt) -> None:
        if isinstance(stmt, A.If):
            self._if(stmt)
            return
        self._generic(stmt)

    def _if(self, stmt: A.If) -> None:
        stmt.arms = [(self.expr(cond), self._visit_block(body))
                     for cond, body in stmt.arms]
        if stmt.otherwise is not None:
            self.block(stmt.otherwise)
        if len(stmt.arms) != 1 or stmt.otherwise is None or not self._take():
            return
        cond, then_body = stmt.arms[0]
        else_body = stmt.otherwise
        stmt.arms = [(self._invert(cond), else_body)]
        stmt.otherwise = then_body
        self.stats.branch_inversions += 1

    def _visit_block(self, block: A.Block) -> A.Block:
        self.block(block)
        return block

    def expr(self, expr: A.Expr) -> A.Expr:
        if isinstance(expr, A.IfExpr):
            expr.cond = self.expr(expr.cond)
            expr.then = self.expr(expr.then)
            expr.otherwise = self.expr(expr.otherwise)
            if self._take():
                expr.cond = self._invert(expr.cond)
                expr.then, expr.otherwise = expr.otherwise, expr.then
                self.stats.branch_inversions += 1
            return expr
        self._generic(expr)
        return expr

    def _invert(self, expr: A.Expr) -> A.Expr:
        # ``if not x then`` inverted is ``if x then``.  This is safe because both
        # forms are used only in a condition position where truthiness, not the
        # exact boolean value, is observed.
        if isinstance(expr, A.Un) and expr.op == "not":
            return expr.operand
        return A.Un(op="not", operand=expr, line=getattr(expr, "line", 0),
                    col=getattr(expr, "col", 0))

    def _generic(self, node: Any) -> None:
        if not dataclasses.is_dataclass(node):
            return
        for field in dataclasses.fields(node):
            value = getattr(node, field.name)
            if isinstance(value, A.Expr):
                setattr(node, field.name, self.expr(value))
            elif isinstance(value, A.Block):
                self.block(value)
            elif isinstance(value, A.Node):
                self._generic(value)
            elif isinstance(value, list):
                setattr(node, field.name, self._list(value))

    def _list(self, values: List[Any]) -> List[Any]:
        out: List[Any] = []
        for value in values:
            if isinstance(value, A.Expr):
                out.append(self.expr(value))
            elif isinstance(value, A.Stmt):
                self.stmt(value)
                out.append(value)
            elif isinstance(value, A.Block):
                self.block(value)
                out.append(value)
            elif isinstance(value, A.Node):
                self._generic(value)
                out.append(value)
            else:
                out.append(value)
        return out

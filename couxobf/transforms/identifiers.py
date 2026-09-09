"""Scope-aware identifier renaming.

The renamer never guesses.  It consumes the symbol table produced by
:mod:`couxobf.sema` and rewrites only names that resolve to a local or a
parameter.  Everything observable from outside the protected code is left
alone:

* globals (read or written) -- renaming them would break the program;
* field names (``obj.name``), method names (``obj:method()``) and table
  constructor keys -- these are data, not bindings, and are frequently public
  API or Roblox property names;
* type-alias names and ``declare`` blocks.

Structure: a single generic tree walk (so no expression form can be forgotten)
rewrites every :class:`Name` whose resolved symbol got a new name, plus a short
list of *declaration* sites, which hold the name in a plain string field rather
than in a ``Name`` node.  Reserving those two mechanisms is what makes this
safe; the walk itself needs no per-node logic.
"""

from __future__ import annotations

from typing import Optional, Set

from ..ast_nodes import (
    Field, Func, Local, LocalFunc, MethodCall, Name, NumFor, GenFor, Param,
    Table, TypeAlias, walk,
)
from ..names import NameGenerator
from ..sema import Analysis


class Renamer:
    def __init__(self, analysis: Analysis, generator: NameGenerator,
                 keep: Optional[Set[str]] = None):
        self.analysis = analysis
        self.gen = generator
        self.keep = set(keep or ())
        self.renamed = 0
        self.references = 0

    def run(self) -> int:
        self._reserve_observable_names()
        for sym in self.analysis.symbols:
            if sym.kind not in ("local", "param"):
                continue
            if sym.name in self.keep:
                continue
            sym.new_name = self.gen.fresh()
            self.renamed += 1
        self._rewrite()
        return self.renamed

    # -- what must not be reused as a generated name ---------------------
    def _reserve_observable_names(self) -> None:
        self.gen.reserve(*self.analysis.globals_read)
        self.gen.reserve(*self.analysis.globals_written)
        self.gen.reserve(*self.keep)
        for node in walk(self.analysis.root):
            if isinstance(node, Field):
                self.gen.reserve(node.name)
            elif isinstance(node, MethodCall):
                self.gen.reserve(node.method)
            elif isinstance(node, Table):
                for item in node.items:
                    if item.kind == "field" and item.key_name:
                        self.gen.reserve(item.key_name)
            elif isinstance(node, TypeAlias):
                self.gen.reserve(node.name)
            elif isinstance(node, Param) and node.name is None:
                continue

    # -- rewriting -------------------------------------------------------
    def _rewrite(self) -> None:
        for node in walk(self.analysis.root):
            if isinstance(node, Name):
                sym = getattr(node, "symbol", None)
                if sym is not None and sym.new_name is not None:
                    node.name = sym.new_name
                    self.references += 1
            elif isinstance(node, Param):
                sym = getattr(node, "symbol", None)
                if sym is not None and sym.new_name is not None:
                    node.name = sym.new_name
            elif isinstance(node, Local):
                for ln, sym in zip(node.names, getattr(node, "symbols", [])):
                    if sym.new_name is not None:
                        ln.name = sym.new_name
            elif isinstance(node, LocalFunc):
                sym = getattr(node, "symbol", None)
                if sym is not None and sym.new_name is not None:
                    node.name.name = sym.new_name
            elif isinstance(node, NumFor):
                sym = getattr(node, "var_sym", None)
                if sym is not None and sym.new_name is not None:
                    node.var.name = sym.new_name
            elif isinstance(node, GenFor):
                for v, sym in zip(node.vars, getattr(node, "var_syms", [])):
                    if sym.new_name is not None:
                        v.name = sym.new_name


def rename(analysis: Analysis, generator: NameGenerator,
           keep: Optional[Set[str]] = None) -> int:
    return Renamer(analysis, generator, keep).run()

"""R9: index-to-number rewriting for provably-static local tables.

The transform (opt-in, ``index_to_num``) replaces the *keys* of certain
tables with per-build numeric handles:

    --!couxobf:no_index_to_num   (optional escape hatch, R8 directive syntax)
    local cfg = { mode = 1, retries = 3 }
    ... cfg.mode ... cfg["retries"] ...

becomes, for a particular build,

    local cfg = { [4821] = 1, [977] = 3 }
    ... cfg[4821] ... cfg[977] ...

so the key strings never appear anywhere in the artifact -- not in the
constructor, not at the access sites, and therefore not in the constant
pool either.  Numeric indexing is if anything marginally faster than string
indexing, so the protection is free at runtime.  Luaq's ``LUAQ_INDEX_TO_NUM``
is the reference; the safety rule below is ours.

Safety: a whitelist, not a heuristic
------------------------------------

Rewriting a key is only sound if *every* way of reaching that key goes
through a literal the pass also rewrites.  One dynamic ``t[k]``, one
``pairs(t)``, one ``f(t)``, and the program's meaning changes -- which this
tool must never do.  So the analysis does not try to prove interesting
programs safe; it accepts a small, obviously-safe class and leaves
everything else untouched:

* the table is bound by ``local t = {...}`` -- one name, one value, the
  symbol is a plain local, never reassigned, never captured as an
  upvalue;
* every constructor entry is a literal *string* key (``field`` items or
  ``["..."]`` items) -- no array part and no computed keys, so the numeric
  handles introduced can collide with nothing;
* every use of ``t`` in the program is either ``t.name`` or ``t["literal"]``
  -- found by resolving every ``Name`` node to its symbol and checking the
  parent node.  Any other parent -- a call argument, a return, an aliasing
  assignment, a dynamic index, a method call, an operator operand -- fails
  the table.

Those conditions mean the table is a purely local record whose shape is
visible to the pass in full: the set of keys is exactly the union of the
constructor's keys and the access sites' keys, and the bijection onto
handles covers all of it.

The pass runs after semantic analysis (it reads ``Name.symbol`` links) and
before IR lowering (so the lowered constants are already numeric, and
table-key protection has nothing left to intern in these tables).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from . import ast_nodes as A
from .rng import Rng

#: Handles are drawn from [1, 2**24): comfortably exact doubles, small enough
#: to look like ordinary table indices, large enough that two builds of the
#: same source disagree on essentially all of them.
_HANDLE_SPACE = 1 << 24

#: Directive that exempts the next local declaration from this pass.  Lives in
#: comments.DIRECTIVES so the pipeline's unknown-directive check accepts it.
ESCAPE_DIRECTIVE = "no_index_to_num"


@dataclass
class RewriteStats:
    """What the pass did, for the build report."""

    tables: int = 0  # tables whose keys were rewritten
    keys: int = 0    # distinct keys mapped across those tables
    sites: int = 0   # access sites (constructor entries + uses) rewritten
    #: `local t = {...}` shapes the pass declined -- exempted by directive,
    #: disqualified by the safety check, or holding keys it cannot rewrite.
    skipped: int = 0


def _key_bytes(name_or_str) -> bytes:
    """Canonical key identity: ``t.foo`` and ``t["foo"]`` are the same key."""
    if isinstance(name_or_str, bytes):
        return name_or_str
    return name_or_str.encode("utf-8", "surrogatepass")


def _constructor_keys(table: A.Table) -> Optional[List[bytes]]:
    """The table's keys if every entry is a literal string key, else None.

    Any array-part entry or computed/numeric key disqualifies the table:
    a numeric handle could collide with an existing numeric key, and the
    pass has no way to rewrite keys it cannot see as literals.
    """
    keys: List[bytes] = []
    for item in table.items:
        if item.kind == "field":
            if not item.key_name:
                return None
            keys.append(_key_bytes(item.key_name))
        elif item.kind == "key":
            if not isinstance(item.key_expr, A.Str):
                return None
            keys.append(item.key_expr.raw)
        else:  # "array" part -- integer keys the pass must not touch
            return None
    return keys


def _parent_slots(root: A.Node) -> Dict[int, Tuple[A.Node, str]]:
    """id(child) -> (parent, slot) so a node can be swapped in its parent.

    Slot names come from ``child_slots``: a plain attribute name, or
    ``name[i]`` for list members.
    """
    loc: Dict[int, Tuple[A.Node, str]] = {}
    for node in A.walk(root):
        for slot, child in A.child_slots(node):
            loc[id(child)] = (node, slot)
    return loc


def _set_slot(parent: A.Node, slot: str, child: A.Node) -> None:
    if "[" in slot:
        name, _, rest = slot.partition("[")
        getattr(parent, name)[int(rest.rstrip("]"))] = child
    else:
        setattr(parent, slot, child)


def _number(handle: int, like: A.Node) -> A.Number:
    return A.Number(value=handle, text=str(handle), line=like.line, col=like.col)


def _bind_exemptions(directives: Sequence[Tuple[int, str]],
                     locals_: List[A.Local]) -> set:
    """Declaration nodes exempted by ``--!couxobf:no_index_to_num``.

    Same binding rule as the virtualization directives: a directive names the
    first local declaration at or after its line.  Declarations are matched,
    not functions, because this pass protects table bindings, and a directive
    before ``local t = {...}`` is unambiguously about that binding.
    """
    exempt = set()
    # (line, position) pairs: the position breaks ties so equal-line
    # declarations never ask Python to compare two AST nodes.
    decls = sorted((int(getattr(n, "line", 0)), i, n)
                   for i, n in enumerate(locals_))
    for line, name in directives:
        if name != ESCAPE_DIRECTIVE:
            continue
        for decl_line, _i, node in decls:
            if decl_line >= line:
                exempt.add(id(node))
                break
    return exempt


def rewrite(root: A.Node, rng: Rng,
            directives: Sequence[Tuple[int, str]] = ()) -> RewriteStats:
    """Rewrite eligible tables in place.  Returns what it did.

    ``root`` must have been through semantic analysis: the pass resolves uses
    by ``Name.symbol`` links, and an unanalysed tree has none.
    """
    stats = RewriteStats()
    loc = _parent_slots(root)

    locals_ = [n for n in A.walk(root) if isinstance(n, A.Local)]
    exempt = _bind_exemptions(directives, locals_)

    for local in locals_:
        if len(local.names) != 1 or len(local.values) != 1:
            continue
        table = local.values[0]
        if not isinstance(table, A.Table):
            continue
        # From here on the shape is `local t = {...}`; every reason not to
        # rewrite it is a declined candidate, and the report counts it so the
        # number of rewritten tables is never the whole story by itself.
        if id(local) in exempt:
            stats.skipped += 1
            continue
        symbols = getattr(local, "symbols", None)
        if not symbols:
            stats.skipped += 1
            continue
        sym = symbols[0]
        if sym.kind != "local" or sym.is_captured or sym.is_assigned:
            stats.skipped += 1
            continue
        ctor_keys = _constructor_keys(table)
        if ctor_keys is None:
            stats.skipped += 1
            continue

        # Safety walk: every use of the symbol must be a literal-key access.
        keys = set(ctor_keys)
        field_uses: List[A.Field] = []
        index_uses: List[A.Index] = []
        safe = True
        for node in A.walk(root):
            if not isinstance(node, A.Name):
                continue
            if getattr(node, "symbol", None) is not sym:
                continue
            parent = loc.get(id(node))
            if parent is None:
                safe = False
                break
            parent = parent[0]
            if isinstance(parent, A.Field) and parent.obj is node:
                keys.add(_key_bytes(parent.name))
                field_uses.append(parent)
            elif (isinstance(parent, A.Index) and parent.obj is node
                  and isinstance(parent.key, A.Str)):
                keys.add(parent.key.raw)
                index_uses.append(parent)
            else:
                safe = False
                break
        if not safe:
            stats.skipped += 1
            continue

        # Per-build bijection key -> handle, drawn in sorted key order so
        # cross-process runs agree.
        keymap: Dict[bytes, int] = {}
        taken: set = set()
        for key in sorted(keys):
            while True:
                handle = 1 + rng.randbelow(_HANDLE_SPACE)
                if handle not in taken:
                    taken.add(handle)
                    keymap[key] = handle
                    break

        # Constructor entries: field items become explicit numeric keys.
        for item in table.items:
            if item.kind == "field":
                key = _key_bytes(item.key_name)
            else:
                key = item.key_expr.raw
            item.kind = "key"
            item.key_name = None
            item.key_expr = _number(keymap[key], item.value)
            stats.sites += 1

        # Access sites: Index keeps its node and swaps the key; Field becomes
        # an Index, swapped inside its own parent.
        for node in index_uses:
            node.key = _number(keymap[node.key.raw], node.key)
            stats.sites += 1
        for node in field_uses:
            replacement = A.Index(obj=node.obj, key=_number(
                keymap[_key_bytes(node.name)], node),
                line=node.line, col=node.col)
            parent, slot = loc[id(node)]
            _set_slot(parent, slot, replacement)
            stats.sites += 1

        stats.tables += 1
        stats.keys += len(keymap)

    return stats

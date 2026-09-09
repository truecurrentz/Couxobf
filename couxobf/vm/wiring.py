"""Choosing what runs in the VM, and emitting the runtime that runs it.

Three decisions live here.

*Which prototypes.*  Not everything can be virtualized -- ``encode.can_virtualize``
draws that line on upvalues, varargs and nested closures, because the VM frame is
an ordinary table and anything a real Luau closure must see cannot live in it.
Among the prototypes that *can* run in the VM, the classifier decides which
*should*: virtualizing a three-line getter costs more in call overhead than it
hides, and a build that virtualizes everything is both slower and, per the
design's own warning, not stronger.

*Which VM each one gets.*  A build groups its virtualized prototypes and draws an
interpreter per group: operand discipline, dispatch shape, opcode map and
instruction format.  That is what makes "multiple VMs per build" (#2, #76, #79)
true instead of aspirational, and it is bounded deliberately -- every group
costs a whole interpreter, so the group count is a knob with a cost the report
states rather than a free good.

*What the runtime looks like.*  The interpreter's local names come from the
build's identifier stream, so the dispatcher is not recognisable by name across
builds.  The four iterator/append helpers are the ones ``lower_back`` already
emits -- sharing them is deliberate.  A second copy of the iteration helper
would be a second thing for an analyst to find and a second place for the two to
drift.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Optional, Any, Callable, Dict, Iterable, List, Sequence, Set

from ..config import VirtualizationLevel
from ..ir import FuncIR
from ..names import make_name_generator
from ..rng import Rng
from . import encode, runtime
from .families import FAMILIES
from .format import (FUSION_RULES, FormatPrefs, FormatSpec,
                       FusionRule, draw)
from .isa import OpcodeMap

#: ``lower_back`` owns these; the interpreter calls them rather than shipping
#: its own copies.
_SHARED = ("_kapp", "_kiter", "_kiterpack", "_kitercheck")

#: Every name the rest of the generated program builds with a ``_k`` prefix.  A
#: VM local colliding with one of these would silently rebind it, so VM names
#: are drawn from outside that space entirely.
_INTERNAL_PREFIX = "_k"


@dataclass
class VMGroup:
    """One interpreter: a family, a dispatcher, a format and an opcode map.

    Everything a deobfuscator has to re-derive per VM lives here, which is why
    the encoder, the generator and the validator all read it from the same
    object instead of each keeping its own copy of a layout.
    """

    index: int
    fmt: FormatSpec
    opmap: OpcodeMap
    family: str
    dispatcher: str
    #: The prototypes this group runs.
    protos: Set[int] = field(default_factory=set)
    #: Interpreter entry points, per group: the shared names plus this group's
    #: own ``exec``/``enter``, so a closure can name the interpreter it belongs
    #: to without a plaintext "which VM is this" field anywhere in the artifact.
    names: Dict[str, str] = field(default_factory=dict)

    def describes(self, proto_id: int) -> bool:
        return proto_id in self.protos


@dataclass
class VMPlan:
    """One build's VMs and the prototypes they execute."""

    opmap: OpcodeMap
    names: Dict[str, str]
    #: Prototype ids selected for the VM.  Anything absent is reconstructed
    #: natively, which is what makes mixed execution the normal case rather
    #: than an option.
    protos: Set[int] = field(default_factory=set)
    #: Name of the table holding each prototype's payload row.
    table: str = ""
    #: Name of the table holding each prototype's constants, and of the one
    #: holding control-flow edges.  Split on purpose (#17): the instruction
    #: blob, the constant table and the edge table are three structures, so
    #: there is no single "VM metadata" object to find and dump.
    consts_table: str = ""
    edges_table: str = ""
    #: The assembled per-prototype record every ``enter`` is handed.
    rows_table: str = ""
    #: Whether the three descriptor tables above are actually kept apart.  See
    #: :func:`prelude_source`; this is :attr:`Config.metadata_fragmentation`.
    fragmented: bool = True
    #: Operand discipline of group 0 -- kept because callers and tests reach for
    #: it, and it is the honest answer whenever the build has one group.
    family: str = "register"
    #: Shuffle each prototype's block layout.  See :mod:`couxobf.vm.layout`.
    permute_blocks: bool = False
    #: Randomness for that shuffle.  Its own domain, so changing the opcode map
    #: does not also re-layout every function.
    layout_rng: Any = None
    #: Shape of the opcode dispatch for group 0.  One of runtime.DISPATCHERS.
    dispatcher: str = "nested_if"
    #: The groups this build emits, and which group owns which prototype.
    groups: List[VMGroup] = field(default_factory=list)
    #: Alias-opcode usage rate, and the fusion rules offered to the encoder.
    alias_chance: float = 0.0
    #: Per-prototype dispatch decisions, for the report.
    decisions: List[Dict[str, Any]] = field(default_factory=list)

    def selects(self, proto: FuncIR) -> bool:
        return proto.proto_id in self.protos

    def group_for(self, proto_id: int) -> Optional[VMGroup]:
        for group in self.groups:
            if group.describes(proto_id):
                return group
        return None

    def fmt_for(self, proto_id: int) -> FormatSpec:
        group = self.group_for(proto_id)
        return group.fmt if group is not None else self.groups[0].fmt

    def opmap_for(self, proto_id: int) -> OpcodeMap:
        group = self.group_for(proto_id)
        return group.opmap if group is not None else self.opmap

    def enter_for(self, proto_id: int) -> str:
        group = self.group_for(proto_id)
        return (group or self.groups[0]).names["enter"]

    def summary(self) -> List[Dict[str, Any]]:
        return [{
            "group": g.index,
            "family": g.family,
            "dispatcher": g.dispatcher,
            "protos": len(g.protos),
            "opcodes": g.opmap.opcode_count(),
            "format": g.fmt.summary(),
        } for g in self.groups]


def structural_fingerprint(plan: "VMPlan") -> bytes:
    """A short digest of what this build decided about its own format.

    Not a hash of the artifact: a hash of the *decisions* -- family, dispatcher,
    opcode count and instruction format per group -- so the same config and seed
    reproduce it and a single changed field does not.

    Two uses, both of them ours.  It goes into the constant pool's additional
    authenticated data, so a pool lifted out of one build fails to open in another
    even when the config looks the same; and it goes into the report, which is how
    our own tooling recognises the format a build produced without a marker string
    sitting in the artifact for somebody to find and delete.

    It is not a tamper seal.  Everything it digests is already visible in the
    emitted code, so an attacker who wants a matching fingerprint changes the build
    and recomputes it.  What it buys is that the *pool* cannot be moved between
    builds, which is a supply-chain accident rather than an adversary.
    """
    import hashlib
    import json

    h = hashlib.sha256()
    for group in plan.groups:
        h.update(json.dumps({
            "group": group.index,
            "family": group.family,
            "dispatcher": group.dispatcher,
            "opcodes": group.opmap.opcode_count(),
            "format": group.fmt.summary(),
        }, sort_keys=True, default=str).encode("utf-8"))
        h.update(b"\n")
    return h.digest()[:8]


def _fresh_names(rng: Rng, count: int, reserved: Iterable[str] = ()) -> List[str]:
    """Unique names outside the ``_k`` space the rest of the output uses."""
    gen = make_name_generator(rng, reserved=set(_SHARED) | set(reserved))
    out: List[str] = []
    while len(out) < count:
        name = gen.fresh()
        if name.startswith(_INTERNAL_PREFIX):
            continue
        out.append(name)
    return out


#: Per-build name roles the interpreter needs, in the order they are drawn.
_ROLES = ("code", "exec", "enter", "call", "getfenv", "acc", "stack", "sp",
          "pc", "regs", "consts", "env", "edges")


def make_plan(rng: Rng, protos: Iterable[int],
              opmap: Optional[OpcodeMap] = None,
              family: str = "register",
              permute_blocks: bool = False,
              layout_rng: Any = None,
              dispatcher: str = "nested_if",
              shared: Optional[Iterable[str]] = None,
              randomize_opcodes: bool = True,
              variety: int = 1,
              fusion: Sequence[FusionRule] = (),
              alias_ratio: float = 0.0,
              alias_chance: float = 0.0,
              fmt_prefs: Optional[FormatPrefs] = None,
              tables: Optional[Sequence[str]] = None,
              names: Optional[Dict[str, str]] = None,
              families: Optional[Sequence[str]] = None,
              dispatchers: Optional[Sequence[str]] = None,
              fragmented: bool = True,
              protos_by_id: Optional[Dict[int, Any]] = None,
              isa_subset: bool = False) -> VMPlan:
    """Build a :class:`VMPlan` from the build's ``vm`` randomness stream.

    ``rng`` should be the domain-separated stream for VM generation, not the
    identifier stream: reusing a stream across unrelated purposes is what makes
    two builds' differences correlate in ways an analyst can exploit.

    ``protos_by_id`` and ``isa_subset`` together give each group the opcodes its
    own prototypes need: ``isa_subset`` asks for the narrowing, and the IR objects
    are what makes it answerable here, where the membership of each group is
    known and the format of each group has just been drawn.  Without the objects
    the request is quietly ignored, because "subset of what" has no answer.

    ``variety`` is how many interpreters to emit.  One is the historical
    behaviour; two or more split the virtualized prototypes across VMs whose
    families, dispatch shapes and instruction formats all differ, which is the
    only arrangement that defeats a devirtualizer written against *a* VM rather
    than against *this* build.  It costs an interpreter per group -- roughly 10
    to 19 KB each -- so it is a knob with a price, and the price is in the
    report.
    """
    shared = tuple(shared or _SHARED)
    proto_ids = sorted(set(protos))
    family = _family_name(family)
    dispatcher = _dispatcher_name(dispatcher, rng)
    tables = tuple(tables or _fresh_names(rng, 4))
    if names is None:
        (code_name, exec_name, enter_name, call_name, getfenv_name,
         acc_name, stack_name, sp_name, pc_name, regs_name, consts_name,
         env_name, edges_name, _spare) = _fresh_names(rng, 14)
        names = {
            "code": code_name,
            "exec": exec_name,
            "enter": enter_name,
            "call": call_name,
            "getfenv": getfenv_name,
            # the accumulator/stack locals the non-register families use
            "acc": acc_name,
            "stack": stack_name,
            "sp": sp_name,
            "pc": pc_name,
            "regs": regs_name,
            "consts": consts_name,
            "env": env_name,
            # the per-prototype control-flow edge table, when a format reads its
            # jump targets through one (#18)
            "edges": edges_name,
        }
    else:
        # A caller-supplied name set: the test harness pins these so a failure
        # names the function it came from.  They must reach the groups too -- a
        # plan whose interpreter and call sites disagree on a name is exactly the
        # "two copies that drift" bug the harness rewrite was for.
        names = dict(names)
    for role, helper in zip(("append", "iter", "iterpack", "itercheck"), shared):
        # shared with lower_back -- see the module docstring
        names.setdefault(role, helper)

    groups = _make_groups(rng, proto_ids, names, variety=variety, family=family,
                          dispatcher=dispatcher, families=families,
                          dispatchers=dispatchers, randomize_opcodes=randomize_opcodes,
                          fusion=fusion, alias_ratio=alias_ratio,
                          alias_chance=alias_chance, prefs=fmt_prefs,
                          protos_by_id=protos_by_id, isa_subset=isa_subset,
                          permute_blocks=permute_blocks)
    # A stable opcode numbering is a real option, not a placeholder: it makes
    # two builds of the same source comparable byte for byte apart from the
    # names, which is what you want when you are checking that a change did
    # what you intended.  It is weaker, and the config says so.
    primary = groups[0]
    return VMPlan(opmap=opmap or primary.opmap,
                  names=names,
                  protos=set(proto_ids),
                  table=tables[0],
                  consts_table=tables[1],
                  edges_table=tables[2],
                  rows_table=tables[3],
                  family=primary.family,
                  permute_blocks=bool(permute_blocks),
                  layout_rng=layout_rng,
                  dispatcher=primary.dispatcher,
                  groups=groups,
                  alias_chance=alias_chance,
                  fragmented=bool(fragmented))


def _make_groups(rng: Rng, proto_ids: List[int], names: Dict[str, str], *,
                 variety: int, family: str, dispatcher: str,
                 families: Optional[Sequence[str]],
                 dispatchers: Optional[Sequence[str]],
                 randomize_opcodes: bool, fusion: Sequence[FusionRule],
                 alias_ratio: float, alias_chance: float,
                 prefs: Optional[FormatPrefs] = None,
                 protos_by_id: Optional[Dict[int, Any]] = None,
                 isa_subset: bool = False,
                 permute_blocks: bool = False) -> List[VMGroup]:
    """Partition the selection into VMs, one per group.

    Assignment is round-robin over the sorted prototype ids rather than random.
    A random split would make the *grouping* another thing to recover, which
    sounds like a feature until you notice it is free to an analyst: the group is
    visible in the emitted artifact either way, because each prototype has to
    name the interpreter it runs on.  What matters is that the groups disagree
    with each other, and round-robin guarantees they get equal populations
    instead of 63 prototypes in one VM and one in the other.
    """
    count = max(1, min(int(variety), 4))
    if len(proto_ids) < 2:
        count = 1
    family_pool = list(families) if families else [family]
    dispatcher_pool = list(dispatchers) if dispatchers else [dispatcher]
    if len(family_pool) < count:
        # Not enough distinct families for the requested groups: fall back to
        # drawing from every family the tool can emit, which is what "more
        # groups" is for.
        family_pool = list(families or FAMILIES)
        rng.shuffle(family_pool)
    if len(dispatcher_pool) < count:
        dispatcher_pool = list(dispatchers or runtime.DISPATCHERS)
        rng.shuffle(dispatcher_pool)

    # Membership is decided here, before the formats, because a per-group
    # instruction set has to know who is in the group.  The assignment below is
    # the round-robin this function has always used; `members` is the same
    # partition, computed once so the opcode subset and the plan cannot
    # disagree about which prototype runs where.
    members: List[List[int]] = [[] for _ in range(count)]
    for i, pid in enumerate(proto_ids):
        members[i % count].append(pid)

    groups: List[VMGroup] = []
    for index in range(count):
        fam = family_pool[index % len(family_pool)]
        disp = dispatcher_pool[index % len(dispatcher_pool)]
        fmt = draw(rng, prefs or FormatPrefs(variety=min(2, count)),
                   fusion_rules=fusion, group=index)
        fused = [(r.first, r.second) for r in fmt.fused]
        # `sparse` spaces the numbering out, so opcode numbers are not a dense
        # 1..N run in every build -- an analyst who assumes density reads the
        # wrong set of arms.
        # Which operations this group needs.  Over-approximated on purpose (see
        # `encode.required_ops`): a missing opcode is a build failure, an extra
        # one is a handler nobody reaches.
        subset: Optional[Set[str]] = None
        if isa_subset and protos_by_id:
            needed: Set[str] = set()
            for pid in members[index]:
                proto = protos_by_id.get(pid)
                if proto is None:
                    needed = None        # type: ignore[assignment]
                    break
                got = encode.required_ops(proto, fmt,
                                          permuted_blocks=permute_blocks)
                if got is None:
                    needed = None        # type: ignore[assignment]
                    break
                needed |= got
            subset = needed or None
        if subset is not None and fused:
            # A pair the encoder may emit has to have both halves and a number.
            subset |= {o for pair in fused for o in pair}
        opmap = (OpcodeMap.identity(ops=subset) if not randomize_opcodes else
                 OpcodeMap.shuffled(rng, alias_ratio=alias_ratio, fused=fused,
                                    sparse=1 if count == 1 else 1 + index,
                                    ops=subset))
        if subset is not None and len(opmap.to_byte) < len(subset):
            # The number space ran out mid-subset (only possible with an
            # aggressive `sparse` on a large group).  Fall back to the full ISA:
            # a group with a handler missing is a broken build, and a group with
            # a few unused arms is merely less diverse.
            opmap = (OpcodeMap.identity() if not randomize_opcodes else
                     OpcodeMap.shuffled(rng, alias_ratio=alias_ratio,
                                        fused=fused, sparse=1))
            subset = None
        own = dict(names)
        if count > 1:
            # Each group's own entry point name, so a build with two VMs does
            # not declare ``enter`` twice and quietly shadow one of them.
            extra = _fresh_names(rng, 2)
            own["exec"] = extra[0]
            own["enter"] = extra[1]
        # The opcode map is the budget: a one-byte field cannot carry more arms
        # than it has numbers, and a group that spaces its numbering out to make
        # the arms harder to line up has fewer of them to spend.  Whatever the
        # map could not fit is therefore dropped from the *format* as well, so
        # the encoder never emits a super-op whose handler has no number.
        fitted = set((opmap.fused or {}).values())
        if len(fitted) != len(fused):
            fmt = replace(fmt, fused=tuple(r for r in fmt.fused
                                           if (r.first, r.second) in fitted))
        groups.append(VMGroup(index=index, fmt=fmt, opmap=opmap, family=fam,
                              dispatcher=disp, names=own))
    for index, group in enumerate(groups):
        group.protos.update(members[index])
    return groups


#: Node-count floor per level, keyed on :class:`VirtualizationLevel` so the
#: config and the selector cannot drift apart.
#:
#: The floor is the "do not VM trivial code" rule made concrete.  Entering the
#: interpreter costs a table allocation, an argument copy and a dispatch loop
#: iteration per instruction, so a prototype smaller than that overhead gains
#: nothing: it runs slower and the handler code an analyst has to read is the
#: same either way.
_SIZE_FLOOR = {
    VirtualizationLevel.NONE: 1 << 30,
    VirtualizationLevel.LIGHT: 24,
    VirtualizationLevel.MEDIUM: 12,
    VirtualizationLevel.HEAVY: 6,
    VirtualizationLevel.MAXIMUM: 1,
}


def select_protos(module, level: Any = VirtualizationLevel.HEAVY,
                  fmt: Optional[FormatSpec] = None) -> Set[int]:
    """Which prototypes of ``module`` should run in the VM.

    Eligibility is ``encode.can_virtualize`` -- upvalues, varargs and nested
    closures are out, because the VM frame is a table and anything a real Luau
    closure must see cannot live in it.  Selection is the size floor above.
    """
    floor = _SIZE_FLOOR[VirtualizationLevel.parse(level)]
    chosen: Set[int] = set()

    def walk(p: FuncIR) -> None:
        if p.proto_id != module.main.proto_id:
            ok, _reason = encode.can_virtualize(p, fmt)
            if ok and p.node_count >= floor:
                chosen.add(p.proto_id)
        for c in p.children:
            walk(c)

    walk(module.main)
    return chosen


def _dispatcher_name(value: Any, rng: Rng) -> str:
    """Resolve a dispatcher choice, picking one at random for ``mixed``.

    ``mixed`` is the default, and it is what makes the dispatcher part of the
    per-build fingerprint rather than a fixed shape.  Choosing here rather than
    in the pipeline keeps the choice tied to the same rng stream that names the
    interpreter's locals, so a build's shape and its names move together.
    """
    name = str(getattr(value, "value", value)).strip().lower()
    if name in ("", "mixed", "none"):
        return rng.choice(list(runtime.DISPATCHERS))
    if name not in runtime.DISPATCHERS:
        raise ValueError(
            f"dispatcher family {value!r} is not implemented; this build can "
            f"emit {', '.join(runtime.DISPATCHERS)} (or mixed)")
    return name


def _family_name(value: Any) -> str:
    """Normalise a family, which may arrive as a ``VMFamily`` enum."""
    name = getattr(value, "value", value)
    key = str(name).strip().lower()
    if key not in FAMILIES:
        raise ValueError(f"unknown VM family {value!r}; expected one of {FAMILIES}")
    return key


def _pack_edges(edges: Sequence[int]) -> bytes:
    """The edge table as bytes: one little-endian u32 per destination."""
    import struct

    return struct.pack("<%dI" % len(edges), *edges)


def prelude_source(plan: VMPlan, encoded: Dict[int, Any],
                   const_expr: Callable[[Any], str],
                   code_expr: Callable[[bytes], str],
                   edges_expr: Optional[Callable[[bytes], str]] = None,
                   entry_guard: Sequence[str] = (),
                   fragmented: Optional[bool] = None) -> str:
    """The interpreters plus the descriptor tables, as Luau source.

    One interpreter per VM group, then three tables keyed by prototype id: the
    payload, the constants, and -- when a format represents jumps indirectly --
    the control-flow edges.  A row is assembled from all three so the interpreter
    still receives one object, but nothing in the artifact holds the whole
    description of a VM at once (#17).

    ``const_expr`` and ``code_expr`` produce the expression text for a pooled
    constant and for a bytecode blob.  Taking them as callbacks keeps this
    module independent of the constant pool, so the unprotected reconstruction
    path can pass literal emitters and the protected one can pass pool reads --
    the same bytecode, protected or not.
    """
    parts: List[str] = []
    for group in plan.groups:
        parts.append(runtime.interpreter_source(group.opmap, group.names,
                                                group.family, group.dispatcher,
                                                group.fmt,
                                                entry_guard=entry_guard))
    payload_rows = []
    const_rows = []
    edge_rows = []
    for pid in sorted(encoded):
        enc = encoded[pid]
        consts = ", ".join(const_expr(v) for v in enc.consts)
        # Deliberately no `entry` or `nparams` here.  Both are already in the
        # payload header, which travels inside the authenticated blob; the
        # interpreter reads them from there.  Putting them here as well created
        # a second, plaintext, unauthenticated copy that an editor could change
        # without invalidating any tag.
        payload_rows.append("  [%d] = %s," % (pid, code_expr(enc.code)))
        const_rows.append("  [%d] = { %s }," % (pid, consts))
        if enc.edges and edges_expr is not None:
            # Four bytes per edge, so the stream itself carries only ordinals
            # and the positions they mean live somewhere else entirely (#18).
            blob = _pack_edges(enc.edges)
            edge_rows.append("  [%d] = %s," % (pid, edges_expr(blob)))
    if not payload_rows:
        # No prototype made it in, so there is nothing to dispatch.  Emitting
        # the interpreter anyway would be dead weight an analyst could study
        # for free.
        return ""
    if fragmented is None:
        fragmented = plan.fragmented
    if not fragmented:
        # One table holding everything about every prototype, which is what a
        # tool that wants to dump the metadata would like: `for pid, row in
        # pairs(T)` yields code, constants and edges together, no assembly step.
        # `plan.table` still has to exist because the interpreter's row reads are
        # written against it, so the single-table build points it at the joined
        # table and skips the split ones.
        joined = []
        for pid in sorted(encoded):
            enc = encoded[pid]
            consts = ", ".join(const_expr(v) for v in enc.consts)
            edges = (" edges = " + edges_expr(_pack_edges(enc.edges)) + ",") if (
                enc.edges and edges_expr is not None) else ""
            joined.append("  [%d] = { code = %s, consts = { %s },%s },"
                          % (pid, code_expr(enc.code), consts, edges))
        parts.append("local %s = {\n%s\n}"
                     % (plan.rows_table, "\n".join(joined)))
        return "\n".join(parts) + "\n"
    parts.append("local %s = {\n%s\n}" % (plan.table, "\n".join(payload_rows)))
    parts.append("local %s = {\n%s\n}"
                 % (plan.consts_table, "\n".join(const_rows)))
    if edge_rows:
        parts.append("local %s = {\n%s\n}"
                     % (plan.edges_table, "\n".join(edge_rows)))

    # Assemble the rows.  What `enter` receives is one record, so the split is
    # invisible to the interpreter and visible to anyone reading the artifact --
    # which is the whole point of splitting metadata across structures: there is
    # no single object to find, dump and hand to a tool.
    joined = []
    for pid in sorted(encoded):
        enc = encoded[pid]
        edges = ("%s[%d]" % (plan.edges_table, pid)) if edge_rows else "nil"
        joined.append("  [%d] = { code = %s[%d], consts = %s[%d], edges = %s },"
                      % (pid, plan.table, pid, plan.consts_table, pid, edges))
    parts.append("local %s = {\n%s\n}"
                 % (plan.rows_table, "\n".join(joined)))
    return "\n".join(parts) + "\n"

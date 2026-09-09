"""Choosing what runs in the VM, and emitting the runtime that runs it.

Two decisions live here.

*Which prototypes.*  Not everything can be virtualized -- ``encode.can_virtualize``
draws that line on upvalues, varargs and nested closures, because the VM frame
is an ordinary table and anything a real Luau closure must see cannot live in
it.  Among the prototypes that *can* run in the VM, the classifier decides
which *should*: virtualizing a three-line getter costs more in call overhead
than it hides, and a build that virtualizes everything is both slower and, per
the design's own warning, not stronger.

*What the runtime looks like.*  The interpreter's local names come from the
build's identifier stream, so the dispatcher is not recognisable by name across
builds.  The four iterator/append helpers are the ones ``lower_back`` already
emits -- sharing them is deliberate.  A second copy of ``_kiter`` would be a
second thing for an analyst to find and a second place for the two to drift.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Set

from ..config import VirtualizationLevel
from ..ir import FuncIR
from ..names import make_name_generator
from ..rng import Rng
from . import encode, runtime
from .families import FAMILIES
from .isa import OpcodeMap

#: ``lower_back`` owns these; the interpreter calls them rather than shipping
#: its own copies.
_SHARED = ("_kapp", "_kiter", "_kiterpack", "_kitercheck")

#: Every name the rest of the generated program builds with a ``_k`` prefix.  A
#: VM local colliding with one of these would silently rebind it, so VM names
#: are drawn from outside that space entirely.
_INTERNAL_PREFIX = "_k"


@dataclass
class VMPlan:
    """One build's VM identity and the prototypes it will execute."""

    opmap: OpcodeMap
    names: Dict[str, str]
    #: Prototype ids selected for the VM.  Anything absent is reconstructed
    #: natively, which is what makes mixed execution the normal case rather
    #: than an option.
    protos: Set[int] = field(default_factory=set)
    #: Name of the table holding the per-prototype descriptors.
    table: str = ""
    #: Operand discipline -- see :mod:`couxobf.vm.families`.
    family: str = "register"
    #: Shuffle each prototype's block layout.  See :mod:`couxobf.vm.layout`.
    permute_blocks: bool = False
    #: Randomness for that shuffle.  Its own domain, so changing the opcode map
    #: does not also re-layout every function.
    layout_rng: Any = None

    def selects(self, proto: FuncIR) -> bool:
        return proto.proto_id in self.protos


def _fresh_names(rng: Rng, count: int) -> List[str]:
    """Unique names outside the ``_k`` space the rest of the output uses."""
    gen = make_name_generator(rng, reserved=set(_SHARED))
    out: List[str] = []
    while len(out) < count:
        name = gen.fresh()
        if name.startswith(_INTERNAL_PREFIX):
            continue
        out.append(name)
    return out


def make_plan(rng: Rng, protos: Iterable[int],
              opmap: Optional[OpcodeMap] = None,
              family: str = "register",
              permute_blocks: bool = False,
              layout_rng: Any = None) -> VMPlan:
    """Build a :class:`VMPlan` from the build's ``vm`` randomness stream.

    ``rng`` should be the domain-separated stream for VM generation, not the
    identifier stream: reusing a stream across unrelated purposes is what makes
    two builds' differences correlate in ways an analyst can exploit.
    """
    fresh = _fresh_names(rng, 9)
    (code_name, exec_name, enter_name, call_name, getfenv_name, table_name,
     acc_name, stack_name, sp_name) = fresh
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
        # shared with lower_back -- see the module docstring
        "append": _SHARED[0],
        "iter": _SHARED[1],
        "iterpack": _SHARED[2],
        "itercheck": _SHARED[3],
    }
    return VMPlan(opmap=opmap or OpcodeMap.shuffled(rng),
                  names=names,
                  protos=set(protos),
                  table=table_name,
                  family=_family_name(family),
                  permute_blocks=bool(permute_blocks),
                  layout_rng=layout_rng)


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


def select_protos(module, level: Any = VirtualizationLevel.HEAVY) -> Set[int]:
    """Which prototypes of ``module`` should run in the VM.

    Eligibility is ``encode.can_virtualize`` -- upvalues, varargs and nested
    closures are out, because the VM frame is a table and anything a real Luau
    closure must see cannot live in it.  Selection is the size floor above.
    """
    floor = _SIZE_FLOOR[VirtualizationLevel.parse(level)]
    chosen: Set[int] = set()

    def walk(p: FuncIR) -> None:
        if p.proto_id != module.main.proto_id:
            ok, _reason = encode.can_virtualize(p)
            if ok and p.node_count >= floor:
                chosen.add(p.proto_id)
        for c in p.children:
            walk(c)

    walk(module.main)
    return chosen


def _family_name(value: Any) -> str:
    """Normalise a family, which may arrive as a ``VMFamily`` enum."""
    name = getattr(value, "value", value)
    key = str(name).strip().lower()
    if key not in FAMILIES:
        raise ValueError(f"unknown VM family {value!r}; expected one of {FAMILIES}")
    return key


def prelude_source(plan: VMPlan, encoded: Dict[int, Any],
                   const_expr: Callable[[Any], str],
                   code_expr: Callable[[bytes], str]) -> str:
    """The interpreter plus the descriptor table, as Luau source.

    ``const_expr`` and ``code_expr`` produce the expression text for a pooled
    constant and for a bytecode blob.  Taking them as callbacks keeps this
    module independent of the constant pool, so the unprotected reconstruction
    path can pass literal emitters and the protected one can pass pool reads --
    the same bytecode, protected or not.
    """
    parts = [runtime.interpreter_source(plan.opmap, plan.names, plan.family)]
    rows = []
    for pid in sorted(encoded):
        enc = encoded[pid]
        consts = ", ".join(const_expr(v) for v in enc.consts)
        # Deliberately no `entry` or `nparams` here.  Both are already in the
        # payload header, which travels inside the authenticated blob; the
        # interpreter reads them from there.  Putting them here as well created
        # a second, plaintext, unauthenticated copy that an editor could
        # change without invalidating any tag.
        rows.append("  [%d] = { code = %s, consts = { %s } },"
                    % (pid, code_expr(enc.code), consts))
    if not rows:
        # No prototype made it in, so there is nothing to dispatch.  Emitting
        # the interpreter anyway would be dead weight an analyst could study
        # for free.
        return ""
    parts.append("local %s = {\n%s\n}" % (plan.table, "\n".join(rows)))
    return "\n".join(parts) + "\n"

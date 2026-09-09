"""Function classification: which functions get virtualized, and how hard.

Virtualizing everything is both slower and *weaker*. A large universal
interpreter is easier to analyse than a small specialized one, because an
analyst writes the decompiler once and reuses it; and a build where every
function is virtualized gives away that the tool was run at maximum settings,
which is itself a fingerprint. So the interesting question is not "can this be
virtualized" but "is it worth it here".

The policy is deliberately conservative and explicit:

* Trivial functions are left alone.  Wrapping a three-line getter in an
  interpreter costs the reader nothing and costs the program a lot.
* The main chunk is never virtualized.  It has to run in order to install the
  runtime the virtualized functions depend on.
* There is a hard budget.  Virtualizing the sixty-first function does not make
  the build harder to read; it makes it slower.
* Everything above is capped by the configured level, so a build asking for
  ``LIGHT`` never gets ``MAXIMUM``.

Scores are static.  Real hot-function detection needs runtime profiling, which
a source-to-source build does not have; what is here is a complexity proxy, and
it is labelled as one rather than passed off as measurement.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .config import Config, VirtualizationLevel
from .ir import IRModule, FuncIR
from .rng import Rng

# Weights for the complexity score.  Loops and branches weigh most because they
# are what makes a function expensive to read *and* expensive to run, which is
# where virtualization both helps most and costs most.
W_NODE = 1.0
W_LOOP = 6.0
W_BRANCH = 4.0
W_CALL = 2.0
W_CLOSURE = 3.0


@dataclass
class Decision:
    """Why a prototype got the level it got -- for the build report."""

    proto_id: int
    name: Optional[str]
    level: int
    score: float
    reason: str


@dataclass
class Classification:
    levels: Dict[int, int] = field(default_factory=dict)
    families: Dict[int, Optional[str]] = field(default_factory=dict)
    decisions: List[Decision] = field(default_factory=list)

    def level(self, proto_id: int) -> int:
        return self.levels.get(proto_id, 0)

    def virtualized(self) -> List[int]:
        return sorted(pid for pid, lvl in self.levels.items() if lvl > 0)

    def count_at_or_above(self, level: int) -> int:
        return sum(1 for lvl in self.levels.values() if lvl >= level)


def score(proto: FuncIR) -> float:
    """A static complexity proxy.

    Not a measurement of runtime cost -- that would need profiling.  It ranks
    functions by how much structure they contain, which is the part that takes
    time to read.
    """
    return (
        proto.node_count * W_NODE
        + proto.loop_count * W_LOOP
        + proto.branch_count * W_BRANCH
        + proto.call_count * W_CALL
        + proto.closure_count * W_CLOSURE
    )


def _is_candidate(proto: FuncIR, module: IRModule, config: Config) -> Optional[str]:
    """Return None if the prototype may be virtualized, else the reason not."""
    if proto.proto_id == 0:
        return "main chunk bootstraps the runtime"
    if proto.node_count < config.min_virtualize_body_nodes:
        return f"trivial ({proto.node_count} nodes < {config.min_virtualize_body_nodes})"
    if config.virtualization_level == VirtualizationLevel.NONE:
        return "virtualization disabled by configuration"
    return None


def classify_module(module: IRModule, config: Config, rng: Rng) -> Classification:
    """Assign a virtualization level to every prototype in ``module``.

    Writes ``proto.virtualization`` and ``proto.vm_family`` as well as returning
    the classification, so downstream passes can read either.
    """
    result = Classification()
    cap = int(config.virtualization_level)

    if cap == 0:
        for proto in module.walk():
            proto.virtualization = 0
            proto.vm_family = None
            result.levels[proto.proto_id] = 0
            result.families[proto.proto_id] = None
            result.decisions.append(
                Decision(proto.proto_id, proto.name, 0, 0.0,
                         "virtualization disabled by configuration"))
        return result

    # Rank candidates, then take the budget.  Ties are broken with the build
    # rng so that two builds of the same source do not pick identically, while
    # a fixed seed still reproduces exactly.
    candidates = []
    for proto in module.walk():
        excluded = _is_candidate(proto, module, config)
        if excluded is not None:
            proto.virtualization = 0
            proto.vm_family = None
            result.levels[proto.proto_id] = 0
            result.families[proto.proto_id] = None
            result.decisions.append(
                Decision(proto.proto_id, proto.name, 0, 0.0, excluded))
            continue
        # The rng draw is a tie-break only; adding it to the score would let a
        # small function outrank a large one on luck.
        candidates.append((score(proto), rng.randbelow(1 << 20), proto))

    candidates.sort(key=lambda t: (t[0], t[1]), reverse=True)

    budget = max(0, int(config.max_vm_functions))
    for rank, (value, _tie, proto) in enumerate(candidates):
        if rank >= budget:
            proto.virtualization = 0
            proto.vm_family = None
            result.levels[proto.proto_id] = 0
            result.families[proto.proto_id] = None
            result.decisions.append(
                Decision(proto.proto_id, proto.name, 0, value,
                         f"outside the budget of {budget} virtualized functions"))
            continue

        level = _level_for(value, cap, config)
        # A prototype that creates closures cannot yet be virtualized above
        # LIGHT: the VM would have to build a closure whose upvalues point into
        # VM state, and that path is not implemented.  Excluding it is honest;
        # silently miscompiling it would not be.
        if proto.closure_count > 0 and level > int(VirtualizationLevel.LIGHT):
            level = int(VirtualizationLevel.LIGHT)
            reason = "creates closures; capped at LIGHT"
        else:
            reason = f"score {value:.1f}"

        proto.virtualization = level
        proto.vm_family = (
            getattr(config.vm_family, "value", config.vm_family)
            if level > 0 else None)
        result.levels[proto.proto_id] = level
        result.families[proto.proto_id] = proto.vm_family
        result.decisions.append(
            Decision(proto.proto_id, proto.name, level, value, reason))

    return result


def _level_for(value: float, cap: int, config: Config) -> int:
    """Map a complexity score onto a level, never exceeding the configured cap.

    Thresholds scale with ``min_virtualize_body_nodes`` so that changing the
    triviality cutoff moves the whole ladder rather than leaving it stranded.
    """
    base = max(1, int(config.min_virtualize_body_nodes))
    if value >= base * 8:
        level = 4
    elif value >= base * 4:
        level = 3
    elif value >= base * 2:
        level = 2
    else:
        level = 1
    return min(level, cap)

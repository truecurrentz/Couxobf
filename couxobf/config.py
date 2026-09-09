"""Build configuration for couxobf.

Everything that changes the output lives here, so that:

* a build is reproducible -- same source + version + config + seed gives
  byte-identical output;
* a build is *describable* -- the report can dump the resolved config;
* no transformation ever reads a global or an ad-hoc ``random`` call.

Levels
------
Several knobs are levels rather than booleans, because "on/off" forces an
all-or-nothing choice that either under-protects or bloats the output.

``virtualization_level`` is per function, not global: the classifier decides
which functions deserve to be virtualized, because putting trivial code in a
VM costs more than it protects.  This config carries the *ceiling*; the
classifier chooses the actual level for each function.
"""

from __future__ import annotations

import dataclasses
import enum
from dataclasses import dataclass, field
from typing import (Any, ClassVar, Dict, FrozenSet, List, Optional,
                    Tuple)

VERSION = "0.1.0"


class VirtualizationLevel(enum.IntEnum):
    """How much of a function's body runs inside the protection VM."""

    NONE = 0
    LIGHT = 1
    MEDIUM = 2
    HEAVY = 3
    MAXIMUM = 4

    @classmethod
    def parse(cls, value: Any) -> "VirtualizationLevel":
        if isinstance(value, cls):
            return value
        if isinstance(value, bool):
            return cls.HEAVY if value else cls.NONE
        if isinstance(value, int):
            return cls(max(0, min(4, value)))
        return cls[value.strip().upper()]


class VMFamily(enum.Enum):
    """The shape of the VM's state machine.

    All four execute the same instruction set semantics; they differ in where
    operands live, which changes the interpreter's shape enough that a
    deobfuscator written for one does not transfer to the others.
    """

    REGISTER = "register"
    STACK = "stack"
    ACCUMULATOR = "accumulator"
    HYBRID = "hybrid"

    @classmethod
    def parse(cls, value: Any) -> "VMFamily":
        if isinstance(value, cls):
            return value
        return cls(str(value).strip().lower())


class DispatcherFamily(enum.Enum):
    """How the VM decides which handler runs next."""

    #: Leave the dispatcher alone.  Without this member the enum could not
    #: express "no dispatcher transform", so a config that wanted one had no
    #: way to decline it -- and Config.pending_fields, which treats an enum
    #: with a NONE member as turn-off-able, had to special-case it.
    NONE = "none"
    NESTED_IF = "nested_if"
    TABLE = "table"
    BUCKET = "bucket"
    SEGMENTED = "segmented"
    DECISION_TREE = "decision_tree"
    STATE_TRANSITION = "state_transition"
    INDIRECT = "indirect"
    MIXED = "mixed"

    @classmethod
    def parse(cls, value: Any) -> "DispatcherFamily":
        if isinstance(value, cls):
            return value
        return cls(str(value).strip().lower())


class CachePolicy(enum.Enum):
    """Decoded-string retention.

    ``NONE`` is the default and the safest against memory inspection: every
    access re-decodes.  ``BOUNDED``/``FULL`` trade that for speed on hot
    strings and are opt-in.
    """

    NONE = "none"
    BOUNDED = "bounded"
    FULL = "full"

    @classmethod
    def parse(cls, value: Any) -> "CachePolicy":
        if isinstance(value, cls):
            return value
        return cls(str(value).strip().lower())


class IntegrityLevel(enum.Enum):
    NONE = "none"
    TAG_ONLY = "tag_only"
    TAG_AND_HASH = "tag_and_hash"

    @classmethod
    def parse(cls, value: Any) -> "IntegrityLevel":
        if isinstance(value, cls):
            return value
        return cls[str(value).strip().upper()]


@dataclass
class Config:
    # ---- selection -------------------------------------------------------
    virtualization_level: VirtualizationLevel = VirtualizationLevel.HEAVY
    vm_family: VMFamily = VMFamily.REGISTER
    max_vm_depth: int = 2
    mixed_execution: bool = True

    # ---- virtualization tuning ------------------------------------------
    #: Permute the opcode numbering.  Off means "the canonical numbers", which
    #: is weaker but makes two builds comparable byte for byte.
    opcode_randomization: bool = True
    #: How many instructions per *number*: 0 is one number per opcode, 1 gives
    #: some opcodes a second alias, 2 and 3 widen both the alias set and the
    #: numbering space.  The count of numbers the dispatcher branches on is
    #: thereby a build-time variable instead of a constant of the tool.
    opcode_aliases: int = 1
    #: Field widths, field order, padding and operand masks -- see
    #: :mod:`couxobf.vm.format`.  This is the switch for "a devirtualizer
    #: written against one artifact does not transfer to another".
    operand_randomization: bool = True
    #: 0 keeps the historical layout, 1 mixes, 2 spends every knob.  A level
    #: rather than a bool because the size cost is real and per-group.
    instruction_formats: int = 1
    #: How many distinct VMs one build emits.  Each group gets its own family,
    #: dispatcher and format, so 2 means two interpreters in the artifact.
    vm_variety: int = 1
    #: Register fields are widened and masked.  A full register permutation is
    #: not on the table: FORLOOP, CALL and SETLIST all address base+1, base+2,
    #: base+3, so a sound permutation needs live-range splitting the lowerer
    #: cannot provide.  Randomizing the *numbering* is available and is what
    #: this does.
    register_randomization: bool = True
    #: Fuse independent instruction pairs into super-instructions (#6).
    instruction_fusion: bool = True
    #: Offer fused pairs as distinct opcodes, growing the handler set.
    super_instructions: bool = True
    handler_splitting: bool = True
    dispatcher_family: DispatcherFamily = DispatcherFamily.MIXED
    #: When several VMs are emitted, give each one a different dispatch shape
    #: instead of drawing one shape for all of them.
    dispatcher_splitting: bool = True
    #: Protect jump targets by biasing or by relative offsets rather than raw
    #: positions, so the numbers in the stream mean nothing without the format.
    pc_protection: bool = True
    #: Keep control-flow edges out of the instruction stream: the payload
    #: carries an ordinal and the destinations live in their own blob.
    edge_indirection: bool = False
    #: Spread VM state across the families (accumulator/stack/register) rather
    #: than one discipline for the whole build.
    state_distribution: bool = True
    call_frame_obfuscation: bool = True

    # ---- control flow ----------------------------------------------------
    control_flow_level: int = 2
    opaque_predicates: bool = True
    branch_inversion: bool = True
    edge_indirection: bool = True
    block_permutation: bool = True
    encoded_pc: bool = True
    epoch_masks: bool = True

    # ---- data protection -------------------------------------------------
    string_protection_level: int = 2
    #: How numbers are stored in the pool.  0 stores the double; 1 stores an
    #: additively or multiplicatively disguised form; 2 also splits large
    #: integers into two halves.  Every scheme is exact in Luau's float
    #: semantics -- the point is that a decoder that only looks for
    #: `string.unpack(">d")` sees nothing -- and NaN, signed zero and the
    #: infinities stay on the exact path because no arithmetic encoding is safe
    #: for them.
    numeric_protection_level: int = 1
    constant_protection_level: int = 2
    table_key_protection: bool = True
    cache_policy: CachePolicy = CachePolicy.NONE
    bounded_cache_size: int = 16
    chunking_level: int = 2
    lazy_decode: bool = True
    chunk_size: int = 4096

    # ---- integrity -------------------------------------------------------
    integrity_level: IntegrityLevel = IntegrityLevel.TAG_AND_HASH
    self_test: bool = True

    # ---- output shaping --------------------------------------------------
    #: Dead-but-valid padding in the flattened dispatcher: 0 none, 1 a few
    #: unreachable states, 2 more.  Bounded on purpose (#63) -- padding is a
    #: fingerprint of its own once it dominates the artifact.
    junk_level: int = 1
    #: Decoy constants in the pool and decoy opcodes in the dispatch chain.
    #: Both are real entries that the program never uses, deliberately without a
    #: recognisable pattern in which ones they are.
    decoys: bool = True
    #: Number of decoy pool entries, per protected build.  Scales with the real
    #: pool so a small file does not gain a conspicuous block of noise.
    decoy_constants: int = 12
    metadata_fragmentation: bool = True
    identifier_polymorphism: bool = True
    fingerprint_reduction: bool = True
    minify: bool = False
    strip_types: bool = True

    # ---- runtime guards --------------------------------------------------
    #: Anti environment-logging: the artifact resolves its own runtime lookups
    #: through a snapshot of the real environment rather than whatever `getfenv`
    #: reports, and refuses to run if that environment has been given a logging
    #: `__index`/`__newindex` pair.  0 off, 1 snapshot, 2 snapshot plus refusal.
    env_guard: int = 1
    #: Anti-dump: the payload is never held in a shape a dumper can print (no
    #: decoded instruction table, no live bytecode for the virtualized
    #: functions), and the guard refuses when the standard dump surfaces --
    #: `string.dump`, `getbytecode`, `getscriptbytecode`, `debug.getinfo` --
    #: have been replaced by something that is not what the runtime captured.
    #: 0 off, 1 detect, 2 detect plus neutralise.
    dump_guard: int = 1
    #: When a guard fires: fail like any other invalid state (the default, and
    #: indistinguishable from a corrupt payload), or keep running.  "ignore"
    #: exists so the checks can be measured without a build dying on a machine
    #: that legitimately has a hooked environment.
    guard_policy: str = "fail"

    # ---- environment -----------------------------------------------------
    #: Compile-check the emitted runtime against the Roblox API surface, and use
    #: only globals Roblox actually provides.  It does not make the build run
    #: Roblox code -- there is no runtime here to run it against, and pretending
    #: otherwise would be the fake verification the design rules out.
    roblox_mode: bool = True
    debug_build: bool = False

    # ---- source handling -------------------------------------------------
    #: Tolerate `#`-style comments (and a `#!` shebang) on input by stripping
    #: them before parsing, and guarantee the output carries no comments at all
    #: -- not `#`, not `--`, not `--[[ ]]`.  Re-parsing after the strip is what
    #: proves the strip did not cut through a string.
    hash_comments: str = "auto"
    #: Emit a build-specific structural fingerprint into the report and the
    #: AAD, so our own tooling can recognise the format this build produced
    #: without a marker string in the artifact itself.
    fingerprint: bool = True

    # ---- determinism -----------------------------------------------------
    reproducible_seed: Optional[int] = None

    # ---- budgets ---------------------------------------------------------
    #: Refuse to keep transformations whose cost is out of proportion.  The
    #: pipeline enforces this by disabling the most expensive optional passes
    #: and rebuilding, then reporting what it gave up -- rather than emitting a
    #: 500x artifact and calling the user satisfied.
    #:
    #: 24 is not a guess at "how much bloat is fine": it is the measured cost of
    #: the most aggressive profile (a maximum build of a small example runs
    #: 12-16x), plus room for a file whose functions are mostly virtualizable.
    #: A ceiling below that would quietly downgrade every maximum build, which
    #: is worse than no ceiling at all, because the user asked for those passes.
    #: 0 disables the check.
    max_output_growth: float = 24.0
    max_vm_functions: int = 64
    min_virtualize_body_nodes: int = 12

    def __post_init__(self) -> None:
        self.virtualization_level = VirtualizationLevel.parse(self.virtualization_level)
        self.vm_family = VMFamily.parse(self.vm_family)
        self.dispatcher_family = DispatcherFamily.parse(self.dispatcher_family)
        self.cache_policy = CachePolicy.parse(self.cache_policy)
        self.integrity_level = IntegrityLevel.parse(self.integrity_level)
        self.max_vm_depth = max(0, min(3, int(self.max_vm_depth)))
        for name in ("control_flow_level", "string_protection_level",
                     "numeric_protection_level", "constant_protection_level",
                     "chunking_level", "junk_level", "opcode_aliases",
                     "instruction_formats", "env_guard", "dump_guard",
                     "decoy_constants"):
            setattr(self, name, max(0, min(3, int(getattr(self, name)))
                                    if name != "decoy_constants"
                                    else max(0, int(getattr(self, name)))))
        self.vm_variety = max(1, min(4, int(self.vm_variety)))
        if self.guard_policy not in ("fail", "ignore"):
            raise ValueError("guard_policy must be 'fail' or 'ignore'")
        if self.hash_comments not in ("auto", "strip", "strict"):
            raise ValueError("hash_comments must be auto, strip or strict")
        self.chunk_size = max(256, int(self.chunk_size))
        if self.reproducible_seed is not None:
            self.reproducible_seed = int(self.reproducible_seed)

    # -- profiles ---------------------------------------------------------
    @classmethod
    def compact(cls) -> "Config":
        return cls(
            virtualization_level=VirtualizationLevel.NONE,
            instruction_formats=0,
            vm_variety=1,
            opcode_aliases=0,
            edge_indirection=False,
            control_flow_level=0,
            string_protection_level=1,
            numeric_protection_level=0,
            constant_protection_level=1,
            chunking_level=0,
            lazy_decode=False,
            integrity_level=IntegrityLevel.TAG_ONLY,
            junk_level=0,
            decoys=False,
            super_instructions=False,
            instruction_fusion=False,
            handler_splitting=False,
            minify=True,
        )

    @classmethod
    def balanced(cls) -> "Config":
        return cls(
            virtualization_level=VirtualizationLevel.MEDIUM,
            control_flow_level=1,
            string_protection_level=2,
            chunking_level=1,
            junk_level=1,
        )

    @classmethod
    def hardened(cls) -> "Config":
        return cls()

    @classmethod
    def maximum(cls) -> "Config":
        return cls(
            virtualization_level=VirtualizationLevel.MAXIMUM,
            max_vm_depth=3,
            control_flow_level=3,
            string_protection_level=3,
            numeric_protection_level=2,
            constant_protection_level=3,
            chunking_level=3,
            junk_level=2,
            # Two VMs, every format knob, fused super-ops, indirect edges.  The
            # price is stated in the report rather than hidden: roughly one
            # extra interpreter.
            vm_variety=2,
            instruction_formats=2,
            opcode_aliases=2,
            edge_indirection=True,
            decoy_constants=24,
        )

    PROFILES = ("compact", "balanced", "hardened", "maximum")

    @classmethod
    def from_profile(cls, name: str) -> "Config":
        key = name.strip().lower()
        if key not in cls.PROFILES:
            raise ValueError(f"unknown profile {name!r}; expected one of {cls.PROFILES}")
        return getattr(cls, key)()

    # -- serialization ----------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for f in dataclasses.fields(self):
            v = getattr(self, f.name)
            if isinstance(v, enum.Enum):
                v = v.value
            out[f.name] = v
        return out

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        known = {f.name for f in dataclasses.fields(cls)}
        unknown = sorted(set(data) - known)
        if unknown:
            raise ValueError(f"unknown config keys: {', '.join(unknown)}")
        return cls(**data)

    def overrides(self, **kwargs: Any) -> "Config":
        return Config.from_dict({**self.to_dict(), **kwargs})

    # -- what this config actually delivers -----------------------------
    #
    # A config field that nothing reads is worse than a missing field: setting
    # it looks like a decision, and the build silently does something else.
    # Thirty-five of the fields below were in that state.  They stay declared
    # because they encode intent for work that is not done yet, but the build
    # now reports them instead of implying they were applied.
    #
    #: Fields that are read by the compiler and change the output.
    IMPLEMENTED: ClassVar[FrozenSet[str]] = frozenset({
        "virtualization_level",
        "vm_family",
        "block_permutation",
        "dispatcher_family",
        "opcode_randomization",
        "opcode_aliases",
        "operand_randomization",
        "instruction_formats",
        "vm_variety",
        "register_randomization",
        "instruction_fusion",
        "super_instructions",
        "pc_protection",
        "edge_indirection",
        "state_distribution",
        "dispatcher_splitting",
        "metadata_fragmentation",
        "string_protection_level",
        "numeric_protection_level",
        "cache_policy",
        "bounded_cache_size",
        "chunking_level",
        "lazy_decode",
        "chunk_size",
        "decoys",
        "decoy_constants",
        "junk_level",
        "control_flow_level",
        "opaque_predicates",
        "branch_inversion",
        "env_guard",
        "dump_guard",
        "guard_policy",
        "roblox_mode",
        "hash_comments",
        "fingerprint",
        "minify",
        "strip_types",
        "reproducible_seed",
        "max_vm_functions",
        "max_output_growth",
        "min_virtualize_body_nodes",
    })

    #: The value at which a field asks for nothing.
    @classmethod
    def _off_value(cls, field: "dataclasses.Field") -> Any:
        if field.type in (bool, "bool"):
            return False
        if field.type in (int, "int", float, "float"):
            return 0
        default = field.default
        if isinstance(default, enum.Enum):
            # an enum with a NONE member can be turned off; one without cannot
            return type(default).NONE if hasattr(type(default), "NONE") else None
        return None

    def pending_fields(self) -> List[Tuple[str, Any]]:
        """Declared capabilities this build will not deliver.

        Only fields whose current value asks for something are reported: a
        feature left off was never requested, so listing it would be noise.
        """
        out: List[Tuple[str, Any]] = []
        for f in dataclasses.fields(self):
            if f.name in self.IMPLEMENTED:
                continue
            value = getattr(self, f.name)
            off = self._off_value(f)
            if off is not None and value == off:
                continue
            out.append((f.name, value))
        return out

    def validate(self) -> List[str]:
        """Return human-readable problems (empty list means the config is fine)."""
        problems: List[str] = []
        if self.cache_policy is not CachePolicy.NONE and self.string_protection_level == 0:
            problems.append("cache_policy is set but string_protection_level is 0")
        if self.cache_policy is CachePolicy.BOUNDED and self.bounded_cache_size < 1:
            problems.append("bounded_cache_size must be >= 1")
        if self.max_vm_depth > 0 and self.virtualization_level is VirtualizationLevel.NONE:
            problems.append("max_vm_depth > 0 has no effect with virtualization_level=none")
        if self.integrity_level is not IntegrityLevel.NONE and self.chunking_level == 0 \
                and self.string_protection_level == 0 and self.constant_protection_level == 0:
            problems.append("integrity checking is enabled but nothing is protected")
        if self.junk_level > 0 and self.minify:
            problems.append("junk_level > 0 is partly undone by minify")
        if self.max_output_growth < 1.0:
            problems.append("max_output_growth must be >= 1.0")
        return problems

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

#: Selector spellings an earlier design advertised.  They stay loadable (the
#: selectors normalize them) but are no longer offered as choices anywhere:
#: there is one VM family and one guarded dispatcher.
_LEGACY_VM_FAMILIES = ("register", "stack", "accumulator", "hybrid")
_LEGACY_DISPATCHERS = ("woven", "nested_if", "table", "bucket", "segmented",
                       "decision_tree", "state_transition", "threaded",
                       "indirect")


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
    """The VM family selector.

    Production output is one woven VM (see :mod:`couxobf.vm.families`): the
    older register/stack/accumulator/hybrid engines were consolidated because
    cloning engines made artifacts larger and gave matchers several
    recognizable interpreter surfaces at once.  The legacy names stay
    loadable so saved configurations do not fail; they all normalize here.
    """

    WOVEN = "woven"

    @classmethod
    def parse(cls, value: Any) -> "VMFamily":
        if isinstance(value, cls):
            return value
        key = str(value).strip().lower()
        if key in _LEGACY_VM_FAMILIES:
            return cls.WOVEN
        return cls(key)


class DispatcherFamily(enum.Enum):
    """How the VM decides which handler runs next.

    The tool emits one guarded woven dispatcher per group; the dispatch
    *shape* variety lives inside the format (ladder vs bank), drawn per
    build, not in this selector.  ``MIXED`` is the don't-care default.  The
    older shape names stay loadable so saved configurations do not fail; they
    all normalize to ``MIXED``.
    """

    #: Leave the dispatcher alone.  Without this member the enum could not
    #: express "no dispatcher transform", so a config that wanted one had no
    #: way to decline it -- and Config.pending_fields, which treats an enum
    #: with a NONE member as turn-off-able, had to special-case it.
    NONE = "none"
    MIXED = "mixed"

    @classmethod
    def parse(cls, value: Any) -> "DispatcherFamily":
        if isinstance(value, cls):
            return value
        key = str(value).strip().lower()
        if key in _LEGACY_DISPATCHERS:
            return cls.MIXED
        return cls(key)


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


@dataclass
class Config:
    # ---- selection -------------------------------------------------------
    virtualization_level: VirtualizationLevel = VirtualizationLevel.HEAVY
    #: Accepted and normalized to the single woven VM; kept so saved configs
    #: naming an older family still load, not so a family can be chosen.
    vm_family: VMFamily = VMFamily.WOVEN

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
    #: One switch for the "best mixed VM" mode.  On means the build chooses and
    #: combines the strongest pieces of every VM architecture and dispatch shape:
    #: single woven VM state and guarded opcode dispatch
    #: dispatch, per-group formats and per-build opcode maps.  Off keeps a single
    #: pinned VM for debugging/reproducibility.
    vm_polymorphism: bool = True
    #: How many distinct VMs one build emits.  In polymorphic mode this is treated
    #: as a floor and the build may raise it enough to exercise more than one
    #: architecture when the program has enough functions.
    vm_variety: int = 1
    #: Register fields are widened and masked.  A full register permutation is
    #: not on the table: FORLOOP, CALL and SETLIST all address base+1, base+2,
    #: base+3, so a sound permutation needs live-range splitting the lowerer
    #: cannot provide.  Randomizing the *numbering* is available and is what
    #: this does.
    register_randomization: bool = True
    #: Fuse independent instruction pairs into super-instructions (#6).
    #: Disabled by default: distinctive fused semantics can be easier to match
    #: than smaller primitive handlers.  The option remains for compatibility.
    instruction_fusion: bool = False
    #: Offer fused pairs as distinct opcodes, growing the handler set.
    #: Disabled by default for the same reason as instruction_fusion.
    super_instructions: bool = False
    dispatcher_family: DispatcherFamily = DispatcherFamily.MIXED
    #: Protect jump targets by biasing or by relative offsets rather than raw
    #: positions, so the numbers in the stream mean nothing without the format.
    pc_protection: bool = True
    #: Disguise the opcode *number* in the payload: the dispatcher still branches
    #: on the number its map assigned, but the stream carries a bijective image
    #: of it (a rotation, an affine map, or a halves swap).  Costs no bytes -- it
    #: is arithmetic on the fetch, not a wider field -- and it is what stops a
    #: table of "byte 7 is ADD", recovered from one build and pointed at another.
    #: Lives inside the instruction format, so it needs `operand_randomization`
    #: on: with variety 0 `FormatSpec.draw` returns the historical format untouched
    #: and there is no cipher field to draw.  `instruction_formats` then decides
    #: how much the format -- and with it the choice of image -- is allowed to move.
    opcode_cipher: bool = True
    #: Give each VM group only the opcodes the prototypes on it actually use,
    #: instead of the full instruction set with handlers nobody calls.  The
    #: dispatcher shrinks per group, so the number of arms becomes a property of
    #: the function; a build whose one VM runs three numeric helpers is not the
    #: build that virtualized a table-heavy one.
    vm_isa_subset: bool = True
    #: R5 (second increment): virtualize functions that *capture upvalues*.
    #: The stub the entry point replaces such a function with builds, per
    #: upvalue, a getter and a setter closure over the same expression the
    #: native reconstruction uses to reach that variable -- so reads and writes
    #: stay live and agree with any native sibling that shares it.  Only a
    #: prototype whose upvalues all resolve into *native* (non-virtualized)
    #: prototypes qualifies; an upvalue that would point into another VM's
    #: frame is still refused, because a VM frame is a table and a real Luau
    #: closure must be able to see what it names.  Off by default: the
    #: accessor closures are new machinery and the fixture list in
    #: tests/test_vm_upvalues.py is the gate that argues for turning it on.
    vm_upvalues: bool = False
    #: R5's third increment: virtualize a function that *creates* closures.
    #: Only children that capture nothing qualify -- a child with no upvalues
    #: needs nothing from the frame it was born in, so the interpreter can
    #: build its entry stub from its own locals -- and a virtualized prototype
    #: takes its virtualizable subtree in with it, because the interpreter has
    #: no function value for a child left native and a helper is usually too
    #: small to earn a place of its own.  A child that captures is served by
    #: accessors the interpreter builds over the parent's frame -- the one
    #: place that can see it -- which is why capturing children need
    #: ``vm_upvalues`` as well: it is the same accessor machinery.  Off by
    #: default for the same reason ``vm_upvalues``
    #: is: it is new machinery, and tests/test_vm_closures.py is the gate.
    vm_closures: bool = False
    #: Keep control-flow edges out of the instruction stream: the payload
    #: carries an ordinal and the destinations live in their own blob.
    edge_indirection: bool = True

    # ---- control flow ----------------------------------------------------
    control_flow_level: int = 2
    opaque_predicates: bool = True
    branch_inversion: bool = True
    block_permutation: bool = True

    # ---- data protection -------------------------------------------------
    string_protection_level: int = 2
    #: How numbers are stored in the pool.  0 stores the double; 1 masks the
    #: double's bytes with a per-entry keystream; 2 also rebuilds exact
    #: integers (abs(v) <= 2**53) from two 32-bit halves at runtime, so no
    #: double bytes for them exist in the blob.  Every scheme is exact in
    #: Luau's float semantics -- the point is that a decoder that only looks
    #: for `string.unpack(">d")` sees nothing -- and NaN, signed zero and the
    #: infinities stay on the masked-double path because no arithmetic
    #: encoding is safe for them.
    numeric_protection_level: int = 1
    constant_protection_level: int = 1
    table_key_protection: bool = True
    #: R9: rewrite the keys of provably-static local tables to per-build
    #: numeric handles, so the key strings never reach the artifact.  Opt-in:
    #: the safety rule is a strict whitelist (see couxobf/index_to_num.py),
    #: so nothing a default build does today changes when this stays off.
    #: A table can bow out with ``--!couxobf:no_index_to_num`` above it.
    index_to_num: bool = False
    cache_policy: CachePolicy = CachePolicy.NONE
    bounded_cache_size: int = 16

    # ---- integrity -------------------------------------------------------
    #: The pool's AEAD tag is always verified; there is no dial for that.
    #: ``self_test`` is the only remaining integrity knob (opt-in build-time
    #: self checks).
    self_test: bool = False

    # ---- output shaping --------------------------------------------------
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

    # ---- output encoding -------------------------------------------------
    #: How sealed blobs (pool ciphertext, string-bank pages, ticket metadata)
    #: are spelled in the artifact.  "dense" ships them as base85 over a
    #: per-build alphabet (1.25 source chars per byte, decoded once at load);
    #: "hex" keeps the historical escaped form (~4 chars per byte) for
    #: debugging and as a stable baseline.  Same protection either way -- the
    #: masking and authenticated encryption are untouched; only the spelling
    #: of already-sealed bytes changes.  The decoder preamble costs a fixed
    #: ~1 KB, so builds whose sealed material is below ~512 bytes keep hex
    #: and say "dense-skipped" in the report.
    blob_encoding: str = "dense"

    # ---- environment -----------------------------------------------------
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
        for name in ("control_flow_level", "string_protection_level",
                     "numeric_protection_level", "constant_protection_level",
                     "opcode_aliases",
                     "instruction_formats", "env_guard", "dump_guard",
                     "decoy_constants"):
            setattr(self, name, max(0, min(3, int(getattr(self, name)))
                                    if name != "decoy_constants"
                                    else max(0, int(getattr(self, name)))))
        self.vm_variety = max(1, min(4, int(self.vm_variety)))
        if self.guard_policy not in ("fail", "ignore"):
            raise ValueError("guard_policy must be 'fail' or 'ignore'")
        if self.blob_encoding not in ("dense", "hex"):
            raise ValueError("blob_encoding must be 'dense' or 'hex'")
        if self.hash_comments not in ("auto", "strip", "strict"):
            raise ValueError("hash_comments must be auto, strip or strict")
        if self.reproducible_seed is not None:
            self.reproducible_seed = int(self.reproducible_seed)

    # -- profiles ---------------------------------------------------------
    @classmethod
    def compact(cls) -> "Config":
        return cls(
            virtualization_level=VirtualizationLevel.NONE,
            instruction_formats=0,
            vm_polymorphism=False,
            vm_variety=1,
            opcode_aliases=0,
            edge_indirection=False,
            control_flow_level=0,
            string_protection_level=1,
            numeric_protection_level=0,
            constant_protection_level=1,
            decoys=False,
            super_instructions=False,
            instruction_fusion=False,
            opcode_cipher=False,
            vm_isa_subset=False,
            minify=True,
        )

    @classmethod
    def balanced(cls) -> "Config":
        return cls(
            virtualization_level=VirtualizationLevel.MEDIUM,
            control_flow_level=1,
            string_protection_level=2,
        )

    @classmethod
    def hardened(cls) -> "Config":
        return cls()

    @classmethod
    def maximum(cls) -> "Config":
        return cls(
            virtualization_level=VirtualizationLevel.MAXIMUM,
            control_flow_level=3,
            string_protection_level=3,
            numeric_protection_level=2,
            constant_protection_level=1,
            # One hardened VM, every format knob, aliases and indirect edges.
            # Fused super-ops are intentionally not enabled by default: they make
            # highly distinctive semantic signatures for a static matcher.
            vm_polymorphism=True,
            instruction_fusion=False,
            super_instructions=False,
            vm_variety=3,
            instruction_formats=2,
            opcode_aliases=2,
            edge_indirection=True,
            env_guard=2,
            dump_guard=2,
            decoy_constants=24,
            max_output_growth=0,
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
    # The fields that were in that state were removed outright (R12) rather
    # than left as inert dials; what remains below are fields the build does
    # not deliver yet, reported by pending_fields instead of implied.
    #
    #: Fields that are read by the compiler and change the output.
    IMPLEMENTED: ClassVar[FrozenSet[str]] = frozenset({
        "virtualization_level",
        "vm_polymorphism",
        "vm_family",
        "block_permutation",
        "opcode_randomization",
        "opcode_aliases",
        "operand_randomization",
        "instruction_formats",
        "vm_variety",
        "register_randomization",
        "instruction_fusion",
        "super_instructions",
        "pc_protection",
        "opcode_cipher",
        "vm_isa_subset",
        "vm_upvalues",
        "vm_closures",
        "edge_indirection",
        "dispatcher_family",
        "metadata_fragmentation",
        "string_protection_level",
        "constant_protection_level",
        "numeric_protection_level",
        "table_key_protection",
        "index_to_num",
        "cache_policy",
        "bounded_cache_size",
        "decoys",
        "decoy_constants",
        "control_flow_level",
        "opaque_predicates",
        "branch_inversion",
        "env_guard",
        "dump_guard",
        "guard_policy",
        "blob_encoding",
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
        if self.max_output_growth != 0 and self.max_output_growth < 1.0:
            problems.append("max_output_growth must be 0 (disabled) or >= 1.0")
        return problems

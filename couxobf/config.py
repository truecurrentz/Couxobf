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
from typing import Any, Dict, List, Optional

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
    opcode_randomization: bool = True
    operand_randomization: bool = True
    register_randomization: bool = True
    instruction_fusion: bool = True
    handler_splitting: bool = True
    dispatcher_family: DispatcherFamily = DispatcherFamily.MIXED
    dispatcher_splitting: bool = True
    super_instructions: bool = True
    pc_protection: bool = True
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
    junk_level: int = 1
    decoys: bool = True
    metadata_fragmentation: bool = True
    identifier_polymorphism: bool = True
    fingerprint_reduction: bool = True
    minify: bool = False
    strip_types: bool = True

    # ---- environment -----------------------------------------------------
    roblox_mode: bool = True
    debug_build: bool = False

    # ---- determinism -----------------------------------------------------
    reproducible_seed: Optional[int] = None

    # ---- budgets ---------------------------------------------------------
    max_output_growth: float = 8.0
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
                     "chunking_level", "junk_level"):
            setattr(self, name, max(0, min(3, int(getattr(self, name)))))
        self.chunk_size = max(256, int(self.chunk_size))
        if self.reproducible_seed is not None:
            self.reproducible_seed = int(self.reproducible_seed)

    # -- profiles ---------------------------------------------------------
    @classmethod
    def compact(cls) -> "Config":
        return cls(
            virtualization_level=VirtualizationLevel.NONE,
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

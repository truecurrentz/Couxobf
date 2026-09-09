"""The end-to-end build: Luau source in, protected Luau out.

One function, :func:`build`, runs the whole pipeline the design specifies:

    source -> lexer/parser -> AST -> semantic analysis -> custom IR
           -> optimization -> semantic transformation -> VM lowering
           -> bytecode encoding -> payload protection -> runtime generation
           -> final Luau -> validation

Every stage is a real module; nothing here re-implements one.  The pipeline's
own job is ordering, seed handling, and reporting -- and refusing to return
output that failed validation.

Two things this module is deliberate about.

*The seed is part of the result.*  A reproducible build means the same source,
version, config and seed produce identical output.  If the caller did not pin a
seed, a fresh one is drawn and handed back, because a build nobody can repeat
is a build nobody can diagnose.

*The report describes cost, not confidence.*  It says what an analyst has to do
and how much work each step is.  It does not produce a security percentage,
because there is no such quantity: the key material ships inside the artifact,
so anything a determined analyst wants badly enough they can eventually get.
"""

from __future__ import annotations

import secrets
import textwrap
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from . import classify as _classify
from . import ir as _ir
from . import lower_back as _lower_back
from . import parser as _parser
from . import sema as _sema
from .config import Config, VirtualizationLevel
from .crypto.kdf import KeyMaterial
from .rng import make_domains
from .verify.output import ValidationReport, validate_or_raise, validate_output

#: How many bytes of seed material a build uses.
SEED_BYTES = 16


class BuildError(Exception):
    """The build could not be completed."""


@dataclass
class BuildStats:
    """What the build did, for the report and for regression tests."""

    input_bytes: int = 0
    output_bytes: int = 0
    prototypes: int = 0
    virtualized: int = 0
    #: Prototype ids the VM took, and why the others were left native.
    native_reasons: Dict[str, int] = field(default_factory=dict)
    opcode_map: Dict[str, int] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    #: Virtualization level per prototype, from the classifier.
    decisions: List[Any] = field(default_factory=list)


@dataclass
class BuildResult:
    """A finished build."""

    source: str
    seed: bytes
    config: Config
    stats: BuildStats
    validation: ValidationReport
    report: str = ""
    #: Names the reconstruction actually chose.  Per-build, so nothing outside
    #: the build can predict them.
    runtime_names: Dict[str, Any] = field(default_factory=dict)


def seed_from_config(config: Config) -> bytes:
    """The build seed: the pinned one if there is one, else a fresh draw.

    A pinned seed goes through SHA-256 rather than being packed straight into
    16 bytes, so that seeds which differ by one bit still diverge completely
    and a small integer seed does not produce a mostly-zero key.
    """
    if config.reproducible_seed is not None:
        from .crypto.sha256 import sha256
        return sha256(b"couxobf/seed/v1\0" +
                      str(int(config.reproducible_seed)).encode())[:SEED_BYTES]
    return secrets.token_bytes(SEED_BYTES)


def build(source: str, config: Optional[Config] = None,
          seed: Optional[bytes] = None, name: str = "input.luau",
          toolchain: Any = None, verify: bool = True) -> BuildResult:
    """Run the whole pipeline and return the protected source.

    ``verify`` defaults to True and raises
    :class:`~couxobf.verify.output.OutputValidationError` on invalid output.
    Turn it off only when the caller intends to validate separately -- an
    unverified build is exactly the failure mode the check exists to prevent.
    """
    started = time.perf_counter()
    config = config or Config()
    seed = seed if seed is not None else seed_from_config(config)
    if len(seed) < SEED_BYTES:
        raise BuildError(f"seed must be at least {SEED_BYTES} bytes")

    # -- front end --------------------------------------------------------
    try:
        ast = _parser.parse(source, name)
    except Exception as exc:
        raise BuildError(f"{name} does not parse: {exc}") from None

    # Semantic analysis runs for its own sake: it is what the identifier
    # renamer and the classifier read, and running it here means a source file
    # that breaks it fails now, at the front, with the file name attached.
    try:
        _sema.ScopeAnalyzer().analyze(ast)
    except Exception as exc:
        raise BuildError(f"{name} failed semantic analysis: {exc}") from None

    # -- IR ---------------------------------------------------------------
    module = _ir.Lowerer().lower(ast)
    domains = make_domains(seed)

    # -- selection --------------------------------------------------------
    # The classifier runs before reconstruction so its decisions can be passed
    # down as an explicit selection.  It writes proto.virtualization as a side
    # effect, which the report reads back.
    classification = _classify.classify_module(module, config,
                                               domains.get("vm"))
    selected = _select_for_vm(module, classification)

    # -- back end ---------------------------------------------------------
    runtime_names: Dict[str, Any] = {}
    out = _lower_back.reconstruct_protected(
        module,
        KeyMaterial.from_seed(seed),
        domains.get("constants"),
        name.encode("utf-8", "surrogatepass"),
        cache_policy=str(getattr(config.cache_policy, "value",
                                 config.cache_policy)),
        cache_bound=config.bounded_cache_size,
        minify=config.minify,
        vm_level=config.virtualization_level,
        vm_rng=domains.get("vm"),
        vm_protos=selected,
        vm_family=config.vm_family,
        block_permutation=config.block_permutation,
        layout_rng=domains.get("cfg"),
        dispatcher_family=config.dispatcher_family,
        opcode_randomization=config.opcode_randomization,
        string_level=config.string_protection_level,
        # Its own stream: reusing the constant pool's randomness for the string
        # bank would correlate two unrelated layouts, which is exactly what
        # domain separation exists to prevent.
        string_rng=domains.get("strings"),
        string_cache_policy=str(getattr(config.cache_policy, "value",
                                        config.cache_policy)),
        names_out=runtime_names,
    )

    stats = _collect_stats(module, classification, out, source)
    stats.elapsed_ms = (time.perf_counter() - started) * 1000.0

    # The emitted helper names, so helper uniqueness is checked against what
    # this build really declared rather than a stale fixed list.  They are
    # per-build now, so a fixed tuple would count zeros and pass silently.
    helpers = tuple((runtime_names.get("helpers")
                     or _lower_back.DEFAULT_HELPERS).values())
    validation = (validate_or_raise(out, source, toolchain, helpers) if verify
                  else validate_output(out, source, toolchain, helpers))

    result = BuildResult(source=out, seed=seed, config=config, stats=stats,
                         validation=validation, runtime_names=runtime_names)
    result.report = cost_report(result)
    return result


def _select_for_vm(module, classification) -> Set[int]:
    """Prototypes the classifier picked that the encoder can actually take.

    The classifier does not know the VM's constraints -- upvalues, varargs and
    nested closures are out, because the VM frame is a table and anything a
    real Luau closure must see cannot live in it.  Intersecting here means the
    reported count is the count that will really be virtualized, not the count
    the classifier wished for.
    """
    from .vm import encode as _encode

    chosen = set()
    for proto in module.walk():
        if classification.level(proto.proto_id) <= 0:
            continue
        ok, _reason = _encode.can_virtualize(proto)
        if ok:
            chosen.add(proto.proto_id)
    return chosen


def _collect_stats(module, classification, out: str, source: str) -> BuildStats:
    from .vm import encode as _encode

    stats = BuildStats(input_bytes=len(source.encode("utf-8", "surrogatepass")),
                       output_bytes=len(out.encode("utf-8", "surrogatepass")))
    # The classifier's own reason, not a guess: it is the thing that decided,
    # so it is the thing that can explain itself.  Reporting "not selected"
    # would hide the node floor, which is the reason most prototypes are left
    # alone and the first setting a user needs to find.
    reasons_by_proto = {d.proto_id: d.reason for d in classification.decisions}
    encodable = {p.proto_id for p in module.walk()
                 if _encode.can_virtualize(p)[0]}
    reasons: Dict[str, int] = {}
    for proto in module.walk():
        stats.prototypes += 1
        pid = proto.proto_id
        if pid in encodable and classification.level(pid) > 0:
            stats.virtualized += 1
            continue
        if pid not in encodable:
            key = _encode.can_virtualize(proto)[1] or "not encodable"
        else:
            key = reasons_by_proto.get(pid) or "not selected"
        reasons[key] = reasons.get(key, 0) + 1
    stats.native_reasons = reasons
    stats.decisions = list(classification.decisions)
    return stats


def cost_report(result: BuildResult) -> str:
    """A deobfuscation cost model, in words.

    Deliberately no percentage and no score.  A number here would imply a
    quantity that does not exist: there is no measurable "how secure" for a
    client-side transform whose key ships with it.
    """
    s = result.stats
    c = result.config
    lines: List[str] = []
    lines.append("couxobf build report")
    lines.append("=" * 46)
    lines.append("")
    lines.append(f"seed (hex)          : {result.seed.hex()}")
    lines.append(f"input               : {s.input_bytes} bytes")
    lines.append(f"output              : {s.output_bytes} bytes "
                 f"({s.output_bytes / max(1, s.input_bytes):.1f}x)")
    lines.append(f"prototypes          : {s.prototypes}")
    lines.append(f"virtualized         : {s.virtualized}")
    lines.append(f"virtualization      : "
                 f"{VirtualizationLevel.parse(c.virtualization_level).name.lower()}")
    lines.append(f"vm family           : {getattr(c.vm_family, 'value', c.vm_family)}")
    lines.append(f"elapsed             : {s.elapsed_ms:.1f} ms")
    lines.append("")

    lines.append("what an analyst has to do")
    lines.append("-" * 46)
    lines.append("1. Locate the interpreter.  Its local names come from the")
    lines.append("   build's identifier stream, so they differ per build.")
    if s.virtualized:
        lines.append(f"2. Recover the opcode numbering.  {_opcode_count()} opcodes")
        lines.append("   are permuted per build; the numbers are only meaningful")
        lines.append("   inside this artifact.")
        lines.append("3. Decode the bytecode.  It is encrypted in the constant")
        lines.append("   pool, so the pool has to be decrypted first -- which")
        lines.append("   means recovering a key that is present in the file.")
        lines.append("4. Re-read the handlers.  Each one is plain Luau, and")
        lines.append("   permuting opcode *numbers* does not change what a")
        lines.append("   handler does.  This step is the real cost, and it is")
        lines.append("   not affected by any setting in this build.")
    else:
        lines.append("2. Read the reconstructed Luau directly.  No prototype met")
        lines.append("   the bar for virtualization, so there is no bytecode")
        lines.append("   and no dispatcher -- only renamed identifiers and an")
        lines.append("   encrypted constant pool.")
    lines.append("")

    pending = c.pending_fields()
    if pending:
        # Named explicitly, because a config field that silently does nothing
        # is the same defect as a report that overstates what it did.  The
        # defaults request all of these, so a default build lists all of them.
        lines.append("requested but not applied")
        lines.append("----------------------------------------------")
        lines.append(f"{len(pending)} declared capabilities are not implemented")
        lines.append("yet. Setting them changes nothing:")
        names = ", ".join(n for n, _ in pending)
        lines.extend(textwrap.wrap(names, width=46,
                                   initial_indent="  ", subsequent_indent="  "))
        lines.append("")

    lines.append("what this does not do")
    lines.append("-" * 46)
    lines.append("* Client-side obfuscation is not irreversible.  Everything")
    lines.append("  needed to run the program is in the file, including the")
    lines.append("  key material, so a determined analyst can decrypt and")
    lines.append("  disassemble it.  This raises cost; it does not prevent.")
    lines.append("* It is not a security boundary.  Secrets that must stay")
    lines.append("  secret belong on a server.  Anything shipped to a client")
    lines.append("  should be treated as readable.")
    lines.append("* Opcode permutation defeats number-based matching, not")
    lines.append("  structural matching.  Two builds share handler shapes.")
    lines.append("")

    if s.native_reasons:
        lines.append("prototypes left native")
        lines.append("-" * 46)
        for reason, count in sorted(s.native_reasons.items(),
                                    key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"  {count:4d}  {reason}")
        lines.append("")
    return "\n".join(lines) + "\n"


def _opcode_count() -> int:
    """How many opcodes the VM permutes, for the report."""
    from .vm.isa import SUPPORTED
    return len(SUPPORTED)

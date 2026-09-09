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

import re
import secrets
import textwrap
import time
import dataclasses
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from . import classify as _classify
from . import comments as _comments
from .vm import format as _vm_format
from .vm import runtime as _vm_runtime
from . import ir as _ir
from . import lower_back as _lower_back
from . import parser as _parser
from . import sema as _sema
from .config import Config, VirtualizationLevel, VMFamily
from .crypto.kdf import KeyMaterial
from .rng import make_domains
from .verify.output import ValidationReport, validate_or_raise, validate_output

#: How many bytes of seed material a build uses.
SEED_BYTES = 16


def _alias_ratio(config) -> float:
    """Chance that an opcode is given an extra number this build.

    A ratio rather than a count, because the useful property is "the number of
    dispatch arms moves with the build" and that depends on how many opcodes the
    ISA has, which is itself a constant of the tool only until the aliases are
    added.
    """
    return {0: 0.0, 1: 0.35, 2: 0.6, 3: 0.8}[int(config.opcode_aliases)]


def _family_rotation(vm_family) -> tuple:
    """Every family this build can spread across, with the pinned one first.

    ``state_distribution`` asks for different VMs in one artifact and
    ``vm_family`` asks for a specific one.  Both are real options, so the
    rotation honors the pin for group 0 and spreads the rest behind it, instead
    of one silently cancelling the other.
    """
    wanted = str(getattr(vm_family, "value", vm_family))
    ordered = [wanted] + [f.value for f in VMFamily if f.value != wanted]
    return tuple(ordered)


def _format_variety(config) -> int:
    """How much the instruction format is allowed to move. 0 means never."""
    if not config.operand_randomization:
        return 0
    return int(config.instruction_formats)


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
    #: `#` comments removed from the input before parsing (#5's input side).
    hash_comments: int = 0
    #: Size ratio the build was asked to stay under, 0 when unset.
    budget_ceiling: float = 0.0
    #: Which pass groups were given up to stay under that ceiling, in order.
    budget_trimmed: List[str] = field(default_factory=list)
    #: What the environment/dump guard ended up doing, from the build itself.
    guard: Dict[str, Any] = field(default_factory=dict)


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

    Two things happen here that a single pass through the stages cannot:

    *the source is prepared* -- :attr:`Config.hash_comments` decides whether
    ``#`` comments are stripped first, and the strip is followed by a re-parse so
    that a comment which looked like one but was inside a string fails the build
    instead of changing the program (:mod:`couxobf.comments`);

    *the output has a budget* -- :attr:`Config.max_output_growth` is a ceiling on
    the size ratio, and the pipeline meets it by giving up transformations in a
    fixed order, least-protection-per-byte first, then says in the report what it
    gave up (:func:`_within_budget`).  Both exist because a build that quietly
    grows 300x or quietly deletes the user's comments is a build whose report is
    fiction.

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
    source_size = len(source.encode("utf-8", "surrogatepass"))

    try:
        text, stripped = _comments.prepare(source, name, config.hash_comments,
                                           _parser.parse)
    except ValueError as exc:
        # A build error, not a ValueError: the caller asked for a build, and the
        # CLI and the web API both report BuildError with the file name in it.
        raise BuildError(str(exc)) from None
    result = _build_once(text, config, seed, name, toolchain, verify,
                         source_size)
    result = _within_budget(text, result, seed, name, toolchain, verify,
                            source_size)
    result.stats.hash_comments = stripped
    result.stats.elapsed_ms = (time.perf_counter() - started) * 1000.0
    result.report = cost_report(result)
    return result


#: What the size budget gives up, in order, least useful per byte first.  Each
#: entry is one rebuild: every field in it is turned off together, because they
#: buy the same kind of noise and a build that lost three single knobs one at a
#: time would report three things nobody could act on.
_BUDGET_TRIMS = (
    (("junk_level", 0), ("decoys", False), ("decoy_constants", 0)),
    (("opaque_predicates", False),),
    (("instruction_fusion", False), ("super_instructions", False)),
    (("opcode_aliases", 0),),
    (("chunking_level", 0), ("lazy_decode", False)),
    (("vm_variety", 1), ("state_distribution", False)),
    (("control_flow_level", 0), ("block_permutation", False)),
    (("edge_indirection", False), ("instruction_formats", 0)),
    (("string_protection_level", 1), ("numeric_protection_level", 0)),
)

#: Human-readable names for the same groups, in the same order, for the report.
_BUDGET_LABELS = (
    "junk states and decoy entries",
    "opaque predicates",
    "instruction fusion",
    "opcode aliases",
    "constant-pool chunking and lazy decode",
    "second VM group",
    "control-flow flattening and block permutation",
    "edge indirection and per-group formats",
    "string and numeric protection",
)


def _within_budget(text: str, result: "BuildResult", seed: bytes, name: str,
                   toolchain: Any, verify: bool, source_size: int
                   ) -> "BuildResult":
    """Rebuild with the cheapest-to-drop passes off until the ratio fits.

    A ceiling is only honest if exceeding it costs something real, and the only
    thing worth giving up is the padding: dropping it makes the artifact smaller
    *and* easier to read, which is precisely the trade the user should be told
    about rather than have made for them silently.  The report names every group
    that was given up, so a build that trimmed does not look like a build that
    configured less.
    """
    ceiling = float(result.config.max_output_growth or 0.0)
    if ceiling < 1.0:
        result.stats.budget_ceiling = 0.0
        return result
    stats = result.stats
    stats.budget_ceiling = ceiling
    ratio = stats.output_bytes / max(1, source_size)
    if ratio <= ceiling:
        return result
    config = result.config
    current = result
    given_up: List[str] = []
    for trims, label in zip(_BUDGET_TRIMS, _BUDGET_LABELS):
        changes = {field_name: value for field_name, value in trims
                   if getattr(config, field_name) != value}
        if not changes:
            continue
        config = dataclasses.replace(config, **changes)
        candidate = _build_once(text, config, seed, name, toolchain, verify,
                                source_size)
        current = candidate
        ratio = candidate.stats.output_bytes / max(1, source_size)
        given_up.append(label)
        if ratio <= ceiling:
            break
    # The list is attached at the end rather than appended per rebuild: every
    # rebuild brings a fresh stats object, and a report that named only the last
    # thing given up would understate what the ceiling cost.
    current.stats.budget_ceiling = ceiling
    current.stats.budget_trimmed = given_up
    return current


#: A `#` with code before it and a space on at least one side: the shape a
#: trailing comment takes, and the one shape the stripper cannot legally touch.
_TRAILING_HASH = re.compile(r"\S\s+#\s")


def _parse_hint(source: str, exc: Exception) -> str:
    """The parser's message, plus the one explanation it cannot give itself.

    `#` mid-line is Luau's length operator, so a stripper that removed it would
    corrupt real code -- which means a file whose author used trailing `#`
    comments fails to parse, and a bare "unexpected token" sends them looking
    through their own code for a typo that is not there.
    """
    text = str(exc)
    for line in source.splitlines():
        if _TRAILING_HASH.search(line):
            return (text + " -- a `#` after code on the same line is the length "
                    "operator in Luau; hash_comments strips only a `#` that starts"
                    " a line, so use `--` for a trailing comment")
    return text


def _build_once(source: str, config: Config, seed: bytes, name: str,
                toolchain: Any, verify: bool, source_size: int) -> BuildResult:
    """One full pass over the stages, with no source preparation and no retry.

    Split out of :func:`build` because the budget loop has to run it more than
    once against the same seed: a rebuild that also re-drew the seed would change
    two things at a time, and nothing in the report would be attributable.
    """
    started = time.perf_counter()
    config = config or Config()

    # -- front end --------------------------------------------------------
    try:
        ast = _parser.parse(source, name)
    except Exception as exc:
        raise BuildError(f"{name} does not parse: {_parse_hint(source, exc)}"
                         ) from None

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
        fmt_prefs=_vm_format.FormatPrefs.from_config(config),
        string_level=config.string_protection_level,
        # Its own stream: reusing the constant pool's randomness for the string
        # bank would correlate two unrelated layouts, which is exactly what
        # domain separation exists to prevent.
        string_rng=domains.get("strings"),
        string_cache_policy=str(getattr(config.cache_policy, "value",
                                        config.cache_policy)),
        # One VM per build is the historical behaviour.  Asking for more groups
        # is what makes "several VM families per artifact" true, and
        # `state_distribution` is the config's name for exactly that spread.
        vm_variety=(max(1, int(config.vm_variety))
                    if (config.state_distribution or config.vm_variety > 1)
                    else 1),
        # Spread, but starting where the user pointed: a build that pinned
        # ``vm_family`` and turned state distribution on still gets that family
        # for group 0, with the rest rotated behind it.  Ignoring the pin would
        # make the config's own field unobservable, which is the one thing a
        # knob is not allowed to be.
        families=(_family_rotation(config.vm_family)
                  if config.state_distribution else None),
        dispatchers=(tuple(_vm_runtime.DISPATCHERS)
                     if config.dispatcher_splitting else None),
        fusion_level=(1 if config.instruction_fusion
                      and config.super_instructions else 0),
        alias_ratio=_alias_ratio(config),
        alias_chance=(0.35 if config.opcode_aliases else 0.0),
        # The environment-logging and dump defences.  Both are read here and
        # nowhere else, so "the guard did not turn on" can only mean one of these
        # two fields was set to 0 -- which is what the report then says.
        env_guard=int(config.env_guard),
        dump_guard=int(config.dump_guard),
        guard_policy=str(config.guard_policy),
        names_out=runtime_names,
    )

    stats = _collect_stats(module, classification, out, source_size)
    stats.guard = dict(runtime_names.get("guard") or {})
    stats.elapsed_ms = (time.perf_counter() - started) * 1000.0

    # The emitted helper names, so helper uniqueness is checked against what
    # this build really declared rather than a stale fixed list.  They are
    # per-build now, so a fixed tuple would count zeros and pass silently.
    helpers = tuple((runtime_names.get("helpers")
                     or _lower_back.DEFAULT_HELPERS).values())
    validation = (validate_or_raise(out, source, toolchain, helpers) if verify
                  else validate_output(out, source, toolchain, helpers))

    return BuildResult(source=out, seed=seed, config=config, stats=stats,
                       validation=validation, runtime_names=runtime_names)


def _guard_report(guard: Dict[str, Any]) -> List[str]:
    """The guard's own words, from the summary the build recorded.

    Printed through :func:`couxobf.guard.Guard.report_lines` rather than
    re-derived here: a report that recomputed what the guard did would be a
    second answer to the same question, and the two drift.
    """
    from . import guard as _guard
    obj = _guard.Guard(env_level=guard.get("env_guard", 0),
                       dump_level=guard.get("dump_guard", 0),
                       policy=guard.get("policy", "fail"),
                       bound=tuple(guard.get("captured") or ()))
    return ["", *obj.report_lines()]


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


def _collect_stats(module, classification, out: str, source_size: int) -> BuildStats:
    from .vm import encode as _encode

    # ``source_size`` is the caller's, because the honest denominator for the
    # growth ratio is what the user handed in -- not the comment-stripped text
    # this pass happened to parse.
    stats = BuildStats(input_bytes=source_size,
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
    if s.hash_comments:
        # Said out loud because the artifact was built from text that is not
        # byte-identical to what was handed in; a report that hides which
        # convention it accepted is a report that cannot be reproduced from.
        lines.append(f"# comments stripped : {s.hash_comments}")
    if s.budget_ceiling >= 1.0:
        lines.append(f"size ceiling        : {s.budget_ceiling:.1f}x input")
        if s.budget_trimmed:
            lines.append("given up to fit     : "
                         + ", ".join(s.budget_trimmed))
    lines.append(f"prototypes          : {s.prototypes}")
    lines.append(f"virtualized         : {s.virtualized}")
    lines.append(f"virtualization      : "
                 f"{VirtualizationLevel.parse(c.virtualization_level).name.lower()}")
    lines.append(f"vm family           : {getattr(c.vm_family, 'value', c.vm_family)}")
    guard = s.guard
    if guard:
        for line in _guard_report(guard):
            lines.append(line)
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

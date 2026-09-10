"""Serverless obfuscation endpoint for the web UI.

Runs on Vercel's Python runtime, or under tools/serve-web.py locally -- both
call :func:`handle`, so the deployed path and the tested path are the same
code rather than two implementations that can drift.

couxobf has no third-party dependencies, so there is no install step and the
cold start is just an import.

Two things this endpoint deliberately does not do.

It does not verify against the Luau toolchain.  Validation that matters here --
does the output reparse, does it introduce a forbidden API, is any helper
declared twice -- is pure Python and runs.  The compile check needs a
luau-compile binary that a serverless container does not have, and pretending
to run it would report a check that never happened.

It does not accept a seed from the client by default.  Every build draws a
fresh 128-bit seed, because a fixed seed means a fixed artifact and the whole
point of per-build polymorphism is that two runs differ.  ``reproducible_seed``
is available for debugging a specific build, and it is labelled as such.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
from typing import Any, Dict, Tuple

from dataclasses import fields as _fields

# The package lives one directory up from api/ in the repository layout, and in
# the same tree when Vercel copies the function.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from couxobf.comments import VALID_MODES as COMMENT_MODES  # noqa: E402
from couxobf.config import (CachePolicy, Config, DispatcherFamily,  # noqa: E402
                            VirtualizationLevel, VMFamily)
from couxobf.guard import POLICIES as GUARD_POLICIES  # noqa: E402
from couxobf.pipeline import BuildError, build  # noqa: E402
from couxobf.vm.families import FAMILIES  # noqa: E402
from couxobf.vm.runtime import DISPATCHERS  # noqa: E402

#: Hard cap on accepted input. A serverless function has a wall clock and a
#: response size limit; refusing early beats timing out halfway.
MAX_INPUT_BYTES = 512 * 1024

#: Option surface, derived from the config rather than listed beside it.
#:
#: This used to be three hand-maintained tables, and they drifted: fields the
#: config grew were refused here, so the UI could not offer them, and the only
#: thing that caught it was somebody noticing a knob was missing.  Deriving the
#: accepted set from :attr:`Config.IMPLEMENTED` makes that impossible -- a field
#: becomes offerable the moment the pipeline starts reading it, and stays
#: unofferable while it is inert, which is the same honesty rule the pending list
#: follows.
#:
#: Ranges are stated per field because the config does not carry them; a field
#: with a bool default needs none, an enum needs its members, and any other type
#: without an entry here is a bug the import below refuses to start with.

#: Integer and float fields, with the bounds ``Config._validate`` enforces.
FIELD_RANGES: Dict[str, Tuple[float, float]] = {
    "opcode_aliases": (0, 4),
    "instruction_formats": (0, 2),
    "vm_variety": (1, 4),
    "control_flow_level": (0, 3),
    "string_protection_level": (0, 3),
    "constant_protection_level": (0, 3),
    "numeric_protection_level": (0, 2),
    "chunking_level": (0, 3),
    "bounded_cache_size": (1, 4096),
    "chunk_size": (256, 1 << 20),
    "decoy_constants": (0, 256),
    "junk_level": (0, 3),
    "env_guard": (0, 2),
    "dump_guard": (0, 2),
    "max_vm_functions": (0, 4096),
    "min_virtualize_body_nodes": (0, 4096),
    "max_output_growth": (0.0, 1000.0),
}

#: String fields that are not enums but take a fixed vocabulary.
FIELD_CHOICES: Dict[str, Tuple[str, ...]] = {
    "guard_policy": GUARD_POLICIES,
    "hash_comments": COMMENT_MODES,
    # Not the enum: DispatcherFamily carries ``table``, ``segmented`` and
    # ``indirect`` so a config file can express the intent, and the runtime
    # raises for them.  Offering a value that is refused at build time is the same
    # lie as a dead control, so this lists what a build can actually emit.
    "dispatcher_family": ("none",) + DISPATCHERS + ("mixed",),
}

#: When a field only has an effect alongside another setting, this says which.
#: The UI greys the control out and leaves it out of the request; without that,
#: every advanced option would read as a knob that can be turned at any time.
#:
#: ``gate`` is a single condition; ``any_of`` means "at least one of these fields
#: is on", which is how a policy field that both guards share is described.
FIELD_REQUIRES: Dict[str, Dict[str, Any]] = {
    "bounded_cache_size": {"field": "cache_policy", "op": "==", "value": "bounded"},
    "decoy_constants": {"field": "decoys", "op": "==", "value": True},
    "opcode_aliases": {"field": "opcode_randomization", "op": "==", "value": True},
    "vm_variety": {"field": "vm_polymorphism", "op": "==", "value": True},
    "instruction_formats": {"field": "operand_randomization", "op": "==", "value": True},
    "operand_randomization": {"field": "virtualization_level", "op": "!=", "value": "none"},
    "register_randomization": {"field": "virtualization_level", "op": "!=", "value": "none"},
    "pc_protection": {"field": "virtualization_level", "op": "!=", "value": "none"},
    "edge_indirection": {"field": "virtualization_level", "op": "!=", "value": "none"},
    "opcode_cipher": {"field": "virtualization_level", "op": "!=", "value": "none"},
    "vm_isa_subset": {"field": "virtualization_level", "op": "!=", "value": "none"},
    "max_vm_functions": {"field": "virtualization_level", "op": "!=", "value": "none"},
    "min_virtualize_body_nodes": {"field": "virtualization_level", "op": "!=", "value": "none"},
    "guard_policy": {"any_of": ["env_guard", "dump_guard"]},
}

_ENUM_FIELDS: Dict[str, Any] = {
    "virtualization_level": VirtualizationLevel,
    "vm_family": VMFamily,
    "dispatcher_family": DispatcherFamily,
    "cache_policy": CachePolicy,
}

#: Implemented compatibility fields that remain available to config files/CLI but
#: are deliberately not exposed by the web/API surface; `vm_polymorphism` is the
#: single public best-mode switch now.
_HIDDEN_SURFACE_FIELDS = {"vm_family", "dispatcher_family", "instruction_fusion", "super_instructions"}


def _plain(value: Any) -> Any:
    return getattr(value, "value", value)


def _name(value: Any, enum_cls: Any) -> str:
    """The lowercase member name, whether the field holds an enum or a string.

    VirtualizationLevel is an IntEnum, so _plain on it yields 0..4 -- a number
    a reader cannot map back to a level.  Names round-trip either way.
    """
    if isinstance(value, enum_cls):
        return value.name.lower()
    try:
        return enum_cls.parse(value).name.lower()
    except (ValueError, KeyError, AttributeError, TypeError):
        return str(value)


def describe() -> Dict[str, Any]:
    """The option surface on its own, for a client that is drawing a form.

    Worth a route of its own rather than making the page guess: the ranges and the
    vocabularies are defined here, and a UI that hardcoded them would be able to
    offer a value the endpoint refuses -- which is the drift this whole file is
    arranged to prevent.  The front end treats this as an enhancement: if the call
    fails (opening ``web/index.html`` from the filesystem, say) it builds the form
    from the same table copied into ``app.js``, and the parity test in
    ``tests/test_web.py`` is what keeps the copy honest.
    """
    # The fields a config can name but the compiler does not read.  Listed rather
    # than offered: a control for one of these would be the dead knob this project
    # keeps having to remove, and leaving the name out entirely would be the other
    # failure -- a user setting `junk_level = 2` and never learning it did nothing.
    declared = {f.name for f in _fields(Config)}
    pending = sorted(declared - set(Config.IMPLEMENTED) - {"reproducible_seed"})

    return {
        "options": OPTIONS,
        "pending": pending,
        "profiles": list(Config.PROFILES),
        "implemented": sorted(Config.IMPLEMENTED),
        # The preset values come from the config rather than being copied into
        # JavaScript, because a preset that was hand-copied is a claim about the
        # profile that goes stale the first time the profile changes -- and it had
        # already drifted here, which is what the "mirrored from Config" comment in
        # app.js was apologising for.
        "profile_values": {
            name: {key: _applied_value(Config.from_profile(name), key)
                   for key in sorted(Config.IMPLEMENTED - _HIDDEN_SURFACE_FIELDS)}
            for name in Config.PROFILES
        },
    }


def handle(payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    """Status code plus a JSON-serialisable body."""
    if (payload or {}).get("mode") == "options":
        return 200, describe()
    try:
        return 200, run(payload.get("source", ""), payload.get("options") or {})
    except ValueError as exc:
        return 400, {"error": str(exc)}
    except BuildError as exc:
        return 422, {"error": str(exc)}
    except Exception as exc:                      # pragma: no cover - safety net
        return 500, {"error": f"{type(exc).__name__}: {exc}"}


def _describe_gate(gate: Dict[str, Any]) -> str:
    """The gating rule in the words the UI prints next to the control.

    Written here rather than in JavaScript so the sentence and the rule cannot
    describe different things.
    """
    if "any_of" in gate:
        return "one of %s must be on" % " or ".join(gate["any_of"])
    return "%s %s %s" % (gate["field"], gate["op"],
                         json.dumps(gate["value"]) if isinstance(
                             gate["value"], str) else gate["value"])


def _enum_label(member: Any) -> str:
    """The word a client uses for an enum member.

    ``VirtualizationLevel`` is an ``IntEnum`` whose *values* are 0..4, and a form
    that offers "0", "1", "2" is a form nobody can read; the other enums are
    string-valued, where the value already is the word.  Naming both the same way
    keeps one code path for every enum field.
    """
    return member.name.lower() if isinstance(member.value, int) else member.value


def _is_float(name: str) -> bool:
    import dataclasses

    for f in dataclasses.fields(Config):
        if f.name == name:
            return isinstance(f.default, float)
    return False


def option_surface() -> Dict[str, Dict[str, Any]]:
    """One descriptor per offerable option: kind, bounds, default, gating.

    The UI builds its form from this, and the endpoint validates against it, so
    the two cannot disagree about what exists.
    """
    import dataclasses

    surface: Dict[str, Dict[str, Any]] = {}
    defaults = {f.name: f.default for f in dataclasses.fields(Config)}
    for name in sorted(Config.IMPLEMENTED - _HIDDEN_SURFACE_FIELDS):
        if name == "reproducible_seed":
            surface[name] = {"kind": "int", "min": 0, "max": (1 << 128) - 1,
                             "default": None}
            continue
        default = defaults[name]
        if name in _ENUM_FIELDS:
            enum = _ENUM_FIELDS[name]
            # An override wins: see FIELD_CHOICES for why the offerable set is not
            # always the whole enum.
            choices = FIELD_CHOICES.get(name)
            surface[name] = {"kind": "enum",
                             "choices": (list(choices) if choices else
                                          [_enum_label(m) for m in enum]),
                             "default": _enum_label(default) if default is not None
                             else None}
        elif isinstance(default, bool):
            surface[name] = {"kind": "bool", "default": default}
        elif isinstance(default, (int, float)):
            low, high = FIELD_RANGES[name]
            surface[name] = {"kind": "float" if _is_float(name) else "int",
                             "min": low, "max": high, "default": default}
        elif name in FIELD_CHOICES:
            surface[name] = {"kind": "choice", "choices": list(FIELD_CHOICES[name]),
                             "default": default}
        else:
            raise AssertionError(
                f"{name}: implemented but with no rule in the option surface")
        spec = surface[name]
        gate = FIELD_REQUIRES.get(name)
        if gate is not None:
            spec["requires"] = dict(gate)
            spec["gate"] = _describe_gate(gate)
    return surface


OPTIONS: Dict[str, Dict[str, Any]] = option_surface()

#: Views of the same surface, kept under the old names because the UI's helper
#: tests and the docs both refer to them by kind.
ENUM_OPTIONS = {n: d["choices"] for n, d in OPTIONS.items() if d["kind"] == "enum"}
INT_OPTIONS = {n: list(range(int(d["min"]), int(d["max"]) + 1))
               for n, d in OPTIONS.items() if d["kind"] == "int"
               and d["max"] <= 4096}
BOOL_OPTIONS = tuple(n for n, d in OPTIONS.items() if d["kind"] == "bool")

#: Accepted integer ranges, derived from INT_OPTIONS so the two cannot drift.
INT_RANGES = {k: (min(v), max(v)) for k, v in INT_OPTIONS.items()}


def _coerce(name: str, value: Any) -> Any:
    """Turn a JSON value into the type the config field holds.

    Wrong types are refused with the accepted range in the message, because the
    alternative -- clamping, or quietly ignoring -- is how a config ends up
    claiming to be stronger than it is.
    """
    spec = OPTIONS[name]
    kind = spec["kind"]
    if kind in ("enum", "choice"):
        allowed = list(spec["choices"])
        if kind == "choice":
            if value not in allowed:
                raise ValueError(f"{name}: expected one of {', '.join(allowed)}")
            return value
        # Parsed through the enum so a config file's `4` and a form's "maximum"
        # mean the same thing, and then checked against what a build can emit:
        # DispatcherFamily has members the VM does not implement, and offering one
        # of those would be a refusal at build time instead of at the door.
        enum = _ENUM_FIELDS[name]
        try:
            member = enum.parse(value)
        except (KeyError, ValueError, TypeError):
            raise ValueError(f"{name}: expected one of {', '.join(allowed)}")
        label = _enum_label(member)
        if label not in allowed:
            raise ValueError(f"{name}: {label} is not something a build emits; "
                             f"expected one of {', '.join(allowed)}")
        return member
    if kind == "bool":
        if isinstance(value, str):
            return value.strip().lower() in ("1", "true", "yes", "on")
        return bool(value)
    low, high = spec["min"], spec["max"]
    if name == "reproducible_seed" and isinstance(value, str):
        # The UI keeps the field as text so a 128-bit hex seed can be pasted in,
        # and a paste with spaces or a 0x prefix is a normal thing to type.
        text = value.strip().replace("_", "")
        try:
            value = int(text, 16) if text.lower().startswith("0x") else int(text)
        except ValueError:
            raise ValueError("reproducible_seed: expected a decimal or 0x hex integer")
    if kind == "float":
        try:
            number = float(value)
        except (TypeError, ValueError):
            raise ValueError(f"{name}: expected a number in {low}..{high}")
        if not low <= number <= high:
            raise ValueError(f"{name}: expected a number in {low}..{high}")
        return number
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name}: expected an integer in {low}..{high}")
    if not low <= value <= high:
        raise ValueError(f"{name}: expected an integer in {low}..{high}")
    return value


def _apply_options(config: Config, options: Dict[str, Any]) -> None:
    """Write the request onto the config, refusing anything it cannot honour."""
    for key, value in (options or {}).items():
        if key == "profile":
            continue                        # already applied by the caller
        if key not in OPTIONS:
            hint = ""
            pending = {n for n, _ in config.pending_fields()}
            if key in pending:
                hint = (" -- that field exists but the pipeline does not read it "
                        "yet, and this endpoint will not pretend otherwise")
            elif key not in {f.name for f in _fields(Config)}:
                hint = " -- not a config field at all"
            raise ValueError(f"unknown option {key!r}{hint}")
        setattr(config, key, _coerce(key, value))


def run(source: str, options: Dict[str, Any]) -> Dict[str, Any]:
    """Build and describe the result.  Raises ValueError on bad input."""
    if not source or not source.strip():
        raise ValueError("the input is empty")
    if len(source.encode("utf-8", "surrogatepass")) > MAX_INPUT_BYTES:
        raise ValueError(f"input exceeds {MAX_INPUT_BYTES // 1024} KiB")

    config = Config.from_profile(str((options or {}).get("profile", "maximum")))
    _apply_options(config, {k: v for k, v in (options or {}).items()
                            if k != "profile"})

    if config.reproducible_seed is None:
        # A fresh 128-bit seed per request.  Not os.urandom folded into a
        # smaller int: the pipeline hashes the seed into domain-separated
        # streams, so it wants the full width.
        config.reproducible_seed = int.from_bytes(secrets.token_bytes(16), "big")

    result = build(source, config, name="input.luau", verify=False)
    pending = [{"name": n, "value": _plain(v)}
               for n, v in config.pending_fields()]
    return {
        "output": result.source,
        "input_bytes": len(source.encode("utf-8", "surrogatepass")),
        "output_bytes": len(result.source.encode("utf-8", "surrogatepass")),
        "prototypes": result.stats.prototypes,
        "virtualized": result.stats.virtualized,
        "seed_hex": f"{config.reproducible_seed:032x}",
        # Every option the endpoint accepted, in the value the build actually
        # used -- not a hand-picked subset.  A list this long is only readable
        # because the UI renders it as a table, and it is worth the space: the
        # question a user asks after a build is "what did that preset do to
        # `instruction_formats`?", and the honest answer is here rather than in a
        # report they have to re-run for.
        "applied": _applied(config, (options or {}).get("profile")),
        "notes": _notes(result),
        "options": OPTIONS,
        "pending": pending,
        "vm_groups": _vm_groups(result.stats),
        "report": result.report,
    }


def _applied_value(config: Config, name: str) -> Any:
    """The field as JSON: enum members by name, everything else as it stands."""
    value = getattr(config, name)
    enum = _ENUM_FIELDS.get(name)
    if enum is not None:
        return _name(value, enum)
    return _plain(value)


def _applied(config: Config, profile: Any) -> Dict[str, Any]:
    """Every option the endpoint took, as the build used it.

    `profile` is in here too: it is the one request key that is not a field, and
    leaving it out would make the table look like a preset had been ignored.
    """
    out: Dict[str, Any] = {"profile": str(profile if profile is not None else "maximum")}
    out.update({name: _applied_value(config, name)
                for name in sorted(Config.IMPLEMENTED)})
    return out


def _vm_groups(stats):
    """One row per interpreter this artifact carries, read off the build itself.

    `vm_variety` above 1 really does emit several VMs with different state models,
    dispatch shapes, opcode counts and instruction formats, and the flag the user
    set names only the first of them.  Showing the request as the result is the
    kind of thing a UI should not be able to do, so the panel is built from the
    plan the pipeline returned.
    """
    rows = []
    for group in getattr(stats, "vm_groups", None) or []:
        fmt = group.get("format") or {}
        rows.append({
            "group": group.get("group", len(rows)),
            "family": group.get("family"),
            "dispatcher": group.get("dispatcher"),
            "prototypes": group.get("protos", 0),
            "opcodes": group.get("opcodes", 0),
            "op_bytes": fmt.get("op_bytes", 1),
            "reg_bytes": fmt.get("reg_bytes", 1),
            "wide_bytes": fmt.get("wide_bytes", 2),
            "target_mode": fmt.get("target_mode", "abs"),
            "op_cipher": fmt.get("op_cipher", "none"),
            "arm_seed": bool(fmt.get("arm_seed")),
            "fused": len(fmt.get("fused") or []),
        })
    return rows


def _notes(result: Any) -> list:
    """Things the reader should know that no single field says.

    The profile gate, the size-budget trims and the guard's own limits all read
    as caveats, and a caveat that only lives in a docstring is a caveat nobody
    sees.
    """
    notes = list(getattr(result, "notes", []) or [])
    stats = result.stats
    for label in getattr(stats, "budget_trimmed", []) or []:
        notes.append("size budget: dropped %s" % label)
    if getattr(stats, "hash_comments", 0):
        notes.append("%d `#` comment line(s) removed from the input"
                     % stats.hash_comments)
    guard = getattr(stats, "guard", None) or {}
    if guard:
        notes.append(
            "guard: env level %s, dump level %s, policy %s; %d library name(s) "
            "captured at load, %d surface(s) re-checked at each VM entry"
            % (guard.get("env_guard", 0), guard.get("dump_guard", 0),
               guard.get("policy", "fail"), len(guard.get("captured") or []),
               len(guard.get("surfaces") or [])))
    return notes


ENUM_PARSERS = dict(_ENUM_FIELDS)


# --- adapters ---------------------------------------------------------------

def handler(environ, start_response):
    """WSGI application.

    Vercel's Python runtime looks for a module-level ``app``; ``app = handler``
    below is that binding, so this same function serves both the deployed
    function and the local dev server.
    """
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        length = 0
    raw = environ["wsgi.input"].read(length) if length else b"{}"
    try:
        payload = json.loads(raw.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        status, body = 400, {"error": "request body is not valid JSON"}
    else:
        status, body = handle(payload)
    data = json.dumps(body).encode("utf-8")
    start_response(f"{status} {'OK' if status == 200 else 'Error'}",
                   [("Content-Type", "application/json"),
                    ("Content-Length", str(len(data)))])
    return [data]


def vercel_handler(request):
    """Vercel Python runtime entry point."""
    try:
        payload = request.get_json(silent=True) or {}
    except Exception:
        payload = {}
    status, body = handle(payload)
    return {"statusCode": status,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(body)}


#: What Vercel's Python runtime imports.
app = handler

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

# The package lives one directory up from api/ in the repository layout, and in
# the same tree when Vercel copies the function.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from couxobf.config import (CachePolicy, Config, DispatcherFamily,  # noqa: E402
                            VirtualizationLevel, VMFamily)
from couxobf.pipeline import BuildError, build  # noqa: E402
from couxobf.vm.families import FAMILIES  # noqa: E402
from couxobf.vm.runtime import DISPATCHERS  # noqa: E402

#: Hard cap on accepted input. A serverless function has a wall clock and a
#: response size limit; refusing early beats timing out halfway.
MAX_INPUT_BYTES = 512 * 1024

#: What the UI can ask for. Anything not in here is rejected rather than
#: silently ignored, which is the failure mode this project keeps running into.
ENUM_OPTIONS = {
    "virtualization_level": ("none", "light", "medium", "heavy", "maximum"),
    "vm_family": tuple(FAMILIES),
    "dispatcher_family": tuple(DISPATCHERS) + ("mixed",),
    "cache_policy": ("none", "bounded", "full"),
}
INT_OPTIONS = {
    # 0..3, not 0..2: the `maximum` profile sets 3, so rejecting it here would
    # mean the API refuses a value its own default produces.  Levels 2 and 3
    # are currently identical -- lower_back activates the string bank at
    # ">= 2" and there is no third tier -- and the UI says so rather than
    # implying a stronger setting exists.
    "string_protection_level": (0, 1, 2, 3),
    "min_virtualize_body_nodes": (0, 4096),
    "bounded_cache_size": (1, 4096),
    "max_vm_functions": (0, 4096),
}
#: Accepted integer ranges, derived from INT_OPTIONS so the two cannot drift.
INT_RANGES = {k: (min(v), max(v)) for k, v in INT_OPTIONS.items()}
BOOL_OPTIONS = (
    "block_permutation",
    "opcode_randomization",
    "identifier_polymorphism",
    "minify",
    "strip_types",
)


def _apply_options(config: Config, options: Dict[str, Any]) -> None:
    for key, value in (options or {}).items():
        if key in ENUM_OPTIONS:
            allowed = ENUM_OPTIONS[key]
            if value not in allowed:
                raise ValueError(f"{key}: expected one of {', '.join(allowed)}")
            # Store the parsed member, not the raw string.  Otherwise a field
            # holds an enum when a profile set it and a str when the request
            # did, and every reader has to cope with both.
            setattr(config, key, ENUM_PARSERS[key].parse(value))
        elif key in INT_OPTIONS:
            low, high = INT_RANGES[key]
            if not isinstance(value, int) or not low <= value <= high:
                raise ValueError(f"{key}: expected an integer in {low}..{high}")
            setattr(config, key, value)
        elif key in BOOL_OPTIONS:
            setattr(config, key, bool(value))
        elif key == "reproducible_seed":
            config.reproducible_seed = int(value)
        else:
            raise ValueError(f"unknown option {key!r}")


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
        "applied": {
            "profile": (options or {}).get("profile", "maximum"),
            "virtualization_level": _name(config.virtualization_level, ENUM_PARSERS["virtualization_level"]),
            "vm_family": _name(config.vm_family, ENUM_PARSERS["vm_family"]),
            "dispatcher_family": _name(config.dispatcher_family, ENUM_PARSERS["dispatcher_family"]),
            "block_permutation": config.block_permutation,
            "opcode_randomization": config.opcode_randomization,
            "string_protection_level": config.string_protection_level,
            # 2 and 3 both mean "fragmented, encrypted, ticketed"; there is no
            # third tier yet, and saying so beats implying one.
            "string_protection_level_note": (
                "levels 2 and 3 are currently identical"
                if config.string_protection_level >= 2 else ""),
            "cache_policy": _name(config.cache_policy, ENUM_PARSERS["cache_policy"]),
            "minify": config.minify,
        },
        "pending": pending,
        "report": result.report,
    }


ENUM_PARSERS = {
    "virtualization_level": VirtualizationLevel,
    "vm_family": VMFamily,
    "dispatcher_family": DispatcherFamily,
    "cache_policy": CachePolicy,
}


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


def handle(payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    """Status code plus a JSON-serialisable body."""
    try:
        return 200, run(payload.get("source", ""), payload.get("options") or {})
    except ValueError as exc:
        return 400, {"error": str(exc)}
    except BuildError as exc:
        return 422, {"error": str(exc)}
    except Exception as exc:                      # pragma: no cover - safety net
        return 500, {"error": f"{type(exc).__name__}: {exc}"}


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

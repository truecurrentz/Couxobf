"""Differential testing: does the protected program behave like the original?

The comparison is over *observable behaviour only*:

* exit status;
* stdout, byte for byte;
* the error message and whether an error occurred.

Luau stack traces embed line numbers that the transformation legitimately
changes, so stderr is normalised: the first error line is kept, and any
``file:line`` / ``stacktrace`` noise is stripped before comparison.  When a
caller wants the strictest check it can pass ``normalize_stderr=False``.

This is the check that actually licenses the aggressive passes.  Compile
validation says the output is valid Luau; only this says it is the *same
program*.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from ..toolchain import RunResult, Toolchain, execute

_TRACE_LINE = re.compile(r"^\s*(stacktrace:|[\w./~-]*:\d+(\.\d+)?\s*)$")
_LOC = re.compile(r"\b[\w./~-]+\.luau?:\d+(:\d+)?\b")


def normalize_stderr(text: str) -> str:
    """Keep the first real error message, drop locations and stack traces."""
    lines = [ln for ln in text.splitlines() if ln.strip() and not _TRACE_LINE.match(ln)]
    cleaned = [_LOC.sub("<loc>", ln) for ln in lines]
    # Luau prefixes runtime errors with the chunk name; keep only the message.
    out: List[str] = []
    for ln in cleaned:
        if ln.startswith("<loc>: "):
            ln = ln.split(": ", 1)[1]
        out.append(ln)
    return "\n".join(out[:4])


@dataclass
class DiffResult:
    ok: bool
    reason: str = ""
    original: Optional[RunResult] = None
    protected: Optional[RunResult] = None
    details: dict = field(default_factory=dict)


def compare_runs(original: RunResult, protected: RunResult,
                 normalize_err: bool = True) -> DiffResult:
    if original.timed_out or protected.timed_out:
        return DiffResult(False, "timeout", original, protected)
    if original.returncode != protected.returncode:
        return DiffResult(
            False, f"exit code {original.returncode} != {protected.returncode}",
            original, protected,
        )
    if original.stdout != protected.stdout:
        return DiffResult(
            False, "stdout differs", original, protected,
            details={
                "original_stdout": original.stdout[:2000],
                "protected_stdout": protected.stdout[:2000],
            },
        )
    o_err = normalize_stderr(original.stderr) if normalize_err else original.stderr
    p_err = normalize_stderr(protected.stderr) if normalize_err else protected.stderr
    if o_err != p_err:
        return DiffResult(False, "stderr differs", original, protected,
                          details={"original_stderr": o_err[:2000], "protected_stderr": p_err[:2000]})
    return DiffResult(True, "", original, protected)


def run_pair(toolchain: Toolchain, original_src: str, protected_src: str,
             timeout: float = 30.0, normalize: bool = True) -> DiffResult:
    a = execute(toolchain, original_src, "orig.luau", timeout=timeout)
    b = execute(toolchain, protected_src, "prot.luau", timeout=timeout)
    return compare_runs(a, b, normalize_err=normalize)

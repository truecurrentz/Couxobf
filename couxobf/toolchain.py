"""Discovery of, and sandboxed access to, the external Luau toolchain.

The build tool never executes user source in-process.  Every dynamic check
goes through a subprocess running a pinned Luau build, which keeps a malicious
or buggy input from touching the compiler:

* ``luau-compile --binary`` is used for *compile-only* validation -- it parses
  and compiles without running anything, so it is safe on untrusted input and
  is the check used by ``--verify``.
* ``luau`` executes a script; it is only used by the test/benchmark harness on
  programs the developer already trusts (their own source and its protected
  output).

Note the distinction the documentation keeps: compile validation proves the
output is *syntactically and structurally* valid Luau.  It says nothing about
whether the protected program behaves like the original -- that is what the
differential harness in :mod:`couxobf.verify.difftest` is for.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional

DEFAULT_TOOLCHAIN = os.path.expanduser("~/.luau-toolchain/bin")

#: Where ``tools/setup-luau.sh`` installs by default.  Kept inside the repo (and
#: gitignored) rather than in the home directory so a checkout is self-contained.
REPO_TOOLCHAIN = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    ".luau-toolchain", "bin")


class ToolchainError(RuntimeError):
    pass


@dataclass
class Toolchain:
    luau: Optional[str]
    analyze: Optional[str]
    compile: Optional[str]

    @property
    def can_execute(self) -> bool:
        return self.luau is not None

    @property
    def can_compile(self) -> bool:
        return self.compile is not None or self.analyze is not None


def find_toolchain(directory: Optional[str] = None) -> Toolchain:
    """Locate the Luau CLI tools.

    Order: ``$COUXOBF_LUAU_DIR`` -> explicit argument -> ``~/.luau-toolchain/bin``
    -> ``PATH``.
    """
    candidates = [
        os.environ.get("COUXOBF_LUAU_DIR"),
        directory,
        REPO_TOOLCHAIN,
        DEFAULT_TOOLCHAIN,
    ]
    found = {}
    for base in candidates:
        if not base:
            continue
        for tool, key in (("luau", "luau"), ("luau-analyze", "analyze"), ("luau-compile", "compile")):
            if key in found:
                continue
            path = os.path.join(base, tool)
            if os.path.isfile(path) and os.access(path, os.X_OK):
                found[key] = path
    for tool, key in (("luau", "luau"), ("luau-analyze", "analyze"), ("luau-compile", "compile")):
        if key not in found:
            path = shutil.which(tool)
            if path:
                found[key] = path
    return Toolchain(found.get("luau"), found.get("analyze"), found.get("compile"))


@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def compile_check(toolchain: Toolchain, source: str, path: str = "check.luau") -> RunResult:
    """Parse + compile without executing (safe on untrusted input)."""
    if toolchain.compile:
        argv = [toolchain.compile, "--binary", path]
    elif toolchain.analyze:
        argv = [toolchain.analyze, path]
    else:
        raise ToolchainError("no Luau compiler available; run tools/setup-luau.sh")
    return _run_with_source(argv, source, path)


def analyze_check(toolchain: Toolchain, source: str, path: str = "check.luau") -> RunResult:
    """Type-aware parse check via ``luau-analyze`` (syntax errors surface here too)."""
    if not toolchain.analyze:
        raise ToolchainError("luau-analyze not available")
    return _run_with_source([toolchain.analyze, path], source, path)


def execute(toolchain: Toolchain, source: str, path: str = "prog.luau",
            timeout: float = 30.0, argv: Optional[List[str]] = None) -> RunResult:
    """Run a Luau script in a subprocess and capture its observable output."""
    if not toolchain.luau:
        raise ToolchainError("luau runtime not available; run tools/setup-luau.sh")
    cmd = [toolchain.luau, path]
    if argv:
        cmd += ["-a", *argv]
    return _run_with_source(cmd, source, path, timeout=timeout)


def _run_with_source(cmd: List[str], source: str, path: str, timeout: float = 30.0) -> RunResult:
    """Run ``cmd`` with ``path`` bound to ``source``.

    The Luau CLI reads real files, so the source is written to a temp file with
    the exact name the tool is given.  stdin is closed and the working directory
    is the temp dir, so a script cannot reach the build tree.
    """
    import tempfile

    with tempfile.TemporaryDirectory(prefix="couxobf-") as tmp:
        full = os.path.join(tmp, os.path.basename(path))
        with open(full, "w", encoding="utf-8", errors="surrogateescape") as fh:
            fh.write(source)
        try:
            proc = subprocess.run(
                cmd, cwd=tmp, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL
            )
        except subprocess.TimeoutExpired as exc:
            return RunResult(-1, (exc.stdout or b"").decode("utf-8", "replace"),
                             "timeout", timed_out=True)
        return RunResult(
            proc.returncode,
            proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"),
        )

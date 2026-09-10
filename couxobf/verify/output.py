"""Post-generation validation: is the thing we produced actually valid Luau?

A build that emits broken output is worse than no build at all, because the
user finds out at runtime in a place where nothing points back here.  So every
build is checked before it is handed over, and a build that fails the check is
rejected rather than returned with a warning.

Four checks, in increasing order of cost:

reparse
    The output must survive our own lexer and parser.  Cheap, and it catches
    the whole class of emission bugs -- a missing separator, an unbalanced
    ``end``, a string escape that swallowed a quote.

compile
    ``luau-compile`` must accept it.  This is the check that catches things our
    parser is more forgiving about than Luau is.

forbidden APIs
    The scaffolding must never introduce a primitive the design rules out --
    ``loadstring``, filesystem or network access, executor-specific globals.
    Counted against the input rather than banned outright: if the user's own
    source used it, that is their business, and failing the build would be us
    vetoing their program.  What is not acceptable is the obfuscator *adding*
    one.

helper uniqueness
    Each shared helper must be declared exactly once.  A second copy is not
    just waste; it is a second thing for an analyst to find and a second place
    for the two to drift apart, which is precisely what the design warns about
    when it says not to emit repeated identical decoders.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

#: Primitives the generated scaffolding must never introduce.  Matched as whole
#: dotted names so ``xloadstring`` or a table key called ``loadstring`` does not
#: trip the check.
FORBIDDEN_APIS: Tuple[Tuple[str, str], ...] = (
    ("loadstring", "dynamic code loading; the protection VM is source-level"),
    ("getloadedmodules", "executor-specific"),
    ("identifyexecutor", "executor-specific"),
    ("io.open", "filesystem access is not available and must not be assumed"),
    ("io.read", "filesystem access is not available and must not be assumed"),
    ("io.write", "filesystem access is not available and must not be assumed"),
    ("os.execute", "process execution is not available"),
    ("os.remove", "filesystem access is not available"),
    ("require", "the output must be self-contained"),
    ("dofile", "filesystem access is not available"),
    ("HttpService", "external runtime services are out of scope"),
    ("HttpGet", "external runtime services are out of scope"),
    ("HttpPost", "external runtime services are out of scope"),
)

#: Helpers the reconstruction emits and shares.  Each must appear exactly once.
SHARED_HELPERS: Tuple[str, ...] = (
    "_kpack", "_kunpk", "_kiter", "_kiterpack", "_kitercheck", "_kapp",
)


class OutputValidationError(Exception):
    """The generated output failed validation and must not be shipped."""


@dataclass
class ValidationReport:
    """What was checked, and what came back."""

    reparsed: bool = False
    compiled: bool = False
    ast_nodes: int = 0
    helper_counts: Dict[str, int] = field(default_factory=dict)
    #: Whether the original/protected execution round-trip was run.
    differential: bool = False
    differential_reason: str = ""
    #: APIs present in the output that were not present in the input.
    added_apis: List[str] = field(default_factory=list)
    problems: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def _dotted(node) -> Optional[str]:
    """Flatten a name expression to its dotted form, or None if it is not one."""
    from .. import ast_nodes as A

    if isinstance(node, A.Name):
        return node.name
    if isinstance(node, A.Field):
        base = _dotted(node.obj)
        return f"{base}.{node.name}" if base else None
    return None


def referenced_names(block) -> set:
    """Every global-style name a block refers to, dotted where applicable.

    Read off the AST rather than matched with a regular expression, because the
    two differ exactly where it matters: a table *key* called ``loadstring``
    produces no name node at all, while ``io.open`` is a ``Field`` whose object
    is a ``Name``.  A regex has to guess between those; the tree already knows.
    """
    from .. import ast_nodes as A
    from ..emit import printer as _printer

    names = set()
    for node in _printer.walk(block):
        if isinstance(node, (A.Name, A.Field)):
            flat = _dotted(node)
            if flat:
                names.add(flat)
            if isinstance(node, A.Name):
                names.add(node.name)
    return names


def _parse_or_none(source: str):
    from .. import parser as _parser
    try:
        return _parser.parse(source, "<input>")
    except Exception:
        return None


def check_forbidden_apis(output: str, original: str = "",
                         output_block=None) -> List[str]:
    """APIs the build introduced that were not already in the user's source.

    Comparing against the input is what makes this usable: the design forbids
    the *obfuscator* relying on these, not the user's program from mentioning
    them.  If the input does not parse there is nothing to compare against, so
    anything forbidden in the output is reported -- the conservative reading,
    and the right one for a check whose job is to reject bad builds.
    """
    out_block = output_block if output_block is not None else _parse_or_none(output)
    if out_block is None:
        return []  # validate_output reports the parse failure separately
    out_names = referenced_names(out_block)

    in_names = set()
    if original:
        in_block = _parse_or_none(original)
        if in_block is not None:
            in_names = referenced_names(in_block)

    added = []
    for name, reason in FORBIDDEN_APIS:
        if name in out_names and name not in in_names:
            added.append(f"{name} ({reason})")
    return added


def check_helper_uniqueness(output: str,
                            helpers: Optional[Iterable[str]] = None
                            ) -> Dict[str, int]:
    """How many times each shared helper is declared.

    ``helpers`` must be the names this build actually emitted.  Passing nothing
    falls back to :data:`SHARED_HELPERS`, which is only correct for builds that
    still use the legacy fixed names -- and note that every count comes back 0
    in that case, so the check passes without checking anything.
    """
    counts = {}
    for helper in (tuple(helpers) if helpers is not None else SHARED_HELPERS):
        counts[helper] = len(
            re.findall(r"(?<![\w])local function " + re.escape(helper) + r"\s*\(",
                       output))
    return counts


def validate_output(output: str, original: str = "",
                    toolchain: Any = None,
                    helpers: Optional[Iterable[str]] = None
                    ) -> ValidationReport:
    """Run every check and collect the problems rather than raising early.

    Returning the full list matters: a build that fails three checks should
    report three, not send the user back three times.
    """
    from .. import parser as _parser
    from ..emit import printer as _printer
    from ..toolchain import compile_check

    report = ValidationReport()

    # -- reparse ---------------------------------------------------------
    try:
        block = _parser.parse(output, "<output>")
        report.reparsed = True
        report.ast_nodes = _printer.count_nodes(block)
    except Exception as exc:
        report.problems.append(f"output does not reparse: {exc}")
        return report  # the remaining checks need a parse

    # -- compile ---------------------------------------------------------
    if toolchain is not None and toolchain.can_compile:
        result = compile_check(toolchain, output, "output.luau")
        if result.returncode == 0:
            report.compiled = True
        else:
            report.problems.append(
                f"luau-compile rejected the output: {result.stderr.strip()[:300]}")

    # -- forbidden APIs --------------------------------------------------
    report.added_apis = check_forbidden_apis(output, original,
                                             output_block=block)
    for api in report.added_apis:
        report.problems.append(f"build introduced a forbidden API: {api}")

    # -- helper uniqueness ----------------------------------------------
    report.helper_counts = check_helper_uniqueness(output, helpers)
    for helper, count in sorted(report.helper_counts.items()):
        if count > 1:
            report.problems.append(
                f"helper {helper} is declared {count} times; it must be shared, "
                f"not duplicated")

    return report


def validate_or_raise(output: str, original: str = "",
                      toolchain: Any = None,
                      helpers: Optional[Iterable[str]] = None
                      ) -> ValidationReport:
    """``validate_output``, but rejects the build instead of reporting it."""
    report = validate_output(output, original, toolchain, helpers)
    if not report.ok:
        raise OutputValidationError(
            "generated output failed validation:\n  " +
            "\n  ".join(report.problems))
    return report

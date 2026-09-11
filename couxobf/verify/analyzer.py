"""Small static analyzer for recognisable obfuscation architecture.

This is not a real deobfuscator.  It is the deliberately cheap pass an analyst
would write first: find dispatcher-shaped loops, flat handler tables, obvious
constant/string decoders, XOR/crypto scaffolding, and opcode-like table keys.
Regression tests use it as a tripwire: if these signatures become reliably
visible again, hardening has regressed even when the protected program still
runs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Set


@dataclass
class StaticFinding:
    kind: str
    count: int
    examples: List[str] = field(default_factory=list)


@dataclass
class StaticReport:
    findings: Dict[str, StaticFinding] = field(default_factory=dict)

    def add(self, kind: str, matches: List[str]) -> None:
        if matches:
            self.findings[kind] = StaticFinding(kind, len(matches), matches[:8])

    def count(self, kind: str) -> int:
        found = self.findings.get(kind)
        return 0 if found is None else found.count

    @property
    def score(self) -> int:
        return sum(f.count for f in self.findings.values())


_PATTERNS = {
    # Classic flattened/native and VM dispatch forms: one loop with a visible
    # selector and a chain/tree of opcode/state comparisons.  `op == op` is just
    # a NaN/liveness guard and is intentionally not counted as dispatch.
    "dispatcher_loop": re.compile(
        r"while\s+(?:true|[A-Za-z_]\w*)\s+do.{0,500}?(?:elseif\s+op\s*==|\bop\s*<=|\(op\s*\*\s*\d+\)\s*%)",
        re.S,
    ),
    "flat_opcode_chain": re.compile(r"\b(?:if|elseif)\s+op\s*==|\bop\s*<=|\(op\s*\*\s*\d+\)\s*%"),
    # The keystream application is the one thing every build must contain,
    # whichever core it drew and whatever the helpers are called: a byte of
    # plaintext XORed with a byte of keystream and put back into a string.
    # The name-independent half of this pattern is what still fires now that
    # the library references are injected as parameters and the LCG constants
    # are drawn per build; the literal markers stay because a build that leaks
    # the words "chacha"/"sha256" is worse than one that does not.
    "xor_crypto": re.compile(
        r"bit32\.bxor|1103515|1103515245|3141786300|chacha|sha256"
        r"|char\s*\(\s*[\w.:]*\bbxor\s*\(\s*[\w.:]*byte\s*\(", re.I),
    "string_decoder": re.compile(r"ticket\s*%\s*3|page\s*=\s*off\s*//|fragment", re.I),
    "constant_pipeline": re.compile(r"\b(?:plain|perm|index|psize)\b.{0,80}\b(?:string\.unpack|page|ticket)", re.S),
}


def _noarg_handlers(source: str) -> Set[str]:
    return set(re.findall(r"local\s+function\s+(_[A-Za-z][A-Za-z0-9]*)\s*\(\s*\)", source))


def _flat_handler_assignments(source: str) -> List[str]:
    handlers = _noarg_handlers(source)
    out: List[str] = []
    if not handlers:
        return out
    for match in re.finditer(r"\b(_[A-Za-z0-9]+)\s*\[\s*(\d{1,6})\s*\]\s*=\s*(_[A-Za-z][A-Za-z0-9]*)", source):
        if match.group(3) in handlers:
            out.append(match.group(0))
    return out


def analyze(source: str) -> StaticReport:
    report = StaticReport()
    for kind, pattern in _PATTERNS.items():
        report.add(kind, [m.group(0) for m in pattern.finditer(source)])
    report.add("handler_function", sorted(_noarg_handlers(source)))
    report.add("flat_handler_table", _flat_handler_assignments(source))
    return report


def opcode_frequency(source: str) -> Dict[int, int]:
    """Count numeric flat-handler keys as a crude opcode-frequency proxy."""
    freq: Dict[int, int] = {}
    handlers = _noarg_handlers(source)
    if not handlers:
        return freq
    for match in re.finditer(r"\b_[A-Za-z0-9]+\s*\[\s*(\d{1,6})\s*\]\s*=\s*(_[A-Za-z][A-Za-z0-9]*)", source):
        if match.group(2) not in handlers:
            continue
        value = int(match.group(1))
        freq[value] = freq.get(value, 0) + 1
    return freq

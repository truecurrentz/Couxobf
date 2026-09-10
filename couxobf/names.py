"""Generated identifier names (identifier polymorphism).

Rules this module enforces:

* names are drawn from the build's ``identifiers`` randomness stream, so a
  different seed produces different names and the same seed reproduces them;
* each build picks a *family* as well as shuffled spelling templates, so the
  output does not carry one recognisable couxobf identifier dialect;
* no template produces a sequential or enumerable pattern -- every name is a
  random draw, not a counter formatted in base 36;
* nothing semantic is encoded: the renamer never maps ``health`` to
  ``health_1``;
* collisions with Luau keywords, with the built-in globals, and with names the
  build does not rename (table keys, method names) are rejected.
"""

from __future__ import annotations

from typing import List, Optional, Set

from .lexer import KEYWORDS
from .rng import Rng
from .sema import GLOBAL_NAMES

LOWER = "abcdefghijklmnopqrstuvwxyz"
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGIT = "0123456789"
MIXED = LOWER + UPPER
IDENT_BODY = MIXED + DIGIT + "_"
AMBIG_START = "IlO_"
AMBIG_BODY = "IlO01_"

# Templates are (alphabet-per-slot) tuples.  The build shuffles and truncates
# this list, so different builds use different name shapes.
TEMPLATES: List[tuple] = [
    (LOWER, DIGIT, LOWER),
    (LOWER, UPPER, DIGIT, LOWER),
    (LOWER, DIGIT, UPPER, LOWER, DIGIT),
    (UPPER, LOWER, DIGIT),
    (LOWER, LOWER, DIGIT, UPPER),
    (UPPER, DIGIT, LOWER, UPPER),
    (LOWER, DIGIT, DIGIT, LOWER, UPPER),
    (UPPER, UPPER, LOWER, DIGIT),
]

# Family-specific prefixes.  They are intentionally short and non-semantic:
# the family, not a source-name hint, decides whether a build looks bare,
# underscore-heavy, mixed, or optically ambiguous.
FAMILY_PREFIXES = {
    "mixed": ["", "", "", "_", "_"],
    "bare": ["", "", "", "", ""],
    "under": ["_", "_", "__", "_"],
    "ambig": ["", "", "_", "__"],
}
FAMILIES = tuple(FAMILY_PREFIXES)


class NameGenerator:
    """Produces unique, non-semantic identifiers for one build."""

    def __init__(self, rng: Rng, reserved: Optional[Set[str]] = None,
                 min_len: int = 3, max_len: int = 8):
        self.rng = rng
        self.reserved: Set[str] = set(reserved or ())
        self.reserved |= GLOBAL_NAMES | KEYWORDS
        self.used: Set[str] = set()
        self.min_len = min_len
        self.max_len = max_len
        self.family = rng.choice(FAMILIES)
        # Pick a per-build subset/order of templates and prefixes.  A subset is
        # enough polymorphism without lengthening every identifier.
        templates = rng.shuffled(list(TEMPLATES))
        keep = max(2, min(len(templates), 3 + rng.randbelow(4)))
        self.templates = templates[:keep]
        self.prefixes = rng.shuffled(list(FAMILY_PREFIXES[self.family]))
        self._attempts = 0

    def reserve(self, *names: str) -> None:
        for n in names:
            if n:
                self.reserved.add(n)

    def fresh(self, hint_ignored: Optional[str] = None) -> str:
        """Return a new unique identifier.

        ``hint_ignored`` exists only to document call sites: hints are never
        used, because a hint derived from the original name would leak
        meaning.
        """
        while True:
            self._attempts += 1
            if self._attempts > 20000:  # pragma: no cover - defensive
                raise RuntimeError("identifier space exhausted")
            name = self._candidate()
            if name in self.used or name in self.reserved:
                continue
            self.used.add(name)
            return name

    def _candidate(self) -> str:
        if self.family == "ambig":
            name = self._ambiguous_candidate()
        else:
            name = self._template_candidate()
        while len(name) < self.min_len:
            name += self.rng.choice(AMBIG_BODY if self.family == "ambig" else IDENT_BODY)
        if len(name) > self.max_len:
            name = name[: self.max_len]
        if name[0].isdigit():
            name = "l" + name
        return name

    def _template_candidate(self) -> str:
        template = self.rng.choice(self.templates)
        prefix = self.rng.choice(self.prefixes)
        body = "".join(self.rng.choice(alpha) for alpha in template)
        if self.family == "bare" and self.rng.chance(0.25):
            # A compact, random-looking identifier with no fixed prefix and no
            # source-name hint.  Length stays bounded by max_len below.
            body += self.rng.choice(IDENT_BODY)
        elif self.family == "under" and not prefix.endswith("_") and self.rng.bool():
            prefix += "_"
        return prefix + body

    def _ambiguous_candidate(self) -> str:
        prefix = self.rng.choice(self.prefixes)
        # Ambiguous names are expensive visually, not by byte count; keep them
        # short so the pass does not crowd out stronger runtime protections.
        length = self.rng.randint(max(1, self.min_len - len(prefix)),
                                  max(1, min(5, self.max_len - len(prefix))))
        first = self.rng.choice(AMBIG_START)
        tail = "".join(self.rng.choice(AMBIG_BODY) for _ in range(length - 1))
        return prefix + first + tail

    def fresh_many(self, n: int) -> List[str]:
        return [self.fresh() for _ in range(n)]


def make_name_generator(rng: Rng, reserved: Optional[Set[str]] = None) -> NameGenerator:
    return NameGenerator(rng, reserved)

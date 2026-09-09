"""Generated identifier names (identifier polymorphism).

Rules this module enforces:

* names are drawn from the build's ``identifiers`` randomness stream, so a
  different seed produces different names and the same seed reproduces them;
* several *spelling templates* exist and the build picks a random subset, so
  the output is not recognisably "the couxobf naming scheme";
* no template produces a sequential or enumerable pattern -- every name is a
  random draw, not a counter formatted in base 36;
* nothing semantic is encoded: the renamer never maps ``health`` to
  ``health_1``;
* collisions with Luau keywords, with the built-in globals, and with names the
  build does not rename (table keys, method names) are rejected.
"""

from __future__ import annotations

from typing import List, Optional, Set

from .rng import Rng
from .sema import GLOBAL_NAMES

LOWER = "abcdefghijklmnopqrstuvwxyz"
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGIT = "0123456789"
MIXED = LOWER + UPPER

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

# Prefix templates: a prefix plus a body.  Kept separate so a build can favour
# underscore-heavy or bare names.
PREFIXES = ["", "", "", "_", "_", "__", "_", "l_", "v_"]


class NameGenerator:
    """Produces unique, non-semantic identifiers for one build."""

    def __init__(self, rng: Rng, reserved: Optional[Set[str]] = None,
                 min_len: int = 3, max_len: int = 8):
        self.rng = rng
        self.reserved: Set[str] = set(reserved or ())
        self.reserved |= GLOBAL_NAMES
        self.used: Set[str] = set()
        self.min_len = min_len
        self.max_len = max_len
        # pick a per-build subset/order of templates and prefixes
        self.templates = rng.shuffled(list(TEMPLATES))
        self.prefixes = rng.shuffled(list(PREFIXES))
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
        template = self.rng.choice(self.templates)
        prefix = self.rng.choice(self.prefixes)
        body = "".join(self.rng.choice(alpha) for alpha in template)
        name = prefix + body
        # pad/truncate into the configured length window
        while len(name) < self.min_len:
            name += self.rng.choice(MIXED)
        if len(name) > self.max_len:
            name = name[: self.max_len]
        if name[0].isdigit():
            name = "l" + name
        return name

    def fresh_many(self, n: int) -> List[str]:
        return [self.fresh() for _ in range(n)]


def make_name_generator(rng: Rng, reserved: Optional[Set[str]] = None) -> NameGenerator:
    return NameGenerator(rng, reserved)

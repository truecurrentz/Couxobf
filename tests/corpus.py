"""Where test programs come from.

Two sources, merged:

* the repo-local ``tests/fixtures/corpus`` -- written here, versioned here,
  always present.  A checkout with no external state still gets every corpus
  test run, which is the property that was missing when the suite hard-linked
  a Luau checkout under /tmp and errored without it.
* the upstream Luau conformance corpus, when a checkout is available
  (``COUXOBF_LUAU_SRC`` or the ``tools/setup-luau.sh`` layout).  Wider is
  better, but it is a bonus, not a prerequisite.
"""

from __future__ import annotations

import glob
import os

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_CORPUS = sorted(glob.glob(os.path.join(HERE, "fixtures", "corpus", "*.luau")))


def _external_disabled() -> bool:
    """Whether the external checkout is deliberately hidden.

    The suite has to pass in a checkout with no external state -- that was the
    whole point of vendoring ``tests/fixtures/corpus``.  Setting
    ``COUXOBF_NO_EXTERNAL_CORPUS=1`` simulates that checkout on a machine
    which *does* have one, so the property is testable instead of assumed,
    and a test that quietly depends on the upstream corpus fails here rather
    than on a contributor's laptop.
    """
    flag = os.environ.get("COUXOBF_NO_EXTERNAL_CORPUS", "")
    return flag.lower() in ("1", "true", "yes", "on")


def _external_dir():
    if _external_disabled():
        return None
    env = os.environ.get("COUXOBF_LUAU_SRC")
    candidates = []
    if env:
        candidates.append(os.path.join(env, "tests", "conformance"))
    for tmp in ("/tmp", os.environ.get("TMPDIR", "/tmp")):
        candidates.append(os.path.join(tmp, "luau-src-0.700", "tests", "conformance"))
    for cand in candidates:
        if os.path.isdir(cand):
            return cand
    return None


def corpus_paths():
    """All corpus programs: repo fixtures first, then any external checkout."""
    paths = list(REPO_CORPUS)
    ext = _external_dir()
    if ext:
        paths += sorted(glob.glob(os.path.join(ext, "*.luau")))
    return paths


CORPUS = corpus_paths()

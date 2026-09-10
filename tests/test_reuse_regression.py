"""The reuse-audit's verdict, pinned as a test.

``tools/reuse-audit.py`` measures what an analyst can carry from one build to
the next and deliberately passes no judgment -- it is a tool for reading.  This
test is the judgment: it drives the same ``_facts``/``compare`` machinery over
the repo corpus and fails when a regression makes builds reusable again.

The structure it pins is the one the audit documents:

* ``stable`` (nothing varies) transfers everything -- the control column; if
  this drops below 1.0, the harness itself is broken, not the protection.
* ``numbered`` (opcode shuffle only) keeps shape and arms (the format never
  moved) but the payload stops decoding -- numbers moved, meaning did not.
* ``hardened`` and ``polymorphic`` transfer almost nothing on any axis.

Thresholds carry slack on purpose: an occasional opcode collision or one
matching draw out of many is noise, while a real regression (a fixed format,
a shared opmap, a constant alphabet) pushes these scores toward 1.0 and
cannot hide inside the slack.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import importlib.util

_spec = importlib.util.spec_from_file_location(
    "reuse_audit",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "tools", "reuse-audit.py"))
reuse_audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(reuse_audit)

from tests.corpus import REPO_CORPUS                    # noqa: E402

#: Small enough to audit quickly, virtualizable enough to carry instructions.
PROGRAMS = [p for p in REPO_CORPUS
            if os.path.basename(p) in ("loops.luau", "stateful.luau")]
SEEDS = (101, 102, 103, 104)


def _case_transfer(source: str, name: str, over: dict) -> dict:
    facts = [reuse_audit._facts(source, name=name, seed=s, **over)
             for s in SEEDS]
    assert all(f["virtualized"] >= 1 for f in facts), (
        "the corpus program must virtualize under the audit config")
    scored = [reuse_audit.compare(facts[i], facts[j])
              for i in range(len(facts)) for j in range(len(facts)) if i != j]
    pairs = [s for s in scored if s["groups_match"]] or scored
    return {key: sum(p[key] for p in pairs) / len(pairs)
            for key in ("numbering", "payload", "shape", "arms", "isa")}


@pytest.mark.parametrize("path", PROGRAMS,
                         ids=lambda p: os.path.basename(p))
def test_the_control_column_still_transfers_everything(path):
    """A protector that varies nothing must stay reproducible build to build:
    if this fails, the audit harness is broken rather than the protection."""
    with open(path, encoding="utf-8") as fh:
        source = fh.read()
    transfer = _case_transfer(source, os.path.basename(path), {
        "opcode_randomization": False, "operand_randomization": False,
        "block_permutation": False, "opcode_cipher": False,
        "vm_isa_subset": False})
    for key in ("numbering", "payload", "shape", "arms"):
        assert transfer[key] == 1.0, (key, transfer)


@pytest.mark.parametrize("path", PROGRAMS,
                         ids=lambda p: os.path.basename(p))
def test_opcode_shuffle_moves_numbers_but_keeps_the_format(path):
    with open(path, encoding="utf-8") as fh:
        source = fh.read()
    transfer = _case_transfer(source, os.path.basename(path), {
        "opcode_randomization": True, "operand_randomization": False,
        "block_permutation": False, "opcode_cipher": False,
        "vm_isa_subset": False})
    # The format never moved, so shape and arms transfer fully...
    assert transfer["shape"] == 1.0, transfer
    assert transfer["arms"] == 1.0, transfer
    # ...while the numbers and the payload they key stop transferring.
    assert transfer["numbering"] < 0.25, transfer
    assert transfer["payload"] < 0.10, transfer


@pytest.mark.parametrize("path", PROGRAMS,
                         ids=lambda p: os.path.basename(p))
def test_shipped_builds_transfer_almost_nothing(path):
    with open(path, encoding="utf-8") as fh:
        source = fh.read()
    for label, over in (("hardened", {}),
                        ("polymorphic", {"vm_variety": 3,
                                         "state_distribution": True,
                                         "dispatcher_family": "mixed"})):
        transfer = _case_transfer(source, os.path.basename(path), over)
        # A recovered table decodes almost none of the next build's stream.
        assert transfer["payload"] < 0.10, (label, transfer)
        assert transfer["numbering"] < 0.25, (label, transfer)
        # And the decoder's own description does not survive: formats and arm
        # orders are per-build draws, so at most a stray matching draw may
        # slip through -- never a majority.
        assert transfer["shape"] <= 0.5, (label, transfer)
        assert transfer["arms"] <= 0.5, (label, transfer)

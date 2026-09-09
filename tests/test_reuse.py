"""The cross-build transfer ceiling, pinned.

Every other test in this suite asks whether a build is *correct*.  This one asks
the question the design is actually for: does knowledge recovered from one build
work on the next?  It drives the matcher in :mod:`tools.reuse-audit`, which sweeps
a payload the way a static tool would and scores a table learned from one build
against another.

The `stable` case is the load-bearing half of the file.  It is a positive control:
a configuration with nothing randomized must score a *perfect* transfer, because an
audit that reported 0% everywhere would look identical to success while measuring
nothing.  If this test ever fails because `stable` stopped transferring, the audit
is broken, not the obfuscator.

The ceilings are deliberately loose (5%) rather than exact.  Two builds whose
opcode spaces are small enough can collide by luck -- a 22-handler VM over a
sparsely numbered byte has a real chance of handing two builds the same number for
one operation -- and a test that fails on that luck gets "fixed" by loosening it
until it cannot fail.  What matters, and what is pinned tightly, is that transfer
is *low* while the positive control is *total*.
"""

import importlib.util
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

_spec = importlib.util.spec_from_file_location(
    "reuse_audit", os.path.join(ROOT, "tools", "reuse-audit.py"))
audit_tool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(audit_tool)

PROGRAM = """local function score(a, b)
  local total = a * b + 2
  if total > 9 then total = total - 9 end
  for i = 1, 3 do total = total + i * a end
  local names = {"alpha", "beta"}
  return names[1] .. total, total
end
local x, y = score(3, 4)
print(x, y)
local z = score(1, 1)
print(z)
"""


#: The single-function program above virtualizes one prototype, which is enough to
#: score a table but not enough to have several VMs: `make_plan` collapses to one
#: group below two prototypes.  This variant exists so the per-group instruction
#: sets can be seen differing from each other rather than merely differing from
#: the full ISA.
BIG_PROGRAM = PROGRAM + """
local function extra1(a) local t = a * 3 + 1 if t > 5 then t = t - 5 end return t end
local function extra2(a, b) local c = a + b * 2 c = c % 7 local d = c * c + b return d, c end
local function extra3(t) local s = 0 for i = 1, #t do s = s + t[i] * i end return s end
print(extra1(2), extra2(3, 4), extra3({1, 2, 3}))
"""


def _case(label: str, seeds: int = 3, program: str = None):
    over = dict(audit_tool.CASES)[label]
    text = PROGRAM if program is None else program
    return [audit_tool._facts(text, name="reuse.luau", seed=17 + i, **over)
            for i in range(seeds)]


def test_the_audit_sees_a_stable_build_as_completely_transferable():
    """Positive control.  A protector that varies nothing must score 100%."""
    builds = _case("stable")
    scores = [audit_tool.compare(a, b) for a in builds for b in builds
              if a is not b]
    assert scores
    for key in ("numbering", "payload", "shape", "arms", "isa"):
        mean = sum(s[key] for s in scores) / len(scores)
        assert mean == 1.0, "%s transferred only %.0f%% between identical builds" % (
            key, mean * 100)
    assert builds[0]["groups"][0]["pairs"], "the sweep found no instructions"


def test_a_hardened_build_transfers_almost_nothing():
    """The number the design exists to produce, kept from drifting upward."""
    builds = _case("hardened")
    pairs = [(a, b) for a in builds for b in builds if a is not b]
    assert pairs
    for a, b in pairs:
        score = audit_tool.compare(a, b)
        assert score["payload"] < 0.05, (
            "a table learned from one build decoded %.0f%% of another's "
            "instructions" % (score["payload"] * 100))
        assert score["shape"] == 0.0, "two builds agreed on the instruction format"
        assert score["arms"] == 0.0, "two builds tested their handlers in order"


def test_the_instruction_set_follows_the_code_in_every_group():
    """Per-group narrowing is visible as different handler counts, not just fewer.

    Three interpreters over three functions do not carry three copies of 43
    handlers, and the sizes are not even equal to each other: the arithmetic group
    needs a different set from the table group.  A build where all three came out
    the same size would mean the subset is being taken from the ISA rather than
    from the prototypes on the group.
    """
    builds = _case("polymorphic", seeds=2, program=BIG_PROGRAM)
    sizes = [sorted(g["opcodes"] for g in build["groups"]) for build in builds]
    for size in sizes:
        assert len(size) == 3, size
        assert all(n > 0 for n in size)
        assert max(size) < 43, "nothing was narrowed: %s" % size
        assert len(set(size)) > 1, "all three groups carry the same set: %s" % size
    # Same program, same selection rule, so the *sizes* are stable while the
    # numbers inside them are not.  That is the honest reading of this knob: the
    # count is a property of the code, the mapping is a property of the build.
    assert sizes[0] == sizes[1]
    a, b = builds
    score = audit_tool.compare(a, b)
    assert score["isa"] == 1.0 and score["numbering"] < 0.5


def test_the_cipher_is_what_separates_moved_numbers_from_meaningless_bytes():
    """The middle column of the audit, kept honest.

    Shuffling opcode numbers already destroys a byte table, so the cipher is not
    what makes `payload` transfer near zero -- and saying otherwise would oversell
    it.  What the cipher buys is visible in `shape`: with the format frozen, two
    builds still agree on every field a decoder has to know, and with the cipher
    and the format drawn per build, they do not.  This test exists so the docs
    cannot drift into claiming more.
    """
    numbered = _case("numbered")
    hardened = _case("hardened")
    transfer = lambda builds: sum(
        audit_tool.compare(a, b)["shape"]
        for a in builds for b in builds if a is not b) / 6.0
    assert transfer(numbered) == 1.0, "shuffle-only builds stopped agreeing on shape"
    assert transfer(hardened) == 0.0, "randomized formats still agree on shape"
    for build in hardened:
        assert build["groups"][0]["shape"]["op_cipher"] != "none"
    for build in numbered:
        assert build["groups"][0]["shape"]["op_cipher"] == "none"


def test_the_report_and_the_audit_agree_about_what_a_group_is():
    """The audit's facts come from the same objects the pipeline reports on.

    Both read `plan.groups`.  If a future change makes the report describe the
    *requested* configuration again -- which is exactly the bug the per-group
    report lines were added to fix -- the two would disagree and this would say so.
    """
    from couxobf.config import Config
    from couxobf.pipeline import build

    config = Config.maximum()
    config.min_virtualize_body_nodes = 1
    config.max_output_growth = 0
    config.reproducible_seed = 5
    result = build(PROGRAM, config, name="reuse.luau", verify=False)
    assert result.stats.vm_groups, "the build virtualized nothing to compare"
    for group in result.stats.vm_groups:
        line = [l for l in result.report.splitlines()
                if l.strip().startswith("vm %d " % group["group"])]
        assert line, group
        assert "%d opcodes" % group["opcodes"] in line[0]
        assert group["format"]["op_cipher"] in line[0]

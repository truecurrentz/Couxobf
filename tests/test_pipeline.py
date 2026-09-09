"""End-to-end build tests: source in, protected Luau out, and it must run.

The pipeline is where every stage meets, so this is the place a regression in
any one of them shows up.  The differential over the corpus is the load-bearing
test: it runs the original and the built output under the pinned toolchain and
compares what they print.

The rest pin the properties the design requires and that are easy to lose:
reproducible builds, validation that actually rejects bad output, and a report
that describes cost without inventing a security score.
"""

import glob
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from couxobf import pipeline
from couxobf.config import Config, VirtualizationLevel
from couxobf.pipeline import BuildError, build, cost_report
from couxobf.toolchain import execute, find_toolchain
from couxobf.verify.output import (OutputValidationError, validate_output,
                                   validate_or_raise)
from test_roundtrip import EXCLUDED, MICRO_DIR, _conformance_dir

TOOLCHAIN = find_toolchain()


def _corpus():
    files = sorted(glob.glob(os.path.join(MICRO_DIR, "*.luau")))
    conf = _conformance_dir()
    if conf:
        files += sorted(glob.glob(os.path.join(conf, "*.luau")))
    return files


def _read(path):
    with open(path, encoding="utf-8", errors="surrogateescape") as fh:
        return fh.read()


# ---------------------------------------------------------------------------
# Differential
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", _corpus(), ids=lambda p: os.path.basename(p))
def test_build_output_matches_original(path):
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available; run tools/setup-luau.sh")
    base = os.path.basename(path)
    if base in EXCLUDED:
        pytest.skip(f"{base}: {EXCLUDED[base]}")
    src = _read(path)

    # min_virtualize_body_nodes lowered from the default 12: at 12 most corpus
    # functions are below the floor and the build would exercise the native
    # path only, which test_roundtrip already covers.
    config = Config(reproducible_seed=7, min_virtualize_body_nodes=4)
    try:
        result = build(src, config, name=base, toolchain=TOOLCHAIN)
    except BuildError as exc:
        pytest.fail(f"{base}: build failed: {exc}")

    original = execute(TOOLCHAIN, src, base, timeout=30)
    protected = execute(TOOLCHAIN, result.source, "built.luau", timeout=30)

    assert original.returncode == protected.returncode, (
        f"{base}: rc {original.returncode} != {protected.returncode}\n"
        f"virtualized={result.stats.virtualized}\n{protected.stderr[:500]}")
    assert original.stdout == protected.stdout, (
        f"{base}: stdout differs\nvirtualized={result.stats.virtualized}\n"
        f"--- original ---\n{original.stdout[:400]}\n"
        f"--- built ---\n{protected.stdout[:400]}")


def test_build_virtualizes_something_over_the_corpus():
    """Same guard as the VM suite, one level up.

    A build that silently virtualizes nothing passes every differential above
    while testing only the native reconstructor.
    """
    total, files = 0, 0
    config = Config(reproducible_seed=7, min_virtualize_body_nodes=4)
    for path in _corpus():
        base = os.path.basename(path)
        if base in EXCLUDED:
            continue
        try:
            result = build(_read(path), config, name=base,
                           toolchain=None, verify=False)
        except BuildError:
            continue
        if result.stats.virtualized:
            total += result.stats.virtualized
            files += 1
    assert total > 100, f"only {total} prototypes virtualized across the corpus"
    assert files > 10, f"only {files} files contributed"


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

def test_same_seed_is_byte_identical():
    src = "local function f(a, b) return a * b + 1 end\nprint(f(3, 4))\n"
    a = build(src, Config(reproducible_seed=11), verify=False)
    b = build(src, Config(reproducible_seed=11), verify=False)
    assert a.source == b.source
    assert a.seed == b.seed


def test_different_seed_differs():
    src = "local function f(a, b) return a * b + 1 end\nprint(f(3, 4))\n"
    a = build(src, Config(reproducible_seed=11), verify=False)
    b = build(src, Config(reproducible_seed=12), verify=False)
    assert a.source != b.source


def test_unpinned_seed_is_reported():
    """A build nobody can repeat is a build nobody can diagnose."""
    a = build("print(1)\n", Config(), verify=False)
    b = build("print(1)\n", Config(), verify=False)
    assert len(a.seed) == pipeline.SEED_BYTES
    assert a.seed != b.seed, "two unpinned builds drew the same seed"
    assert a.seed.hex() in a.report


def test_pinned_seed_derives_stably():
    """A small integer seed must not produce a mostly-zero key."""
    seed = pipeline.seed_from_config(Config(reproducible_seed=1))
    assert len(seed) == pipeline.SEED_BYTES
    assert seed != b"\x00" * pipeline.SEED_BYTES
    assert seed == pipeline.seed_from_config(Config(reproducible_seed=1))
    assert seed != pipeline.seed_from_config(Config(reproducible_seed=2))


# ---------------------------------------------------------------------------
# Front-end failures
# ---------------------------------------------------------------------------

def test_unparseable_input_raises_build_error():
    with pytest.raises(BuildError) as exc:
        build("local x = = 1\n", Config(), verify=False)
    assert "does not parse" in str(exc.value)


def test_short_seed_is_refused():
    with pytest.raises(BuildError):
        build("print(1)\n", Config(), seed=b"\x01\x02", verify=False)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def test_validation_rejects_unparseable_output():
    report = validate_output("local x = = 1\n")
    assert not report.ok
    assert any("reparse" in p for p in report.problems)


def test_validation_flags_an_api_the_build_added():
    """Counted against the input, not banned outright.

    If the user's own source used `loadstring`, that is their program and
    failing the build would be us vetoing it.  What is not acceptable is the
    obfuscator introducing one.
    """
    from couxobf.verify.output import check_forbidden_apis
    assert check_forbidden_apis('loadstring("x")()\n', "print(1)\n")
    assert not check_forbidden_apis('loadstring("x")()\n', 'loadstring("y")()\n')
    # a table key or a longer identifier must not trip it
    assert not check_forbidden_apis('local t = { loadstring = 1 }\n', "")
    assert not check_forbidden_apis('local myloadstring = 1\n', "")


def test_validation_flags_a_duplicated_helper():
    from couxobf.verify.output import check_helper_uniqueness
    counts = check_helper_uniqueness(
        "local function _kapp(a) end\nlocal function _kapp(b) end\n")
    assert counts["_kapp"] == 2
    report = validate_output(
        "local function _kapp(a) end\nlocal function _kapp(b) end\n")
    assert any("_kapp" in p and "2 times" in p for p in report.problems)


def test_validate_or_raise_raises():
    with pytest.raises(OutputValidationError):
        validate_or_raise("local x = = 1\n")


def test_real_build_passes_validation():
    result = build("local t = {1, 2, 3}\nfor i = 1, 3 do print(t[i]) end\n",
                   Config(reproducible_seed=3, min_virtualize_body_nodes=1),
                   toolchain=TOOLCHAIN)
    assert result.validation.ok, result.validation.problems
    assert result.validation.reparsed
    if TOOLCHAIN.can_compile:
        assert result.validation.compiled
    assert result.validation.ast_nodes > 0


def test_helper_uniqueness_holds_on_a_real_build():
    """One shared copy of each helper, never one per virtualized prototype."""
    result = build("local t = {1, 2, 3}\nfor i = 1, 3 do print(t[i]) end\n",
                   Config(reproducible_seed=3, min_virtualize_body_nodes=1),
                   toolchain=TOOLCHAIN)
    for helper, count in result.validation.helper_counts.items():
        assert count <= 1, f"{helper} declared {count} times"
    # and the helpers the body needs are actually there
    assert result.validation.helper_counts["_kunpk"] == 1


# ---------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------

def test_report_has_no_security_percentage():
    """The design forbids a meaningless score."""
    result = build("local function f(x) return x * 2 end\nprint(f(4))\n",
                   Config(reproducible_seed=5, min_virtualize_body_nodes=1),
                   verify=False)
    text = result.report.lower()
    assert "%" not in result.report, "the report contains a percentage"
    for banned in ("security score", "security rating", "100% secure",
                   "unbreakable", "impossible to reverse"):
        assert banned not in text


def test_report_states_its_own_limits():
    """It must say plainly that this is not a security boundary."""
    result = build("local function f(x) return x * 2 end\nprint(f(4))\n",
                   Config(reproducible_seed=5, min_virtualize_body_nodes=1),
                   verify=False)
    text = result.report.lower()
    assert "not irreversible" in text
    assert "not a security boundary" in text
    assert "server" in text, "the report should point secrets at a server"


def test_report_explains_why_nothing_was_virtualized():
    """A user whose build virtualized nothing needs to be told why."""
    result = build("local function f(x) return x * 2 end\nprint(f(4))\n",
                   Config(reproducible_seed=5),  # default node floor: 12
                   verify=False)
    assert result.stats.virtualized == 0
    assert "trivial" in result.report, (
        "the report should name the node floor, not just say 'not selected'")


def test_report_lists_virtualized_count_when_it_happens():
    result = build("local function f(x) return x * 2 end\nprint(f(4))\n",
                   Config(reproducible_seed=5, min_virtualize_body_nodes=1),
                   verify=False)
    assert result.stats.virtualized == 1
    assert "virtualized         : 1" in result.report


def test_compact_profile_virtualizes_nothing():
    """COMPACT is the profile for when the interpreter's size is not worth it."""
    config = Config.from_profile("compact")
    assert config.virtualization_level is VirtualizationLevel.NONE
    result = build("local function f(x) return x * 2 end\nprint(f(4))\n",
                   config, verify=False)
    assert result.stats.virtualized == 0


# ---------------------------------------------------------------------------
# identifier stripping
# ---------------------------------------------------------------------------
#
# Config has an `identifier_polymorphism` knob and the package shipped a
# scope-aware Renamer for it. Neither does anything: the reconstructor replaces
# every local and parameter with an index into a per-prototype register table,
# so there are no user identifiers left to rename. Measured across 20 corpus
# files, running the Renamer changed the output in 2 of them and left 18
# byte-identical -- and in the two it changed it introduced a bare identifier
# where a register index had been. So the capability is delivered
# unconditionally by the reconstruction scheme, and the knob has nothing left
# to control. These tests pin the capability; the knob stays listed as pending
# because setting it genuinely changes nothing.

NAMED_SOURCE = '''local calculateGrandTotal = 1
local function resolveCustomerDiscount(customerAccount, loyaltyTier)
  local appliedDiscountRate = 0
  if loyaltyTier == "gold" then
    appliedDiscountRate = 0.15
  end
  return customerAccount * (1 - appliedDiscountRate)
end
local shippingCostEstimate = resolveCustomerDiscount(100, "gold")
print(shippingCostEstimate, calculateGrandTotal)
'''

#: Names long and distinctive enough that a substring match cannot be a
#: coincidence against a generated helper name.
USER_NAMES = ("calculateGrandTotal", "resolveCustomerDiscount",
              "customerAccount", "loyaltyTier", "appliedDiscountRate",
              "shippingCostEstimate")


def _identifiers_present(source: str, names) -> list:
    """Whole-word matches only.

    A plain substring search reports false positives from the generated
    helpers, which is how a leak check ends up asserting nothing.
    """
    return [n for n in names
            if re.search(r"(?<![\w_])" + re.escape(n) + r"(?![\w_])", source)]


@pytest.mark.parametrize("level", ("none", "light", "heavy", "maximum"))
def test_no_user_identifier_survives_the_build(level):
    out = build(NAMED_SOURCE,
                Config(reproducible_seed=11, virtualization_level=level,
                       min_virtualize_body_nodes=1),
                verify=False).source
    leaked = _identifiers_present(out, USER_NAMES)
    assert not leaked, f"{level}: user identifiers survived: {leaked}"


def test_identifier_stripping_is_unconditional():
    """The knob does not control it, so turning it off must not restore names."""
    for flag in (True, False):
        out = build(NAMED_SOURCE,
                    Config(reproducible_seed=11, virtualization_level="none",
                           identifier_polymorphism=flag),
                    verify=False).source
        assert not _identifiers_present(out, USER_NAMES), flag


def test_globals_are_preserved():
    """What the program can observe from outside must keep working.

    ``print`` survives as a global lookup, but ``string`` and ``format`` do
    not appear anywhere in the output: they are constants, so they go into the
    encrypted pool like every other string.  That is why the assertion is on
    behaviour rather than on the text -- checking for the literal would fail
    for the right reason.
    """
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    src = 'print(string.format("%d", 42))\nprint(#{"a", "b"})\n'
    out = build(src, Config(reproducible_seed=11, virtualization_level="none"),
                verify=False).source
    assert re.search(r"(?<![\w_])print(?![\w_])", out), "print was renamed away"
    original = execute(TOOLCHAIN, src, "g.luau", timeout=30)
    protected = execute(TOOLCHAIN, out, "p.luau", timeout=30)
    assert original.returncode == protected.returncode, protected.stderr[:300]
    assert original.stdout == protected.stdout

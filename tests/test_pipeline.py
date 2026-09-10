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

#: Compute-heavy corpus programs whose virtualized build is slow enough to run
#: past the default ``execute()`` budget.  Their OUTPUT is identical to the
#: original -- the cost is the expected, documented price of virtualizing tight
#: numeric loops (docs/SECURITY.md) -- so the differential test extends the
#: protected-side budget here instead of weakening the equivalence check.  The
#: original always runs under the fast default.
PROTECTED_TIMEOUT = {
    "buffers.luau": 240,
    "constructs.luau": 240,
}

TOOLCHAIN = find_toolchain()


def _corpus():
    from tests.corpus import REPO_CORPUS
    files = sorted(glob.glob(os.path.join(MICRO_DIR, "*.luau")))
    # The repo-local corpus always runs: it is written here and versioned here,
    # so a checkout without an external Luau source tree still exercises the
    # full-build differential over multi-block, loop- and table-heavy programs.
    files += [p for p in REPO_CORPUS if os.path.basename(p) not in
              {os.path.basename(f) for f in files}]
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
    protected = execute(TOOLCHAIN, result.source, "built.luau",
                        timeout=PROTECTED_TIMEOUT.get(base, 30))

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


def test_same_seed_is_byte_identical_across_processes():
    """Reproducibility must survive the interpreter's hash randomization.

    The bootstrap-order shuffle used to read its candidates off a set of
    strings, whose iteration order follows PYTHONHASHSEED: two processes with
    one seed produced two artifacts, because a shuffle of a differently
    ordered list lands on a different permutation even with identical random
    draws.  The single-process test above cannot see that bug; this one runs
    the same pinned build in two subprocesses under different hash seeds and
    compares the finished output byte for byte.
    """
    import subprocess
    src = ("local function f(a, b)\n"
           "  local t = {x = a, y = b}\n"
           "  for i = 1, 4 do t.x += i * t.y end\n"
           "  return t.x, t.y\n"
           "end\n"
           "print(f(3, 4))\n")
    program = (
        "import hashlib, sys\n"
        "from couxobf.config import Config\n"
        "from couxobf.pipeline import build\n"
        "src = sys.argv[1]\n"
        "r = build(src, Config(reproducible_seed=11, min_virtualize_body_nodes=1),\n"
        "          name='det.luau', verify=False)\n"
        "print(hashlib.sha256(r.source.encode()).hexdigest())\n"
    )
    digests = []
    for hashseed in ("1", "424242"):
        env = dict(os.environ, PYTHONHASHSEED=hashseed)
        proc = subprocess.run([sys.executable, "-c", program, src],
                              capture_output=True, text=True, timeout=120,
                              env=env,
                              cwd=os.path.dirname(os.path.dirname(
                                  os.path.abspath(__file__))))
        assert proc.returncode == 0, proc.stderr[-400:]
        digests.append(proc.stdout.strip())
    assert digests[0] == digests[1], (
        "the same source, config and seed produced different artifacts in "
        "two processes -- some stage still depends on hash ordering")


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
    # The names are per-build now, so assert against what this build actually
    # emitted.  Checking a hardcoded name would KeyError -- and checking a name
    # that is merely *absent* would count zero and pass without verifying
    # anything, which is the failure this test exists to prevent.
    emitted = set(result.runtime_names["helpers"].values())
    assert emitted, "the build reported no helper names at all"
    assert set(result.validation.helper_counts) == emitted
    assert all(result.validation.helper_counts[h] == 1 for h in emitted), (
        result.validation.helper_counts)


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


# ---------------------------------------------------------------------------
# comment stripping
# ---------------------------------------------------------------------------
#
# The pipeline is source -> lexer -> parser -> AST -> printer, and the AST has
# no comment node, so comments cannot survive: there is nothing to carry them.
# That is the right architecture for this -- a regex stripper would have to
# understand strings and long brackets to avoid eating code -- but it is worth
# pinning, because "add comment preservation for debug builds" is an obvious
# future request and the default must stay clean.

COMMENTED_SOURCE = '''-- a line comment
local greeting = "hello" -- inline comment
--[[ a long comment
     over several lines ]]
--[=[ a level-one long comment, with ]] inside it ]=]
--!strict
--!nonstrict
print(greeting) -- trailing
--[[=] nested-looking ]=]]
'''


@pytest.mark.parametrize("profile", ("compact", "balanced", "hardened", "maximum"))
@pytest.mark.parametrize("minify", (False, True))
def test_no_comment_survives_the_build(profile, minify):
    out = build(COMMENTED_SOURCE,
                Config.from_profile(profile).overrides(
                    reproducible_seed=5, minify=minify,
                    min_virtualize_body_nodes=1),
                verify=False).source
    # The comment markers themselves, not just the text: a stripper that left
    # `--` behind with nothing after it would still emit a comment.
    assert "--" not in out, "a comment marker survived"
    assert "[[" not in out and "]]" not in out, "a long bracket survived"
    for text in ("a line comment", "inline comment", "a long comment",
                 "level-one long comment", "trailing", "nested-looking"):
        assert text not in out, text
    # ...and the directive comments are gone too, since they are comments
    assert "strict" not in out and "nonstrict" not in out


def test_comment_stripping_does_not_eat_code():
    """A comment adjacent to meaningful tokens must not take them with it.

    `]]` inside a level-one long comment, and `--` inside a string literal, are
    the two cases a naive stripper gets wrong.  Checking behaviour is the only
    assertion that covers both.
    """
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    src = ('local s = "a--b" -- comment\n'
           'local t = "-- not a comment"\n'
           'print(s, t, #"--")\n')
    out = build(src, Config(reproducible_seed=5, virtualization_level="none"),
                verify=False).source
    assert "--" not in out, "a comment marker survived"
    original = execute(TOOLCHAIN, src, "c.luau", timeout=30)
    protected = execute(TOOLCHAIN, out, "c2.luau", timeout=30)
    assert original.returncode == protected.returncode, protected.stderr[:300]
    assert original.stdout == protected.stdout


# ---------------------------------------------------------------------------
# decoy pool entries and the build fingerprint
#
# Both are pool-level features, and both are only visible in the artifact through
# the count of entries it carries -- which is exactly where a wrong slot number
# would hide.  So the load-bearing test here is differential: a build with 32
# decoys interleaved into the pool has to print the same thing as the source,
# because every read site kept pointing at its own constant.
# ---------------------------------------------------------------------------

CONSTANTS_PROGRAM = '''local KEYS = {"alpha", "beta", "gamma", "delta", "epsilon", "zeta"}
local WEIGHTS = {0.15, 4.75, 12.5, 0.05, 250.0, 1.0}

local function describe(i)
  local key = KEYS[i]
  local weight = WEIGHTS[i]
  local total = #key * weight
  if weight > 4 then
    total = total + weight * 2
  end
  return string.format("%s/%d=%.3f", key, #key, total), total
end

local grand = 0
for i = 1, #KEYS do
  local line, value = describe(i)
  grand = grand + value
  print(line)
end
print(string.format("grand %.4f", grand))
for i = #KEYS, 1, -1 do
  print(i .. ":" .. KEYS[i] .. "=" .. WEIGHTS[i])
end
'''


def _decoy_config(**over):
    config = Config.maximum()
    config.min_virtualize_body_nodes = 1
    # The size budget would trade the decoys away on a file this small, and the
    # point of these builds is the decoys.
    config.max_output_growth = 0
    for key, value in over.items():
        setattr(config, key, value)
    return config


def test_decoys_are_planted_and_reported():
    out = build(CONSTANTS_PROGRAM, _decoy_config(decoy_constants=32),
                name="decoys.luau", verify=False)
    assert out.stats.pool_decoys > 0, out.stats.pool_decoys
    assert "pool decoys" in out.report
    assert str(out.stats.pool_decoys) in out.report


def test_turning_the_switch_off_leaves_the_pool_clean():
    out = build(CONSTANTS_PROGRAM, _decoy_config(decoys=False),
                name="decoys.luau", verify=False)
    assert out.stats.pool_decoys == 0
    assert "none" in out.report.split("pool decoys")[1][:60]


@pytest.mark.skipif(not TOOLCHAIN.can_execute, reason="luau runtime not available")
def test_a_pool_full_of_decoys_prints_what_the_source_prints():
    for count in (0, 8, 48):
        config = _decoy_config(decoys=count > 0, decoy_constants=count)
        out = build(CONSTANTS_PROGRAM, config, name="decoys.luau", verify=True)
        want = execute(TOOLCHAIN, CONSTANTS_PROGRAM, "want.luau", timeout=30)
        got = execute(TOOLCHAIN, out.source, "got.luau", timeout=30)
        assert got.returncode == 0, (count, got.stderr[:400])
        assert want.stdout == got.stdout, (count, want.stdout, got.stdout)


CIPHER_PROGRAM = """local function score(a, b)
  local t = a * b + 2
  if t > 9 then t = t - 9 end
  for i = 1, 3 do t = t + i * a end
  return t
end
print(score(3, 4), score(1, 1), score(0, 7))
"""


def _live_config(**over):
    config = Config.hardened()
    config.min_virtualize_body_nodes = 1
    # The budget trades passes away on a program this size, and the point of
    # these builds is the pass being measured.
    config.max_output_growth = 0
    for key, value in over.items():
        setattr(config, key, value)
    return config


def test_the_opcode_cipher_is_in_the_reader_not_only_in_the_config():
    """On: the generated fetch undoes something.  Off: it reads a byte.

    "The flag reached the build" cannot mean "the output differs", because every
    draw downstream of a disabled knob moves too -- that test would pass on a
    field nothing reads.  So the assertion is about the one line the field owns:
    the opcode reader.  Both builds are executed by `verify=True`, which is the
    half that matters most: a disguise the encoder applies and the interpreter
    forgets is a wrong program, not an insecure one.
    """
    off = build(CIPHER_PROGRAM, _live_config(opcode_cipher=False,
                                             reproducible_seed=4),
                name="cipher.luau", verify=True)
    on = build(CIPHER_PROGRAM, _live_config(opcode_cipher=True,
                                            reproducible_seed=4),
               name="cipher.luau", verify=True)
    assert off.stats.virtualized >= 1 and on.stats.virtualized >= 1
    for group in off.stats.vm_groups:
        ro = group["readers"]["ro"]
        bare = re.compile(r"function %s\(a\)\s*return\s+_bd\(\w+,\s*a\)\s*end"
                          % re.escape(ro))
        assert bare.search(off.source), "the reader should be a plain byte fetch"
    for group in on.stats.vm_groups:
        ro = group["readers"]["ro"]
        bare = re.compile(r"function %s\(a\)\s*return\s+_bd\(\w+,\s*a\)\s*end"
                          % re.escape(ro))
        assert not bare.search(on.source), "the cipher did not reach the interpreter"
    assert all(g["format"]["op_cipher"] == "none" for g in off.stats.vm_groups)
    assert all(g["format"]["op_cipher"] != "none" for g in on.stats.vm_groups)
    assert "opcode cipher none" in off.report
    assert "opcode cipher none" not in on.report
    # and both agree with the source they protect
    assert off.stats.output_bytes > len(CIPHER_PROGRAM)


def test_the_isa_subset_makes_smaller_vms_not_just_different_ones():
    """Narrowing the instruction set is measured in arms and in bytes.

    A group that runs three arithmetic functions should not carry a handler for
    `GETGLOBAL`, and the artifact should be *cheaper* for it -- this is the one
    diversity knob in the tool that reduces output size, which is what makes it
    worth having under a size ceiling at all.
    """
    narrow = build(CIPHER_PROGRAM, _live_config(vm_isa_subset=True, reproducible_seed=9),
                   name="isa.luau", verify=True)
    whole = build(CIPHER_PROGRAM, _live_config(vm_isa_subset=False, reproducible_seed=9),
                  name="isa.luau", verify=True)
    assert narrow.stats.virtualized == whole.stats.virtualized >= 1
    assert len(narrow.source) < len(whole.source)
    top = lambda out: max(g["opcodes"] for g in out.stats.vm_groups)
    assert top(narrow) < top(whole)
    assert "opcodes" in narrow.report


def test_the_report_lists_every_vm_group_the_artifact_carries():
    """One line per interpreter, read out of the plan rather than off the config.

    `--vm-family register` names one family, and a build with `vm_variety` above 1
    ships several: different dispatchers, opcode counts, field widths and target
    modes per group.  A report that echoed the config would describe a build that
    did not happen, and every structural claim in the checklist would rest on the
    request instead of the artifact.
    """
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(repo, "examples", "maze.luau"), encoding="utf-8") as fh:
        source = fh.read()
    out = build(source, _maze_config(vm_variety=3, state_distribution=True,
                                     dispatcher_family="mixed"),
                name="maze.luau", verify=False)
    groups = out.stats.vm_groups
    # The knob is honored: as many groups as the selection can populate, each
    # carrying at least one prototype, and never more than requested.
    assert 2 <= len(groups) <= 3, [g.get("family") for g in groups]
    assert all(g.get("protos", 0) >= 1 for g in groups), groups
    assert {(g.get("family"), g.get("dispatcher")) for g in groups} == {("woven", "woven")}
    # The groups disagree with each other on something structural -- otherwise
    # "several VMs" would be several copies of one.  Formats are per-group
    # draws, so with more than one group at least one descriptor field differs.
    if len(groups) > 1:
        # summary() carries nested dicts and lists, so the dedupe key is a
        # canonical JSON spelling rather than a tuple of items.
        import json
        fmts = {json.dumps(g.get("format") or {}, sort_keys=True)
                for g in groups}
        assert len(fmts) > 1, "every group drew the same format"
    # The group lines are the indented ones; "vm family (config)" is the request,
    # which is a different fact and is printed as such.
    lines = [l for l in out.report.splitlines() if l.startswith("  vm ")]
    assert len(lines) == len(groups), lines
    for group in groups:
        line = lines[group["group"]]
        assert group["family"] in line and group["dispatcher"] in line
        assert "%d opcodes" % group["opcodes"] in line
    # the request is still printed, and labelled as the request
    assert "vm family (config)" in out.report


def test_the_fingerprint_is_a_digest_of_the_decisions_not_of_the_file():
    """Same config and seed, same fingerprint; a different format, a different one.

    A hash of the emitted source would be a hash of everything, including the parts
    the format did not touch, and would then change for reasons nobody can read.
    """
    def fingerprint(**over):
        out = build(CONSTANTS_PROGRAM, _decoy_config(**over),
                    name="decoys.luau", verify=False)
        return out.stats.fingerprint

    base = fingerprint(reproducible_seed=7)
    assert re.fullmatch(r"[0-9a-f]{16}", base), base
    assert fingerprint(reproducible_seed=7) == base, "not reproducible from the seed"
    assert fingerprint(reproducible_seed=7, instruction_formats=0) != base
    # Legacy family switches now normalize to the same single woven VM.
    assert fingerprint(reproducible_seed=7, vm_polymorphism=False,
                       vm_family="stack") == base
    assert fingerprint(reproducible_seed=7, opcode_randomization=False) != base
    assert fingerprint(reproducible_seed=8) != base


def test_the_fingerprint_reports_three_states_not_two():
    """Declined, drawn-but-unbound, and drawn-and-bound are different facts.

    A digest of the format decisions exists as soon as a VM plan is drawn, which
    happens even when every candidate prototype was rejected and the interpreter
    never runs.  Binding that digest into the pool's AAD is a separate claim -- the
    pool of *this* artifact cannot open under another artifact's running format --
    and it is false for a build with nothing virtualized.  Reporting the one as the
    other would let `--vm-family` look like it changed a program that has no VM, and
    would tell a reader their pool is keyed when nothing is keying it.
    """
    tiny = "local function f(x) return x * 2 end\nprint(f(4))\n"

    bound = build(tiny, Config(reproducible_seed=3, min_virtualize_body_nodes=1,
                               fingerprint=True), verify=False)
    assert bound.stats.virtualized == 1
    assert bound.stats.fingerprint and bound.stats.fingerprint_bound
    assert "The constant pool is authenticated" in bound.report

    drawn = build(CONSTANTS_PROGRAM, _decoy_config(reproducible_seed=7), verify=False)
    assert drawn.stats.virtualized == 0, "this fixture must be the no-VM case"
    assert re.fullmatch(r"[0-9a-f]{16}", drawn.stats.fingerprint)
    assert not drawn.stats.fingerprint_bound
    assert "bind nothing here" in drawn.report

    keyless = build(tiny, Config(reproducible_seed=3, virtualization_level="none",
                                 fingerprint=True), verify=False)
    assert not keyless.stats.fingerprint
    assert keyless.stats.fingerprint_requested
    assert "asked for, not produced" in keyless.report


def test_the_fingerprint_can_be_declined_and_says_so():
    off = build(CONSTANTS_PROGRAM, _decoy_config(fingerprint=False),
                name="decoys.luau", verify=False)
    assert off.stats.fingerprint == ""
    assert "fingerprint" in off.report and "off" in off.report.split("fingerprint")[1][:60]


# ---------------------------------------------------------------------------
# metadata layout (Config.metadata_fragmentation)
# ---------------------------------------------------------------------------

def _maze_config(**over):
    config = Config.hardened()
    config.min_virtualize_body_nodes = 1
    config.max_output_growth = 0
    for key, value in over.items():
        setattr(config, key, value)
    return config


def test_metadata_fragmentation_decides_whether_one_table_holds_everything():
    """On, a row points at sibling tables; off, the row carries the payload itself.

    The observable difference is in the assembled row.  Split, it reads
    `code = T[3]` -- a reference into the payload table, with the constants and the
    edge table somewhere else; unsplit, it reads `code = get(47)`, the pool accessor
    called inline, because there is nothing else to point at.  A tool that wants the
    whole description of a VM gets one table to dump in the second case and three to
    line up in the first, which is the entire content of the option, so the test
    asserts that shape rather than a byte count.
    """
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(repo, "examples", "maze.luau"), encoding="utf-8") as fh:
        source = fh.read()
    split = build(source, _maze_config(metadata_fragmentation=True),
                  name="maze.luau", verify=False).source
    whole = build(source, _maze_config(metadata_fragmentation=False),
                  name="maze.luau", verify=False).source
    assert re.search(r"code=\w+\[\d+\]", split), "the tables were not split apart"
    assert not re.search(r"code=\w+\[\d+\]", whole), "off still emitted references"
    assert re.search(r"code=\w+\(", whole), "the unsplit row does not carry its payload"
    # Both have to be the same program, and both run: the interpreter is handed one
    # record either way, so the only thing that changed is where the pieces live.
    assert "code=" in split and "code=" in whole


#: The corners the two VM-diversity knobs can be pushed into when they are
#: combined with the knobs they sit next to.
_VM_CORNERS = {
    "cipher with formats pinned": dict(opcode_cipher=True, operand_randomization=False),
    "cipher with numbering fixed": dict(opcode_cipher=True, opcode_randomization=False),
    "subset with numbering fixed": dict(vm_isa_subset=True, opcode_randomization=False),
    "subset with aliases off": dict(vm_isa_subset=True, opcode_aliases=0),
    "subset with formats pinned": dict(vm_isa_subset=True, instruction_formats=0),
    "both off": dict(opcode_cipher=False, vm_isa_subset=False),
    "both on with one vm": dict(vm_variety=1),
}


def test_the_vm_diversity_knobs_are_correct_in_their_corners():
    """Each pairing of the new knobs with an old one has to build and run.

    A cipher drawn against a format that was never randomized, or a narrowed
    instruction set built from a map with no aliases to lose, are the pairings
    where an encoder and a reader can drift apart without anything static
    noticing: both sides read the same descriptor, so a descriptor nobody
    contradicts is invisible until the program prints the wrong number.  Running
    the artifact under the pinned runtime is the only check that catches it, which
    is why this test pays for seven builds instead of asserting on text.  The
    corners are also where an inert knob hides, so the narrowed-vs-full handler
    counts are compared to make sure the subset *did* something in each one.
    """
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available; run tools/setup-luau.sh")
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(repo, "examples", "inventory.luau"),
              encoding="utf-8") as fh:
        source = fh.read()
    original = execute(TOOLCHAIN, source, "inventory.luau", timeout=30)
    narrowed, full = [], []
    for name, over in sorted(_VM_CORNERS.items()):
        config = Config.maximum()
        config.min_virtualize_body_nodes = 1
        config.max_output_growth = 0
        config.reproducible_seed = 1
        for key, value in over.items():
            setattr(config, key, value)
        result = build(source, config, name="inventory.luau", verify=True)
        protected = execute(TOOLCHAIN, result.source, "built.luau", timeout=60)
        assert protected.stdout == original.stdout, f"{name}: output changed"
        assert protected.returncode == original.returncode, (            f"{name}: rc {original.returncode} != {protected.returncode}"            f"\n{protected.stderr[:300]}")
        arms = [g["opcodes"] for g in result.stats.vm_groups]
        assert arms and all(a > 0 for a in arms), f"{name}: no VM to check"
        (full if over.get("vm_isa_subset") is False or not config.vm_isa_subset
         else narrowed).append(max(arms))
    assert narrowed and full, "the corner table lost one of its two halves"
    assert max(narrowed) < max(full), (
        f"the subset stopped narrowing: {narrowed} against {full}")

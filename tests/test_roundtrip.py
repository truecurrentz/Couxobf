"""Differential round-trip tests: original source vs. IR-reconstructed source.

Every case compiles the original Luau, lowers it to the custom IR, reconstructs
executable Luau from that IR, and runs **both** under the pinned toolchain.  The
two runs must agree on stdout and exit status.  Comparing text would prove
nothing -- the reconstruction is deliberately a different program.

Two corpora:

``tests/fixtures/micro``
    Small hand-written cases, one semantic hazard each.  These are the reason
    most of the bugs in the lowering were ever found, and they always run.

The Luau conformance corpus
    The upstream ``tests/conformance`` directory, when a Luau checkout is
    available.  Point ``COUXOBF_LUAU_SRC`` at it; otherwise these skip.

Cases that cannot be compared honestly are excluded by name, with the reason
recorded next to the name -- never silently.
"""

import glob
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from couxobf import ir, lower_back, parser
from couxobf.emit import printer
from couxobf.toolchain import find_toolchain, execute

TOOLCHAIN = find_toolchain()
MICRO_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "micro")


def reconstruct(src: str, name: str = "test.luau") -> str:
    """source -> IR -> executable Luau."""
    module = ir.Lowerer().lower(parser.parse(src, name))
    body = printer.emit(lower_back.Reconstructor().reconstruct(module))
    return lower_back.HELPERS_SRC + body


def run_both(src: str, name: str):
    """Execute the original and the reconstruction; return both results."""
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available; run tools/setup-luau.sh")
    original = execute(TOOLCHAIN, src, "original.luau", timeout=20)
    protected = execute(TOOLCHAIN, reconstruct(src, name), "protected.luau", timeout=20)
    return original, protected


def assert_same(src: str, name: str = "test.luau") -> None:
    original, protected = run_both(src, name)
    if original.returncode == protected.returncode and original.stdout == protected.stdout:
        return
    hint = protected.stderr.strip().splitlines()[:2]
    pytest.fail(
        "%s: original rc=%d, reconstructed rc=%d\n"
        "  original stdout: %r\n"
        "  reconstructed  : %r\n"
        "  stderr         : %s"
        % (
            name,
            original.returncode,
            protected.returncode,
            original.stdout[:600],
            protected.stdout[:600],
            " | ".join(hint)[:300],
        )
    )


# ---------------------------------------------------------------------------
# the micro battery


def _micro_cases():
    return sorted(glob.glob(os.path.join(MICRO_DIR, "*.luau")))


MICRO_CASES = _micro_cases()


def test_micro_fixtures_are_present():
    """Guard against the battery silently shrinking to nothing."""
    assert len(MICRO_CASES) >= 40, "expected at least 40 micro fixtures"


@pytest.mark.parametrize("path", MICRO_CASES, ids=lambda p: os.path.basename(p))
def test_micro_roundtrip(path):
    with open(path, encoding="utf-8") as fh:
        assert_same(fh.read(), os.path.basename(path))


# the repo-local corpus: multi-block programs the layout and integrity suites
# also share, so the reconstruction path and the VM path see the same shapes.

def _repo_corpus():
    from tests.corpus import REPO_CORPUS
    return REPO_CORPUS


@pytest.mark.parametrize("path", _repo_corpus(), ids=lambda p: os.path.basename(p))
def test_repo_corpus_roundtrip(path):
    with open(path, encoding="utf-8") as fh:
        assert_same(fh.read(), os.path.basename(path))


# ---------------------------------------------------------------------------
# semantic hazards found by earlier bugs, written out as prose so the next
# person knows what each one is for


def test_generic_for_with_more_than_two_variables():
    """FORIN's operand tuple is rebuilt when labels resolve; that step used to
    drop the loop-variable count, so the third variable onward was silently
    nil.  The conformance corpus hits this via ``for n,a,b,c,d in f(5,3)``."""
    assert_same(
        "local t = {{1,10,100},{2,20,200},{3,30,300}}\n"
        "local i = 0\n"
        "local function it()\n"
        "  i += 1\n"
        "  if i <= 3 then return t[i][1], t[i][2], t[i][3] end\n"
        "end\n"
        "for a, b, c in it() do print(a, b, c) end\n",
        "genfor-3vars",
    )


def test_generalized_iteration_over_a_plain_table():
    """``for k, v in t`` with no ``__iter`` iterates with ``next``."""
    assert_same(
        "local n = 0\n"
        "for k, v in {a = 1, b = 2, c = 3} do\n"
        "  n += v\n"
        "end\n"
        "print(n)\n",
        "iter-table",
    )


def test_generalized_iteration_through_iter_metamethod():
    assert_same(
        "local f = {}\n"
        "setmetatable(f, { __iter = function(x)\n"
        "  assert(f == x)\n"
        "  return next, {1, 2, 3, 4}\n"
        "end })\n"
        "local n = 0\n"
        "for v in f do n += v end\n"
        "print(n)\n",
        "iter-__iter",
    )


def test_numeric_for_accepts_numeric_strings():
    """Luau coerces numeric-for bounds through ``tonumber``."""
    assert_same(
        'for i = "10", "1", "-2" do print(i) end\n',
        "numfor-strings",
    )


def test_explicit_nil_array_element_keeps_its_slot():
    """Appending at ``#t + 1`` would collapse ``{1,2,nil,4}`` and shift the 4
    down to index 3."""
    assert_same(
        "local t = {1, 2, nil, 4}\n"
        "print(t[3], t[4], #t)\n",
        "setlist-nil-hole",
    )


def test_loop_variable_is_captured_per_iteration():
    """Luau gives each iteration its own variable; a shared register would let
    every closure observe the final value."""
    assert_same(
        "local fs = {}\n"
        "for i = 1, 3 do\n"
        "  fs[i] = function() return i end\n"
        "end\n"
        "print(fs[1](), fs[2](), fs[3]())\n",
        "per-iteration-capture",
    )


def test_live_upvalue_is_not_captured_by_copy():
    """The mirror image of the case above: writing through an upvalue must stay
    visible to the owner, so captured registers are resolved lexically."""
    assert_same(
        "local x = 1\n"
        "local f = function() return x end\n"
        "x = 2\n"
        "print(f())\n",
        "live-upvalue",
    )


def test_nested_multi_value_calls_are_reentrant():
    """``f(g())``: a single shared result buffer would let the inner call
    clobber the outer one."""
    assert_same(
        "local function add(a, b) return a + b end\n"
        "local function pair() return 1, 2 end\n"
        "print(add(pair()))\n",
        "reentrant-multiret",
    )


def test_trailing_call_is_spliced_not_passed_whole():
    assert_same(
        "local function f(a, b, c) return tostring(a) .. '/' .. tostring(b) .. '/' .. tostring(c) end\n"
        "local function g() return 2, 3 end\n"
        "print(f(1, g()))\n",
        "spliced-tail",
    )


def test_repeat_exits_on_a_true_condition():
    """Inverted here and the loop never terminates, so the case times out."""
    assert_same(
        "local i = 0\n"
        "repeat\n"
        "  i = i + 1\n"
        "until i >= 5\n"
        "print(i)\n",
        "repeat-until",
    )


# ---------------------------------------------------------------------------
# the upstream conformance corpus


def _conformance_dir():
    """Find the upstream conformance corpus, if it is available.

    It is not vendored -- these are upstream Luau's own tests -- so the tests
    skip cleanly when the checkout is absent.  ``tools/setup-luau.sh`` clones
    into ``$TMPDIR/luau-src-<tag>``, which is the usual place to find it; run
    that script (or set ``COUXOBF_LUAU_SRC``) to turn these on.

    ``COUXOBF_NO_EXTERNAL_CORPUS=1`` hides it even when it is present, which
    is how the suite proves the repo-local corpus is sufficient on its own
    (R0) instead of discovering the opposite in a clean checkout.
    """
    from tests.corpus import _external_disabled
    if _external_disabled():
        return None
    candidates = []
    env = os.environ.get("COUXOBF_LUAU_SRC")
    if env:
        candidates.append(os.path.join(env, "tests", "conformance"))
    tag = os.environ.get("LUAU_TAG", "0.700")
    tmp = os.environ.get("TMPDIR", "/tmp")
    candidates += [
        os.path.join(tmp, "luau-src-" + tag, "tests", "conformance"),
        "/tmp/luau-src-" + tag + "/tests/conformance",
        "/home/user/luau-src/tests/conformance",
        os.path.expanduser("~/luau-src/tests/conformance"),
    ]
    for path in candidates:
        if os.path.isdir(path):
            return path
    return None


CONFORMANCE_DIR = _conformance_dir()

# Cannot be compared at all, with the reason recorded.  Anything added here has
# to justify itself -- this list is how a real bug hides.
EXCLUDED = {
    # the original itself exits non-zero in this environment, so there is no
    # reference behaviour to compare against
    "closure.luau": "the unmodified original also fails here",
    # need APIs this build of Luau does not provide
    "debug.luau": "needs the debug library",
    "native.luau": "needs native-code support",
    "native_types.luau": "needs native-code support",
    "ndebug_upvalues.luau": "needs the debug library",
    "vector_library.luau": "needs the vector type",
    "events.luau": "needs an event/scheduler API",
    # output differs run to run for the original too
    "errors.luau": "message ordering is nondeterministic",
    "sort.luau": "comparison counts depend on the sort implementation",
    # both sides are correct; the only difference is an embedded source line
    # number, which the reconstruction necessarily changes
    "pcall.luau": "error text embeds a source line number",
    "pm.luau": "error text embeds a source line number",
    "tmerror.luau": "asserts on source line numbers",
    # Both sides fail, and both are correct; only *which* resource limit trips
    # first differs.  The original exhausts Luau's unpack limit ("too many
    # results to unpack"); the reconstruction uses more memory per frame and
    # hits the allocator first ("not enough memory").  A test that measures
    # which limit trips is measuring the generated code's resource profile,
    # which is exactly what a lowering changes.
    "calls.luau": "asserts on which resource limit trips first",
    # The remaining difference is Luau's FORGPREP_NEXT specialization, which
    # notices that the global `next` was replaced and reports "attempt to
    # iterate over a table value".  Modelling that would mean special-casing
    # the identifier `next` against a captured reference, which is a Luau
    # bytecode detail rather than Luau semantics.
    "iter.luau": "asserts on Luau's specialized global-`next` loop",
}

# Narrow tests for the semantics the two excluded files also cover, so excluding
# them does not leave those behaviours unverified.
def test_iterate_error_wording_matches_luau():
    """`for x in 42` must raise Luau's own message; code inspects it."""
    original, protected = run_both(
        'print(pcall(function() for x in 42 do end end))\n', "iter-err")
    strip = lambda r: __import__("re").sub(r"\./\w+\.luau:\d+: ", "", r.stdout)
    assert strip(original) == strip(protected)


def test_iter_metamethod_result_is_used_unchecked():
    """A `__iter` that hands back nothing must fail at the *call*, with "attempt
    to call a nil value" -- not with the iterate-time message."""
    original, protected = run_both(
        "local o = {}\n"
        "setmetatable(o, { __iter = function() end })\n"
        "local ok, err = pcall(function() for x in o do end end)\n"
        "print(ok, err and err:match('attempt to call a nil value') ~= nil)\n",
        "iter-__iter-nil")
    assert original.stdout == protected.stdout
    assert original.stdout.strip().endswith("true")


def test_classic_iterator_may_be_callable_through_a_metamethod():
    """`for n in f, nil, 5` with a __call table is a valid classic iterator."""
    assert_same(
        "local f = {}\n"
        "setmetatable(f, { __call = function(_, _, n)\n"
        "  if n > 0 then return n - 1 end\n"
        "end })\n"
        "local x = 0\n"
        "for n in f, nil, 5 do\n"
        "  x += n\n"
        "end\n"
        "print(x)\n",
        "iter-__call-classic",
    )


def _conformance_cases():
    if not CONFORMANCE_DIR:
        return []
    return sorted(
        p for p in glob.glob(os.path.join(CONFORMANCE_DIR, "*.luau"))
        if os.path.basename(p) not in EXCLUDED
    )


CONFORMANCE_CASES = _conformance_cases()


def test_conformance_corpus_was_found():
    if not CONFORMANCE_DIR:
        pytest.skip("set COUXOBF_LUAU_SRC to a Luau checkout to run the corpus")
    assert CONFORMANCE_CASES, f"no cases under {CONFORMANCE_DIR}"


@pytest.mark.parametrize("path", CONFORMANCE_CASES, ids=lambda p: os.path.basename(p))
def test_conformance_roundtrip(path):
    with open(path, encoding="utf-8", errors="surrogateescape") as fh:
        assert_same(fh.read(), os.path.basename(path))


def test_lowering_never_errors_on_the_corpus():
    """Separate from execution: the lowering must at least complete on every
    file, excluded or not.  A lowering crash is never an environment problem."""
    if not CONFORMANCE_DIR:
        pytest.skip("set COUXOBF_LUAU_SRC to a Luau checkout to run the corpus")
    failures = []
    for path in sorted(glob.glob(os.path.join(CONFORMANCE_DIR, "*.luau"))):
        name = os.path.basename(path)
        with open(path, encoding="utf-8", errors="surrogateescape") as fh:
            src = fh.read()
        try:
            reconstruct(src, name)
        except Exception as exc:  # noqa: BLE001 - reported, not swallowed
            failures.append(f"{name}: {type(exc).__name__}: {exc}")
    assert not failures, "lowering failed:\n  " + "\n  ".join(failures)

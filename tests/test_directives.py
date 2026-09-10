"""R8: `--!couxobf:` source directives for per-function virtualization control.

A directive comment names the first function declared after it (Luaq's
model, in this tool's own spelling): ``no_virtualize`` keeps that function
native whatever the classifier would score it, and ``virtualize`` forces it
into the VM even when the score calls it trivial.  The directive is a
request about *which* functions the VM takes, not a licence to ignore what
the VM cannot represent -- the closure cap, the main-chunk rule and the
config's level ceiling all still stand, and the report says so when they
override the request.

The tests pin the scanner (a directive-shaped string or long comment is not
a directive), the binding (nearest directive before a declaration wins), the
classifier overrides, and the two honesty rules: an unknown spelling fails
the build, and a directive that could not apply is reported as ignored
rather than implied to have run.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from couxobf import classify, comments, parser
from couxobf import ir as irmod
from couxobf.config import Config, VirtualizationLevel
from couxobf.pipeline import build
from couxobf.rng import Rng
from couxobf.toolchain import execute, find_toolchain

TOOLCHAIN = find_toolchain()


# ---------------------------------------------------------------------------
# the scanner
# ---------------------------------------------------------------------------

def test_the_scanner_finds_line_directives():
    src = ("--!couxobf:no_virtualize\n"
           "local function a() return 1 end\n"
           "  --!couxobf:virtualize\n"
           "local function b() return 2 end\n")
    got = [(d.line, d.name) for d in comments.find_directives(src)]
    assert got == [(1, "no_virtualize"), (3, "virtualize")]


def test_directive_shaped_strings_and_long_comments_are_not_directives():
    src = ('local s = "--!couxobf:no_virtualize"\n'
           "local t = [=[\n--!couxobf:virtualize\n]=]\n"
           "--[[ --!couxobf:no_virtualize ]]\n"
           'print(s, t --[[@keep]] )\n')
    assert comments.find_directives(src) == []


def test_unknown_directive_names_are_still_reported_by_the_scanner():
    """The scanner tells what it saw; refusing the build is the pipeline's
    job, and it can only refuse what the scanner reports."""
    src = "--!couxobf:no_virtulize\nlocal function a() return 1 end\n"
    got = comments.find_directives(src)
    assert [(d.line, d.name) for d in got] == [(1, "no_virtulize")]


# ---------------------------------------------------------------------------
# binding + classifier overrides
# ---------------------------------------------------------------------------

DIRECTIVE_SRC = (
    "--!couxobf:no_virtualize\n"
    "local function hot(n)\n"
    "  local t = 0\n"
    "  for i = 1, n do\n"
    "    if i % 3 == 0 then t = t + i * 2\n"
    "    elseif i % 2 == 0 then t = t - i\n"
    "    else t = t + 1 end\n"
    "  end\n"
    "  return t\n"
    "end\n"
    "--!couxobf:virtualize\n"
    "local function forced(x)\n"
    "  return x * 2 + 1\n"
    "end\n"
    "local function plain(n)\n"
    "  local t = 1\n"
    "  for i = 1, n do t = t + i end\n"
    "  return t\n"
    "end\n"
    "print(hot(30), forced(2), plain(10))\n"
)


def _module(src):
    return irmod.Lowerer().lower(parser.parse(src, "dir.luau"))


def _by_name(cls):
    return {d.name: d for d in cls.decisions}


def test_no_virtualize_keeps_a_hot_function_native():
    module = _module(DIRECTIVE_SRC)
    cls = classify.classify_module(
        module, Config(min_virtualize_body_nodes=1), Rng(b"\x07" * 16),
        directives=comments.find_directives(DIRECTIVE_SRC))
    dec = _by_name(cls)
    assert dec["hot"].level == 0
    assert "no_virtualize" in dec["hot"].reason
    # The forced function is trivial (3 nodes) but the directive overrides
    # the score floor.
    assert dec["forced"].level > 0
    assert "virtualize" in dec["forced"].reason
    # The undirected function still follows the score.
    assert dec["plain"].level > 0
    assert cls.directives_applied == {"no_virtualize": 1, "virtualize": 1}


def test_the_nearest_directive_wins():
    src = ("--!couxobf:virtualize\n"
           "--!couxobf:no_virtualize\n"
           "local function hot(n)\n"
           "  local t = 0\n"
           "  for i = 1, n do t = t + i end\n"
           "  return t\n"
           "end\n"
           "print(hot(4))\n")
    module = _module(src)
    cls = classify.classify_module(
        module, Config(min_virtualize_body_nodes=1), Rng(b"\x07" * 16),
        directives=comments.find_directives(src))
    assert _by_name(cls)["hot"].level == 0, "the directive closest to the declaration wins"


def test_a_directive_with_no_function_after_it_is_moot():
    src = "print(1)\n--!couxobf:virtualize\n"
    module = _module(src)
    cls = classify.classify_module(
        module, Config(min_virtualize_body_nodes=1), Rng(b"\x07" * 16),
        directives=comments.find_directives(src))
    assert cls.directives_applied == {"ignored": 1}


def test_directives_stand_down_when_the_config_disables_the_vm():
    module = _module(DIRECTIVE_SRC)
    cls = classify.classify_module(
        module,
        Config(virtualization_level=VirtualizationLevel.NONE,
               min_virtualize_body_nodes=1),
        Rng(b"\x07" * 16),
        directives=comments.find_directives(DIRECTIVE_SRC))
    assert cls.virtualized() == []
    dec = _by_name(cls)
    assert "ignored" in dec["forced"].reason
    assert cls.directives_applied["ignored"] >= 1


def test_directive_forced_functions_rank_ahead_of_the_budget():
    """With room for exactly one virtualized function, the explicit request
    takes it and the score-based candidate is the one that waits."""
    module = _module(DIRECTIVE_SRC)
    cls = classify.classify_module(
        module, Config(min_virtualize_body_nodes=1, max_vm_functions=1),
        Rng(b"\x07" * 16),
        directives=comments.find_directives(DIRECTIVE_SRC))
    dec = _by_name(cls)
    assert dec["forced"].level > 0
    assert dec["hot"].level == 0
    assert dec["plain"].level == 0


# ---------------------------------------------------------------------------
# pipeline behaviour
# ---------------------------------------------------------------------------

def test_an_unknown_directive_refuses_the_build():
    src = "--!couxobf:no_virtulize\nlocal function a(x) return x end\nprint(a(1))\n"
    with pytest.raises(Exception) as exc:
        build(src, Config(reproducible_seed=3), name="typo.luau", verify=False)
    msg = str(exc.value)
    assert "no_virtulize" in msg
    assert "--!couxobf:no_virtualize" in msg, "the error must name the fix"


def test_a_directive_build_executes_like_its_source():
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    out = build(DIRECTIVE_SRC, Config(reproducible_seed=11),
                name="dir.luau", verify=True)
    assert out.stats.directives == {"no_virtualize": 1, "virtualize": 1}
    dec = {d.name: d for d in out.stats.decisions}
    assert dec["hot"].level == 0 and "no_virtualize" in dec["hot"].reason
    assert dec["forced"].level > 0 and "virtualize" in dec["forced"].reason
    assert "source directives" in out.report
    want = execute(TOOLCHAIN, DIRECTIVE_SRC, "want.luau", timeout=30)
    got = execute(TOOLCHAIN, out.source, "got.luau", timeout=30)
    assert got.returncode == 0, got.stderr[:300]
    assert got.stdout == want.stdout


def test_directives_survive_hash_comment_stripping():
    """`#` comments are stripped before parsing; directives are `--` comments
    and must come through that preparation untouched."""
    src = ("#!/usr/bin/env luau\n"
           "--!couxobf:virtualize\n"
           "local function forced(x)\n  return x * 2 + 1\nend\n"
           "print(forced(21))\n")
    out = build(src, Config(reproducible_seed=11), name="dir.luau",
                verify=False)
    assert out.stats.hash_comments == 1
    assert out.stats.directives == {"virtualize": 1}

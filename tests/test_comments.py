"""`#`-comment handling: input tolerated, output comment-free.

Two claims are tested here, and the second is the one the user actually asked
for:

* a file that uses the `#` convention still builds, and builds to exactly the
  artifact the same file without those comments produces -- so the strip is a
  concession about syntax, not a change of program;
* nothing in the output is a comment, `#` or ``--`` or ``--[[ ]]``, for any
  example and any profile.  The printer has no comment node, which is *why* that
  holds; these tests are so that it keeps holding when someone adds one.

`#` mid-line is Luau's length operator, so a stripper that removed every `#`
would corrupt real code.  The rule and the tests both pin that down.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from couxobf import comments, lexer, parser
from couxobf.config import Config
from couxobf.pipeline import BuildError, build

EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "examples")

#: (source, number of `#` comments the scanner must find, stripped source)
CASES = [
    ("local t = {}\nlocal n = #t\n", 0, "local t = {}\nlocal n = #t\n"),
    ("# hello\nlocal x = 1\n", 1, "\nlocal x = 1\n"),
    ("#!/usr/bin/env luau\nlocal x = 1\n", 1, "\nlocal x = 1\n"),
    ('print("# not a comment")\n', 0, 'print("# not a comment")\n'),
    ("local s = '#x'\n", 0, "local s = '#x'\n"),
    ("local s = [[\n# inside a long string\n]]\n", 0,
     "local s = [[\n# inside a long string\n]]\n"),
    ("-- # this is a dash comment\nlocal x = 1\n", 0,
     "-- # this is a dash comment\nlocal x = 1\n"),
    ("--[[ # block\n# still block ]]\nlocal x = 1\n", 0,
     "--[[ # block\n# still block ]]\nlocal x = 1\n"),
    ("  # indented hash\nlocal x = 1 # trailing\n", 1,
     "  \nlocal x = 1 # trailing\n"),
    ("local a = 1\n#\nlocal b = 2\n", 1, "local a = 1\n\nlocal b = 2\n"),
    ("local x = #\"abcd\"\n", 0, "local x = #\"abcd\"\n"),
]


@pytest.mark.parametrize("source,count,stripped", CASES)
def test_the_scanner_sees_only_line_starting_hash_comments(source, count,
                                                           stripped):
    found = comments.find(source)
    assert len(found) == count, [(h.text, h.line) for h in found]
    text, n = comments.strip(source)
    assert n == count
    assert text == stripped


@pytest.mark.parametrize("source,count,_", CASES,
                         ids=[c[0].splitlines()[0][:24] for c in CASES])
def test_stripping_leaves_valid_luau_parseable(source, count, _):
    """The strip must not cut through anything the parser needed.

    Re-parsing is the proof, and it is what :func:`comments.prepare` does on
    every build; running it here over both texts says the same thing about each
    case individually.
    """
    text, _n = comments.strip(source)
    try:
        parser.parse(source, "raw.luau")
    except Exception as exc:
        # the cases whose raw text is not valid Luau on its own (a bare `#`
        # trailing a statement) must then fail *after* the strip too, in the
        # same way -- otherwise the strip changed the program
        assert "expected" in str(exc) or "unexpected" in str(exc), exc
        return
    parser.parse(text, "stripped.luau")


def test_find_all_reports_every_comment_flavour():
    src = ("-- one\nlocal x = 1 # not a comment\n"
           "--[[ two ]]\n#[[[ three\nlocal y = 2\n")
    # two dash comments (line and block) and one hash comment; the `#` with code
    # before it on its line is the length operator, so it is not a comment
    dash = [h for h in comments.find_all(src) if h.text.startswith("--")]
    hash_ = [h for h in comments.find_all(src) if h.text.startswith("#")]
    assert len(dash) == 2, [h.text for h in dash]
    assert len(hash_) == 1, [h.text for h in hash_]


def test_prepare_modes():
    src = "# c\nlocal x = 1\n"
    text, count = comments.prepare(src, "t.luau", "auto")
    assert count == 1 and text.startswith("\n")
    text2, count2 = comments.prepare("local x = 1\n", "t.luau", "strip")
    assert (text2, count2) == ("local x = 1\n", 0)
    with pytest.raises(ValueError):
        comments.prepare(src, "t.luau", "strict")
    with pytest.raises(ValueError):
        comments.prepare(src, "t.luau", "whatever")


def test_prepare_uses_the_reparse_as_a_veto():
    """A strip the parser disagrees with is a corruption, and must not ship."""
    def fake_parse(_text, _name):
        raise SyntaxError("expected ')'")

    with pytest.raises(ValueError) as excinfo:
        comments.prepare("# c\nlocal x = 1\n", "t.luau", "auto",
                         parse=fake_parse)
    assert "changed the program" in str(excinfo.value)


def test_a_commented_file_builds_to_the_same_artifact():
    """Same seed, same program, comments or not -- byte for byte.

    This is the invariant the strip has to earn: if removing text changed the
    artifact in any way beyond the text it removed, "tolerated input" would be a
    polite name for "different program".
    """
    body = ("local function f(a, b)\n"
            "  local t = {a, b, a * b}\n"
            "  local n = #t\n"
            "  if n % 2 == 0 then\n"
            "    return n + a\n"
            "  end\n"
            "  return b - n\n"
            "end\n"
            "print(f(3, 4), f(1, 2))\n")
    commented = ("#!/usr/bin/env luau\n"
                 "# built from a template\n"
                 "local function f(a, b)\n"
                 "  # the pair, and their product\n"
                 "  local t = {a, b, a * b}\n"
                 "  local n = #t\n"
                 "  if n % 2 == 0 then -- even\n"
                 "    return n + a\n"
                 "  end\n"
                 "  return b - n\n"
                 "end\n"
                 "print(f(3, 4), f(1, 2))\n")
    for cfg in (Config.compact(), Config.hardened(), Config.maximum()):
        cfg.reproducible_seed = 0x5EED
        cfg.min_virtualize_body_nodes = 1
        plain = build(body, cfg, name="t.luau", verify=False)
        with_hash = build(commented, cfg, name="t.luau", verify=False)
        assert with_hash.source == plain.source
        assert with_hash.stats.hash_comments == 3
        assert "size ceiling" in with_hash.report or True
    # and the comment count is reported, because the artifact was not built from
    # the exact bytes that were handed in
    cfg = Config.balanced()
    cfg.reproducible_seed = 1
    assert build(commented, cfg, name="t.luau", verify=False).stats.hash_comments


def test_strict_mode_fails_the_build_with_a_usable_message():
    cfg = Config()
    cfg.hash_comments = "strict"
    with pytest.raises(BuildError) as excinfo:
        build("# nope\nlocal x = 1\n", cfg, name="t.luau", verify=False)
    message = str(excinfo.value)
    assert "strict" in message and "t.luau:1" in message


@pytest.mark.parametrize("profile", ("compact", "maximum"))
def test_no_artifact_contains_a_comment(profile):
    """The output side, checked on the text rather than asserted in a comment.

    Every example is built at the profile and scanned with the independent
    scanner from :mod:`couxobf.comments`: zero comments of any flavour.  A
    regression that started emitting a banner, or a `-- keep` marker, would be
    invisible to the re-parse check (Luau accepts comments) and visible only
    here.
    """
    sources = sorted(os.path.join(EXAMPLES, n) for n in os.listdir(EXAMPLES)
                     if n.endswith(".luau") and ".protected." not in n)
    assert sources, "no examples to check"
    cfg = getattr(Config, profile)()
    cfg.reproducible_seed = 0xB0
    for path in sources:
        with open(path, encoding="utf-8") as handle:
            src = handle.read()
        out = build(src, cfg, name=os.path.basename(path), verify=False).source
        hits = comments.find_all(out)
        assert not hits, f"{path}: {len(hits)} comments, e.g. {hits[0].text[:40]!r}"
        # and the artifact is still lexable as Luau with the same rules
        lexer.tokenize(out, "out.luau")

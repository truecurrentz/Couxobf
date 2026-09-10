"""`#`-style comments: tolerated on input, absent on output.

Luau itself has no `#` comment -- `#` is the length operator, and the only place
the language accepts one at the start of a line is a `#!` shebang.  Real source
files in the wild do carry them (tools that emit Luau through a template, scripts
meant to be runnable both ways), and an obfuscator that dies on them is not
protecting anything.

So this module does two things, and the second is what makes the first
trustworthy:

* :func:`find` locates `#` comments the only way that cannot be wrong -- by
  scanning the way the lexer does, so a ``#`` inside a string, inside a long
  bracket, or used as an operator is never mistaken for a comment.
* :func:`prepare` applies the strip and then *re-parses* the result.  A strip
  that cut through a string silently changes the program; the re-parse is what
  turns that into a build failure instead of a confidently wrong artifact.

The output side is structural rather than textual: the printer has no comment
node at all, so no path leads a comment into the artifact -- and
:mod:`tests.test_comments` checks the emitted tokens instead of trusting that
sentence.
"""

from __future__ import annotations

import re
from typing import Any, List, NamedTuple, Optional, Tuple

#: `#` runs to the end of its line; the language has no block form of it.
_TO_END_OF_LINE = re.compile(r"#[^\n]*")
_LONG_OPEN = re.compile(r"\[(=*)\[")

#: What :data:`~couxobf.config.Config.hash_comments` accepts.
VALID_MODES = ("auto", "strip", "strict")


class HashComment(NamedTuple):
    """One comment range, ``start`` inclusive and ``end`` exclusive."""

    start: int
    end: int
    line: int
    text: str


def _long_open_at(source: str, at: int) -> Optional[Tuple[int, int]]:
    """``(bracket level, index past the opener)`` if a long bracket starts here."""
    m = _LONG_OPEN.match(source, at)
    if not m:
        return None
    return len(m.group(1)), m.end()


def _skip_long(source: str, at: int, level: int) -> int:
    """Index just past the ``]==]`` matching the opener that ended at ``at``."""
    close = "]" + "=" * level + "]"
    end = source.find(close, at)
    return len(source) if end < 0 else end + len(close)


def _skip_quoted(source: str, at: int, quote: str) -> int:
    """Index just past a short string, tolerating escapes and an unterminated end.

    An unterminated string stops at the newline rather than running to the end of
    the file: the real lexer has to produce that error, and this scan must not
    have already deleted part of the file on its way past it.
    """
    i = at + 1
    n = len(source)
    while i < n:
        ch = source[i]
        if ch == "\\":
            i += 2
            continue
        if ch == quote:
            return i + 1
        if ch == "\n":
            return i
        i += 1
    return n


def find(source: str) -> List[HashComment]:
    """Every `#` line comment in ``source``, in order, skipping string bodies.

    The scan keeps its own idea of where a string starts, including the
    long-bracket forms, because that is the difference between a comment and an
    operator: ``local n = #t`` and ``print("#")`` both carry a ``#`` that must
    survive.  A ``#`` counts only when nothing but whitespace precedes it on its
    line, which is also the only shape Luau would otherwise reject outright.
    """
    return _scan(source, dashes=False)


def find_all(source: str) -> List[HashComment]:
    """Every comment in ``source`` -- ``--``, ``--[[ ]]==`` and ``#`` alike.

    This exists for one purpose: the printer has no comment node, so the claim
    "this artifact contains no comments" is about the *text*, and checking it
    needs a scanner that is independent of the printer.  A test that grepped for
    ``--`` would fail on `a -- b` arithmetic-free but pass on a stray ``--`` inside
    a string, which is the same error in the other direction.
    """
    return _scan(source, dashes=True)


#: What a directive comment looks like: the whole comment is the directive.
#: Only short ``--`` comments qualify -- a marker buried inside a
#: ``--[=[ ... ]=]`` block is data, and treating it as configuration is how a
#: string becomes a setting.
_DIRECTIVE = re.compile(r"^--!couxobf:\s*([A-Za-z_][A-Za-z0-9_]*)\s*$")

#: The directive names the build understands.  ``no_virtualize`` keeps the
#: following function native; ``virtualize`` forces it into the VM regardless
#: of its complexity score; ``no_index_to_num`` exempts the following local
#: declaration from the R9 key-rewriting pass.  Luaq's per-function opt-outs
#: were the reference; the spellings are this tool's own.
DIRECTIVES = ("no_virtualize", "virtualize", "no_index_to_num")


class Directive(NamedTuple):
    """One ``--!couxobf:`` directive: the line it sits on and the name it asks."""

    line: int
    name: str


def find_directives(source: str) -> List[Directive]:
    """Every ``--!couxobf:<name>`` directive comment, with its line.

    Uses the same string-aware scan as everything else in this module, so a
    directive-shaped string literal or long comment is not a directive.  A
    directive names the first function declared at or after its line -- the
    declaration that follows it -- which is what the classifier binds; a
    directive with no function after it is silently moot.  Unknown names are
    returned as-is: the caller refuses the build, because a misspelled
    directive that quietly did nothing is the dead knob this project keeps
    removing.
    """
    out: List[Directive] = []
    for hit in _scan(source, dashes=True):
        text = source[hit.start:hit.end].strip()
        m = _DIRECTIVE.match(text)
        if m:
            out.append(Directive(hit.line, m.group(1)))
    return out


def _scan(source: str, dashes: bool) -> List[HashComment]:
    hits: List[HashComment] = []
    i = 0
    n = len(source)
    line = 1
    fresh = True  # nothing but whitespace since the start of this line
    while i < n:
        ch = source[i]
        if ch == "\n":
            line += 1
            i += 1
            fresh = True
            continue
        if ch in " \t\r":
            i += 1
            continue
        if fresh and ch == "#":
            m = _TO_END_OF_LINE.match(source, i)
            end = m.end() if m else i + 1
            hits.append(HashComment(i, end, line, source[i:end]))
            i = end
            continue
        fresh = False
        if ch == "-" and source.startswith("--", i):
            opened = _long_open_at(source, i + 2)
            if opened:
                nxt = _skip_long(source, opened[1], opened[0])
                line += source.count("\n", i, nxt)
                if dashes:
                    hits.append(HashComment(i, nxt, line, source[i:nxt]))
                i = nxt
                continue
            j = source.find("\n", i)
            end = n if j < 0 else j
            if dashes:
                hits.append(HashComment(i, end, line, source[i:end]))
            i = end
            continue
        if ch in "\"'":
            nxt = _skip_quoted(source, i, ch)
            line += source.count("\n", i, nxt)
            i = nxt
            continue
        if ch == "[":
            opened = _long_open_at(source, i)
            if opened:
                nxt = _skip_long(source, opened[1], opened[0])
                line += source.count("\n", i, nxt)
                i = nxt
                continue
        i += 1
    return hits


def strip(source: str) -> Tuple[str, int]:
    """Replace every `#` comment with nothing, keeping the line it sat on.

    Newlines survive the cut on purpose: line numbers in the stripped text then
    match the lines the user wrote, so a verification failure reports the same line
    as it would have for the original file.
    """
    hits = find(source)
    if not hits:
        return source, 0
    parts: List[str] = []
    last = 0
    for hit in hits:
        parts.append(source[last:hit.start])
        last = hit.end
    parts.append(source[last:])
    return "".join(parts), len(hits)


def prepare(source: str, name: str, mode: str = "auto",
            parse: Optional[Any] = None) -> Tuple[str, int]:
    """Apply :attr:`Config.hash_comments` and prove the strip was safe.

    ``auto`` strips only when the source actually uses the convention; ``strip``
    always runs the stripper, which is a way to make two builds differ by nothing
    else; ``strict`` refuses, for the user who would rather be told than quietly
    rewritten.

    ``parse`` is the parser used for the proof.  Leaving it out is what the
    tokenizer-only tests do; a build always supplies it.
    """
    if mode not in VALID_MODES:
        raise ValueError("hash_comments must be one of %s, got %r"
                         % (", ".join(VALID_MODES), mode))
    hits = find(source)
    if mode == "strict":
        if hits:
            raise ValueError(
                "%s:%d: `#` comment, and hash_comments='strict' refuses them; "
                "use 'auto' or 'strip' to accept the convention"
                % (name, hits[0].line))
        return source, 0
    if not hits:
        return source, 0
    text, count = strip(source)
    if parse is not None:
        try:
            parse(text, name)
        except Exception as exc:
            raise ValueError(
                "%s: removing `#` comments changed the program (re-parse failed:"
                " %s); send this file in, and use hash_comments='strict' to keep"
                " the source untouched meanwhile" % (name, exc)) from None
    return text, count

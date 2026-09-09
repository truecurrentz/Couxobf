"""A hand-written lexer for Luau source.

This is a real lexer (not regex source rewriting): it produces a token stream
with byte-exact string contents, exact numeric literal text, and source
positions used for diagnostics.

Luau specifics handled here:

* long brackets ``[[ ... ]]`` / ``[==[ ... ]==]`` for strings and comments;
* ``//`` (floor division) and the compound assignments ``+= -= *= /= //= %=
  ^= ..=``;
* backtick *interpolated* strings (`` `a{x}b` ``); the interior is kept verbatim
  and re-lexed/re-parsed by the parser, so nested braces, strings and comments
  inside an interpolation are handled by the same code paths;
* Luau numeric literals: decimal, hexadecimal (incl. hex floats with ``p``),
  binary (``0b``), and ``_`` digit separators;
* escape sequences ``\\a \\b \\f \\n \\r \\t \\v \\\\ \\" \\' \\ddd \\xXX
  \\u{XXX} \\z`` and backslash-newline.

Luau has **no** ``goto``/``::label::`` (verified against the pinned toolchain),
so ``::`` is not a token here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

KEYWORDS = frozenset(
    """and break continue do else elseif end false for function if in local nil not
    or repeat return then true until while""".split()
)

# Contextual keywords: they are ordinary NAMEs but start constructs.
CONTEXTUAL = frozenset({"type", "export", "self"})

SIMPLE_ESCAPES = {
    "a": 7,
    "b": 8,
    "f": 12,
    "n": 10,
    "r": 13,
    "t": 9,
    "v": 11,
    "\\": 92,
    '"': 34,
    "'": 39,
}


class LexError(Exception):
    def __init__(self, message: str, line: int, col: int):
        super().__init__(f"{line}:{col}: {message}")
        self.line = line
        self.col = col


@dataclass
class Token:
    kind: str  # NAME, NUMBER, STRING, INTERP, OP, KEYWORD, EOF
    value: object
    line: int
    col: int
    offset: int = 0
    text: str = ""  # original source text (numbers keep their literal form)
    is_float: bool = False
    interp: Optional[object] = None  # INTERP: list of parts (str | raw expr text)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Token({self.kind},{self.value!r},{self.line}:{self.col})"


# Longest-first so that `..=` wins over `..` wins over `.`.
OPERATORS = [
    "...",
    "..=",
    "//=",
    "<<=",
    ">>=",
    "==",
    "~=",
    "<=",
    ">=",
    "..",
    "//",
    "->",
    "+=",
    "-=",
    "*=",
    "/=",
    "%=",
    "^=",
    "<<",
    ">>",
    "+",
    "-",
    "*",
    "/",
    "%",
    "^",
    "#",
    "&",
    "~",
    "|",
    "<",
    ">",
    "=",
    "(",
    ")",
    "{",
    "}",
    "[",
    "]",
    ";",
    ":",
    ",",
    ".",
    "?",
]

_DIGITS = set("0123456789")
_HEX = set("0123456789abcdefABCDEF")
_NAME_START = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
_NAME_CONT = _NAME_START | _DIGITS


def _is_name_start(ch: str) -> bool:
    return ch in _NAME_START or ord(ch) > 127  # Luau permits UTF-8 in names


def _is_name_cont(ch: str) -> bool:
    return ch in _NAME_CONT or ord(ch) > 127


class Lexer:
    def __init__(self, source: str, name: str = "<input>"):
        self.src = source
        self.name = name
        self.pos = 0
        self.line = 1
        self.col = 1
        self.tokens: List[Token] = []

    # -- low level --------------------------------------------------------
    def _error(self, msg: str) -> LexError:
        return LexError(msg, self.line, self.col)

    def _peek(self, k: int = 0) -> str:
        i = self.pos + k
        return self.src[i] if i < len(self.src) else ""

    def _advance(self, n: int = 1) -> str:
        out = self.src[self.pos : self.pos + n]
        for ch in out:
            if ch == "\n":
                self.line += 1
                self.col = 1
            else:
                self.col += 1
        self.pos += n
        return out

    def _at(self, text: str) -> bool:
        return self.src.startswith(text, self.pos)

    def _peek_in(self, chars: str, k: int = 0) -> bool:
        """EOF-safe membership test: at EOF `_peek()` is "" which is `in` everything."""
        ch = self._peek(k)
        return ch != "" and ch in chars

    # -- entry ------------------------------------------------------------
    def tokenize(self) -> List[Token]:
        while True:
            self._skip_trivia()
            line, col, off = self.line, self.col, self.pos
            ch = self._peek()
            if ch == "":
                self.tokens.append(Token("EOF", None, line, col, off))
                return self.tokens
            if _is_name_start(ch):
                self._read_name(line, col, off)
            elif ch in _DIGITS or (ch == "." and self._peek(1) in _DIGITS):
                self._read_number(line, col, off)
            elif ch in "\"'":
                self._read_short_string(line, col, off)
            elif ch == "`":
                self._read_interp_string(line, col, off)
            elif ch == "[" and self._long_bracket_level() >= 0:
                self._read_long_string(line, col, off)
            else:
                self._read_operator(line, col, off)

    def _skip_trivia(self) -> None:
        while self.pos < len(self.src):
            ch = self._peek()
            if ch in " \t\r\n\v\f":
                self._advance()
            elif ch == "-" and self._peek(1) == "-":
                self._advance(2)
                if self._peek() == "[":
                    level = self._long_bracket_level()
                    if level >= 0:
                        self._skip_long_bracket(level)
                        continue
                while self.pos < len(self.src) and self._peek() != "\n":
                    self._advance()
            else:
                return

    def _long_bracket_level(self) -> int:
        """Return the number of ``=`` in a long bracket at the cursor, else -1."""
        if self._peek() != "[":
            return -1
        i = self.pos + 1
        n = 0
        while self.src[i : i + 1] == "=":
            n += 1
            i += 1
        if self.src[i : i + 1] == "[":
            return n
        return -1

    def _skip_long_bracket(self, level: int) -> str:
        closer = "]" + "=" * level + "]"
        self._advance(len(closer))  # consume opener
        start = self.pos
        idx = self.src.find(closer, start)
        if idx < 0:
            raise self._error("unfinished long string/comment")
        body = self.src[start:idx]
        self._advance(idx + len(closer) - self.pos)
        return body

    # -- tokens -----------------------------------------------------------
    def _read_name(self, line: int, col: int, off: int) -> None:
        start = self.pos
        self._advance()
        while self.pos < len(self.src) and _is_name_cont(self._peek()):
            self._advance()
        text = self.src[start : self.pos]
        if text in KEYWORDS:
            self.tokens.append(Token("KEYWORD", text, line, col, off, text))
        else:
            self.tokens.append(Token("NAME", text, line, col, off, text))

    def _read_number(self, line: int, col: int, off: int) -> None:
        start = self.pos
        is_float = False
        try:
            if self._peek() == "0" and self._peek_in("xX", 1):
                self._advance(2)
                body = self._consume(_HEX | {"_"})
                if self._peek() == ".":
                    is_float = True
                    self._advance()
                    body += "." + self._consume(_HEX | {"_"})
                if self._peek_in("pP"):
                    # Only a *hex float* exponent may swallow a sign; `0x1p3-1`
                    # must lex as `0x1p3` minus `1`.
                    is_float = True
                    self._advance()
                    sign = ""
                    if self._peek_in("+-"):
                        sign = self._advance()
                    body += "p" + sign + self._consume(_DIGITS | {"_"})
                value = _parse_hex_float(body) if is_float else _parse_hex_int(body)
            elif self._peek() == "0" and self._peek_in("bB", 1):
                self._advance(2)
                body = self._consume(set("01_"))
                value = int(body, 2)
            else:
                body = self._consume(_DIGITS | {"_"})
                if self._peek() == "." and not self._at(".."):
                    is_float = True
                    self._advance()
                    body += "." + self._consume(_DIGITS | {"_"})
                if self._peek_in("eE"):
                    is_float = True
                    self._advance()
                    sign = ""
                    if self._peek_in("+-"):
                        sign = self._advance()
                    body += "e" + sign + self._consume(_DIGITS | {"_"})
                value = _parse_decimal(body, is_float)
        except ValueError as exc:
            raise self._error(f"malformed number near '{self.src[start:self.pos]}'") from exc
        text = self.src[start : self.pos]
        self.tokens.append(Token("NUMBER", value, line, col, off, text, is_float))

    def _consume(self, allowed: set) -> str:
        out = []
        while self.pos < len(self.src) and self._peek() in allowed:
            ch = self._advance()
            if ch != "_":
                out.append(ch)
        return "".join(out)

    def _read_short_string(self, line: int, col: int, off: int) -> None:
        quote = self._advance()
        raw = bytearray()
        while True:
            ch = self._peek()
            if ch == "":
                raise self._error("unfinished string")
            if ch == "\n":
                raise self._error("unfinished string")
            if ch == quote:
                self._advance()
                break
            if ch == "\\":
                self._advance()
                raw += self._read_escape()
                continue
            raw += self._advance().encode("utf-8", "surrogateescape")
        text = self.src[off : self.pos]
        self.tokens.append(Token("STRING", bytes(raw), line, col, off, text))

    def _read_escape(self) -> bytes:
        ch = self._peek()
        if ch == "":
            raise self._error("unfinished escape")
        if ch in SIMPLE_ESCAPES:
            self._advance()
            return bytes([SIMPLE_ESCAPES[ch]])
        if ch == "x":
            self._advance()
            hexd = self._advance(2)
            if len(hexd) != 2 or any(c not in _HEX for c in hexd):
                raise self._error("invalid \\x escape")
            return bytes([int(hexd, 16)])
        if ch == "u":
            self._advance()
            if self._advance() != "{":
                raise self._error("invalid \\u escape")
            digits = []
            while self._peek() != "}":
                if self._peek() == "":
                    raise self._error("unfinished \\u escape")
                digits.append(self._advance())
            self._advance()
            cp = int("".join(digits) or "0", 16)
            if cp > 0x7FFFFFFF:
                raise self._error("Unicode value too large")
            try:
                return chr(cp).encode("utf-8", "surrogatepass")
            except (ValueError, UnicodeEncodeError) as exc:
                raise self._error("invalid Unicode escape") from exc
        if ch == "z":
            self._advance()
            while self.pos < len(self.src) and self._peek() in " \t\r\n\v\f":
                self._advance()
            return b""
        if ch == "\n":
            self._advance()
            return b"\n"
        if ch in _DIGITS:
            digits = self._advance()
            for _ in range(2):
                if self._peek() in _DIGITS:
                    digits += self._advance()
            v = int(digits)
            if v > 255:
                raise self._error("decimal escape too large")
            return bytes([v])
        raise self._error(f"invalid escape sequence '\\{ch}'")

    def _read_long_string(self, line: int, col: int, off: int) -> None:
        level = self._long_bracket_level()
        body = self._skip_long_bracket(level)
        if body.startswith("\n"):
            body = body[1:]
        elif body.startswith("\r\n"):
            body = body[2:]
        raw = body.encode("utf-8", "surrogateescape")
        self.tokens.append(Token("STRING", raw, line, col, off, self.src[off : self.pos]))

    def _read_interp_string(self, line: int, col: int, off: int) -> None:
        self._advance()  # backtick
        parts: List[object] = []
        literal: List[str] = []
        while True:
            ch = self._peek()
            if ch == "":
                raise self._error("unfinished interpolated string")
            if ch == "`":
                self._advance()
                break
            if ch == "\\":
                self._advance()
                esc = self._peek()
                if esc == "`":
                    literal.append("\\`")
                    self._advance()
                elif esc == "{":
                    literal.append("\\{")
                    self._advance()
                elif esc == "u":
                    # `\u{0041}` is a Unicode escape here, NOT an interpolation.
                    literal.append("\\u")
                    self._advance()
                    if self._peek() != "{":
                        raise self._error("invalid \\u escape")
                    literal.append(self._advance())
                    while self._peek() != "}":
                        if self._peek() == "":
                            raise self._error("unfinished \\u escape")
                        literal.append(self._advance())
                    literal.append(self._advance())
                elif esc == "":
                    raise self._error("unfinished escape")
                else:
                    literal.append("\\" + self._advance())
                continue
            if ch == "{":
                if literal:
                    parts.append("".join(literal))
                    literal = []
                self._advance()
                expr = self._read_interp_expr()
                parts.append(("expr", expr))
                continue
            literal.append(self._advance())
        if literal:
            parts.append("".join(literal))
        self.tokens.append(
            Token("INTERP", parts, line, col, off, self.src[off : self.pos], interp=parts)
        )

    def _read_interp_expr(self) -> str:
        """Capture one ``{ ... }`` interpolation body, brace- and string-aware."""
        depth = 1
        out = []
        while True:
            ch = self._peek()
            if ch == "":
                raise self._error("unfinished interpolation")
            if ch == "{":
                depth += 1
                out.append(self._advance())
                continue
            if ch == "}":
                depth -= 1
                out.append(self._advance())
                if depth == 0:
                    return "".join(out)[:-1]
                continue
            if ch in "\"'":
                quote = self._advance()
                out.append(quote)
                while True:
                    c2 = self._peek()
                    if c2 == "":
                        raise self._error("unfinished string in interpolation")
                    if c2 == "\\":
                        out.append(self._advance())
                        out.append(self._advance())
                        continue
                    out.append(self._advance())
                    if c2 == quote:
                        break
                continue
            if ch == "`":
                # Nested interpolated string: scan it *without* emitting tokens
                # (calling _read_interp_string here would corrupt the stream).
                start = self.pos
                self._scan_nested_backtick()
                out.append(self.src[start : self.pos])
                continue
            if ch == "-" and self._peek(1) == "-":
                while self.pos < len(self.src) and self._peek() != "\n":
                    out.append(self._advance())
                continue
            out.append(self._advance())


    def _scan_nested_backtick(self) -> None:
        """Skip over a nested interpolated string without emitting tokens."""
        if self._peek() != "`":
            raise self._error("expected '`'")
        self._advance()
        while True:
            ch = self._peek()
            if ch == "":
                raise self._error("unfinished interpolated string")
            if ch == "\\":
                self._advance(2)
                continue
            if ch == "`":
                self._advance()
                return
            if ch == "{":
                # Must consume the '{' first: _read_interp_expr assumes the
                # opening brace is already gone (depth starts at 1).
                self._advance()
                self._read_interp_expr()
                continue
            self._advance()

    def _read_operator(self, line: int, col: int, off: int) -> None:
        for op in OPERATORS:
            if self._at(op):
                self._advance(len(op))
                self.tokens.append(Token("OP", op, line, col, off, op))
                return
        raise self._error(f"unexpected character '{self._peek()}'")


def _parse_decimal(body: str, is_float: bool):
    if is_float:
        return float(body)
    return int(body)


def _parse_hex_int(body: str) -> int:
    return int(body.replace("_", ""), 16)


def _parse_hex_float(body: str) -> float:
    """Parse a hex float mantissa/exponent (``1p3``, ``1.8p-2``)."""
    body = body.replace("_", "")
    mant_part, sep, exp_part = body.partition("p")
    int_part, _, frac_part = mant_part.partition(".")
    value = float(int(int_part, 16)) if int_part else 0.0
    scale = 1.0 / 16.0
    for d in frac_part:
        value += int(d, 16) * scale
        scale /= 16.0
    exp = int(exp_part) if exp_part else 0
    return value * (2.0**exp)


def decode_source_escapes(text: str) -> bytes:
    """Decode Luau escape sequences inside a source fragment into raw bytes.

    Used for the literal parts of interpolated strings, where the lexer keeps
    the source text verbatim so that re-emission is lossless.
    """
    lex = Lexer(text)
    out = bytearray()
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text) and text[i + 1] in "`{":
            out += text[i + 1].encode("utf-8")
            i += 2
            continue
        if ch != "\\":
            out += ch.encode("utf-8", "surrogateescape")
            i += 1
            continue
        lex.pos = i + 1
        lex.src = text
        out += lex._read_escape()
        i = lex.pos
    return bytes(out)


def tokenize(source: str, name: str = "<input>") -> List[Token]:
    return Lexer(source, name).tokenize()


_SIMPLE_ESCAPES = {
    "a": b"\x07", "b": b"\x08", "f": b"\x0c", "n": b"\x0a",
    "r": b"\x0d", "t": b"\x09", "v": b"\x0b", "\\": b"\\",
    "\"": b"\"", "\'": b"\'", "\n": b"\x0a",
}


def unescape_text(text: str) -> bytes:
    """Decode the escape sequences in a Luau string or interpolation literal.

    Interpolated-string literal chunks are carried by the parser exactly as
    they appeared between the braces, escapes and all, so anything that turns
    them into runtime bytes has to decode them here.  Emitting them verbatim
    would turn a real newline into a backslash followed by ``n``.
    """
    out = bytearray()
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c != "\\":
            out += c.encode("utf-8", "surrogatepass")
            i += 1
            continue
        i += 1
        if i >= n:
            out += b"\\"
            break
        e = text[i]
        if e in _SIMPLE_ESCAPES:
            out += _SIMPLE_ESCAPES[e]
            i += 1
        elif e == "z":
            i += 1
            while i < n and text[i] in " \t\r\n\v\f":
                i += 1
        elif e == "x":
            out.append(int(text[i + 1 : i + 3], 16))
            i += 3
        elif e == "u":
            j = text.index("}", i)
            cp = int(text[i + 2 : j], 16)
            out += chr(cp).encode("utf-8", "surrogatepass")
            i = j + 1
        elif e.isdigit():
            j = i
            while j < n and j - i < 3 and text[j].isdigit():
                j += 1
            out.append(int(text[i:j]) & 0xFF)
            i = j
        else:
            out += e.encode("utf-8", "surrogatepass")
            i += 1
    return bytes(out)

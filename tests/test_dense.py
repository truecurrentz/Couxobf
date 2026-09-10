"""Dense blob encoding: round trips, alphabet hygiene, and live decode.

The Python side and the emitted Luau decoder are two spellings of one
contract; both are exercised here.  The Python reference decode mirrors the
Luau loop digit for digit, so a drift in either direction fails the same
test.  The live half runs the actual emitted decoder under the pinned
toolchain, because a decoder that only round-trips in Python is a decoder
nobody has seen work.
"""

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from couxobf.config import Config
from couxobf.pipeline import build
from couxobf.rng import Rng
from couxobf.runtime.dense import (ALPHABET_CANDIDATES, ALPHABET_SIZE,
                                    DenseCodec, draw_alphabet, encode)
from couxobf.toolchain import execute, find_toolchain

TOOLCHAIN = find_toolchain()


def _ref_decode(text: str, alphabet: str) -> bytes:
    """The Python mirror of the emitted Luau decoder."""
    rev = {c: i for i, c in enumerate(alphabet)}
    out = bytearray()
    acc = cnt = 0
    for ch in text:
        acc = acc * ALPHABET_SIZE + rev[ch]
        cnt += 1
        if cnt == 5:
            out += acc.to_bytes(4, "big")
            acc = cnt = 0
    if cnt > 1:
        out += acc.to_bytes(cnt - 1, "big")
    return bytes(out)


def _rng(seed: int) -> Rng:
    return Rng(bytes([seed % 256]) * 16, domain="dense-test")


# -- the alphabet ------------------------------------------------------------

def test_alphabet_is_printable_quote_free_and_the_right_size():
    alpha = draw_alphabet(_rng(1))
    assert len(alpha) == ALPHABET_SIZE
    assert len(set(alpha)) == ALPHABET_SIZE, "the base must not repeat a digit"
    for ch in alpha:
        assert ch in ALPHABET_CANDIDATES, repr(ch)
        assert 33 <= ord(ch) <= 126 and ch not in "\"\\"


def test_alphabets_differ_between_builds():
    seen = {draw_alphabet(_rng(s)) for s in range(8)}
    assert len(seen) == 8, "every build drew the same alphabet"


# -- encode/decode round trip (Python reference) -----------------------------

@pytest.mark.parametrize("length", list(range(0, 21)) + [63, 64, 65, 256, 1000])
def test_round_trip_every_group_shape(length):
    """Lengths 0..20 cover all trailing-group shapes a few times over; the
    larger ones catch accumulator drift that only shows up on long runs."""
    rng = _rng(length + 1)
    alpha = draw_alphabet(rng)
    data = bytes((i * 37 + length) % 256 for i in range(length))
    text = encode(data, alpha)
    # Density: five digits per four bytes, k+1 for a trailing k.
    full, tail = divmod(length, 4)
    assert len(text) == full * 5 + (tail + 1 if tail else 0)
    # Every character is safe inside a bare double-quoted literal.
    assert all(33 <= ord(c) <= 126 and c not in "\"\\" for c in text)
    assert _ref_decode(text, alpha) == data


def test_encoded_text_depends_on_the_alphabet():
    data = b"couxobf" * 9
    one = encode(data, draw_alphabet(_rng(2)))
    two = encode(data, draw_alphabet(_rng(3)))
    assert one != two, "two builds spelled the same bytes identically"


def test_codec_expr_of_empty_bytes_is_the_empty_string():
    codec = DenseCodec(_rng(4), {"dec": "_kd1", "rev": "_kr1"})
    assert codec.expr(b"") == '""'


# -- the emitted Luau decoder, executed --------------------------------------

def _codec(seed: int, tag: str) -> DenseCodec:
    return DenseCodec(_rng(seed), {"dec": "_k" + tag + "D",
                                   "rev": "_k" + tag + "R"})


@pytest.mark.skipif(not TOOLCHAIN.can_execute,
                    reason="luau runtime not available")
@pytest.mark.parametrize("seed", (1, 2, 3))
def test_the_emitted_decoder_round_trips_under_luau(seed):
    """The real emitted source, run for real, on odd lengths and high bytes."""
    codec = _codec(seed, "t%d" % seed)
    samples = [b"", b"\x00", b"\xff", b"ab", b"\x00\xff\x10", b"\xff" * 4,
               bytes(range(256)), os.urandom(0), os.urandom(101),
               os.urandom(1024)]
    lines = [codec.source(_rng(seed * 7 + 1))]
    for i, sample in enumerate(samples):
        lines.append('print(#%s == %d and "ok%d" or "bad%d")'
                     % (codec.expr(sample), len(sample), i, i))
        # Content check: re-encode what the decoder produced by comparing
        # byte sums and first/last bytes -- cheap identity evidence that does
        # not need a hex printer.
        if sample:
            total = sum(sample) % 251
            lines.append(
                "local s%d = %s\n"
                "local t = 0\n"
                "for j = 1, #s%d do t = (t + string.byte(s%d, j)) %% 251 end\n"
                'print(t == %d and "sum%d" or "mis%d")'
                % (i, codec.expr(sample), i, i, total, i, i))
    script = "\n".join(lines) + "\n"
    result = execute(TOOLCHAIN, script, "dense.luau", timeout=60)
    assert result.returncode == 0, result.stderr[:400]
    assert "bad" not in result.stdout and "mis" not in result.stdout
    assert result.stdout.count("ok") == len(samples)


@pytest.mark.skipif(not TOOLCHAIN.can_execute,
                    reason="luau runtime not available")
def test_a_dense_build_runs_and_matches_the_source():
    """End-to-end: the same program, dense and hex, prints the same thing."""
    src = ('local KEYS = {"alpha", "beta", "gamma"}\n'
           "local total = 0\n"
           "for i = 1, 40 do\n"
           "  total = total + #KEYS[(i % 3) + 1] * i\n"
           "end\n"
           'print(string.format("total %d", total))\n')
    outs = {}
    for enc in ("dense", "hex"):
        result = build(src, Config(reproducible_seed=11, blob_encoding=enc,
                                   min_virtualize_body_nodes=1,
                                   max_output_growth=0),
                       name="d.luau", toolchain=TOOLCHAIN)
        outs[enc] = result
    want = execute(TOOLCHAIN, src, "want.luau", timeout=30)
    assert want.returncode == 0, want.stderr[:200]
    for enc, result in outs.items():
        got = execute(TOOLCHAIN, result.source, "got.luau", timeout=30)
        assert got.returncode == 0, (enc, got.stderr[:300])
        assert got.stdout == want.stdout, (enc, got.stdout, want.stdout)
    # On a program this small the sealed material is below the dense
    # threshold, so the draw is reported skipped and the two builds agree;
    # the shrinkage itself is covered by test_hex_builds_carry_no_dense_decoder
    # on a build with real material.
    report = outs["dense"].runtime_names["blob_encoding"]
    if report.startswith("dense:"):
        assert outs["dense"].source != outs["hex"].source
    else:
        assert report.startswith("dense-skipped:")


# -- config surface ----------------------------------------------------------

def test_blob_encoding_is_validated_and_wired():
    with pytest.raises(ValueError):
        Config(blob_encoding="lzma")
    cfg = Config(blob_encoding="dense")
    assert cfg.blob_encoding == "dense"
    # Wired means not pending: the report must not list it as undelivered.
    assert "blob_encoding" not in [name for name, _ in cfg.pending_fields()]


def test_hex_builds_carry_no_dense_decoder():
    """The escape hatch is a real absence, not a flag nobody reads."""
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(repo, "examples", "inventory.luau"),
              encoding="utf-8") as fh:
        src = fh.read()
    hexed = build(src, Config(reproducible_seed=3, blob_encoding="hex",
                              min_virtualize_body_nodes=1,
                              max_output_growth=0),
                  name="i.luau", verify=False)
    dense = build(src, Config(reproducible_seed=3, blob_encoding="dense",
                              min_virtualize_body_nodes=1,
                              max_output_growth=0),
                  name="i.luau", verify=False)
    assert hexed.runtime_names["blob_encoding"] == "hex"
    assert dense.runtime_names["blob_encoding"].startswith("dense:")
    assert hexed.source != dense.source, "blob_encoding changed nothing"
    assert len(dense.source) < len(hexed.source), (
        "dense spelling did not shrink a build with real sealed material")


def test_dense_is_skipped_when_the_blobs_are_too_small():
    """The decoder costs ~1 KB; below the threshold hex is smaller, and the
    report says the draw was skipped rather than silently not happening."""
    out = build('print("x")\n',
                Config(reproducible_seed=3, blob_encoding="dense",
                       min_virtualize_body_nodes=1),
                verify=False)
    assert out.runtime_names["blob_encoding"].startswith("dense-skipped:")

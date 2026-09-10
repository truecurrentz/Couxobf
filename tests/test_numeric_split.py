"""R7: exact-integer numeric constants stored as split 32-bit halves.

``numeric_protection_level = 2`` rebuilds exact-integer constants from two
32-bit halves at runtime (``hi * 2**32 + lo``) instead of carrying their
double bytes.  The halves are exact by construction -- the encoder only
splits values the reconstruction cannot round -- so the protection costs
nothing in behaviour: the correctness story is a bit-exact round trip on
every value the split claims, and a fall-through to the masked-double path
for every value it does not.

The tests pin three layers:

* the eligibility rule (what may be split, including the edges: 2**53,
  negative zero, NaN, the infinities, non-integers);
* the wire round trip through the Python mirror decoder;
* the emitted Luau decoder, exercised by running a protected build whose
  constants are exactly the ones the split claims.
"""

import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from couxobf import ir, lower_back, parser
from couxobf.constpool import (
    TAG_NUM_MASKED,
    TAG_NUM_SPLIT,
    _split_halves,
    decode_pool,
    serialize_dynamic,
)
from couxobf.crypto.kdf import KeyMaterial
from couxobf.rng import Rng, make_domains, new_seed
from couxobf.toolchain import execute, find_toolchain

TOOLCHAIN = find_toolchain()

#: Every exact-integer double the split must claim, including the edges.
SPLITTABLE = (
    0.0, 1.0, -1.0,
    2.0**31, -(2.0**31), 2.0**32 - 1, 2.0**32, -(2.0**32),
    2.0**53, -(2.0**53), 2.0**53 - 1, -(2.0**53) + 1,
    123456789012345.0, -98765432109876.0, 42.0,
)

#: Values the split must refuse: the reconstruction would not be exact, or
#: arithmetic cannot carry the payload at all.
UNSPLITTABLE = (
    0.5, -0.25, 1e300, -1e300, 2.0**53 + 2, 2.0**60,
    float("inf"), float("-inf"), float("nan"), -0.0,
)


def _bits(v):
    return struct.pack(">d", float(v))


def test_eligibility_claims_exactly_the_exact_integers():
    for v in SPLITTABLE:
        assert _split_halves(v) is not None, v
    for v in UNSPLITTABLE:
        assert _split_halves(v) is None, v
    # Booleans are ints in Python but must never reach the number path.
    assert _split_halves(True) is None
    assert _split_halves(False) is None


def test_the_split_reconstructs_bit_for_bit():
    for v in SPLITTABLE:
        hi, lo = _split_halves(v)
        assert 0 <= lo < 2**32, (v, lo)
        back = float(hi) * 4294967296.0 + float(lo)
        assert _bits(back) == _bits(v), v


def test_level_two_emits_splits_and_level_one_does_not():
    values = [2.0**40 + 7, -(2.0**37) - 3, 0.5, b"k"]
    rng = Rng(b"\x05" * 16)
    blob = serialize_dynamic(list(values), rng, numeric_level=2)
    tags = _entry_tags(blob)
    assert TAG_NUM_SPLIT in tags, "level 2 must split eligible integers"
    assert tags.count(TAG_NUM_SPLIT) == 2, tags

    rng = Rng(b"\x05" * 16)
    blob = serialize_dynamic(list(values), rng, numeric_level=1)
    tags = _entry_tags(blob)
    assert TAG_NUM_SPLIT not in tags, "level 1 keeps the masked-double path"
    assert TAG_NUM_MASKED in tags


def _entry_tags(blob: bytes):
    """Walk a serialized pool and return its tag sequence."""
    (count,) = struct.unpack_from(">I", blob, 0)
    pos, tags = 4, []
    for _ in range(count):
        tag = blob[pos]
        tags.append(tag)
        pos += 1
        if tag in (0,):
            continue
        if tag == 1:
            pos += 1
        elif tag in (2, 6):
            pos += 8
        elif tag == 3:
            (length,) = struct.unpack_from(">I", blob, pos)
            pos += 4 + length
        elif tag == 4:
            pos += 12
        elif tag == 5:
            (frags,) = struct.unpack_from(">H", blob, pos)
            pos += 2
            for _f in range(frags):
                _seed, length = struct.unpack_from(">IH", blob, pos)
                pos += 6 + length
    assert pos == len(blob), "entry walk must consume the whole pool"
    return tags


def test_the_python_mirror_round_trips_a_split_pool():
    values = list(SPLITTABLE) + list(UNSPLITTABLE) + [b"str", None, True]
    rng = Rng(b"\x06" * 16)
    blob = serialize_dynamic(list(values), rng, numeric_level=2)
    back = decode_pool(blob)
    assert len(back) == len(values)
    for want, got in zip(values, back):
        if isinstance(want, float) and want != want:
            assert isinstance(got, float) and got != got, "NaN must survive"
        elif want is None or isinstance(want, bool):
            assert got is want or got == want, (want, got)
        elif isinstance(want, (int, float)):
            assert _bits(got) == _bits(want), (want, got)
        else:
            assert got == want, (want, got)


def test_a_maximum_pool_executes_like_its_source():
    """The emitted Luau decoder must agree with the encoder on every split.

    The program prints each claimed constant and a couple of sums of them,
    so any rounding in ``hi * 2**32 + lo`` changes the output.
    """
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    nums = ", ".join(repr(v) for v in SPLITTABLE[:10])
    src = (
        "local t = {%s}\n"
        "for i = 1, #t do print(t[i]) end\n"
        "print(t[3] + t[4], t[8] - t[7])\n" % nums
    )
    module = ir.Lowerer().lower(parser.parse(src, "split.luau"))
    seed = new_seed()
    protected_src = lower_back.reconstruct_protected(
        module, KeyMaterial.from_seed(seed),
        make_domains(seed).get("constants"), b"split",
        numeric_level=2)
    # The artifact carries the split decoder and no raw double bytes for the
    # split values: finding the reconstruction rule is the positive check.
    assert 'string.unpack(">i4I4"' in protected_src, \
        "the split decoder must be emitted"
    original = execute(TOOLCHAIN, src, "orig.luau", timeout=20)
    protected = execute(TOOLCHAIN, protected_src, "prot.luau", timeout=20)
    assert original.returncode == 0, original.stderr[:200]
    assert (protected.returncode, protected.stdout) == \
        (original.returncode, original.stdout), (
            "split constants must print identically\n  want %r\n  got %r"
            % (original.stdout, protected.stdout))

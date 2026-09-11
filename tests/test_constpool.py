"""Tests for the encrypted constant pool and the protected output path.

Two things are verified, and they are different claims:

1. **The encoding is bit-exact.**  Constants survive the round trip through
   bytes without changing value -- including NaN, signed zero, the infinities,
   and strings holding every byte value.  This is checked on the Python side
   against the wire format and on the Luau side against the real runtime,
   because the two decoders are separate implementations.

2. **Protecting constants does not change behaviour.**  Every micro fixture is
   run twice: once as written, once through the full protected path.  The two
   must agree.

Neither test claims the constants are secret from someone who runs the code.
They are not; see ``docs/SECURITY.md``.
"""

import glob
import itertools
import math
import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from couxobf import ir, lower_back, parser
from couxobf.constpool import (
    ConstantPool,
    ConstantPoolError,
    decode_pool,
    encode_value,
    serialize,
)
from couxobf.crypto.kdf import KeyMaterial
from couxobf.runtime.constpool_runtime import (
    FAILURE_MESSAGE, ConstantPoolRuntime, default_names)
from couxobf.rng import make_domains, new_seed
from couxobf.config import Config
from couxobf.pipeline import build
from couxobf.toolchain import find_toolchain, execute

TOOLCHAIN = find_toolchain()
MICRO_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "micro")

# Bit patterns, compared byte for byte.  Comparing floats with == would pass
# for 0.0 vs -0.0 and fail for every NaN, which is exactly backwards.
BITS = lambda v: struct.pack(">d", float(v))

TRICKY = [
    None,
    True,
    False,
    0,
    1,
    -1,
    0.1,
    1 / 3,
    2 ** 53,
    1e308,
    float("inf"),
    float("-inf"),
    float("nan"),
    -0.0,
    b"",
    b"hello",
    bytes(range(256)),
    b"\x00\xff\x0a\x22\x5c",
    "unicode: héllo → 世界".encode("utf-8"),
]


def make_pool(context: bytes = b"test-build", **kw) -> ConstantPool:
    seed = new_seed()
    return ConstantPool(KeyMaterial.from_seed(seed),
                        make_domains(seed).get("constants"), context, **kw)


def same_value(a, b) -> bool:
    """Equality that respects NaN, signed zero and the int/float collapse."""
    if a is None or isinstance(a, bool):
        return a is b
    if isinstance(a, (int, float)):
        return BITS(a) == BITS(b)
    return a == b


# ---------------------------------------------------------------------------
# the wire format


def test_encode_tags_are_distinct_per_type():
    assert encode_value(None)[0] != encode_value(True)[0]
    assert encode_value(True)[0] != encode_value(1)[0]
    assert encode_value(1)[0] != encode_value(b"x")[0]


def test_serialize_round_trips_bit_exactly():
    got = decode_pool(serialize(TRICKY))
    assert len(got) == len(TRICKY)
    for want, have in zip(TRICKY, got):
        assert same_value(want, have), (want, have)


def test_decode_rejects_a_truncated_header():
    with pytest.raises(ConstantPoolError):
        decode_pool(b"\x00\x00")


def test_decode_rejects_an_unknown_tag():
    with pytest.raises(ConstantPoolError):
        decode_pool(struct.pack(">I", 1) + b"\x7f")


def test_decode_rejects_trailing_bytes():
    good = serialize([1])
    with pytest.raises(ConstantPoolError):
        decode_pool(good + b"\x00")


def test_encode_rejects_unsupported_types():
    with pytest.raises(ConstantPoolError):
        encode_value([1, 2, 3])


# ---------------------------------------------------------------------------
# interning


def test_equal_numbers_share_a_slot():
    pool = make_pool()
    assert pool.slot(1) == pool.slot(1.0), "Luau cannot tell these apart"


def test_signed_zero_is_not_interned_with_zero():
    """`1 / -0.0` is -inf and `1 / 0.0` is +inf, so collapsing them changes
    observable behaviour."""
    pool = make_pool()
    assert pool.slot(0.0) != pool.slot(-0.0)
    assert BITS(decode_pool(serialize([-0.0]))[0]) == BITS(-0.0)


def test_true_is_not_interned_with_one():
    pool = make_pool()
    assert pool.slot(True) != pool.slot(1)
    assert pool.slot(True) != pool.slot(1.0)


def test_distinct_strings_get_distinct_slots():
    pool = make_pool()
    assert pool.slot(b"a") != pool.slot(b"b")
    assert pool.slot(b"a") == pool.slot(b"a")


def test_slots_are_one_based_and_dense():
    pool = make_pool()
    slots = [pool.slot(v) for v in TRICKY]
    assert slots == list(range(1, len(TRICKY) + 1))
    assert len(pool) == len(TRICKY)


# ---------------------------------------------------------------------------
# sealing


def test_sealed_pool_opens_back_to_the_plaintext():
    pool = make_pool()
    for v in TRICKY:
        pool.slot(v)
    sealed = pool.seal()
    back = decode_pool(sealed.open_plaintext())
    assert len(back) == len(TRICKY)
    for want, have in zip(decode_pool(pool.plaintext()), back):
        assert same_value(want, have), (want, have)


def test_ciphertext_hides_the_plaintext():
    pool = make_pool()
    pool.slot(b"a-very-recognisable-string")
    pool.slot(12345.5)
    sealed = pool.seal()
    assert b"a-very-recognisable-string" not in sealed.ciphertext


def test_seal_is_bound_to_the_build_context():
    """The same constants under two build contexts must not open as each other;
    the AAD covers the context."""
    a = make_pool(b"build-a")
    b = make_pool(b"build-b")
    for v in TRICKY:
        a.slot(v)
        b.slot(v)
    sa, sb = a.seal(), b.seal()
    # each opens with its own key and AAD
    la, lb = decode_pool(sa.open_plaintext()), decode_pool(sb.open_plaintext())
    assert all(same_value(x, y) for x, y in zip(la, lb))
    # but the AAD differs, so the tag does not transfer
    from couxobf.crypto.protected import compute_tag

    assert compute_tag(sa.key, sa.nonce, sa.ciphertext, sb.aad) != sa.tag


def test_sealing_an_empty_pool_is_refused():
    with pytest.raises(ConstantPoolError):
        make_pool().seal()


def test_seal_is_idempotent():
    pool = make_pool()
    pool.slot(1)
    first = pool.seal()
    assert pool.seal() is first


def test_two_builds_from_different_seeds_differ():
    a, b = make_pool(), make_pool()
    for v in TRICKY:
        a.slot(v)
        b.slot(v)
    assert a.seal().ciphertext != b.seal().ciphertext


def test_reproducible_for_a_fixed_seed():
    seed = new_seed()
    outs = []
    for _ in range(2):
        pool = ConstantPool(KeyMaterial.from_seed(seed),
                            make_domains(seed).get("constants"), b"same")
        for v in TRICKY:
            pool.slot(v)
        s = pool.seal()
        outs.append((s.key, s.nonce, s.ciphertext, s.tag))
    assert outs[0] == outs[1]


# ---------------------------------------------------------------------------
# the Luau decoder


def _luau_checks(names, sealed, values, shape=None, order=None):
    """Build a script that reads every slot and prints whether it is correct.

    ``order`` reads the slots back in an order other than 1..N, which is what
    catches an index that only works when it is walked from the start.
    """
    rt = ConstantPoolRuntime(names, cache_policy="full", shape=shape)
    src = rt.emit(sealed.key, sealed.nonce, sealed.tag, sealed.ciphertext, sealed.aad,
                  shape=shape)
    slots = list(range(1, len(values) + 1))
    if order == "reverse":
        slots = list(reversed(slots))
    lines = [f"local v{i} = {rt.accessor}({i})" for i in slots]
    for i, v in enumerate(values, start=1):
        if isinstance(v, float) and math.isnan(v):
            lines.append(f'print({i}, v{i} ~= v{i})')
        elif v is None:
            lines.append(f"print({i}, v{i} == nil)")
        elif isinstance(v, bool):
            lines.append(
                f'print({i}, type(v{i}) == "boolean" and v{i} == {str(v).lower()})')
        elif isinstance(v, (int, float)):
            raw = "".join("\\x%02x" % c for c in BITS(v))
            lines.append(f'print({i}, string.pack(">d", v{i}) == "{raw}")')
        else:
            raw = "".join("\\x%02x" % c for c in v)
            lines.append(f'print({i}, #v{i} == {len(v)} and v{i} == "{raw}")')
    return src + "\n" + "\n".join(lines) + "\n"


@pytest.mark.parametrize("policy", ["none", "bounded", "full"])
def test_luau_decoder_matches_python(policy):
    """Two independent decoders -- the Python mirror and the generated Luau --
    must agree on every constant, under every cache policy."""
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    pool = make_pool(cache_policy=policy)
    for v in TRICKY:
        pool.slot(v)
    sealed = pool.seal()
    src = _luau_checks(default_names(), sealed, TRICKY)
    result = execute(TOOLCHAIN, src, "pool.luau", timeout=30)
    assert result.returncode == 0, result.stderr[:400]
    lines = [l for l in result.stdout.strip().split("\n") if l.strip()]
    assert len(lines) == len(TRICKY)
    bad = [l for l in lines if not l.rstrip().endswith("true")]
    assert not bad, f"policy={policy}: {bad}"


@pytest.mark.parametrize("order", ["forward", "reverse"])
def test_every_drawn_decoder_shape_decodes_the_same_pool(order):
    """The decoder's shape is drawn per region, so every combination has to work.

    Three axes: whether the entry offsets are built all at load time or scanned
    forward on demand, how the ticket mask is folded back into a slot number,
    and whether a type byte reaches its materializer through an if-chain or a
    table.  All twelve decode the same pool -- they exist so two regions of one
    artifact are not the same runtime with the names changed.

    Reading the slots backwards is the case the incremental scan has to get
    right: it can only walk forward, so a slot already passed has to have been
    remembered.
    """
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    pool = make_pool()
    for v in TRICKY:
        pool.slot(v)
    sealed = pool.seal()
    combos = [
        dict(zip(ConstantPoolRuntime.SHAPES, pick))
        for pick in itertools.product(*ConstantPoolRuntime.SHAPES.values())
    ]
    assert len(combos) == 12, combos
    for shape in combos:
        src = _luau_checks(default_names(), sealed, TRICKY, shape=shape,
                           order=order)
        result = execute(TOOLCHAIN, src, "pool.luau", timeout=30)
        assert result.returncode == 0, "%s: %s" % (shape, result.stderr[:400])
        lines = [l for l in result.stdout.strip().split("\n") if l.strip()]
        assert len(lines) == len(TRICKY), (shape, len(lines))
        bad = [l for l in lines if not l.rstrip().endswith("true")]
        assert not bad, f"shape={shape} order={order}: {bad}"


def test_the_shape_draw_really_varies():
    """A shape that never moves is a fixed signature with extra steps.

    One build draws one shape per region; across builds every axis has to
    appear.
    """
    seen = {key: set() for key in ConstantPoolRuntime.SHAPES}
    for seed in range(24):
        result = build("local a = 1\nprint(a)\n",
                       Config(reproducible_seed=seed), name="s.luau",
                       verify=False)
        for region in result.runtime_names.get("pool_regions") or ():
            drawn = dict(zip(sorted(ConstantPoolRuntime.SHAPES),
                             region["shape"].split("/")))
            for key, value in drawn.items():
                seen[key].add(value)
    for key, allowed in ConstantPoolRuntime.SHAPES.items():
        assert seen[key] == set(allowed), (key, sorted(seen[key]))


def test_runtime_literals_are_masked_fragments_not_whole_blobs():
    pool = make_pool()
    for v in TRICKY:
        pool.slot(v)
    sealed = pool.seal()
    names = default_names()
    rt = ConstantPoolRuntime(names)
    src = rt.emit(sealed.key, sealed.nonce, sealed.tag, sealed.ciphertext, sealed.aad)
    assert names["lit"] in src
    literal = lambda raw: '"' + "".join("\\x%02x" % b for b in raw) + '"'
    for blob in (sealed.key, sealed.nonce, sealed.tag, sealed.ciphertext, sealed.aad):
        assert literal(blob) not in src


def test_tampering_with_the_pool_is_detected():
    """The tag covers the ciphertext; flipping a bit must stop the runtime
    rather than hand back garbage constants."""
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    pool = make_pool()
    for v in TRICKY:
        pool.slot(v)
    sealed = pool.seal()
    for flip in (0, 7, 100, len(sealed.ciphertext) - 1):
        bad = bytearray(sealed.ciphertext)
        bad[flip] ^= 0x01
        rt = ConstantPoolRuntime(default_names())
        src = rt.emit(sealed.key, sealed.nonce, sealed.tag, bytes(bad), sealed.aad)
        src += f"\nprint({rt.accessor}(1))\n"
        result = execute(TOOLCHAIN, src, "pool.luau", timeout=30)
        assert result.returncode != 0, f"bit flip at {flip} was not detected"
        assert FAILURE_MESSAGE in result.stderr, result.stderr[:200]


def test_wrong_aad_is_rejected():
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    pool = make_pool(b"real-build")
    for v in TRICKY:
        pool.slot(v)
    sealed = pool.seal()
    rt = ConstantPoolRuntime(default_names())
    src = rt.emit(sealed.key, sealed.nonce, sealed.tag, sealed.ciphertext,
                  b"stolen-build" + b"\x00" * 7)
    src += f"\nprint({rt.accessor}(1))\n"
    result = execute(TOOLCHAIN, src, "pool.luau", timeout=30)
    assert result.returncode != 0
    assert FAILURE_MESSAGE in result.stderr, result.stderr[:200]


# ---------------------------------------------------------------------------
# the protected output path


def test_protected_output_contains_no_plaintext_constants():
    """The point of the pool: the *values* must not appear in the artifact."""
    src = (
        'local secret = "a distinctive marker"\n'
        "local key = \"hunter2\"\n"
        "local t = {alpha = 1, beta = 2}\n"
        'local o = {}\nfunction o:gamma() end\n'
        "print(secret, key, t.alpha, t.beta)\n"
    )
    seed = new_seed()
    out = lower_back.reconstruct_protected(
        ir.Lowerer().lower(parser.parse(src, "t.luau")),
        KeyMaterial.from_seed(seed),
        make_domains(seed).get("constants"),
        b"test-build",
    )
    # string values, table keys and method names all live in the pool
    for needle in ("a distinctive marker", "hunter2", "alpha", "beta", "gamma"):
        assert needle not in out, f"{needle!r} leaked into the protected output"


def test_pool_call_sites_use_per_build_tickets_not_raw_slots():
    src = 'local a = "one"\nlocal b = "two"\nprint(a, b, 123)\n'
    seed = b"\x42" * 16
    runtime_names = {}
    out = lower_back.reconstruct_protected(
        ir.Lowerer().lower(parser.parse(src, "tickets.luau")),
        KeyMaterial.from_seed(seed),
        make_domains(seed).get("constants"),
        b"tickets",
        names_out=runtime_names,
    )
    get = runtime_names["pool"]["get"]
    assert "bit32.bxor(i," in out, "runtime should deticket pool requests"
    assert f"{get}(1)" not in out
    assert f"{get}(2)" not in out


def test_global_names_remain_visible_and_why():
    """The counterweight to the test above, and a promise about what the pool
    does *not* do.

    Global names stay in the output because Luau resolves a global against the
    calling function's own environment.  Hiding the name behind an environment
    table captured at load time breaks ``setfenv``, which is a semantic change
    and therefore not a trade this tool makes.  If this test starts failing,
    someone has reintroduced that indirection -- check ``setfenv`` next.
    """
    seed = new_seed()
    out = lower_back.reconstruct_protected(
        ir.Lowerer().lower(parser.parse('print("x")\n', "t.luau")),
        KeyMaterial.from_seed(seed),
        make_domains(seed).get("constants"),
        b"test-build",
    )
    assert "print" in out, "global names are expected to stay visible"


def test_setfenv_still_changes_what_a_global_means():
    """The bug the test above guards against, stated as behaviour."""
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    src = (
        "A = 10\n"
        "local f = function() A = A + 1; return A end\n"
        "print(f())\n"
        "setfenv(f, {A = 100})\n"
        "print(f())\n"
        "print(A)\n"
    )
    original = execute(TOOLCHAIN, src, "original.luau", timeout=20)
    seed = new_seed()
    protected_src = lower_back.reconstruct_protected(
        ir.Lowerer().lower(parser.parse(src, "setfenv.luau")),
        KeyMaterial.from_seed(seed),
        make_domains(seed).get("constants"),
        b"setfenv",
    )
    protected = execute(TOOLCHAIN, protected_src, "protected.luau", timeout=20)
    assert original.returncode == 0, original.stderr[:200]
    assert (original.returncode, original.stdout) == (
        protected.returncode, protected.stdout
    ), "setfenv must still affect global reads in the protected build\n  want %r\n  got %r" % (
        original.stdout, protected.stdout)


def test_protected_output_is_reproducible():
    src = 'print("x")\nlocal t = {1, 2, 3}\nreturn t[2]\n'
    module = ir.Lowerer().lower(parser.parse(src, "t.luau"))
    outs = []
    for _ in range(2):
        seed = new_seed()  # fixed below by reusing one seed
        seed = b"\x11" * 16
        outs.append(lower_back.reconstruct_protected(
            module, KeyMaterial.from_seed(seed),
            make_domains(seed).get("constants"), b"repro"))
    assert outs[0] == outs[1], "same seed must give byte-identical output"


def test_different_seeds_give_different_output():
    src = 'print("x")\nreturn 1\n'
    module = ir.Lowerer().lower(parser.parse(src, "t.luau"))
    a, b = new_seed(), new_seed()
    out_a = lower_back.reconstruct_protected(
        module, KeyMaterial.from_seed(a), make_domains(a).get("constants"), b"ctx")
    out_b = lower_back.reconstruct_protected(
        module, KeyMaterial.from_seed(b), make_domains(b).get("constants"), b"ctx")
    assert out_a != out_b


def _micro():
    return sorted(glob.glob(os.path.join(MICRO_DIR, "*.luau")))


@pytest.mark.parametrize("path", _micro(), ids=lambda p: os.path.basename(p))
def test_protected_output_preserves_behaviour(path):
    """The strongest check available: run the fixture as written and run it
    protected, and require the same stdout and exit status."""
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    name = os.path.basename(path)
    original = execute(TOOLCHAIN, src, "original.luau", timeout=20)
    seed = new_seed()
    protected_src = lower_back.reconstruct_protected(
        ir.Lowerer().lower(parser.parse(src, name)),
        KeyMaterial.from_seed(seed),
        make_domains(seed).get("constants"),
        name.encode("utf-8"),
        cache_policy="bounded",
    )
    protected = execute(TOOLCHAIN, protected_src, "protected.luau", timeout=30)
    assert (original.returncode, original.stdout) == (
        protected.returncode, protected.stdout
    ), "%s: rc %d->%d\n  want %r\n  got  %r\n  err %s" % (
        name, original.returncode, protected.returncode,
        original.stdout[:400], protected.stdout[:400],
        " | ".join(protected.stderr.splitlines()[:2])[:300],
    )


# ---------------------------------------------------------------------------
# decoy entries (Config.decoys, Config.decoy_constants)
#
# A decoy is a fully encoded pool entry that no instruction reaches.  These tests
# are about the two ways that can fail to be true: the count drifting out of
# control, and a "decoy" that is really just a duplicate of a live constant --
# which the interner would have folded anyway, so the pool would claim noise it
# does not have.
# ---------------------------------------------------------------------------

def _seed(tag: bytes) -> bytes:
    """A 16-byte seed built from a short label, so each test is reproducible.

    KeyMaterial wants the full build width; padding a short literal would be a
    second way to be nondeterministic if the padding ever moved.
    """
    return (tag * 4)[:16]


def _pool(seed: bytes, **kw) -> ConstantPool:
    """A pool with a fixed seed, so a planting pattern is reproducible."""
    return ConstantPool(KeyMaterial.from_seed(seed),
                        make_domains(seed).get("constants"),
                        b"decoy-build", **kw)


REAL = [b"GetPartsC", 45.0, b"inventory", 3.25, b"total", 12.5, b"sku"]


def test_no_decoys_leaves_the_pool_exactly_as_the_intererner_made_it():
    pool = _pool(_seed(b"seed-0"))
    slots = [pool.slot(v) for v in REAL]
    assert pool.values == REAL
    assert slots == list(range(1, len(REAL) + 1))
    assert pool.decoys_planted == 0


def test_decoys_are_planted_between_the_real_entries_not_after_them():
    pool = _pool(_seed(b"seed-1"), decoys=10)
    for v in REAL:
        pool.slot(v)
    values = pool.values
    assert pool.decoys_planted > 0, "the budget was there and nothing was planted"
    positions = [i for i, v in enumerate(values) if v not in REAL]
    # Trailing-only noise is the shape that costs an analyst nothing: cut the tail
    # and the pool is clean again.  A decoy inside the range the payload indexes is
    # the one that has to be reasoned about.
    assert min(positions) < len(REAL), (
        f"every decoy is after the last live entry: {positions}")
    assert positions != list(range(min(positions), min(positions) + len(positions))), (
        f"the decoys are one contiguous block, which is a run to delete: {positions}")


def test_a_decoy_is_a_real_constant_not_a_placeholder():
    """Each one has to survive the same encode/decode round trip a live entry does.

    A decoy that decodes to nil, or that the decoder cannot walk, is not noise --
    it is a marker that says "the entries around me are the real ones".
    """
    pool = _pool(_seed(b"seed-2"), decoys=10)
    for v in REAL:
        pool.slot(v)
    decoded = decode_pool(pool.plaintext())
    assert len(decoded) == len(pool.values)
    decoys = [v for v in decoded if v not in REAL]
    assert decoys, decoded
    for value in decoys:
        assert value is not None and not isinstance(value, bool)
        assert isinstance(value, (bytes, int, float)), value
        if isinstance(value, (int, float)):
            assert math.isfinite(value), f"{value!r} is a sentinel, not a constant"
            assert abs(value) < 1e6, f"{value!r} is out of scale with the pool"
        else:
            assert 1 <= len(value) <= 24, value


def test_a_decoy_never_duplicates_a_live_constant():
    pool = _pool(_seed(b"seed-3"), decoys=24)
    for v in REAL:
        pool.slot(v)
    seen = [pool._key_for(v) for v in pool.values]
    assert len(seen) == len(set(seen)), "the pool holds the same value twice"


def test_the_budget_is_a_ceiling_and_a_small_pool_spends_part_of_it():
    """`decoy_constants` scales with the pool instead of padding small files.

    A 7-constant pool asked for 200 decoys must not gain 200: a block of noise
    much larger than the data is its own signature.  And the ceiling has to hold,
    or the size cost of the option is not bounded.
    """
    small = _pool(_seed(b"seed-4"), decoys=200)
    for v in REAL:
        small.slot(v)
    assert 0 < small.decoys_planted < len(REAL) * 2, small.decoys_planted

    big = _pool(_seed(b"seed-5"), decoys=6)
    for i in range(80):
        big.slot(b"key%d" % i)
        big.slot(float(i))
    assert big.decoys_planted == 6, "the budget is a ceiling, not a rate"


def test_the_same_seed_plants_the_same_pool():
    """Everything about the artifact is a function of the seed; noise included.

    Otherwise "reproduce this build" and "the decoys were different" cannot both be
    true, and a regression test for the pool would have nothing to compare.
    """
    def build(seed):
        pool = _pool(seed, decoys=8)
        for v in REAL:
            pool.slot(v)
        return pool.plaintext()

    seed = _seed(b"seed-6")
    assert build(seed) == build(seed)
    assert build(_seed(b"seed-7")) != build(seed)


def test_sealing_reports_the_count_the_decoder_has_to_walk():
    """`SealedPool.count` is what the runtime's index loop reads.

    The decoder walks `count` entries, so a count that ignores the decoys would
    stop mid-pool and every slot after the cut would be nil -- a silent wrong
    answer rather than a failure.
    """
    pool = _pool(_seed(b"seed-8"), decoys=8)
    for v in REAL:
        pool.slot(v)
    sealed = pool.seal()
    assert sealed.count == len(pool.values) > len(REAL)
    assert len(decode_pool(sealed.open_plaintext())) == sealed.count


def test_the_slot_number_of_a_real_constant_is_its_position_in_the_pool():
    """Decoys shift later slots; they must never shift an earlier one.

    This is the one invariant a reader cannot recover from the artifact, so it is
    the one worth writing down: every site that asked for slot 3 has to get the
    value it interned, whatever noise was planted after it.
    """
    pool = _pool(_seed(b"seed-9"), decoys=12)
    slots = {}
    for v in REAL:
        slots[v] = pool.slot(v)
    decoded = decode_pool(pool.plaintext())
    for value, slot in slots.items():
        assert same_value(decoded[slot - 1], value), (value, slot)


def test_the_context_binds_the_pool_to_a_build_and_nothing_else_does():
    """The AAD is the whole of the "you cannot move a pool between builds" claim.

    Two pools sealed with the same key material but different contexts must not open
    in each other, and the ciphertext alone must not be enough to read a pool.  This
    is what makes the build fingerprint (Config.fingerprint) worth a byte of the
    header: the digest of the format decisions goes into the context here, so a pool
    lifted into a build whose format differs fails authentication rather than
    returning constants that belong to another artifact.
    """
    from couxobf.crypto.protected import open_ as open_pool

    def sealed_with(context):
        pool = _pool(_seed(b"bind"), decoys=0)
        pool.context = context
        for value in REAL:
            pool.slot(value)
        return pool.seal()

    a = sealed_with(b"build-a")
    b = sealed_with(b"build-b")
    assert a.aad != b.aad
    assert a.key == b.key, "same seed should give same key material"
    # The *tag* is what changes, not the ciphertext: an additional authenticated
    # data value authenticates the context, it does not decorrelate the keystream
    # (which depends on key and nonce alone).  Same pool, same key, same nonce here
    # -- so the ciphertexts match, and that is not a leak of anything an attacker
    # did not already have.
    assert a.tag != b.tag
    # Opening your own pool works; opening it with the other build's AAD does not.
    assert decode_pool(open_pool(a.key, a.nonce, a.ciphertext, a.tag, a.aad))
    with pytest.raises(Exception):
        open_pool(b.key, b.nonce, a.ciphertext, a.tag, b.aad)
    with pytest.raises(Exception):
        open_pool(a.key, a.nonce, a.ciphertext, a.tag, b.aad)


# ---------------------------------------------------------------------------
# R6: per-group pool regions
#


def _variety_build(name="maze.luau", variety=2, seed=41):
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "..", "examples", name), encoding="utf-8") as fh:
        # The size ceiling is off: at 24x this example has already given up
        # its second group, and a test that asked for two and got one would
        # be asserting nothing.
        return build(fh.read(), Config(reproducible_seed=seed,
                                       vm_variety=variety,
                                       max_output_growth=0),
                     name=name, verify=False)


def test_a_virtualized_build_seals_one_region_per_group_plus_native():
    """R6: the constants stop sharing one blob and one accessor.

    Recovering one accessor used to yield every constant in the program.  With
    the split it yields one region's worth, and the report says how many
    regions the build actually carries rather than implying there is one.
    """
    result = _variety_build()
    regions = result.runtime_names["pool_regions"]
    labels = [r["label"] for r in regions]
    assert "native" in labels, labels
    groups = [r for r in regions if r["label"].startswith("vm group")]
    assert len(groups) >= 2, labels          # variety=2
    assert sum(r["protos"] for r in groups) == result.stats.virtualized
    # Every region is a different sealed structure: different accessor, and a
    # different AAD, which is the only thing that makes them different pools
    # rather than one pool declared twice.
    gets = [r["get"] for r in regions]
    aads = [r["aad"] for r in regions]
    assert len(set(gets)) == len(gets), gets
    assert len(set(aads)) == len(aads), aads
    for get in gets:
        assert get in result.source
    assert "constant pools" in result.report


def test_a_blob_lifted_from_one_region_does_not_open_in_another():
    """The property the split is for, tested rather than asserted.

    Each region is authenticated against the format that reads it -- a group's
    pool against that group's interpreter -- so a blob moved between regions
    fails the tag instead of returning the constants of another group.  The
    contexts here are the ones the build uses: the group fingerprint, not the
    whole-plan digest, which is what would let group 0's blob open under
    group 1 inside the same artifact.
    """
    from couxobf.crypto.protected import open_ as open_pool
    from couxobf.constpool import ConstantPool
    from couxobf.crypto.kdf import KeyMaterial
    from couxobf.rng import Rng, make_domains

    seed = b"\x71" * 16
    keys = KeyMaterial.from_seed(seed)
    contexts = {}
    result = _variety_build()
    for region in result.runtime_names["pool_regions"]:
        contexts[region["label"]] = bytes.fromhex(region["aad"])

    def sealed_with(tag: bytes):
        pool = ConstantPool(keys, Rng(seed), b"region:" + tag,
                            cache_policy="none")
        for value in REAL:
            pool.slot(value)
        return pool.seal()

    sealed = {label: sealed_with(label.encode() + aad)
              for label, aad in contexts.items()}
    for label, s in sealed.items():
        assert decode_pool(open_pool(s.key, s.nonce, s.ciphertext, s.tag,
                                     s.aad, enc_domain=s.enc_domain,
                                     mac_domain=s.mac_domain,
                                     cipher=s.cipher))
    labels = list(sealed)
    for source in labels:
        for target in labels:
            if source == target:
                continue
            with pytest.raises(Exception):
                open_pool(sealed[target].key, sealed[target].nonce,
                          sealed[source].ciphertext, sealed[source].tag,
                          sealed[target].aad,
                          enc_domain=sealed[source].enc_domain,
                          mac_domain=sealed[source].mac_domain,
                          cipher=sealed[source].cipher)

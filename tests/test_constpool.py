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


def _luau_checks(names, sealed, values):
    """Build a script that reads every slot and prints whether it is correct."""
    rt = ConstantPoolRuntime(names, cache_policy="full")
    src = rt.emit(sealed.key, sealed.nonce, sealed.tag, sealed.ciphertext, sealed.aad)
    lines = [f"local v{i} = {rt.accessor}({i})" for i in range(1, len(values) + 1)]
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
                  b"couxobf/constpool/v1\0stolen-build")
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

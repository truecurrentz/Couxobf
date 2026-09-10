"""Every cipher core and every structural variant, against real references.

The crypto runtime is emitted, not fixed, so a bug in one drawn shape is a bug
in a fraction of builds -- the kind that ships.  This module walks the axes
that :class:`couxobf.crypto.cipher.CipherSpec` can take and, for each one,
runs the generated Luau under the pinned toolchain and compares it byte for
byte against:

* :mod:`hashlib` / :mod:`hmac` for SHA-256 and HMAC-SHA256 (authoritative),
* the Python cores for keystream generation,
* FIPS-197 and NIST SP 800-38A for AES-128 itself,
* the seal/open format in :mod:`couxobf.crypto.protected`, in both directions.

It also pins the property the whole exercise exists for: two builds that drew
different cores do not share a crypto signature, and two builds with the same
core but different shapes do not emit the same text.
"""

from __future__ import annotations

import hashlib
import hmac
import itertools
import os
import random
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from couxobf.crypto import aes as aesmod
from couxobf.crypto import chacha20 as chachamod
from couxobf.crypto.cipher import AES_CTR, CHA_CHA, CipherSpec, draw
from couxobf.crypto.protected import compute_tag, seal
from couxobf.rng import Rng
from couxobf.runtime.luau_crypto import crypto_runtime
from couxobf.toolchain import find_toolchain

TOOLCHAIN = find_toolchain()
NAMES = {"xor": "kx", "sha": "kh", "mac": "km", "open": "ko", "seal": "ks"}


def _run_luau(script: str) -> str:
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available; run tools/setup-luau.sh")
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "driver.luau")
        with open(path, "w") as fh:
            fh.write(script)
        proc = subprocess.run([TOOLCHAIN.luau, "driver.luau"], cwd=tmp,
                              capture_output=True, timeout=900)
        if proc.returncode != 0:
            raise AssertionError(
                f"luau driver failed (rc={proc.returncode}):\n"
                + proc.stderr.decode("utf-8", "replace")[:3000])
        return proc.stdout.decode("utf-8", "replace")


def _hex(b: bytes) -> str:
    return b.hex()


def _driver(spec: CipherSpec, seed: bytes, cases) -> str:
    """A Luau program exercising one emitted module, printing ``label<TAB>hex``."""
    rng = Rng(seed, "crypto-shape-test")
    body = crypto_runtime(NAMES, cipher=spec, rng=rng)
    lines = [
        "local C = (function()",
        body,
        "end)()",
        "local function unhex(h)",
        "  local t = table.create(#h // 2)",
        "  for i = 1, #h // 2 do",
        "    t[i] = string.char(tonumber(string.sub(h, 2 * i - 1, 2 * i), 16))",
        "  end",
        "  return table.concat(t)",
        "end",
        "local function hex(s)",
        "  if s == nil then return 'NIL' end",
        "  local t = table.create(#s)",
        "  for i = 1, #s do t[i] = string.format('%02x', string.byte(s, i)) end",
        "  return table.concat(t)",
        "end",
    ]
    for label, kind, args in cases:
        blob = args[:-1] if kind == "xor" else args
        hexed = ", ".join('unhex("%s")' % a.hex() for a in blob)
        fn = {"sha": NAMES["sha"], "mac": NAMES["mac"], "xor": NAMES["xor"],
              "open": NAMES["open"], "seal_tag": NAMES["seal"],
              "open_raw": NAMES["open"]}[kind]
        if kind == "xor":
            lines.append(f'print("{label}\\t" .. hex(C.{fn}({hexed}, {args[-1]})))')
        elif kind == "seal_tag":
            lines.append(
                f'local _ct, _tag = C.{fn}({hexed}) print("{label}\\t" .. hex(_tag))')
        else:
            lines.append(f'print("{label}\\t" .. hex(C.{fn}({hexed})))')
    return "\n".join(lines) + "\n"


def _parse(out: str):
    got = {}
    for line in out.splitlines():
        if "\t" not in line:
            continue
        label, value = line.split("\t", 1)
        got[label] = value.strip()
    return got


# ---------------------------------------------------------------------------
# the primitives, against published vectors
# ---------------------------------------------------------------------------

def test_aes128_matches_fips197():
    key = bytes(range(16))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = aesmod.encrypt_block(aesmod.expand_key(key), pt)
    assert ct.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"


def test_aes128_sbox_is_the_published_table():
    assert aesmod.SBOX[0] == 0x63
    assert aesmod.SBOX[1] == 0x7C
    assert aesmod.SBOX[255] == 0x16
    # every entry is a bijection: 256 distinct bytes
    assert len(set(aesmod.SBOX)) == 256


def test_aes128_ctr_matches_sp800_38a():
    """NIST SP 800-38A F.5.1, the AES-128 CTR vector set."""
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    ctr0 = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    pt = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710")
    want = (
        "874d6191b620e3261bef6864990db6ce"
        "9806f66b7970fdff8617187bb9fffdff"
        "5ae4df3edbd5d35e5b4f09020db03eab"
        "1e031dda2fbe03d1792170a0f3009cee")
    rk = aesmod.expand_key(key)
    ks = b"".join(aesmod._ctr_block(rk, ctr0[:12],
                                    int.from_bytes(ctr0[12:], "big") + i)
                  for i in range(4))
    assert bytes(a ^ b for a, b in zip(pt, ks)).hex() == want


def test_chacha20_matches_rfc8439():
    """RFC 8439 §2.4.2 block test, via the keystream helper."""
    key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    nonce = bytes.fromhex("000000090000004a00000000")
    want = (
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e")
    got = chachamod.chacha20_xor(key, nonce, bytes(64), counter=1)
    assert got.hex() == want


# ---------------------------------------------------------------------------
# generated Luau, across the shape axes
# ---------------------------------------------------------------------------

_QR_ORDERS = ((), ())
_SIGMA = (1634760805, 857760878, 2036477234, 1797285236)


def _specs():
    """The shape combinations worth running.

    Not the full cross product -- that is thousands of Luau executions -- but
    every axis at both of its interesting ends, plus a few random draws so a
    combination nobody thought to enumerate is covered too.
    """
    out = []
    # chacha20: direct / schedule, each table style, each schedule form
    for table_style, sha_schedule in itertools.product(
            ("literal", "fragmented"), ("array", "window")):
        out.append(CipherSpec(core=CHA_CHA, qr_style="direct",
                              table_style=table_style,
                              sha_schedule=sha_schedule,
                              rounds_per_iteration=2))
    for rpi in (1, 5, 10):
        out.append(CipherSpec(core=CHA_CHA, qr_style="schedule",
                              qr_order=tuple(
                                  tuple(q) for q in chachamod.COLUMN_ROUNDS)
                              + tuple(tuple(q) for q in chachamod.DIAGONAL_ROUNDS),
                              rounds_per_iteration=rpi,
                              table_style="fragmented",
                              sha_schedule="window"))
    # aes128: generated vs tabulated S-box, split vs branched final round
    for gen, split in itertools.product((True, False), (True, False)):
        out.append(CipherSpec(core=AES_CTR, generate_sbox=gen,
                              split_final=split, table_style="fragmented",
                              sha_schedule="array"))
        out.append(CipherSpec(core=AES_CTR, generate_sbox=gen,
                              split_final=split, table_style="literal",
                              sha_schedule="window"))
    # permuted composition order, on both cores
    out.append(CipherSpec(core=CHA_CHA, compose_order=(3, 1, 0, 5, 2, 4),
                          sha_schedule="window"))
    out.append(CipherSpec(core=AES_CTR, compose_order=(5, 4, 3, 2, 1, 0),
                          generate_sbox=True))
    # and a handful of whatever the real draw produces
    rnd = random.Random(0x5EED)
    for i in range(6):
        out.append(draw(Rng(bytes(rnd.randrange(256) for _ in range(16)),
                            "draw-%d" % i)))
    return out


@pytest.mark.parametrize("spec", _specs(),
                         ids=lambda s: "%s-%s" % (s.core, s.identity()))
def test_emitted_core_matches_python(spec):
    """The emitted module computes exactly what the Python side computes."""
    rnd = random.Random(0xC0FFEE)
    cases = []
    expected = {}

    for i, n in enumerate([0, 1, 55, 56, 63, 64, 65, 200]):
        msg = bytes(rnd.randrange(256) for _ in range(n))
        cases.append((f"sha{i}", "sha", [msg]))
        expected[f"sha{i}"] = hashlib.sha256(msg).hexdigest()

    for i, (klen, mlen) in enumerate([(16, 0), (32, 64), (100, 50), (200, 300)]):
        key = bytes(rnd.randrange(256) for _ in range(klen))
        msg = bytes(rnd.randrange(256) for _ in range(mlen))
        cases.append((f"hmac{i}", "mac", [key, msg]))
        expected[f"hmac{i}"] = hmac.new(key, msg, hashlib.sha256).hexdigest()

    for i, n in enumerate([0, 1, 15, 16, 17, 63, 64, 65, 300]):
        key = bytes(rnd.randrange(256) for _ in range(32))
        nonce = bytes(rnd.randrange(256) for _ in range(12))
        data = bytes(rnd.randrange(256) for _ in range(n))
        cases.append((f"xor{i}", "xor", [key, nonce, data, 1]))
        expected[f"xor{i}"] = spec.xor_bytes(key, nonce, data, 1).hex()

    # a non-zero starting counter, which is how the bank seeks into a page
    key = bytes(rnd.randrange(256) for _ in range(32))
    nonce = bytes(rnd.randrange(256) for _ in range(12))
    data = bytes(rnd.randrange(256) for _ in range(200))
    cases.append(("xor_seek", "xor", [key, nonce, data, 7]))
    expected["xor_seek"] = spec.xor_bytes(key, nonce, data, 7).hex()

    for i, n in enumerate([0, 7, 64, 500]):
        key = bytes(rnd.randrange(256) for _ in range(32))
        nonce = bytes(rnd.randrange(256) for _ in range(12))
        aad = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 40)))
        plain = bytes(rnd.randrange(256) for _ in range(n))
        # Build the sealed form with Python, open it with Luau: this is the
        # interop direction the artifact depends on, and it only means
        # something if Python sealed with the same core Luau will decrypt
        # with -- which is what passing the spec through does.
        nn, sealed_ct, tag = seal(key, plain, aad, nonce=nonce, cipher=spec)
        cases.append((f"open{i}", "open", [key, nonce, sealed_ct, tag, aad]))
        expected[f"open{i}"] = plain.hex()
        cases.append((f"tag{i}", "seal_tag", [key, nonce, plain, aad]))
        expected[f"tag{i}"] = compute_tag(key, nonce, sealed_ct, aad).hex()

    key = bytes(rnd.randrange(256) for _ in range(32))
    nonce = bytes(rnd.randrange(256) for _ in range(12))
    nn, ct, tag = seal(key, b"secret payload", b"build-7", nonce=nonce,
                       cipher=spec)
    bad = bytearray(ct)
    bad[0] ^= 0xFF
    cases.append(("tamper_ct", "open", [key, nonce, bytes(bad), tag, b"build-7"]))
    expected["tamper_ct"] = "NIL"
    bad_tag = bytearray(tag)
    bad_tag[5] ^= 0x01
    cases.append(("tamper_tag", "open", [key, nonce, ct, bytes(bad_tag), b"build-7"]))
    expected["tamper_tag"] = "NIL"

    got = _parse(_run_luau(_driver(spec, b"\x11" * 16, cases)))
    missing = [k for k in expected if k not in got]
    assert not missing, f"driver produced no result for {missing}"
    for k, want in expected.items():
        assert got[k] == want, f"{k} ({spec.core}): luau={got[k][:64]} want={want[:64]}"


# ---------------------------------------------------------------------------
# the property the polymorphism exists for
# ---------------------------------------------------------------------------

def test_the_two_cores_share_no_constant_signature():
    """A build that drew AES carries no ChaCha constant, and vice versa."""
    chacha = crypto_runtime(NAMES, cipher=CipherSpec(core=CHA_CHA))
    aes = crypto_runtime(NAMES, cipher=CipherSpec(core=AES_CTR))
    # 0x61707865 / 0x3320646e / 0x79622d32 / 0x6b206574 are "expand 32-byte k"
    for word in (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574):
        assert hex(word) not in aes.lower(), (
            f"an AES build still carries the ChaCha sigma word {hex(word)}")
    # the AES S-box head is the other direction's giveaway
    for probe in ("0x63, 0x7c", "0x63,0x7c"):
        assert probe not in chacha.lower(), (
            "a ChaCha build carries a tabulated AES S-box")
    assert chacha != aes


def test_shape_variation_changes_the_source_not_the_bytes():
    """Different shapes emit different text and identical keystream."""
    key = bytes(range(32))
    nonce = bytes(range(12))
    data = bytes(range(200))
    sources = set()
    for spec in _specs():
        rng = Rng(b"\x22" * 16, "shape")
        sources.add(crypto_runtime(NAMES, cipher=spec, rng=rng))
        # identical bytes across every variant of a core
        for other in _specs():
            if other.core != spec.core:
                continue
            assert spec.xor_bytes(key, nonce, data, 1) == \
                other.xor_bytes(key, nonce, data, 1), (
                    f"{spec.core}: shape changed the keystream")
    # not one blob of boilerplate with the names swapped
    assert len(sources) > len(_specs()) // 2, (
        f"{len(sources)} distinct sources for {len(_specs())} shapes")


def test_internal_names_are_drawn_and_do_not_shadow_publics():
    """Per-build internal names, and none of them shadows the public API."""
    a = crypto_runtime(NAMES, cipher=CipherSpec(), rng=Rng(b"\x01" * 16, "n"))
    b = crypto_runtime(NAMES, cipher=CipherSpec(), rng=Rng(b"\x02" * 16, "n"))
    assert a != b, "two builds emitted byte-identical crypto sources"
    for public in NAMES.values():
        # a local that shadows a public name would compile and then call the
        # wrong thing at the first decrypt
        assert ("local %s " % public) not in a
        assert ("local %s," % public) not in a


def test_drawn_specs_are_reproducible():
    """The report describes a build, so the draw has to be repeatable."""
    for seed in (b"\x00" * 16, b"\xff" * 16, bytes(range(16))):
        rng_a = Rng(seed, "cipher")
        rng_b = Rng(seed, "cipher")
        assert draw(rng_a) == draw(rng_b)
    a, b = draw(Rng(b"\x01" * 16, "cipher")), draw(Rng(b"\x02" * 16, "cipher"))
    assert a.summary() != b.summary() or a.core == b.core

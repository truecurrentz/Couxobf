"""Python-side crypto correctness.

Two things are checked here that the rest of the project depends on:

* the primitives match published test vectors and the standard library;
* the SHA-256 round constants are *derived* from their mathematical definition
  and still agree with :mod:`hashlib`, so the table handed to the Luau emitter
  cannot be a transcription error.
"""

import hashlib
import hmac
import os
import random
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from couxobf.crypto.chacha20 import chacha20_block, chacha20_xor
from couxobf.crypto.kdf import KeyMaterial, derive_key, hkdf_expand, hkdf_extract
from couxobf.crypto.protected import compute_tag, enc_key, mac_key, open_, open_blob, seal, sealed_blob
from couxobf.crypto.sha256 import H_INIT, K, hmac_sha256, sha256

SEQ_KEY = bytes(range(32))


def test_chacha20_block_rfc8439_2_3_2():
    nonce = bytes.fromhex("000000090000004a00000000")
    block = chacha20_block(SEQ_KEY, 1, nonce)
    assert block.hex() == (
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )


def test_chacha20_keystream_rfc8439_2_4_2():
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you "
        b"only one tip for the future, sunscreen would be it."
    )
    nonce = bytes.fromhex("000000000000004a00000000")
    ct = chacha20_xor(SEQ_KEY, nonce, plaintext, counter=1)
    assert ct.hex().startswith("6e2e359a2568f98041ba0728dd0d6981")
    assert chacha20_xor(SEQ_KEY, nonce, ct, counter=1) == plaintext


def test_sha256_constants_are_the_fips_180_4_values():
    assert len(K) == 64
    assert K[0] == 0x428A2F98 and K[1] == 0x71374491
    assert K[63] == 0xC67178F2
    assert H_INIT == [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ]


def test_sha256_matches_hashlib_across_padding_boundaries():
    rnd = random.Random(7)
    for n in list(range(0, 130)) + [255, 256, 257, 1000, 4096]:
        data = bytes(rnd.randrange(256) for _ in range(n))
        assert sha256(data) == hashlib.sha256(data).digest(), n
    assert sha256(b"abc").hex() == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert sha256(b"").hex() == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_hmac_matches_stdlib_including_long_keys():
    rnd = random.Random(11)
    for klen in (0, 1, 32, 63, 64, 65, 128):
        for mlen in (0, 1, 64, 200):
            key = bytes(rnd.randrange(256) for _ in range(klen))
            msg = bytes(rnd.randrange(256) for _ in range(mlen))
            assert hmac_sha256(key, msg) == hmac.new(key, msg, hashlib.sha256).digest()


def test_hkdf_rfc5869_case_1():
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    prk = hkdf_extract(salt, ikm)
    assert prk.hex() == (
        "077709362c2e32df0ddc3f0dc47bba63"
        "90b6c73bb50f9c3122ec844ad7c2b3e5"
    )
    okm = hkdf_expand(prk, bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42)
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )


def test_key_material_purposes_are_independent():
    seed = bytes(range(16))
    km = KeyMaterial.from_seed(seed)
    values = [km.strings, km.payload, km.integrity, km.constants]
    assert len(set(values)) == 4, "purpose separation produced a collision"
    assert all(len(v) == 32 for v in values)
    assert KeyMaterial.from_seed(seed).strings == km.strings
    assert KeyMaterial.from_seed(bytes(range(1, 17))).strings != km.strings
    # a region subkey must never equal the top-level purpose key
    assert km.region_key("vm-payload", b"chunk-3") == derive_key(
        km.seed, "region-vm-payload", b"chunk-3"
    )
    assert km.region_key("vm-payload", b"chunk-3") != derive_key(
        km.seed, "vm-payload", b"chunk-3"
    )


def test_payload_seal_open_roundtrip_and_tamper_detection():
    key = os.urandom(32)
    blob = sealed_blob(key, b"protected payload", b"build-1")
    assert open_blob(key, blob, b"build-1") == b"protected payload"

    for flip in (0, 13, 40, len(blob) - 1):
        bad = bytearray(blob)
        bad[flip] ^= 0x01
        with pytest.raises(ValueError):
            open_blob(key, bytes(bad), b"build-1")

    with pytest.raises(ValueError):
        open_blob(key, blob, b"build-2")
    with pytest.raises(ValueError):
        open_blob(os.urandom(32), blob, b"build-1")


def test_payload_uses_context_bound_subkeys_not_raw_chacha_key():
    key = bytes(range(32))
    nonce = bytes(range(12))
    aad = b"build-context"
    plain = b"protected payload"
    _nonce, ct, tag = seal(key, plain, aad, nonce=nonce)

    assert enc_key(key, nonce, aad) != key
    assert mac_key(key, nonce, aad) != key
    assert enc_key(key, nonce, aad) != mac_key(key, nonce, aad)
    assert chacha20_xor(key, nonce, plain, counter=1) != ct
    assert open_(key, nonce, ct, tag, aad) == plain


def test_tag_covers_nonce_and_lengths():
    """Same plaintext under different nonces/AAD must produce different tags."""
    key = os.urandom(32)
    n1, ct1, t1 = seal(key, b"data", b"aad", nonce=bytes(12))
    n2, ct2, t2 = seal(key, b"data", b"aad", nonce=bytes([1]) + bytes(11))
    assert t1 != t2
    assert compute_tag(key, n1, ct1, b"aad") == t1
    assert compute_tag(key, n1, ct1, b"aad2") != t1
    assert open_(key, n1, ct1, t1, b"aad") == b"data"

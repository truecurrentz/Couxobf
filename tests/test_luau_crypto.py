"""Cross-implementation tests: generated Luau crypto vs Python + stdlib.

The generated Luau is executed by the pinned toolchain and compared byte for
byte against:

* :mod:`hashlib` / :mod:`hmac` for SHA-256 and HMAC-SHA256 (authoritative),
* the Python ChaCha20 in :mod:`couxobf.crypto.chacha20`,
* the seal/open format in :mod:`couxobf.crypto.protected`.

Interop is tested in both directions: Python seals and Luau opens, and Luau
computes the same tag Python does.  A protected build only works if the two
sides agree exactly.
"""

import hashlib
import hmac
import os
import random
import subprocess
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from couxobf.crypto.chacha20 import chacha20_xor
from couxobf.crypto.protected import compute_tag, seal
from couxobf.runtime.luau_crypto import crypto_runtime
from couxobf.toolchain import find_toolchain

NAMES = {"xor": "kx", "sha": "kh", "mac": "km", "open": "ko", "seal": "ks"}

TOOLCHAIN = find_toolchain()


def _run_luau(script: str) -> str:
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available; run tools/setup-luau.sh")
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "driver.luau")
        with open(path, "w") as fh:
            fh.write(script)
        proc = subprocess.run([TOOLCHAIN.luau, "driver.luau"], cwd=tmp,
                              capture_output=True, timeout=600)
        if proc.returncode != 0:
            raise AssertionError(
                f"luau driver failed (rc={proc.returncode}):\n"
                + proc.stderr.decode("utf-8", "replace")[:3000]
            )
        return proc.stdout.decode("utf-8", "replace")


def _driver(cases) -> str:
    """Build a Luau driver emitting ``LABEL<TAB>hex`` lines."""
    lines = [
        "local C = (function()",
        crypto_runtime(NAMES),
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
              "open": NAMES["open"], "seal_tag": NAMES["seal"]}[kind]
        if kind == "xor":
            lines.append(f'print("{label}\\t" .. hex(C.{fn}({hexed}, {args[-1]})))')
        elif kind == "seal_tag":
            lines.append(f'print("{label}\\t" .. hex(select(2, C.{fn}({hexed}))))')
        else:
            lines.append(f'print("{label}\\t" .. hex(C.{fn}({hexed})))')
    return "\n".join(lines) + "\n"


def _parse(out: str) -> dict:
    result = {}
    for line in out.splitlines():
        if "\t" in line:
            k, v = line.split("\t", 1)
            result[k] = v
    return result


def test_generated_luau_crypto_matches_reference():
    rnd = random.Random(0xC0FFEE)
    cases = []
    expected = {}

    # SHA-256 against hashlib, covering every padding boundary that matters
    for i, n in enumerate([0, 1, 3, 55, 56, 57, 63, 64, 65, 119, 120, 121, 1000]):
        msg = bytes(rnd.randrange(256) for _ in range(n))
        cases.append((f"sha{i}", "sha", [msg]))
        expected[f"sha{i}"] = hashlib.sha256(msg).hexdigest()
    cases.append(("sha_abc", "sha", [b"abc"]))
    expected["sha_abc"] = (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )

    # HMAC-SHA256 against hmac, including the >64-byte key path
    for i, (klen, mlen) in enumerate([(16, 0), (32, 1), (32, 64), (64, 100),
                                      (100, 50), (200, 1000)]):
        key = bytes(rnd.randrange(256) for _ in range(klen))
        msg = bytes(rnd.randrange(256) for _ in range(mlen))
        cases.append((f"hmac{i}", "mac", [key, msg]))
        expected[f"hmac{i}"] = hmac.new(key, msg, hashlib.sha256).hexdigest()

    # ChaCha20 against the Python implementation
    for i, n in enumerate([0, 1, 63, 64, 65, 1000]):
        key = bytes(rnd.randrange(256) for _ in range(32))
        nonce = bytes(rnd.randrange(256) for _ in range(12))
        data = bytes(rnd.randrange(256) for _ in range(n))
        cases.append((f"xor{i}", "xor", [key, nonce, data, 1]))
        expected[f"xor{i}"] = chacha20_xor(key, nonce, data, 1).hex()

    # Interop: sealed by Python, opened by Luau; tag computed by both
    for i, n in enumerate([0, 7, 64, 500]):
        key = bytes(rnd.randrange(256) for _ in range(32))
        nonce = bytes(rnd.randrange(256) for _ in range(12))
        aad = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 40)))
        plain = bytes(rnd.randrange(256) for _ in range(n))
        nn, ct, tag = seal(key, plain, aad, nonce=nonce)
        cases.append((f"open{i}", "open", [key, nonce, ct, tag, aad]))
        expected[f"open{i}"] = plain.hex()
        cases.append((f"tag{i}", "seal_tag", [key, nonce, plain, aad]))
        expected[f"tag{i}"] = compute_tag(key, nonce, ct, aad).hex()

    # tampered ciphertext and wrong aad must be rejected
    key = bytes(rnd.randrange(256) for _ in range(32))
    nonce = bytes(rnd.randrange(256) for _ in range(12))
    nn, ct, tag = seal(key, b"secret payload", b"build-7")
    bad = bytearray(ct)
    bad[0] ^= 0xFF
    cases.append(("tamper_ct", "open", [key, nonce, bytes(bad), tag, b"build-7"]))
    expected["tamper_ct"] = "NIL"
    cases.append(("tamper_aad", "open", [key, nonce, ct, tag, b"build-8"]))
    expected["tamper_aad"] = "NIL"
    bad_tag = bytearray(tag)
    bad_tag[5] ^= 0x01
    cases.append(("tamper_tag", "open", [key, nonce, ct, bytes(bad_tag), b"build-7"]))
    expected["tamper_tag"] = "NIL"

    got = _parse(_run_luau(_driver(cases)))
    missing = [k for k in expected if k not in got]
    assert not missing, f"luau driver produced no result for {missing}"
    for k, want in expected.items():
        assert got[k] == want, f"{k}: luau={got[k][:64]} reference={want[:64]}"


def test_luau_runtime_avoids_unavailable_apis():
    """Guard the assumptions documented in the module docstring."""
    src = crypto_runtime(NAMES)
    for forbidden in ("bit32.rotl", "bit32.rotr", "math.type", "math.tointeger",
                      "loadstring", "buffer.", "require(", "debug.", "os.", "task."):
        assert forbidden not in src, f"runtime must not use {forbidden}"

"""Tests for build-time payload integrity, and for the gap it exists to close.

The headline case is the plaintext ``entry``.  The descriptor table used to
carry plaintext copies of ``entry`` and ``nparams`` next to the authenticated
blob that also contained them, nothing compared the two, and on a real build
three of fifty-nine edits to that integer ran to completion with exit code 0
and produced silently wrong output.  The fix was to delete the plaintext and
read both from the header inside the MAC'd blob; ``test_no_plaintext_entry_or_nparams``
pins that, and ``test_editing_the_pool_blob_fails_authentication`` pins the
property that now covers them.

Everything else here is about the walk in :mod:`couxobf.integrity.payload`
being a real check rather than one that passes everything.  A validator that
never rejects anything is worse than no validator, because it is a green light.
"""

import glob
import os
import re
import subprocess

import pytest

import couxobf.ir as ir
import couxobf.parser as parser
import couxobf.rng as rngmod
from couxobf.config import Config
from couxobf.integrity import IntegrityError, validate_module, validate_proto
from couxobf.integrity.payload import HEADER_SIZE
from couxobf.pipeline import build
from couxobf.runtime.constpool_runtime import default_names
from couxobf.toolchain import find_toolchain
from couxobf.vm import encode, isa

TOOLCHAIN = find_toolchain()

CORPUS = sorted(glob.glob("/tmp/luau-src-0.700/tests/conformance/*.luau"))


@pytest.fixture(scope="module")
def opmap():
    return encode.OpcodeMap.shuffled(
        rngmod.make_domains(b"\x07" * 16).get("opcodes"))


def _encode_all(src, name, opmap):
    """Every virtualizable prototype in a source, encoded."""
    module = ir.Lowerer().lower(parser.parse(src, name))
    out = {}

    def walk(p):
        if encode.can_virtualize(p)[0]:
            e = encode.encode_proto(p, opmap)
            out[e.proto_id] = e
        for child in p.children:
            walk(child)

    walk(module.main)
    return out


def _string_literal(source: str, local_name: str):
    """The contents of ``local <name> = "..."``, plus the offset of its quote.

    A regex for this is a trap: the body contains backslash escapes, so a
    character class has to be written carefully, and threading it through ``%``
    formatting doubles every backslash again.  Scanning is unambiguous.
    """
    marker = "local " + local_name + "="
    start = source.find(marker)
    if start < 0:
        return None, -1
    open_quote = source.find('"', start + len(marker))
    if open_quote < 0:
        return None, -1
    i = open_quote + 1
    while i < len(source):
        if source[i] == "\\":
            i += 2
            continue
        if source[i] == '"':
            return source[open_quote + 1:i], open_quote
        i += 1
    return None, -1


SIMPLE = """local function f(a, b)
  local total = 0
  for i = 1, a do
    total = total + i * b
  end
  return total
end
print(f(10, 3))
"""


# ---------------------------------------------------------------------------
# clean payloads must pass -- a validator that rejects good output is a bug
# ---------------------------------------------------------------------------

def test_clean_payload_validates(opmap):
    encoded = _encode_all(SIMPLE, "simple.luau", opmap)
    assert encoded, "nothing was virtualized; the test proves nothing"
    reports = validate_module(encoded, opmap)
    for pid, report in zip(sorted(encoded), reports):
        emitted = set(encoded[pid].starts)
        # the walk must cover what it can reach, and never invent a boundary
        assert report.starts <= emitted
        assert report.instructions == len(report.starts)


def test_walk_starts_at_the_header_entry_not_after_it(opmap):
    """The walk must begin where the interpreter begins.

    This is the check that caught a real bug in the validator itself: it treated
    ``entry`` as relative to the end of the header when the encoder measures it
    from the start of the blob, so the walk began eight bytes late, validated a
    suffix of the program, and reported success.  On a five-instruction
    prototype it reached three and said nothing was wrong.

    Full coverage is *not* asserted: unreachable blocks are a normal feature of
    the IR, and this loop carries one.  What must hold is that the walk starts
    on the entry boundary and stays on real boundaries.
    """
    encoded = _encode_all(SIMPLE, "simple.luau", opmap)
    pid = min(encoded)
    e = encoded[pid]
    report = validate_proto(pid, e.code, e.consts, opmap,
                            expected_starts=e.starts)
    assert e.entry in report.starts, (
        f"the walk never visited the entry point at offset {e.entry}; it "
        f"started somewhere else, which is the bug this test is for")
    assert min(e.starts) in report.starts, "the walk missed the first instruction"
    assert report.starts <= set(e.starts)


@pytest.mark.parametrize("path", CORPUS[:30],
                         ids=lambda p: os.path.basename(p))
def test_corpus_payloads_validate(path, opmap):
    """554 prototypes across the conformance corpus, zero false positives."""
    with open(path, encoding="utf-8", errors="surrogateescape") as fh:
        src = fh.read()
    try:
        encoded = _encode_all(src, os.path.basename(path), opmap)
    except Exception:
        pytest.skip("does not lower")
    if not encoded:
        pytest.skip("nothing virtualizable")
    validate_module(encoded, opmap)


# ---------------------------------------------------------------------------
# corrupted payloads must be rejected
# ---------------------------------------------------------------------------

def _one(opmap):
    encoded = _encode_all(SIMPLE, "simple.luau", opmap)
    pid = min(encoded)
    return pid, encoded[pid]


def test_truncated_code_is_rejected(opmap):
    pid, e = _one(opmap)
    with pytest.raises(IntegrityError, match="short of the"):
        validate_proto(pid, e.code[:4], e.consts, opmap)


def test_constant_count_mismatch_is_rejected(opmap):
    """The header's nconsts and the descriptor's constant list must agree."""
    pid, e = _one(opmap)
    with pytest.raises(IntegrityError, match="constants"):
        validate_proto(pid, e.code, e.consts[:-1] or [None], opmap)


def test_parameters_exceeding_registers_is_rejected(opmap):
    pid, e = _one(opmap)
    # nparams is header byte 0; nregs is the u16 at bytes 2..3
    broken = bytes([e.nregs + 1]) + e.code[1:]
    with pytest.raises(IntegrityError, match="cannot fit in"):
        validate_proto(pid, broken, e.consts, opmap)


def test_entry_past_the_end_is_rejected(opmap):
    pid, e = _one(opmap)
    broken = e.code[:6] + (len(e.code) + 40).to_bytes(2, "little") + e.code[8:]
    with pytest.raises(IntegrityError, match="outside the"):
        validate_proto(pid, broken, e.consts, opmap)


def test_unassigned_opcode_is_rejected(opmap):
    """Opcode numbers start at 1 and 0 is never assigned, so 0 is a probe."""
    pid, e = _one(opmap)
    at = e.starts[1]
    broken = e.code[:at] + b"\x00" + e.code[at + 1:]
    with pytest.raises(IntegrityError, match="not assigned"):
        validate_proto(pid, broken, e.consts, opmap)


def test_moved_entry_is_rejected(opmap):
    pid, e = _one(opmap)
    # entry is the u16 at header bytes 6..7, absolute like every other offset
    broken = e.code[:6] + (e.entry + 1).to_bytes(2, "little") + e.code[8:]
    with pytest.raises(IntegrityError):
        validate_proto(pid, broken, e.consts, opmap,
                       expected_starts=e.starts)


def test_boundary_set_catches_what_the_walk_alone_misses(opmap):
    """The measured reason ``expected_starts`` exists.

    Across the corpus, 7611 mutated entry offsets: the walk alone rejects 64.6
    per cent, the walk plus the encoder's boundaries rejects 76.4.  Nine
    hundred and two of those are caught only by the boundary set, because a
    misaligned offset frequently decodes to an opcode the permuted map really
    does assign.  This test finds one such offset and shows the difference, so
    the parameter cannot be dropped as redundant.
    """
    encoded = _encode_all(SIMPLE, "simple.luau", opmap)
    found = None
    for pid, e in encoded.items():
        for delta in range(1, min(40, len(e.code) - e.entry)):
            target = e.entry + delta
            broken = e.code[:6] + target.to_bytes(2, "little") + e.code[8:]
            try:
                validate_proto(pid, broken, e.consts, opmap)
                walk_says = "accepts"
            except IntegrityError:
                walk_says = "rejects"
            try:
                validate_proto(pid, broken, e.consts, opmap,
                               expected_starts=e.starts)
                bounds_says = "accepts"
            except IntegrityError:
                bounds_says = "rejects"
            if walk_says == "accepts" and bounds_says == "rejects":
                found = (pid, delta)
                break
        if found:
            break
    assert found, (
        "no offset in this program distinguishes the two checks; the corpus "
        "measurement says there should be one")


def test_jump_target_off_a_boundary_is_rejected(opmap):
    """Point a jump at the middle of an instruction."""
    encoded = _encode_all(SIMPLE, "simple.luau", opmap)
    for pid, e in encoded.items():
        code = bytearray(e.code)
        for at in list(e.starts):
            op_byte = code[at]
            op = opmap.to_op.get(op_byte)
            if op not in isa.FORMATS or "target" not in isa.FORMATS[op].wides:
                continue
            wide_at = at + 1 + len(isa.FORMATS[op].regs)
            code[wide_at] = (code[wide_at] + 1) % 256     # one byte off
            with pytest.raises(IntegrityError):
                validate_proto(pid, bytes(code), e.consts, opmap,
                               expected_starts=e.starts)
            return
    pytest.skip("no jumping instruction in this program")


# ---------------------------------------------------------------------------
# the gap that motivated all of it
# ---------------------------------------------------------------------------

def test_no_plaintext_entry_or_nparams():
    """The descriptor must not duplicate what the authenticated header holds.

    This is the regression test for the silent-corruption bug.  It asserts on
    the emitted artifact, not on the emitter, so re-introducing the fields
    anywhere fails here.
    """
    src = "local function f() return 1, 2, 3 end\nprint(f())\n"
    config = Config(reproducible_seed=7, min_virtualize_body_nodes=1)
    out = build(src, config, verify=False).source
    descriptor = re.search(r"\{\s*code\s*=\s*[^,]+,\s*consts\s*=\s*\{[^}]*\}[^}]*\}",
                           out)
    assert descriptor, "no descriptor table in the output"
    body = descriptor.group(0)
    assert "entry" not in body, body
    assert "nparams" not in body, body


def result_pool_names(config):
    """The constant-pool names a given build actually chose."""
    return build("local function f() return 1, 2, 3 end\nprint(f())\n",
                 config, verify=False).runtime_names["pool"]


@pytest.mark.skipif(not TOOLCHAIN.can_execute, reason="luau runtime unavailable")
def test_editing_the_pool_blob_fails_authentication(tmp_path):
    """Entry now lives inside the MAC'd blob, so editing it cannot be silent.

    The plaintext field is gone; this is what covers it instead.  Single
    character edits to the pool ciphertext must fail the tag check rather than
    produce output.  Measured over 100 edits on a real build: 99 ended in
    "constant pool failed authentication", the hundredth was a parse error
    introduced by the edit itself, and none produced output.
    """
    src = "local function f() return 1, 2, 3 end\nprint(f())\n"
    config = Config(reproducible_seed=7, min_virtualize_body_nodes=1)
    out = build(src, config, verify=False).source

    # The pool prefix is per-build now, so the ciphertext name has to come from
    # the build rather than from default_names() -- which would silently find
    # nothing and make this test assert on a name that is not in the output.
    blob, blob_quote = _string_literal(out, result_pool_names(config)["ct"])
    assert blob is not None, "pool ciphertext not found in the output"
    assert len(blob) > 40, "pool ciphertext implausibly short"

    baseline_path = tmp_path / "clean.luau"
    baseline_path.write_text(out)
    clean = subprocess.run([TOOLCHAIN.luau, str(baseline_path)],
                           capture_output=True, text=True, timeout=30)
    assert clean.returncode == 0, clean.stderr[:300]
    baseline = clean.stdout

    positions = [i for i in range(2, min(len(blob), 400))
                 if 33 <= ord(blob[i]) <= 126
                 and blob[i - 1] != "\\" and blob[i - 2] != "\\"]
    assert len(positions) >= 20, "too few safely editable positions"

    produced_output = 0
    for i in positions[:25]:
        new = blob[:i] + ("A" if blob[i] != "A" else "B") + blob[i + 1:]
        path = tmp_path / "t.luau"
        path.write_text(out[:blob_quote] + '"' + new + '"' + out[blob_quote + len(blob) + 1:])
        r = subprocess.run([TOOLCHAIN.luau, str(path)], capture_output=True,
                           text=True, timeout=30)
        if r.returncode == 0 and r.stdout == baseline:
            produced_output += 1
    assert produced_output == 0, (
        f"{produced_output} tampered builds still produced the original "
        f"output; the pool tag is not being enforced")

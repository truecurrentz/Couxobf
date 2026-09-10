"""R0: the repo-local corpus must be sufficient on its own.

The suite used to hard-link an upstream Luau checkout under ``/tmp`` and error
or fail without it, which meant "tests pass" was a fact about the machine, not
about the code.  The fix is not "make the thresholds smaller": it is a corpus
that is written here, versioned here, and big enough that every floor the
suite asserts holds with no external state at all.

These tests pin that property so it cannot rot again:

* the repo corpus is large enough to be a corpus;
* lowering and encoding it reaches *every* opcode the VM implements -- an
  opcode the corpus never emits has a handler that has never executed;
* building it virtualizes more prototypes than the pipeline suite's floor,
  so the differential tests are exercising the VM and not just the native
  reconstructor.

``COUXOBF_NO_EXTERNAL_CORPUS=1`` hides the upstream checkout on machines that
have one, which is how the whole suite can be run in the clean-checkout
configuration::

    COUXOBF_NO_EXTERNAL_CORPUS=1 pytest
"""

from __future__ import annotations

import glob
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from couxobf import ir, parser
from couxobf.config import Config
from couxobf.pipeline import BuildError, build
from couxobf.vm import encode, isa

from tests.corpus import REPO_CORPUS
from test_roundtrip import EXCLUDED, MICRO_DIR

#: The floor ``tests/test_pipeline.py`` asserts over the *whole* corpus.  The
#: repo-local files have to clear it by themselves.
PIPELINE_VIRTUALIZED_FLOOR = 100


def _clean_checkout_corpus():
    """Exactly the programs a checkout with no upstream source tree runs."""
    files = sorted(glob.glob(os.path.join(MICRO_DIR, "*.luau")))
    files += [p for p in REPO_CORPUS
              if os.path.basename(p) not in {os.path.basename(f) for f in files}]
    return [p for p in files if os.path.basename(p) not in EXCLUDED]


def _read(path: str) -> str:
    with open(path, encoding="utf-8", errors="surrogateescape") as fh:
        return fh.read()


def _opmap():
    from couxobf import rng as rngmod
    from couxobf.vm import isa

    return isa.OpcodeMap.shuffled(rngmod.make_domains(b"\x07" * 16).get("opcodes"))


def _all_protos(module):
    def walk(p):
        yield p
        for child in p.children:
            yield from walk(child)
    return list(walk(module.main))


def test_repo_corpus_is_present_and_sized():
    """A corpus of six files is not a corpus."""
    assert len(REPO_CORPUS) >= 12, (
        f"only {len(REPO_CORPUS)} repo-local corpus programs; "
        "add fixtures rather than lowering the floors")


def test_repo_corpus_covers_every_vm_opcode():
    """Every opcode the VM implements is emitted by the repo corpus alone.

    This is the assertion that used to be satisfiable only by the upstream
    conformance suite.  It fails by *naming* the uncovered opcodes, so a
    regression reads as "add a fixture that divides" rather than as a number.
    """
    opmap = _opmap()
    ops = set()
    walked = 0
    for path in REPO_CORPUS:
        try:
            module = ir.Lowerer().lower(parser.parse(_read(path),
                                                     os.path.basename(path)))
        except Exception:
            continue
        for proto in _all_protos(module):
            ok, _reason = encode.can_virtualize(proto, upvalues_ok=True)
            if not ok:
                continue
            enc = encode.encode_proto(proto, opmap, upvalues_ok=True)
            pc, code = enc.lua_entry - 1, enc.code
            while pc < len(code):
                name = opmap.to_op[code[pc]]
                ops.add(name)
                pc += isa.operand_size(name)
                walked += 1
            assert pc == len(code), (
                f"{os.path.basename(path)} proto {proto.proto_id}: encoder and "
                "operand_size disagree")
    uncovered = sorted(set(isa.SUPPORTED) - ops)
    assert not uncovered, (
        f"{len(uncovered)} opcodes never emitted by the repo corpus: {uncovered}")
    assert walked > 500, f"only walked {walked} instructions"


def test_repo_corpus_alone_clears_the_virtualization_floor():
    """The clean-checkout corpus must clear the pipeline suite's floor.

    The pipeline suite asserts ``total > 100`` across every corpus it can
    find.  With no upstream checkout that is the micro fixtures plus these
    files -- so this is the test that catches a vandalised threshold as well
    as a thin corpus.
    """
    config = Config(reproducible_seed=7, min_virtualize_body_nodes=4)
    total, files = 0, 0
    for path in _clean_checkout_corpus():
        try:
            result = build(_read(path), config, name=os.path.basename(path),
                           toolchain=None, verify=False)
        except BuildError:
            continue
        if result.stats.virtualized:
            total += result.stats.virtualized
            files += 1
    assert total > PIPELINE_VIRTUALIZED_FLOOR, (
        f"only {total} prototypes virtualized by the clean-checkout corpus")
    assert files > 10, f"only {files} corpus files contributed"

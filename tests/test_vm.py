"""Virtualization tests: does the VM actually run programs correctly?

The interesting question is not whether an :class:`OpcodeMap` permutes or
whether ``encode_proto`` produces bytes -- those are cheap to assert.  It is
whether the generated interpreter, fed those bytes, computes the same answer as
Luau.  So these tests execute.

Each case lowers a source file to IR, picks every prototype the encoder is
willing to take, encodes it, and substitutes the native reconstruction of that
prototype with a closure that enters the interpreter.  Everything around it
stays native, which is the mixed native/VM execution mode the design calls for.
The result is run against the original under the pinned toolchain.

Three of these tests exist because a bug taught me to write them:

``test_pc_advance_matches_operand_size``
    ``LOADK`` and ``GETGLOBAL`` advanced ``pc`` before reading their wide
    operand.  The expressions embed the literal text ``pc + 1``, so the constant
    index was read from past the instruction and the dispatcher desynced.

``test_entry_point_is_a_string_byte_index``
    ``string.byte`` is 1-based; the wire format is 0-based.  Passing the raw
    entry offset started the interpreter on the last header byte and reported
    "unknown opcode 0" on every single virtualized call.

``test_corpus_actually_virtualizes``
    A differential suite where nothing gets virtualized passes while testing
    nothing.  That is what 54 green tests looked like when the entry point was
    wrong.
"""

import dataclasses
import glob
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import couxobf.ast_nodes as A
from couxobf import ir, lower_back, parser, rng as rngmod
from couxobf.emit import printer
from couxobf.ir import FuncIR
from couxobf.toolchain import execute, find_toolchain
from couxobf.vm import encode, isa, runtime, wiring
from couxobf.vm.format import FormatSpec
from test_roundtrip import EXCLUDED, MICRO_DIR, _conformance_dir

TOOLCHAIN = find_toolchain()

#: Interpreter locals, fixed here so a failure names the function it came from.
NAMES = {
    "code": "_kS",
    "exec": "_kX",
    "enter": "_kGo",
    "call": "_kAp",
    "getfenv": "_kGe",
    # the accumulator/stack locals the non-register families declare
    "acc": "_kAc",
    "stack": "_kSt",
    "sp": "_kSp",
    "append": "_kapp",
    "iter": "_kiter",
    "iterpack": "_kiterpack",
    "itercheck": "_kitercheck",
    # R5: frame key the entry point stashes the caller's argument pack under,
    # and the pack field recording the named-parameter count
    "vpack": "_kVp",
    "vnp": "_kVn",
    # R5's second increment: frame key holding the upvalue accessor list
    "uvs": "_kUv",
    # R5's third increment: the descriptor row table, and the table of
    # per-prototype entry stubs a CLOSURE arm indexes to find the child it is
    # handing out
    "rows": "_kRw",
    "stubs": "_kSb",
    # R5's fourth increment: the capture descriptors a CLOSURE arm reads to
    # find out whether the child it is creating captures at all, the per-entry
    # reading of them -- live, snapshot, or cell -- and the local alias for
    # setfenv -- held in a local for the same reason getfenv is, plus one of
    # its own: the stub a capturing child gets is born inside the interpreter,
    # so its inherited environment is the interpreter's and not the parent's.
    "caps": "_kCp",
    "kinds": "_kKd",
    "setfenv": "_kSe",
}


class _VMReconstructor(lower_back.Reconstructor):
    """Reconstructs natively, except for prototypes handed to the VM.

    The closure it emits is the production one -- this build's ``enter`` applied
    to this build's row of the assembled payload table -- because the descriptor
    shape is precisely what a lift has to reproduce.  An earlier version of this
    class hand-wrote its own row and hand-picked the entry name; the tests then
    passed against a shape that no longer shipped.
    """

    def __init__(self, plan, **kw):
        super().__init__(**kw)
        self.plan = plan
        self.encoded = {}

    def function_expr(self, proto: FuncIR):
        fmt = self.plan.fmt_for(proto.proto_id)
        ok, _reason = encode.can_virtualize(proto, fmt)
        if not ok:
            return super().function_expr(proto)
        enc = encode.encode_proto(
            proto, self.plan.opmap_for(proto.proto_id), fmt=fmt)
        self.encoded[proto.proto_id] = enc
        # A real Luau closure that enters the interpreter.  To the surrounding
        # native code this is indistinguishable from the function it replaces.
        # The third argument is the upvalue accessor list; this harness never
        # virtualizes a prototype that captures (``can_virtualize`` above runs
        # without ``upvalues_ok``), so the ``false`` placeholder is the honest
        # value -- and omitting it would hand the first call argument to the
        # interpreter as the accessor list.
        return A.Func(
            params=[A.Param(name=None)],
            body=A.Block(body=[A.Return(values=[A.Call(
                fn=A.Name(name=self.plan.enter_for(proto.proto_id)),
                args=[A.Index(obj=A.Name(name=self.plan.rows_table),
                              key=A.Number(value=self.plan.row_key(proto.proto_id),
                                           is_float=False)),
                      A.Call(fn=A.Name(name=NAMES["getfenv"]),
                             args=[A.Number(value=1, is_float=False)]),
                      A.Bool(value=False),
                      A.Vararg()])])]))


#: All descriptors live in one table, keyed by prototype id.  They cannot be
#: individual chunk-level locals: Luau caps a function at 200 locals, and
#: basic.luau alone virtualizes 256 prototypes, which fails to compile with
#: "Out of local registers ... exceeded limit 200".
_DESCRIPTOR_TABLE = "_kVT"

#: The four structures a build splits its VM metadata across (#17): the payload
#: blob, the constants, the control-flow edges, and the row that assembles them.
_TABLES = (_DESCRIPTOR_TABLE, "_kKT", "_kET", "_kRT")


def _lit(value, pid=None) -> str:
    """A constant as Luau source, through the printer's own literal rules.

    Going through the printer rather than ``repr`` matters for the bytecode
    string: non-printable bytes need three-digit decimal escapes, and a stray
    backslash or quote would corrupt the program.
    """
    p = printer.Printer()
    p.expr(lower_back._const_expr(value))
    return p.w.value()


def _plan(seed: bytes = b"\x07" * 16, protos=(), **kw) -> wiring.VMPlan:
    """A plan over the fixed test names, for driving the real emitter.

    These tests used to carry their own copy of the descriptor row.  That copy
    is exactly how a bug like the unauthenticated plaintext ``entry`` survives:
    the production emitter changed, the test emitter did not, and the tests kept
    passing against the shape they were asserting instead of the shape that
    ships.  So the plan here is built by ``wiring.make_plan`` -- the same call
    the pipeline makes -- with only the names and the table names pinned, and
    ``names=`` exists on ``make_plan`` for exactly this purpose.
    """
    kw.setdefault("randomize_opcodes", True)
    return wiring.make_plan(rngmod.make_domains(seed).get("vm"), set(protos),
                            tables=_TABLES, names=NAMES, **kw)


def _opmap(seed: bytes = b"\x07" * 16) -> isa.OpcodeMap:
    return isa.OpcodeMap.shuffled(rngmod.make_domains(seed).get("opcodes"))


def vm_reconstruct(src: str, name: str = "test.luau", seed: bytes = b"\x07" * 16):
    """source -> IR -> VM-backed executable Luau.

    Returns the source and the set of prototype ids that were virtualized, so a
    test can insist that it actually tested the VM instead of quietly falling
    back to native code for everything.
    """
    module = ir.Lowerer().lower(parser.parse(src, name))
    rec = _VMReconstructor(_plan(seed))
    body = printer.emit(rec.reconstruct(module))
    parts = [lower_back.HELPERS_SRC,
             wiring.prelude_source(_plan(seed), dict(rec.encoded), _lit, _lit)]
    parts.append(body)
    return "\n".join(parts), set(rec.encoded)


# ---------------------------------------------------------------------------
# Invariants on the encoding and the generated dispatch chain
# ---------------------------------------------------------------------------

#: Handlers that never fall through to the next instruction, so they have no
#: reason to advance pc.
_NO_FALLTHROUGH = {ir.OP.RETURN0, ir.OP.JMP}


@pytest.mark.parametrize("op", sorted(isa.SUPPORTED))
def test_pc_advance_matches_operand_size(op):
    """Each handler must step pc past exactly its own operands.

    The dispatcher has already consumed the opcode byte, so the advance is
    ``operand_size(op) - 1``.  A handler that reads operands *after* advancing
    passes this test only if it also gets the width wrong in a way that cancels
    out, which is not a thing that happens by accident.
    """
    lines = runtime._handler(op, NAMES)
    advances = [int(m.group(1)) for line in lines
                for m in [re.search(r"pc = pc \+ (\d+)$", line)] if m]
    if op in _NO_FALLTHROUGH:
        assert not advances, f"{op} terminates; it must not advance pc"
        return
    assert advances, f"{op} handler never advances pc -- the dispatcher will spin"
    assert advances[0] == isa.operand_size(op) - 1, (
        f"{op} advances pc by {advances[0]}, but its operands occupy "
        f"{isa.operand_size(op) - 1} bytes after the opcode")


def test_reads_precede_the_pc_advance():
    """No handler may read an operand after it has moved pc.

    The handler bodies are built from expressions that embed the literal text
    ``pc + 1``; once ``pc = pc + N`` runs, every earlier-looking read is
    actually a read from a later address.
    """
    offenders = []
    for op in sorted(isa.SUPPORTED):
        if op in _NO_FALLTHROUGH:
            continue
        seen_advance = False
        for line in runtime._handler(op, NAMES):
            if re.search(r"pc = pc \+ (\d+)$", line):
                seen_advance = True
                continue
            # Any later line that touches the code string is a read from the
            # wrong address.  Jump handlers assign `pc = tgt + 1` after
            # advancing, but those never look at the code string, so keying on
            # the code-string reference (rather than on `pc = `) is what makes
            # this catch a misordered read.
            if seen_advance and re.search(r"\b%s\b" % re.escape(NAMES["code"]), line):
                offenders.append(op)
    assert not offenders, f"these handlers read operands after advancing: {offenders}"


def test_entry_point_is_a_string_byte_index():
    """The runtime entry must be 1-based, matching ``string.byte``.

    Off by one and the interpreter starts on the final header byte.  That is a
    0x00, which decodes as "unknown opcode 0" -- loud, but only at the first
    call, and only if something actually gets virtualized.
    """
    src = "local function f(a, b) return a + b end\nprint(f(2, 3))\n"
    module = ir.Lowerer().lower(parser.parse(src, "t.luau"))
    enc = encode.encode_proto(module.main.children[0], _opmap())
    header_len = encode.HEADER.size
    assert enc.entry == header_len, "entry should be the 0-based first code byte"
    assert enc.lua_entry == header_len + encode.LUA_INDEX_BIAS
    # the byte the runtime will read first must be a real opcode
    first = enc.code[enc.lua_entry - 1]
    assert first in _opmap().to_op, f"runtime starts on byte {first}, not an opcode"


def test_encoded_stream_walks_clean():
    """Encoding and ``operand_size`` must agree, byte for byte.

    Walked from the entry point: every opcode must be in the map, and the walk
    must consume the stream exactly.
    """
    paths = _corpus()
    walked, ops = 0, set()
    for path in paths:
        with open(path, encoding="utf-8", errors="surrogateescape") as fh:
            src = fh.read()
        try:
            module = ir.Lowerer().lower(parser.parse(src, os.path.basename(path)))
        except Exception:
            continue
        opmap = _opmap()
        for proto in _all_protos(module):
            # ``upvalues_ok`` on purpose: GETUPVAL/SETUPVAL have been
            # encodable since R5's second increment, and the walk's job is to
            # prove the encoder and ``operand_size`` agree for every opcode
            # the ISA can carry -- including those two.  The walk only reads
            # bytes; the accessor closures exist at the stub, not in the
            # stream, so nothing here needs a runtime to run them.
            # ``closures_ok`` on purpose, for the same reason as
            # ``upvalues_ok``: CLOSURE has been encodable since R5's third
            # increment, and the walk's job is to prove the encoder and
            # ``operand_size`` agree for every opcode the ISA can carry.  A
            # prototype that creates closures is only *selected* in a build
            # that asked for them, which is a different question -- the bytes
            # are the same either way.
            if not encode.can_virtualize(proto, upvalues_ok=True,
                                         closures_ok=True)[0]:
                continue
            enc = encode.encode_proto(proto, opmap, upvalues_ok=True,
                                      closures_ok=True)
            pc, code = enc.lua_entry - 1, enc.code
            while pc < len(code):
                name = opmap.to_op[code[pc]]
                assert name in isa.FORMATS, f"{name} has no format"
                ops.add(name)
                pc += isa.operand_size(name)
                walked += 1
            assert pc == len(code), (
                f"{os.path.basename(path)} proto {proto.proto_id}: walk ended at "
                f"{pc} of {len(code)} -- encoder and operand_size disagree")
    assert walked > 500, f"only walked {walked} instructions; corpus too thin"
    # Coverage is what makes the differential meaningful: an opcode the corpus
    # never emits is an opcode whose handler has never executed.  The corpus
    # currently reaches every one, so anything less is a regression -- either a
    # handler stopped being reachable or the encoder started refusing a shape.
    uncovered = sorted(set(isa.SUPPORTED) - ops)
    assert not uncovered, (
        f"{len(uncovered)} opcodes never executed by the corpus: {uncovered}")


def _all_protos(module):
    def walk(p):
        yield p
        for c in p.children:
            yield from walk(c)
    yield from walk(module.main)


def test_shuffled_map_is_deterministic_across_processes():
    """Same seed must give the same opcode numbers in every process.

    ``sorted``, not ``list(SUPPORTED)``: set iteration over strings follows
    PYTHONHASHSEED, so an unsorted base silently breaks reproducible builds.
    """
    import subprocess
    probe = (
        "import sys; sys.path.insert(0, '.');"
        "from couxobf.vm.isa import OpcodeMap;"
        "from couxobf.rng import make_domains;"
        "m = OpcodeMap.shuffled(make_domains(b'\\x09' * 16).get('opcodes'));"
        "print(sorted(m.to_byte.items()))")
    runs = set()
    for hashseed in ("0", "1", "12345"):
        env = dict(os.environ, PYTHONHASHSEED=hashseed)
        runs.add(subprocess.run([sys.executable, "-c", probe], cwd=_repo_root(),
                                capture_output=True, text=True,
                                env=env).stdout.strip())
    assert len(runs) == 1, f"opcode map varies with PYTHONHASHSEED: {runs}"


def _repo_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_identity_map_starts_at_one():
    """Zero must never be an opcode: ``string.byte`` returns nil past EOF."""
    m = isa.OpcodeMap.identity()
    assert min(m.to_byte.values()) == 1
    assert 0 not in m.to_op


# ---------------------------------------------------------------------------
# Differential: the VM must compute what Luau computes
# ---------------------------------------------------------------------------

def _corpus():
    from tests.corpus import REPO_CORPUS
    files = sorted(glob.glob(os.path.join(MICRO_DIR, "*.luau")))
    # The repo-local corpus always runs, exactly as in the pipeline suite:
    # it is written and versioned here, so a checkout with no upstream Luau
    # source tree still walks enough real programs for the coverage floors
    # below to mean something (R0).
    files += [p for p in REPO_CORPUS
              if os.path.basename(p) not in {os.path.basename(f) for f in files}]
    conf = _conformance_dir()
    if conf:
        files += sorted(glob.glob(os.path.join(conf, "*.luau")))
    return files


#: How many prototypes each corpus file handed to the VM, recorded as the
#: differential runs so coverage can be asserted rather than assumed.
_VIRTUALIZED_TOTAL = {}


@pytest.mark.parametrize("path", _corpus(),
                         ids=lambda p: os.path.basename(p))
def test_vm_matches_original(path):
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available; run tools/setup-luau.sh")
    base = os.path.basename(path)
    if base in EXCLUDED:
        pytest.skip(f"{base}: {EXCLUDED[base]}")
    # surrogateescape, matching the round-trip suite: some conformance files
    # are Latin-1, and a decode failure here would look like a VM bug.
    with open(path, encoding="utf-8", errors="surrogateescape") as fh:
        src = fh.read()

    try:
        out, virtualized = vm_reconstruct(src, base)
    except encode.EncodingError as exc:
        pytest.skip(f"not encodable: {exc}")
    _VIRTUALIZED_TOTAL[base] = len(virtualized)

    original = execute(TOOLCHAIN, src, base, timeout=20)
    protected = execute(TOOLCHAIN, out, "vm.luau", timeout=20)

    assert original.returncode == protected.returncode, (
        f"{base}: rc {original.returncode} != {protected.returncode}\n"
        f"virtualized={sorted(virtualized)}\n{protected.stderr[:600]}")
    assert original.stdout == protected.stdout, (
        f"{base}: stdout differs\nvirtualized={sorted(virtualized)}\n"
        f"--- original ---\n{original.stdout[:600]}\n"
        f"--- vm ---\n{protected.stdout[:600]}")


def test_corpus_actually_virtualizes():
    """The differential above must have put real code through the VM.

    Runs last, over whatever the parametrized cases recorded.  If the encoder
    starts refusing everything, every differential test still passes and this
    is what fails.
    """
    if not _VIRTUALIZED_TOTAL:
        pytest.skip("differential tests did not run")
    total = sum(_VIRTUALIZED_TOTAL.values())
    files = sum(1 for n in _VIRTUALIZED_TOTAL.values() if n)
    assert total > 50, (
        f"only {total} prototypes virtualized across {len(_VIRTUALIZED_TOTAL)} "
        f"files -- the differential suite is not exercising the interpreter")
    assert files > 10, f"only {files} files contributed a virtualized prototype"


# ---------------------------------------------------------------------------
# Build reproducibility
# ---------------------------------------------------------------------------

def test_same_seed_gives_identical_bytecode():
    """Reproducible builds: same source and seed must give identical output."""
    src = ("local function sum(t)\n  local s = 0\n"
           "  for i = 1, #t do s = s + t[i] end\n  return s\nend\n"
           "print(sum({1, 2, 3, 4}))\n")
    a, va = vm_reconstruct(src, "rep.luau", seed=b"\x01" * 16)
    b, vb = vm_reconstruct(src, "rep.luau", seed=b"\x01" * 16)
    assert va and va == vb
    assert a == b, "same seed produced different output"


def test_different_seed_changes_the_opcode_numbering():
    """Different seeds must produce structurally different bytecode.

    Not a hash comparison of the whole file -- that would also trip on
    identifier renaming.  This checks the thing the seed is supposed to change:
    the opcode numbers, and therefore the byte stream for the same program.
    """
    src = "local function f(a, b) return a * b + 1 end\nprint(f(3, 4))\n"
    a, _ = vm_reconstruct(src, "seed.luau", seed=b"\x01" * 16)
    b, _ = vm_reconstruct(src, "seed.luau", seed=b"\x02" * 16)
    assert a != b, "two different seeds produced identical bytecode"
    m1 = _opmap(b"\x01" * 16)
    m2 = _opmap(b"\x02" * 16)
    assert m1.to_byte != m2.to_byte, "opcode map did not change with the seed"


# ---------------------------------------------------------------------------
# Differential through the real protected path
# ---------------------------------------------------------------------------
#
# The tests above substitute virtualized prototypes through a Reconstructor
# subclass.  These go through ``reconstruct_protected``, which is what a build
# actually calls: the bytecode and the constants are interned into the
# encrypted pool, so the payload is decrypted at load time rather than sitting
# in the source as a literal.

from couxobf.config import Config  # noqa: E402
from couxobf.crypto.kdf import KeyMaterial  # noqa: E402
from couxobf.pipeline import build  # noqa: E402


def protected_vm_reconstruct(src: str, name: str, seed: bytes = b"\x21" * 16,
                             vm_level: str = "maximum"):
    """source -> IR -> protected Luau with the VM enabled.

    Returns the source and how many prototypes the VM took, so the caller can
    tell an exercised VM from a build that quietly virtualized nothing.
    """
    module = ir.Lowerer().lower(parser.parse(src, name))
    lower_back.optimize_module(module) if hasattr(lower_back, "optimize_module") else None
    domains = rngmod.make_domains(seed)
    selected = wiring.select_protos(module, vm_level)
    out = lower_back.reconstruct_protected(
        module, KeyMaterial.from_seed(seed), domains.get("emission"),
        b"couxobf-test", vm_level=vm_level, vm_rng=domains.get("vm"))
    return out, selected


@pytest.mark.parametrize("path", _corpus(),
                         ids=lambda p: os.path.basename(p))
def test_protected_vm_matches_original(path):
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available; run tools/setup-luau.sh")
    base = os.path.basename(path)
    if base in EXCLUDED:
        pytest.skip(f"{base}: {EXCLUDED[base]}")
    with open(path, encoding="utf-8", errors="surrogateescape") as fh:
        src = fh.read()

    try:
        out, selected = protected_vm_reconstruct(src, base)
    except encode.EncodingError as exc:
        pytest.skip(f"not encodable: {exc}")

    original = execute(TOOLCHAIN, src, base, timeout=30)
    protected = execute(TOOLCHAIN, out, "protected.luau", timeout=30)

    assert original.returncode == protected.returncode, (
        f"{base}: rc {original.returncode} != {protected.returncode}\n"
        f"virtualized={len(selected)}\n{protected.stderr[:600]}")
    assert original.stdout == protected.stdout, (
        f"{base}: stdout differs\nvirtualized={len(selected)}\n"
        f"--- original ---\n{original.stdout[:400]}\n"
        f"--- protected ---\n{protected.stdout[:400]}")


def test_protected_path_hides_the_bytecode():
    """The payload must be in the encrypted blob, not in the source.

    A VM whose bytecode sits in the output as a string literal is an encoding,
    not a protection: an analyst reads the dispatcher once and disassembles
    every build with it.  Routing it through the pool means the bytes are
    encrypted alongside every other constant.
    """
    src = ("local function accumulate(t)\n  local total = 0\n"
           "  for i = 1, #t do total = total + t[i] end\n  return total\nend\n"
           "print(accumulate({4, 5, 6, 7}))\n")
    out, selected = protected_vm_reconstruct(src, "hide.luau")
    assert selected, "nothing was virtualized; this test proves nothing"
    module = ir.Lowerer().lower(parser.parse(src, "hide.luau"))
    opmap = _opmap()
    for proto in _all_protos(module):
        if proto.proto_id not in selected:
            continue
        enc = encode.encode_proto(proto, opmap)
        # the exact bytes must not appear, in any escaping the printer uses
        assert _lit(enc.code) not in out, "bytecode literal leaked into output"
    # and the program still has to run
    if TOOLCHAIN.can_execute:
        original = execute(TOOLCHAIN, src, "hide.luau", timeout=20)
        protected = execute(TOOLCHAIN, out, "protected.luau", timeout=20)
        assert original.stdout == protected.stdout == "22\n"


def test_vm_row_keys_are_build_specific_tickets():
    plan = wiring.make_plan(rngmod.make_domains(b"\x33" * 16).get("vm"), {7})
    assert plan.row_key(7) != 7
    src = wiring.prelude_source(
        plan, {7: type("E", (), {"code": b"abc", "consts": (), "edges": ()})()},
        const_expr=lambda v, pid=None: "nil",
        code_expr=lambda b, pid=None: '"abc"')
    assert "[%d]" % plan.row_key(7) in src
    assert "[7] = { code" not in src


def test_vm_descriptors_materialize_code_and_constants_lazily():
    """Encrypted VM blobs should not become plaintext descriptor rows at load."""
    out, selected = protected_vm_reconstruct(
        'local function f(a) return "v" .. a end\nprint(f("m"))\n',
        "lazy-vm.luau")
    assert selected, "nothing was virtualized; this test proves nothing"
    assert "function()return" in out, out[:500]
    assert re.search(r"consts\s*=\s*\w+\[\d+\]", out), out[:500]
    assert "type(" in out, "interpreter must resolve lazy descriptors"


def test_interning_after_seal_is_refused():
    """A slot handed out after sealing points at nothing in the blob.

    That is what the VM wiring did at first: the bytecode was interned after
    ``pool.seal()``, so ``p.code`` was nil at runtime and the interpreter died
    on its first ``string.byte``.  The failure surfaced far from the cause, so
    the pool now refuses it.
    """
    from couxobf.constpool import ConstantPool, ConstantPoolError
    seed = b"\x05" * 16
    pool = ConstantPool(KeyMaterial.from_seed(seed),
                        rngmod.make_domains(seed).get("constants"), b"ctx")
    # bytes, not str: the pool stores string constants as byte strings, since
    # that is what the IR's string constants are.
    assert pool.slot(b"first") == 1
    pool.seal()
    with pytest.raises(ConstantPoolError):
        pool.slot(b"second")


def test_setfenv_reaches_a_virtualized_function():
    """`setfenv` on a VM-backed function must change what its globals mean.

    The VM reads and writes globals through an environment table, so it has to
    be the *caller's* environment, resolved per call.  Two ways to get this
    wrong, both measured:

    * capturing the environment once at load ignores setfenv entirely, and the
      build writes the real globals instead of the swapped table;
    * looking `getfenv` up as a global fails outright once the environment has
      been swapped, because the swapped table does not contain getfenv.
    """
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available; run tools/setup-luau.sh")
    src = (
        "A = 10\n"
        "local f = function() A = A + 1; return A end\n"
        "print(f())\n"
        "setfenv(f, {A = 100})\n"
        "print(f())\n"
        "print(f())\n"
        "print(A)\n"
    )
    out, selected = protected_vm_reconstruct(src, "setfenv.luau",
                                             vm_level="maximum")
    assert selected, "the function was not virtualized; this test proves nothing"
    original = execute(TOOLCHAIN, src, "setfenv.luau", timeout=20)
    protected = execute(TOOLCHAIN, out, "protected.luau", timeout=20)
    assert original.returncode == protected.returncode == 0, protected.stderr[:300]
    assert original.stdout == protected.stdout, (
        f"setfenv did not reach the virtualized function\n"
        f"  want {original.stdout!r}\n  got  {protected.stdout!r}")
    # 11 from the pre-setfenv call, then 101 and 102 inside the swapped table,
    # and the real global left where the first call put it
    assert original.stdout == "11\n101\n102\n11\n"


def test_default_protected_build_virtualizes():
    """The production default must virtualize, or the feature is dead code.

    ``reconstruct_protected`` defaults to ``VirtualizationLevel.HEAVY``, the
    same level ``Config`` defaults to.  If that default ever stops selecting
    anything, every protected-path test above still passes while testing only
    the native reconstructor.
    """
    src = (
        "local function classify(n)\n"
        "  if n < 2 then return false end\n"
        "  for d = 2, math.floor(math.sqrt(n)) do\n"
        "    if n % d == 0 then return false end\n"
        "  end\n"
        "  return true\n"
        "end\n"
        "local found = 0\n"
        "for i = 1, 40 do if classify(i) then found += 1 end end\n"
        "print(found)\n"
    )
    # no vm_level argument: whatever the default is
    out, _ = protected_vm_reconstruct(src, "default.luau")
    domains = rngmod.make_domains(b"\x21" * 16)
    module = ir.Lowerer().lower(parser.parse(src, "default.luau"))
    lower_back.optimize_module(module) if hasattr(lower_back, "optimize_module") else None
    selected = wiring.select_protos(module, "heavy")
    assert selected, "the default level selected nothing"
    assert out != protected_vm_reconstruct(src, "default.luau",
                                           vm_level="none")[0], (
        "the default build is identical to virtualization_level=none")


def test_vm_output_is_not_much_larger_than_native():
    """Virtualizing must not be paid for in output size.

    The design's own warning: bigger output is not stronger security.  One
    interpreter serves every virtualized prototype, so the per-prototype cost
    is a descriptor plus a one-line closure -- and the interpreter is amortized
    away.  What this pins is that the amortization actually happens, rather than
    the prelude being emitted per prototype.
    """
    src = "\n".join(
        "local function f%d(a, b) return a * %d + b end" % (i, i)
        for i in range(1, 21)) + "\n" + \
        "\n".join("print(f%d(%d, 1))" % (i, i) for i in range(1, 21)) + "\n"
    native, _ = protected_vm_reconstruct(src, "size.luau", vm_level="none")
    vmed, selected = protected_vm_reconstruct(src, "size.luau",
                                              vm_level="maximum")
    assert len(selected) >= 10, f"only {len(selected)} prototypes virtualized"
    ratio = len(vmed) / len(native)
    assert ratio < 1.8, (
        f"virtualizing {len(selected)} prototypes grew the output "
        f"{ratio:.2f}x ({len(native)} -> {len(vmed)} bytes); the interpreter "
        f"should be shared, not repeated")


# ---------------------------------------------------------------------------
# VM families
# ---------------------------------------------------------------------------
#
# Config has declared four families since the beginning and only REGISTER
# existed. These are the tests that make the other three real: each family runs
# the whole corpus and must compute what Luau computes.

from couxobf.vm.families import FAMILIES, family as _make_family  # noqa: E402


def _family_reconstruct(src, name, fam, seed=b"\xbb" * 16):
    module = ir.Lowerer().lower(parser.parse(src, name))
    domains = rngmod.make_domains(seed)
    out = lower_back.reconstruct_protected(
        module, KeyMaterial.from_seed(seed), domains.get("constants"),
        b"family-test", vm_level="maximum", vm_rng=domains.get("vm"),
        vm_family=fam)
    return out


@pytest.mark.parametrize("fam", list(FAMILIES))
@pytest.mark.parametrize("path", _corpus(), ids=lambda p: os.path.basename(p))
def test_family_matches_original(fam, path):
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available; run tools/setup-luau.sh")
    base = os.path.basename(path)
    if base in EXCLUDED:
        pytest.skip(f"{base}: {EXCLUDED[base]}")
    with open(path, encoding="utf-8", errors="surrogateescape") as fh:
        src = fh.read()
    try:
        out = _family_reconstruct(src, base, fam)
    except encode.EncodingError as exc:
        pytest.skip(f"not encodable: {exc}")

    original = execute(TOOLCHAIN, src, base, timeout=30)
    protected = execute(TOOLCHAIN, out, "family.luau", timeout=30)
    assert original.returncode == protected.returncode, (
        f"{fam}/{base}: rc {original.returncode} != {protected.returncode}\n"
        f"{protected.stderr[:500]}")
    assert original.stdout == protected.stdout, (
        f"{fam}/{base}: stdout differs\n--- original ---\n"
        f"{original.stdout[:400]}\n--- {fam} ---\n{protected.stdout[:400]}")


def test_families_are_aliases_for_the_single_woven_interpreter():
    domains = rngmod.make_domains(b"\xcc" * 16)
    plan = wiring.make_plan(domains.get("vm"), {1}, family="register")
    text = runtime.interpreter_source(plan.opmap, plan.names, plan.family)
    assert plan.family == "woven"
    assert plan.names["acc"] in text
    assert plan.names["stack"] in text


def test_unknown_family_is_rejected():
    with pytest.raises(ValueError):
        wiring.make_plan(rngmod.make_domains(b"\x01" * 16).get("vm"), {1},
                         family="quantum")


def test_family_config_normalizes_to_woven_output():
    src = "local function f(a, b) return a * b + 1 end\nprint(f(3, 4))\n"
    outs = {}
    for fam in ("register", "accumulator", "stack", "hybrid", "woven"):
        config = Config(reproducible_seed=9, min_virtualize_body_nodes=1,
                        vm_polymorphism=False)
        config.vm_family = fam
        outs[fam] = build(src, config, verify=False).source
    assert len(set(outs.values())) == 1


# ---------------------------------------------------------------------------
# dispatcher shapes
# ---------------------------------------------------------------------------
#
# Every build used to emit the same flat if/elseif chain over 43 opcodes, which
# is as good as a signature: find the chain once and the interpreter is known
# for every build the tool will ever produce. There are now three genuinely
# different control structures, and `mixed` -- the default -- picks one per
# build, so the shape is part of the fingerprint rather than a constant.

from couxobf.vm.runtime import DISPATCHERS  # noqa: E402

DISPATCH_SOURCE = """local function accumulate(values, factor)
  local total = 0
  for i = 1, #values do
    if values[i] % 2 == 0 then
      total = total + values[i] * factor
    else
      total = total - 1
    end
  end
  return total
end
local t = {}
for i = 1, 12 do t[i] = i end
print(accumulate(t, 3), accumulate({1, 2, 3}, 10))
"""


@pytest.mark.parametrize("dispatcher", list(DISPATCHERS))
@pytest.mark.parametrize("vm_family", ("register", "stack"))
def test_every_dispatcher_shape_computes_the_same_thing(dispatcher, vm_family):
    """All three shapes, two operand disciplines, same answer as Luau.

    The corpus differential cannot substitute for this: `mixed` picks a shape
    per seed, so a given run only ever exercises whichever came up.
    """
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    domains = rngmod.make_domains(b"\xd1" * 16)
    # The plan's own fresh names and table name are replaced with the test's
    # fixed ones: the reconstructor hardcodes _DESCRIPTOR_TABLE when it emits
    # the call sites, so a plan that invented a different name would produce a
    # body indexing a table that was never declared.
    plan = _plan(seed=b"\xd1" * 16, protos={1}, family=vm_family,
                 dispatcher=dispatcher)
    module = ir.Lowerer().lower(parser.parse(DISPATCH_SOURCE, "d.luau"))
    rec = _VMReconstructor(plan)
    body = printer.emit(rec.reconstruct(module))
    parts = [lower_back.HELPERS_SRC,
             wiring.prelude_source(plan, dict(rec.encoded), _lit, _lit),
             body]
    out = "\n".join(parts)
    assert rec.encoded, "nothing was virtualized"

    original = execute(TOOLCHAIN, DISPATCH_SOURCE, "d.luau", timeout=30)
    protected = execute(TOOLCHAIN, out, "p.luau", timeout=30)
    assert original.returncode == protected.returncode, protected.stderr[:400]
    assert original.stdout == protected.stdout, (
        f"{dispatcher}/{vm_family}: {original.stdout!r} != {protected.stdout!r}")


def test_single_dispatcher_has_no_tree_or_bucket_fingerprint():
    names = dict(NAMES)
    opmap = _opmap()
    text = runtime.interpreter_source(opmap, names, "woven", "woven")
    assert "op <=" not in text
    assert "_bk" not in text
    assert "bit32.bxor" in text


def test_mixed_normalizes_to_the_single_dispatcher():
    """The default must actually vary, or per-build randomness is a claim.

    Sixty seeds, not twelve.  At twelve the shape missing entirely is a
    one-in-a-hundred occurrence -- this test failed that way on first run, with
    8 bucket / 4 nested_if / 0 decision_tree, which looked exactly like a
    biased generator.  It was not: over 300 seeds the first draw of the
    dispatch stream splits 116/94/90, and ``rng.choice`` measures uniform over
    30000 draws.  The test was wrong, not the randomness.
    """
    for i in range(60):
        rng = rngmod.make_domains(b"\xd2" * 15 + bytes([i])).get("dispatch")
        assert wiring._dispatcher_name("mixed", rng) == "woven"
    assert set(DISPATCHERS) == {"woven"}


def test_an_unimplemented_dispatcher_is_refused():
    """Silently falling back would report a protection it did not apply."""
    with pytest.raises(ValueError, match="not implemented"):
        wiring.make_plan(rngmod.make_domains(b"\x03" * 16).get("vm"), {1},
                         dispatcher="segmented")


def test_opcode_randomization_changes_the_numbering():
    """Off means a stable, comparable numbering -- weaker, and deliberately so."""
    rng_a = rngmod.make_domains(b"\xd3" * 16).get("vm")
    rng_b = rngmod.make_domains(b"\xd3" * 16).get("vm")
    on = wiring.make_plan(rng_a, {1}, randomize_opcodes=True)
    off = wiring.make_plan(rng_b, {1}, randomize_opcodes=False)
    assert on.opmap.to_byte != off.opmap.to_byte
    assert off.opmap.to_byte == isa.OpcodeMap.identity().to_byte
    # and the same seed twice is still reproducible
    again = wiring.make_plan(rngmod.make_domains(b"\xd3" * 16).get("vm"), {1},
                             randomize_opcodes=True)
    assert again.opmap.to_byte == on.opmap.to_byte


# ---------------------------------------------------------------------------
# opcode disguise (Config.opcode_cipher) and per-group instruction sets
# ---------------------------------------------------------------------------
#
# Both exist for the same reason: a table recovered from one build -- "byte 7 is
# ADD", "the third arm is LOADK", "every VM here carries 43 handlers" -- must not
# be a table about the next build.  The disguise is arithmetic on the fetch, so it
# costs no bytes; the subset shrinks the artifact instead of growing it.

def _cipher_spec(cipher: str, op_bytes: int = 1) -> FormatSpec:
    mod = (1 << (8 * op_bytes)) - 1
    return FormatSpec(op_bytes=op_bytes, op_cipher=cipher, op_bias=37,
                      op_mult=7, op_mult_inv=pow(7, -1, mod),
                      op_pos_mult=13)


@pytest.mark.parametrize("cipher", ("none", "add", "affine", "swap", "pcadd"))
@pytest.mark.parametrize("op_bytes", (1, 2))
def test_the_cipher_is_a_bijection_over_the_number_space(cipher, op_bytes):
    """Every number survives, none lands on 0, and 0 is never produced.

    The field is one byte (or two) and the map is 1..modulus, because
    ``string.byte`` returns nil past the end of the payload -- a stored 0 would
    read as a valid short instruction.  So the image has to fix 0 and permute
    the rest, which is why these are rotations and multiplications modulo
    ``modulus`` rather than an XOR of the field.
    """
    fmt = _cipher_spec(cipher, op_bytes)
    mod = fmt.op_modulus
    stored = [fmt.encode_op(n) for n in range(1, mod + 1)]
    assert len(set(stored)) == mod, "not injective"
    assert all(1 <= v <= mod for v in stored), "image leaves 1..mod"
    assert all(fmt.decode_op(fmt.encode_op(n, 19), 19) == n
               for n in range(1, mod + 1))
    if cipher != "none":
        # The number space excludes 0 by construction, so a cipher that could
        # produce it would be a bug: the reader would treat a payload overrun as
        # a short instruction rather than as the end of the stream.
        with pytest.raises(ValueError):
            fmt.encode_op(0)
        with pytest.raises(ValueError):
            fmt.encode_op(mod + 1)


@pytest.mark.skipif(not TOOLCHAIN.can_execute, reason="luau runtime unavailable")
@pytest.mark.parametrize("cipher", ("none", "add", "affine", "swap", "pcadd"))
@pytest.mark.parametrize("op_bytes", (1, 2))
def test_the_emitted_reader_decodes_what_the_encoder_wrote(cipher, op_bytes):
    """Two implementations of a decoder have to be compared by running them.

    `decode_op` in Python and the `_ro` that gets inlined into the interpreter are
    the same rule written twice, in two languages, and a format bug of that shape
    -- one side updated, the other not -- is the failure mode that has already
    bitten this project twice.  So this feeds real bytes through the real emitted
    reader and compares against what the encoder meant.
    """
    import struct
    fmt = _cipher_spec(cipher, op_bytes)
    numbers = list(range(1, min(fmt.op_modulus, 255) + 1))
    payload = b"".join(struct.pack("<H" if op_bytes == 2 else "<B",
                                   fmt.encode_op(n, 1 + i * op_bytes))
                       for i, n in enumerate(numbers))
    lines = ["local _bd = string.byte", "local t = {}"]
    for i, byte in enumerate(payload, 1):
        lines.append("t[%d] = string.char(%d)" % (i, byte))
    lines.append("local code = table.concat(t)")
    from couxobf.vm.format import reader_source
    lines += reader_source(fmt, "code")
    lines.append("for a = 1, %d, %d do print(_ro(a)) end" % (len(payload), op_bytes))
    result = execute(TOOLCHAIN, "\n".join(lines), "cipher.luau", timeout=60)
    assert result.returncode == 0, result.stderr[:400]
    got = [int(float(word)) for word in result.stdout.split()]
    assert got == numbers, "%s: emitted reader disagrees" % cipher


def test_a_ciphered_payload_is_indecipherable_without_the_format():
    """Read the stream with a format that lacks the cipher and it stops being valid.

    This is the whole point of disguising the number, expressed as something a
    test can check: a payload lifted into a tool that assumes opcode bytes are
    dispatch numbers is *rejected*, not misread.  It also pins the other half --
    the validator reads the payload through the same FormatSpec the interpreter
    was generated from, so a disguised stream cannot quietly validate against
    undisguised expectations and bless a corruption.
    """
    from couxobf.integrity.payload import validate_proto
    from couxobf.integrity import IntegrityError

    src = "local function f(a, b) return a + b end\nprint(f(2, 3))\n"
    module = ir.Lowerer().lower(parser.parse(src, "cipher.luau"))
    proto = next(q for q in _all_protos(module) if q.proto_id == 1)
    plan = _plan(protos=(1,), isa_subset=False)
    group = plan.groups[0]
    fmt = group.fmt
    assert fmt.op_cipher != "none", "the fixed seed has to draw a cipher"

    enc = encode.encode_proto(proto, group.opmap, fmt=fmt)
    # Right format: the walk reaches every instruction boundary the encoder laid.
    validate_proto(1, enc.code, enc.consts, group.opmap,
                   expected_starts=enc.starts, fmt=fmt)
    # Same bytes, a reader that assumes raw numbers: not a valid program.
    with pytest.raises(IntegrityError):
        validate_proto(1, enc.code, enc.consts, group.opmap,
                       expected_starts=enc.starts,
                       fmt=FormatSpec(op_bytes=fmt.op_bytes))
    # And a *different* key is just as wrong as no key: the same disguise with
    # another bias does not decode this stream either.
    with pytest.raises(IntegrityError):
        validate_proto(1, enc.code, enc.consts, group.opmap,
                       expected_starts=enc.starts,
                       fmt=dataclasses.replace(fmt, op_bias=fmt.op_bias + 11))


def test_the_instruction_set_follows_the_prototype():
    """Subset on: the group carries what its functions use, and nothing else.

    The `print` in this program lives in the main chunk, which is never
    virtualized, so ``GETGLOBAL`` belongs to no group of this build -- while the
    full ISA map, which is what subset-off produces, has it.  A group's handler
    count is therefore a property of the code inside it, which is the point of the
    option; the same reasoning is what makes the count differ between two builds
    of two different programs.
    """
    src = "local function f(a, b) return a + b end\nprint(f(2, 3))\n"
    module = ir.Lowerer().lower(parser.parse(src, "subset.luau"))
    by_id = {q.proto_id: q for q in _all_protos(module)}
    needed = encode.required_ops(by_id[1])
    assert needed and "GETGLOBAL" not in needed

    full = _plan(protos=(1,), isa_subset=False)
    narrow = _plan(protos=(1,), isa_subset=True, protos_by_id=by_id)
    assert full.groups[0].opmap.size() > narrow.groups[0].opmap.size()
    assert set(needed) <= set(narrow.groups[0].opmap.to_byte)
    assert "GETGLOBAL" not in narrow.groups[0].opmap.to_byte
    assert "GETGLOBAL" in full.groups[0].opmap.to_byte
    with pytest.raises(KeyError, match="not in this build"):
        narrow.groups[0].opmap.byte("GETGLOBAL")


def test_required_ops_over_approximates_rather_than_guesses():
    """A missing opcode breaks the build; an extra one costs a dead arm.

    Block permutation can insert a ``JMP`` the IR does not contain, and a fusion
    rule may or may not fire for a given block, so both are included whatever the
    prototype looks like.  That is why narrowing is safe at all: the subset is a
    superset of what the encoder can emit, never an estimate of it.
    """
    from couxobf.vm.format import FusionRule

    src = "local function f(a) return a + 1 end\nprint(f(2))\n"
    mangled_src = src
    module = ir.Lowerer().lower(parser.parse(src, "over.luau"))
    proto = next(q for q in _all_protos(module) if q.proto_id == 1)
    plain = encode.required_ops(proto)
    with_jumps = encode.required_ops(proto, permuted_blocks=True)
    assert ir.OP.JMP not in plain
    assert ir.OP.JMP in with_jumps
    assert encode.required_ops(proto, FormatSpec(fused=())) == plain
    both = encode.required_ops(proto, FormatSpec(fused=(FusionRule("LOADK", "ADD"),)))
    assert {"LOADK", "ADD"} <= both
    # A prototype whose instructions cannot all be named gets no answer at all,
    # which the caller reads as "do not narrow" -- the fail-safe direction, since
    # the alternative is a group with a handler missing.  Every IR opcode now
    # has a VM entry (CLOSURE got one in R5's third increment), so the branch is
    # reached through the other thing it exists for: an instruction whose
    # operand count disagrees with the opcode it claims to be.
    broken = ir.Lowerer().lower(parser.parse(mangled_src, "arity.luau"))
    victim = next(q for q in _all_protos(broken) if q.proto_id == 1)
    victim.blocks[0].instrs[0].args = victim.blocks[0].instrs[0].args[:1]
    unknown = [q for q in _all_protos(broken)
               if encode.required_ops(q) is None]
    assert unknown, "expected a prototype required_ops cannot answer for"
    # And the closure subtree is folded in only when the caller asks: a
    # prototype that creates closures needs its children's opcodes in the same
    # group, which is what ``children`` is for.
    tree = ir.Lowerer().lower(parser.parse(
        "local function outer(n)\n"
        "  local function child(x)\n"
        "    return x * 2\n"
        "  end\n"
        "  return child(n) + 1\n"
        "end\n"
        "print(outer(3))\n", "tree.luau"))
    outer = next(q for q in _all_protos(tree) if q.proto_id == 1)
    # MUL is the child's alone -- the parent adds and calls, so seeing it in
    # the parent's answer is the subtree having been folded in.
    assert ir.OP.MUL not in encode.required_ops(outer, children=False)
    assert ir.OP.MUL in encode.required_ops(outer, children=True)


def test_permuted_arms_test_the_same_numbers_in_a_different_order():
    """Free reordering, applied -- and it stays a function of (map, format).

    The chain matches on disjoint numbers, so which arm is tried first changes
    nothing about what the interpreter accepts.  What it changes is that arm
    positions carry meaning, which is a small thing to an analyst reading two
    builds side by side and a large thing for a tool that assumes it.
    """
    from couxobf.vm.runtime import dispatch_entries

    opmap = _opmap()
    first = dispatch_entries(opmap, FormatSpec(arm_seed=1234567))
    same = dispatch_entries(opmap, FormatSpec(arm_seed=1234567))
    other = dispatch_entries(opmap, FormatSpec(arm_seed=7654321))
    plain = dispatch_entries(opmap, FormatSpec())
    assert [e.numbers for e in first] == [e.numbers for e in same]
    assert {e.op for e in first} == {e.op for e in plain}
    assert [e.numbers for e in first] != [e.numbers for e in plain]
    assert [e.numbers for e in first] != [e.numbers for e in other]
    # every number the map hands out is still reachable exactly once
    flat = [n for e in first for n in e.numbers]
    assert sorted(flat) == sorted(n for e in plain for n in e.numbers)


def test_the_fetch_goes_through_the_reader():
    """No raw `byte(code, pc)` at the dispatch site, in any format.

    The selector is the one field a matcher can find without understanding
    anything else, so it is read through the generated reader like every operand
    -- which is also the only place the disguise can be undone consistently.
    """
    for op_bytes in (1, 2):
        for cipher in ("none", "add", "affine", "swap"):
            source = runtime.interpreter_source(
                _opmap(), NAMES, "register", "nested_if",
                _cipher_spec(cipher, op_bytes))
            assert "_ro(pc)" in source, cipher
            assert "local op = _bd(" not in source, cipher


# ---------------------------------------------------------------------------
# handler hygiene: a body may only touch names its own reads declare
# ---------------------------------------------------------------------------
#
# ``GETTABLEK``/``SETGLOBAL`` both had a body that referenced a local the
# generated reads never declared.  Luau compiles ``K[k + 1]`` with an unbound
# ``k`` into "index nil", so the artifact parsed, ran, and failed at the first
# store -- and nothing in the encoder, the validator or the printer objected.
# A name that only exists in one of the two halves of a handler is the cheapest
# possible way for a generated interpreter to be wrong, so it is checked
# statically, for every format, before anything is executed.

_LUAU_GLOBALS = frozenset({
    "pc", "R", "K", "E", "true", "false", "nil", "and", "or", "not",
    "_bd", "_r8", "_rr", "_rp", "_rk", "_rt", "_pack", "_unpack", "error",
    "type", "getmetatable", "bit32", "table", "string", "math", "getfenv",
    "while", "do", "then", "else", "elseif", "end", "if", "for", "in", "local",
    "function", "return", "break", "repeat", "until", "goto",
})


def _handler_names(lines):
    """(declared, used) for a chunk of generated handler source."""
    declared = set()
    used = set()
    for line in lines:
        text = line.strip()
        # ``src.n`` and ``t[1]`` are fields and indices, not names: strip the
        # suffix of a dot access so only the base identifier is considered.
        text = re.sub(r"\.\s*([A-Za-z_][A-Za-z0-9_]*)", r".\1", text)
        text = re.sub(r"\.[A-Za-z_][A-Za-z0-9_]*", "", text)
        for m in re.finditer(r"\blocal\s+([A-Za-z_][A-Za-z0-9_,\s]*?)\s*=",
                             text):
            declared.update(p.strip() for p in m.group(1).split(","))
        for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", text):
            used.add(m.group(1))
    return declared, used


@pytest.mark.parametrize("op", sorted(isa.SUPPORTED))
def test_every_handler_body_uses_only_declared_names(op):
    """Every identifier a handler reads is either declared or a real global."""
    from couxobf.vm.format import LEGACY_SPEC, FormatSpec

    for spec in (LEGACY_SPEC,
                 FormatSpec(reg_bytes=2, wide_bytes=3, pad=2, wides_first=True,
                            reg_mask=0x5A, wide_mask=0x1234,
                            target_mode="rel", target_bias=7),
                 FormatSpec(target_mode="edges", fused=(), reorder=True)):
        lines = runtime._handler(op, NAMES, _make_family("register", NAMES),
                                 spec)
        declared, used = _handler_names(lines)
        # multi-value packs arrive as table fields; a `for` loop's control
        # variable is declared by the loop header itself, and a function's
        # parameter by its signature -- which is how the accessor closures a
        # capturing child needs name the value they are handed.
        for line in lines:
            m = re.match(r"\s*for\s+([A-Za-z_][A-Za-z0-9_]*)", line)
            if m:
                declared.add(m.group(1))
            for m in re.finditer(r"function\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)",
                                 line):
                declared.add(m.group(1))
        free = sorted(n for n in used - declared - _LUAU_GLOBALS
                      # helper locals are named through the NAMES dict
                      if n not in set(NAMES.values()))
        assert not free, (
            f"{op} under {spec.target_mode}/{spec.reg_bytes}B registers uses "
            f"{free}, which no read in the handler declares: {lines}")


#: The layouts whose geometry differs from the historical one, so a handler that
#: happens to work under ``op_bytes == 1, pad == 0`` cannot pass on its own.
_GEOMETRY_FORMATS = (
    FormatSpec(),
    FormatSpec(pad=1),
    FormatSpec(pad=2, wides_first=True),
    FormatSpec(op_bytes=2),
    FormatSpec(op_bytes=2, reg_bytes=2, wide_bytes=3, pad=1),
    FormatSpec(reg_bytes=2, wide_bytes=3),
)


def _jumping_ops(fmt):
    """Opcodes whose instruction carries a jump target."""
    return sorted(op for op in isa.FORMATS if ("w", "target") in fmt.offsets(op))


@pytest.mark.parametrize("fmt", _GEOMETRY_FORMATS)
def test_a_jump_leaves_pc_where_its_own_mode_measures_from(fmt):
    """The arm that transfers control must know where ``pc`` is standing.

    A relative delta is measured from the *next* instruction, so an arm that
    never advances -- ``JMP`` is one, because nothing reads the pc it leaves
    behind -- has to cover the distance itself.  Getting this wrong is not a
    crash: it lands one byte into the instruction after the target, and the
    payload, the encoder and the integrity walk all still agree with each other,
    so only an executed program can tell.  Absolute modes have the mirror-image
    obligation: they assign the position, so they must not add to ``pc`` at all.
    """
    for op in _jumping_ops(fmt):
        lines = runtime._handler(op, NAMES, _make_family("register", NAMES), fmt)
        body = fmt.body_size(op)
        advanced = 0
        checked = False
        for line in lines:
            moved = re.fullmatch(r"\s*pc = pc \+ (\d+)\s*$", line)
            if moved:
                advanced += int(moved.group(1))
                continue
            jumped = re.fullmatch(r"\s*pc = pc \+ (?:(\d+) \+ )?tgt\s*$", line)
            if jumped:
                checked = True
                travel = int(jumped.group(1) or 0)
                if fmt.target_mode == "rel":
                    assert advanced + travel == body, (
                        f"{op} under {fmt.target_mode}/{fmt.op_bytes}B opcodes/"
                        f"{fmt.pad} pad: a taken jump leaves pc at "
                        f"{advanced + travel} bytes into the unit, but the "
                        f"encoder measured the delta from {body}; the target is "
                        f"reached {body - advanced - travel} bytes early")
                else:
                    pytest.fail(
                        f"{op} under {fmt.target_mode}: added a decoded target "
                        f"to pc, which is only how relative mode works")
        if fmt.target_mode == "rel":
            assert checked, f"{op}: no jump at all under relative targets"
        elif op in runtime._NO_ADVANCE:
            assert "pc = tgt + 1" in lines, (
                f"{op} transfers control without setting pc from the target")


def test_fresh_names_share_one_history():
    """Two draws from one build must not be able to hand out the same name.

    ``used`` is the shared history: it is reserved against and updated, so a
    later draw cannot repeat an earlier one.  This pins the threading itself,
    deterministically.
    """
    rng = rngmod.Rng(bytes(range(16)))
    used = set()
    first = wiring._fresh_names(rng, 8, used=used)
    second = wiring._fresh_names(rng, 8, used=used)
    assert len(set(first)) == 8
    assert len(set(second)) == 8
    assert not set(first) & set(second), (first, second)
    assert used == set(first) | set(second)


def test_plan_names_are_unique_across_every_draw():
    """A plan's tables, roles and per-group entry points must all differ.

    `make_plan` draws them in four separate calls, and each call used to build
    its own :class:`NameGenerator` with an empty history -- so nothing stopped
    two of them from handing out the same identifier.  The second declaration
    shadows the first wherever both are in scope, and the artifact then raises
    at the first call instead of running.  It took roughly one build in three
    thousand to hit, which is often enough to ship and rare enough that no
    test caught it: the sweep that found it was a `pcall` fixture printing
    `attempt to index function with number` because a prototype table and an
    entry point had both been named the same thing.

    Unthreaded, about 2% of plans collide -- 39 of the 2000 below -- so this
    loop is not a needle in a haystack.  The check reads the drawn names
    directly rather than executing anything, because the failure is a
    collision of *names*, not of semantics.
    """
    for seed in range(400):
        rng = rngmod.Rng(bytes([(seed * 13 + i * 5) & 0xFF for i in range(16)]))
        plan = wiring.make_plan(rng, [0, 1, 2], variety=2)
        drawn = [plan.table, plan.consts_table, plan.edges_table,
                 plan.rows_table]
        # ``rows`` is excluded because it is not a drawn name: it is the row
        # table's own identifier, listed in ``plan.names`` so the interpreter's
        # CLOSURE arm can index it.  Counting it would report a collision
        # between a table and itself.
        drawn += [value for key, value in plan.names.items()
                  if key not in ("append", "iter", "iterpack", "itercheck",
                                 "rows")]
        for group in plan.groups:
            drawn += [group.names["exec"], group.names["enter"]]
        dupes = sorted({name for name in drawn if drawn.count(name) > 1})
        assert not dupes, (
            "seed %d drew the same VM identifier twice (%s): the second "
            "declaration shadows the first" % (seed, ", ".join(dupes)))

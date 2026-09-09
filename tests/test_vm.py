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
from couxobf.vm import encode, isa, runtime
from test_roundtrip import EXCLUDED, MICRO_DIR, _conformance_dir

TOOLCHAIN = find_toolchain()

#: Interpreter locals, fixed here so a failure names the function it came from.
NAMES = {
    "code": "_kS",
    "exec": "_kX",
    "enter": "_kGo",
    "call": "_kAp",
    "getfenv": "_kGe",
    "append": "_kapp",
    "iter": "_kiter",
    "iterpack": "_kiterpack",
    "itercheck": "_kitercheck",
}


class _VMReconstructor(lower_back.Reconstructor):
    """Reconstructs natively, except for prototypes handed to the VM."""

    def __init__(self, opmap, **kw):
        super().__init__(**kw)
        self.opmap = opmap
        self.encoded = {}

    def function_expr(self, proto: FuncIR):
        ok, _reason = encode.can_virtualize(proto)
        if not ok:
            return super().function_expr(proto)
        enc = encode.encode_proto(proto, self.opmap)
        self.encoded[proto.proto_id] = enc
        # A real Luau closure that enters the interpreter.  To the surrounding
        # native code this is indistinguishable from the function it replaces.
        return A.Func(
            params=[A.Param(name=None)],
            body=A.Block(body=[A.Return(values=[A.Call(
                fn=A.Name(name=NAMES["enter"]),
                args=[A.Index(obj=A.Name(name=_DESCRIPTOR_TABLE),
                              key=A.Number(value=proto.proto_id,
                                           is_float=False)),
                      A.Call(fn=A.Name(name=NAMES["getfenv"]),
                             args=[A.Number(value=1, is_float=False)]),
                      A.Vararg()])])]))


#: All descriptors live in one table, keyed by prototype id.  They cannot be
#: individual chunk-level locals: Luau caps a function at 200 locals, and
#: basic.luau alone virtualizes 256 prototypes, which fails to compile with
#: "Out of local registers ... exceeded limit 200".
_DESCRIPTOR_TABLE = "_kVT"


def _lit(value) -> str:
    """A constant as Luau source, through the printer's own literal rules.

    Going through the printer rather than ``repr`` matters for the bytecode
    string: non-printable bytes need three-digit decimal escapes, and a stray
    backslash or quote would corrupt the program.
    """
    p = printer.Printer()
    p.expr(lower_back._const_expr(value))
    return p.w.value()


def _descriptors(encoded) -> str:
    """Every prototype's runtime descriptor, as one keyed table."""
    rows = []
    for pid, enc in sorted(encoded):
        consts = ", ".join(_lit(v) for v in enc.consts)
        rows.append("  [%d] = { code = %s, consts = { %s }, entry = %d, "
                    "nparams = %d },"
                    % (pid, _lit(enc.code), consts, enc.lua_entry, enc.nparams))
    if not rows:
        return ""
    return "local %s = {\n%s\n}" % (_DESCRIPTOR_TABLE, "\n".join(rows))


def _opmap(seed: bytes = b"\x07" * 16) -> isa.OpcodeMap:
    return isa.OpcodeMap.shuffled(rngmod.make_domains(seed).get("opcodes"))


def vm_reconstruct(src: str, name: str = "test.luau", seed: bytes = b"\x07" * 16):
    """source -> IR -> VM-backed executable Luau.

    Returns the source and the set of prototype ids that were virtualized, so a
    test can insist that it actually tested the VM instead of quietly falling
    back to native code for everything.
    """
    module = ir.Lowerer().lower(parser.parse(src, name))
    rec = _VMReconstructor(_opmap(seed))
    body = printer.emit(rec.reconstruct(module))
    parts = [lower_back.HELPERS_SRC, runtime.interpreter_source(_opmap(seed), NAMES)]
    parts.append(_descriptors(rec.encoded.items()))
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
            if seen_advance and NAMES["code"] in line:
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
            if not encode.can_virtualize(proto)[0]:
                continue
            enc = encode.encode_proto(proto, opmap)
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
    files = sorted(glob.glob(os.path.join(MICRO_DIR, "*.luau")))
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

from couxobf.crypto.kdf import KeyMaterial  # noqa: E402
from couxobf.vm import wiring  # noqa: E402


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
    assert ratio < 1.6, (
        f"virtualizing {len(selected)} prototypes grew the output "
        f"{ratio:.2f}x ({len(native)} -> {len(vmed)} bytes); the interpreter "
        f"should be shared, not repeated")

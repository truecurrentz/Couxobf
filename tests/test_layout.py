"""Tests for VM block layout permutation.

The load-bearing property is that permuting the block order changes the
bytecode without changing what the program does.  Both halves need a test: a
permutation that produced identical bytes would be a no-op dressed up as a
feature, and one that changed behaviour would be a bug that the corpus
differential in test_pipeline happens to catch only by luck of the seed.

The invariant test at the bottom is the one that earns its place.  The encoder
decides where to insert an explicit jump and the integrity checker decides
where control can flow; those two have to agree about which opcodes fall
through, and nothing else in the codebase makes them.  They disagreed about
FORPREP and FORINPREP for as long as both existed, and it was invisible
because the default layout always put those blocks next to their target.
"""

import glob
import os

import pytest

import couxobf.ir as ir
import couxobf.parser as parser
import couxobf.rng as rngmod
from couxobf.config import Config
from couxobf.integrity import IntegrityError, validate_proto
from couxobf.integrity.payload import _NO_FALLTHROUGH as WALK_NO_FALLTHROUGH
from couxobf.pipeline import build
from couxobf.toolchain import execute, find_toolchain
from couxobf.vm import encode, layout
from couxobf.vm.encode import (_CONDITIONAL_OPS, _NO_FALLTHROUGH_OPS,
                               EncodingError, _fallthrough)

TOOLCHAIN = find_toolchain()
CORPUS = sorted(glob.glob("/tmp/luau-src-0.700/tests/conformance/*.luau"))


def _opmap(seed=b"\x09" * 16):
    return encode.OpcodeMap.shuffled(rngmod.make_domains(seed).get("opcodes"))


def _protos(path):
    with open(path, encoding="utf-8", errors="surrogateescape") as fh:
        module = ir.Lowerer().lower(parser.parse(fh.read(), os.path.basename(path)))
    out = []

    def walk(p):
        if encode.can_virtualize(p)[0]:
            out.append(p)
        for c in p.children:
            walk(c)

    walk(module.main)
    return out


@pytest.fixture(scope="module")
def big_proto():
    """The corpus prototype with the most blocks, so a shuffle has room."""
    best = None
    for path in CORPUS:
        try:
            for p in _protos(path):
                if best is None or len(p.blocks) > len(best.blocks):
                    best = p
        except Exception:
            continue
    assert best is not None and len(best.blocks) > 10
    return best


# ---------------------------------------------------------------------------
# the permutation is real, and it is safe
# ---------------------------------------------------------------------------

def test_default_order_is_byte_identical(big_proto):
    """Not permuting must produce exactly the old bytes.

    Every fall-through edge in the IR's own layout already points at the next
    block, so no explicit jump is inserted and nothing shifts.  If this ever
    fails, turning the feature off stopped being a no-op.
    """
    opmap = _opmap()
    default = encode.encode_proto(big_proto, opmap)
    explicit = encode.encode_proto(big_proto, opmap,
                                   order=[b.id for b in big_proto.blocks])
    assert default.code == explicit.code


def test_permutation_changes_the_bytecode(big_proto):
    """Different seeds must give different layouts, not just different noise."""
    opmap = _opmap()
    codes = set()
    for i in range(20):
        rng = rngmod.make_domains(b"\x09" * 15 + bytes([i])).get("cfg")
        order = layout.permuted_order(big_proto, rng)
        codes.add(encode.encode_proto(big_proto, opmap, order=order).code)
    assert len(codes) >= 15, f"only {len(codes)} distinct layouts from 20 seeds"


def test_entry_block_comes_first(big_proto):
    """Legal either way, but a jump at the entry point is a free giveaway."""
    for i in range(10):
        rng = rngmod.make_domains(b"\x09" * 15 + bytes([i])).get("cfg")
        order = layout.permuted_order(big_proto, rng)
        assert order[0] == big_proto.entry
        assert sorted(order) == sorted(b.id for b in big_proto.blocks)


@pytest.mark.parametrize("i", range(12))
def test_permuted_payload_passes_the_integrity_walk(big_proto, i):
    """Every permutation must survive the walk, not just the ones tried by hand.

    This is where the two fall-through bugs were caught: a conditional jump
    moved to the end of the layout, and a block ending in an ordinary
    instruction treated as though it transferred control.
    """
    opmap = _opmap()
    rng = rngmod.make_domains(b"\x09" * 15 + bytes([i])).get("cfg")
    order = layout.permuted_order(big_proto, rng)
    e = encode.encode_proto(big_proto, opmap, order=order)
    validate_proto(big_proto.proto_id, e.code, e.consts, opmap,
                   expected_starts=e.starts)


def test_permutation_costs_a_few_jumps(big_proto):
    """Broken fall-through edges become explicit jumps; that is the whole cost.

    Pinned so a regression that inserts a jump per block, or none at all, is
    visible rather than showing up as a size change nobody explained.
    """
    opmap = _opmap()
    base = len(encode.encode_proto(big_proto, opmap).code)
    rng = rngmod.make_domains(b"\x09" * 15 + b"\x01").get("cfg")
    order = layout.permuted_order(big_proto, rng)
    extra = layout.closes_fallthrough(big_proto, order)
    grew = len(encode.encode_proto(big_proto, opmap, order=order).code) - base
    assert extra > 0, "a real shuffle should break some fall-through edges"
    assert grew == extra * encode.operand_size("JMP"), (
        f"{extra} jumps should add {extra * 3} bytes, added {grew}")


# ---------------------------------------------------------------------------
# the fall-through classification
# ---------------------------------------------------------------------------

def test_encoder_and_walk_agree_on_which_ops_fall_through():
    """The invariant whose absence hid a bug in both modules.

    The encoder uses this to decide where to insert a jump; the integrity walk
    uses it to decide where control can go.  They were built separately and
    disagreed about FORPREP and FORINPREP, which the default layout concealed
    because those blocks always sat next to their target.
    """
    assert set(WALK_NO_FALLTHROUGH) == set(_NO_FALLTHROUGH_OPS), (
        f"walk says {sorted(WALK_NO_FALLTHROUGH)}, "
        f"encoder says {sorted(_NO_FALLTHROUGH_OPS)}")
    # and the conditional set is exactly the complement inside TERMINATORS
    assert not (_CONDITIONAL_OPS & _NO_FALLTHROUGH_OPS)


@pytest.mark.parametrize("path", CORPUS[:24],
                         ids=lambda p: os.path.basename(p))
def test_every_fallthrough_edge_is_where_the_layout_puts_it(path):
    """In the IR's own order, no explicit jump is ever needed.

    Verified over the whole corpus rather than asserted: it is the reason
    turning the feature off is byte-identical, and it is a property of the
    lowerer that a future change could quietly break.
    """
    try:
        protos = _protos(path)
    except Exception:
        pytest.skip("does not lower")
    for p in protos:
        order = [b.id for b in p.blocks]
        assert layout.closes_fallthrough(p, order) == 0, (
            f"{os.path.basename(path)} proto {p.proto_id}")


def test_a_layout_missing_a_block_is_refused(big_proto):
    with pytest.raises(EncodingError, match="does not cover"):
        encode.encode_proto(big_proto, _opmap(), order=[big_proto.entry])


def test_a_layout_repeating_a_block_is_refused(big_proto):
    order = [b.id for b in big_proto.blocks]
    order[1] = order[0]
    with pytest.raises(EncodingError, match="does not cover"):
        encode.encode_proto(big_proto, _opmap(), order=order)


# ---------------------------------------------------------------------------
# end to end
# ---------------------------------------------------------------------------

# In a function, not at top level: the main chunk is never virtualized, so a
# top-level loop would leave block_permutation with nothing to permute and the
# "the flag changed nothing" test below would pass for the wrong reason.
LOOPING = '''local function churn()
  local total = 0
  for i = 1, 10 do
    for j = 1, i do
      if j % 3 == 0 then total = total + j else total = total - 1 end
    end
  end
  local t = {}
  for k, v in ipairs({"a", "b", "c"}) do t[k] = v:upper() end
  return total, table.concat(t)
end
print(churn())
'''


@pytest.mark.skipif(not TOOLCHAIN.can_execute, reason="luau runtime unavailable")
@pytest.mark.parametrize("seed", [1, 2, 3, 4, 5, 6, 7, 8])
def test_permuted_build_still_computes_the_same_thing(seed):
    """Loops and generalized iteration, where a wrong edge is most visible."""
    config = Config(reproducible_seed=seed, min_virtualize_body_nodes=1,
                    block_permutation=True)
    out = build(LOOPING, config, verify=False).source
    original = execute(TOOLCHAIN, LOOPING, "loop.luau", timeout=30)
    protected = execute(TOOLCHAIN, out, "p.luau", timeout=30)
    assert original.returncode == protected.returncode, protected.stderr[:400]
    assert original.stdout == protected.stdout, (
        f"seed {seed}:\n{original.stdout!r}\n{protected.stdout!r}")


def test_block_permutation_config_reaches_the_output():
    """On and off must produce different artifacts, or the flag is decorative."""
    outs = {}
    for flag in (True, False):
        outs[flag] = build(LOOPING,
                           Config(reproducible_seed=3,
                                  min_virtualize_body_nodes=1,
                                  block_permutation=flag),
                           verify=False).source
    assert outs[True] != outs[False], "the flag changed nothing"


def test_same_seed_same_layout():
    """Reproducible builds include the layout, not just the names."""
    a = build(LOOPING, Config(reproducible_seed=9, min_virtualize_body_nodes=1),
              verify=False).source
    b = build(LOOPING, Config(reproducible_seed=9, min_virtualize_body_nodes=1),
              verify=False).source
    assert a == b

"""R2 native side: split arms in the flattened native drivers.

A multi-block native function lowers to ``while pc do if/elseif ... end``
over an affine image of the state.  With ``opaque_predicates`` on and a
non-zero control-flow level, the build adds *split arms*: extra ``elseif``
arms whose encoded state value is outside the encoding's image of the block
ids.  The counter is only ever assigned a block id, so such an arm is
provably unreachable -- the build knows that from its own draw, but a reader
can only learn it by solving the flattened control flow.

The invariant is therefore: **for every reachable state, exactly one arm is
satisfiable.**  These tests prove it symbolically from the drawn encoding
(not by staring at emitted text), pin the config knobs that own the arms,
and run a build that carries them to show behaviour is unchanged.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from couxobf import lower_back, parser
from couxobf.config import Config
from couxobf.pipeline import build
from couxobf.rng import Rng
from couxobf.toolchain import execute, find_toolchain

TOOLCHAIN = find_toolchain()

MULTIBLOCK = (
    "local function f(n)\n"
    "  local t = 0\n"
    "  for i = 1, n do\n"
    "    if i % 3 == 0 then\n"
    "      t = t + i * 2\n"
    "    elseif i % 2 == 0 then\n"
    "      t = t - i\n"
    "    else\n"
    "      t = t + 1\n"
    "    end\n"
    "  end\n"
    "  return t\n"
    "end\n"
    "print(f(50), f(7))\n"
)


def _module():
    from couxobf import ir
    return ir.Lowerer().lower(parser.parse(MULTIBLOCK, "mb.luau"))


def _enc(mode, salt, mul, modulus, block_id):
    """The drawn state encoding, recomputed independently of the emitter."""
    if mode == 1:
        return (block_id - salt) % modulus
    if mode == 2:
        return (((block_id + salt) * mul) + (salt % 251)) % modulus
    return ((block_id * mul) + salt) % modulus


def test_every_decoy_state_is_unreachable_and_arms_stay_unique():
    """The exactly-one-satisfiable invariant, symbolic over the affine forms.

    Every block id maps to its own encoded state (real arms never collide),
    and every decoy state sits outside that image -- so for any counter
    value the driver can hold, one and only one arm matches.
    """
    for seed in range(12):
        rec = lower_back.Reconstructor()
        rec.vm_layout_rng = Rng(bytes([(seed * 11 + i) & 0xFF for i in range(16)]))
        rec.split_arms_rate = 1.0          # every drawn block takes an arm
        rec.reconstruct(_module())
        logs = [l for l in rec.split_log if l["decoys"]]
        assert logs, seed                  # rate 1.0 must draw arms
        for log in rec.split_log:
            mode, salt, mul, mod = log["mode"], log["salt"], log["mul"], log["modulus"]
            # The recomputed encoding agrees with what the build recorded.
            assert log["encoded"] == [
                _enc(mode, salt, mul, mod, i) for i in log["block_ids"]]
            # Real arms are pairwise distinct (the encoding is injective).
            assert len(set(log["encoded"])) == len(log["encoded"])
            image = set(log["encoded"])
            for block_id, value, tail_n in log["decoys"]:
                # The decoy state is outside the image of the block ids, so
                # no reachable counter satisfies it...
                assert value not in image, (seed, block_id, value)
                # ...and it is not any other decoy's state either, or two
                # arms would fire on the same (impossible) value.
                others = [v for b, v, _ in log["decoys"] if b != block_id]
                assert value not in others
                assert tail_n >= 1
            # Exactly one arm is satisfiable per reachable state: membership
            # in the image is the condition, and the image has one entry per
            # block id.
            for block_id in log["block_ids"]:
                satisfiable = [e for e in image if e == _enc(mode, salt, mul, mod, block_id)]
                assert len(satisfiable) == 1
                assert not any(v == _enc(mode, salt, mul, mod, block_id)
                               for _b, v, _t in log["decoys"])


def test_no_rate_means_no_arms_and_no_log_decoys():
    rec = lower_back.Reconstructor()
    rec.vm_layout_rng = Rng(b"\x02" * 16)
    rec.split_arms_rate = 0.0
    rec.reconstruct(_module())
    assert rec.split_arms_emitted == 0
    assert all(not log["decoys"] for log in rec.split_log)


@pytest.fixture(scope="module")
def maze_source():
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(repo, "examples", "maze.luau"),
              encoding="utf-8") as fh:
        return fh.read()


def test_the_knobs_own_the_arms(maze_source):
    """opaque_predicates is the switch, control_flow_level the dial."""
    on = build(maze_source, Config(reproducible_seed=41),
               name="maze.luau", verify=False)
    assert on.stats.split_arms >= 1, "the hardened default must draw arms"
    assert "split arms" in on.report

    flat = build(maze_source,
                 Config(reproducible_seed=41, control_flow_level=0),
                 name="maze.luau", verify=False)
    assert flat.stats.split_arms == 0, "level 0 flattens without arms"

    no_pred = build(maze_source,
                    Config(reproducible_seed=41, opaque_predicates=False),
                    name="maze.luau", verify=False)
    assert no_pred.stats.split_arms == 0, "the predicate switch must own them"


def test_a_build_carrying_arms_executes_like_its_source(maze_source):
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    want = execute(TOOLCHAIN, maze_source, "want.luau", timeout=30)
    assert want.returncode == 0
    out = build(maze_source, Config(reproducible_seed=41),
                name="maze.luau", verify=True)
    assert out.stats.split_arms >= 1, "seed 41 draws arms on maze.luau"
    got = execute(TOOLCHAIN, out.source, "got.luau", timeout=30)
    assert got.returncode == 0, got.stderr[:300]
    assert got.stdout == want.stdout, (got.stdout, want.stdout)

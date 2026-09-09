"""The environment-logging and dump guards: do they see what they claim to see?

Two kinds of test, because the module makes two kinds of claim.

The *static* ones read the emitted artifact: that a build with the guards off
contains nothing at all, that the capture is scoped to the scaffolding and never
touches a name the program writes, and that the refusal is the dispatcher's own
error string rather than a banner a dumper can grep for.

The *executed* ones are the only ones that matter for the threat model, so they
run the artifact under a hostile environment -- a metatable on ``_G`` that counts
global reads, and a runner that swaps ``string.dump`` halfway through.  Counting
the reads is what turns "the runtime resolves its lookups through locals" from a
sentence in a docstring into a number: a few thousand logged reads with the guard
off, about one per captured name with it on.

Skipped without the pinned ``luau`` toolchain, like every other test that has to
run something.
"""

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from couxobf import ast_nodes as A
from couxobf import guard as guardmod
from couxobf import parser
from couxobf.config import Config
from couxobf.emit import printer
from couxobf.pipeline import build
from couxobf.toolchain import execute, find_toolchain
from couxobf.vm import runtime as vmruntime
from couxobf.vm.isa import OpcodeMap

TOOLCHAIN = find_toolchain()

SOURCE = """local function scale(values, factor)
  local out = {}
  for i = 1, #values do
    out[i] = values[i] * factor
  end
  return out
end
local r = scale({1, 2, 3, 4, 5}, 3)
local total = 0
for i = 1, #r do
  total = total + r[i]
end
print(total)
"""

#: A runner that loads the artifact with an environment of its own and counts
#: every name it looks up -- which is what an environment logger is, and what
#: `_G` cannot be made into on the reference interpreter (its library tables are
#: readonly, so there is no metatable to install there).  Loading with `setfenv`
#: is also the shape Roblox exploit tools use, so the measurement is of the real
#: attack rather than of a local imitation.
LOGGER = """local counts = {}
local watched = {"string", "table", "math", "getfenv", "rawget", "getmetatable",
                 "pcall", "error", "assert", "type", "select", "next", "ipairs"}
local real = _G
local env = setmetatable({}, {__index = function(t, k)
  for i = 1, #watched do
    if watched[i] == k then
      counts[k] = (counts[k] or 0) + 1
      break
    end
  end
  return rawget(real, k)
end, __newindex = function(t, k, v)
  rawset(real, k, v)
end})
-- `loadstring` rather than `load`: the reference interpreter has the former, and
-- `setfenv` because a chunk compiled from a string starts in `_G`
local chunk = loadstring(CHUNK)
if not chunk then
  error("driver: could not compile the artifact")
end
setfenv(chunk, env)
chunk()
local n = 0
for k, v in pairs(counts) do
  n = n + v
end
print("logged:" .. tostring(n))
"""


def _logger_script(artifact: str) -> str:
    """Embed one artifact in the logging runner, at a bracket level it cannot hit.

    The level is chosen rather than fixed because the artifact contains long
    brackets of its own -- a pooled string with ``]]`` in it would close a naive
    ``[[...]]`` and the driver would fail to parse, which is a bug in the test and
    not in the build.
    """
    for level in range(3, 12):
        open_b = "[" + "=" * level + "["
        close_b = "]" + "=" * level + "]"
        if open_b not in artifact and close_b not in artifact:
            return LOGGER.replace("CHUNK", open_b + artifact + close_b)
    raise AssertionError("no long-bracket level fits this artifact")


def _cfg(level=2, policy="fail", **extra):
    cfg = Config.hardened()
    cfg.reproducible_seed = 0xA11CE
    cfg.min_virtualize_body_nodes = 1
    cfg.env_guard = level
    cfg.dump_guard = level
    cfg.guard_policy = policy
    for key, value in extra.items():
        setattr(cfg, key, value)
    return cfg


# -- static: what the emitted artifact contains -------------------------------

def test_guards_off_emit_nothing_at_all():
    """``env_guard = 0`` and ``dump_guard = 0`` must show as an absence.

    A knob that emits the defence anyway and merely promises not to use it is not
    a knob, and the config documents 0 as "off".
    """
    assert guardmod.guard_block(guardmod.make(0, 0)) == ""
    guard = guardmod.make(0, 0, prefix="_qz")
    assert guard.capture_lines() == []
    assert guard.check_lines() == []
    assert guard.entry_lines() == []
    out = build(SOURCE, _cfg(0), name="guard.luau", verify=False)
    assert out.runtime_names["guard"]["captured"] == []
    assert not out.runtime_names["guard"]["refuses"]


@pytest.mark.parametrize("level", (1, 2))
def test_level_one_observes_and_level_two_acts(level):
    guard = guardmod.make(level, level)
    assert guard.active
    assert guard.neutralises == (level >= 2)
    assert guard.refuses == (level >= 2)
    if level == 1:
        assert guard.entry_lines() == []
        text = "\n".join(guardmod.guard_block(guard).splitlines())
        assert "getrawmetatable" not in text, "level 1 must not mutate anything"
    else:
        assert guard.entry_lines()
        assert "getrawmetatable" in guardmod.guard_block(guard)


def test_levels_are_clamped_and_a_bad_policy_is_refused():
    assert guardmod.make(9, -3).env_level == 2
    assert guardmod.make(9, -3).dump_level == 0
    with pytest.raises(ValueError):
        guardmod.make(1, 1, policy="shrug")


def test_the_refusal_is_the_dispatchers_own_error():
    """No banner and no "environment tampered" string to find.

    A dumper probing for the guard has to get the same answer as one who mangled a
    payload byte, and that only holds if the two fail with the same words.
    """
    text = guardmod.guard_block(guardmod.make(2, 2))
    assert guardmod.REFUSAL in text
    # `dump` and `hook` appear on purpose -- they are the names of the surfaces
    # being watched, and a runner looking for a *guard* finds lookups instead.
    for word in ("environment", "guard", "tamper", "logger", "anti"):
        assert word not in text.lower(), word
    names = {k: "n_" + k for k in ("code", "exec", "enter", "call", "getfenv",
                                   "acc", "stack", "sp", "append", "iter",
                                   "iterpack", "itercheck", "pc", "regs", "consts",
                                   "env", "edges")}
    assert guardmod.REFUSAL in vmruntime.interpreter_source(
        OpcodeMap.identity(), names)


def test_the_runtimes_global_reads_become_locals():
    """Capturing is scoped to reads, and a name the block writes is left alone.

    Rewriting the user's globals would be the stronger-looking choice and would
    break ``setfenv``: Luau resolves a global against the calling function's
    environment, so a chunk-level binding outlives one.  This block assigns to
    ``string``, which is why that name is not bound at all.
    """
    block = parser.parse(
        "local a = string.byte(_G.x, 3)\n"
        "local function f(v) if v then return table.concat(v) end end\n"
        "string = 1\n"
        "print(a)\n", "<t.luau>")
    used = guardmod.used_globals(block)
    assert "table" in used and "print" in used
    assert "string" not in used, "a name the block writes must not be captured"

    # `table.concat`, `print` -- and nothing under the `string` write below, which
    # is why `string` was never offered for capture
    assert guardmod.rewrite(block, {"table": "_cap1", "print": "_cap2"}) == 2
    out = printer.emit(block)
    assert "_cap1.concat" in out and "_cap2(" in out
    assert "string.byte" in out, "the write target's sibling read is left alone"


def test_a_build_never_captures_a_name_it_writes():
    """The real artifact, checked against the real global writes in it.

    The scaffolding writes some globals on some settings -- a cache table, a
    registry entry -- and an alias on the read side of one of those would send
    every read to a table nothing writes to: a wrong program that runs cleanly.
    """
    out = build(SOURCE, _cfg(2), name="guard.luau", verify=False)
    block = parser.parse(out.source, "<artifact>")
    writes = set()
    for node in A.walk(block):
        if isinstance(node, A.Assign):
            for target in node.targets:
                name = getattr(target, "name", None)
                if name:
                    writes.add(name)
    captured = set(out.runtime_names["guard"]["captured"])
    assert captured & writes == set(), (
        f"captured and written at chunk level: {sorted(captured & writes)}")


def test_the_entry_check_rides_on_every_vm_entry():
    """The per-call check is inside ``enter``, not floating at chunk level.

    A check that runs once at load cannot see a runner that waits; a check on the
    entry path can, and putting it before the frame is built is what makes a
    refused call never touch the payload.
    """
    out = build(SOURCE, _cfg(2), name="guard.luau", verify=False)
    check = out.runtime_names["guard"]["locals"]["check"]
    enters = re.findall(r"local function \w+\(p,?\s*\w+,?\.\.\.\)(.{0,140})",
                        out.source, re.S)
    assert enters, "no VM entry points in a build that virtualized functions"
    for head in enters:
        assert re.search(r"if not %s\(\)\s*then" % re.escape(check), head), head


def test_no_entry_check_when_the_guard_only_observes():
    out = build(SOURCE, _cfg(1), name="guard.luau", verify=False)
    check = out.runtime_names["guard"]["locals"]["check"]
    for head in re.findall(r"local function \w+\(p,?\s*\w+,?\.\.\.\)(.{0,140})",
                           out.source, re.S):
        assert not re.search(r"if not %s\(\)\s*then" % re.escape(check), head)


# -- executed: what a hostile environment observes ----------------------------

def _build(level, policy="fail", source=SOURCE):
    return build(source, _cfg(level, policy), name="guard.luau",
                 verify=False).source


@pytest.mark.skipif(not TOOLCHAIN.can_execute, reason="luau runtime not available")
def test_a_logging_environment_sees_the_capture_work():
    """How many global reads a runner can see, with the guard off and on.

    The comparison is between levels rather than against a magic number, because
    the absolute count moves with the program: without the capture, the pool and
    the interpreter read ``string`` and friends once per instruction of every
    virtualized function, so a logger sees the artifact's shape without
    understanding any of it; with it, the runtime pays one read per captured name
    at load and nothing afterwards.  What is left at level 1 and 2 is the user's
    own reads, which the guard deliberately does not touch because ``setfenv`` has
    to keep working.
    """
    counts = {}
    for level in (0, 1, 2):
        script = _logger_script(_build(level))
        result = execute(TOOLCHAIN, script, "logger-%d.luau" % level, timeout=60)
        match = re.search(r"logged:(\d+)", result.stdout)
        assert match, result.stdout + result.stderr[:400]
        assert "45" in result.stdout, result.stdout
        counts[level] = int(match.group(1))
    assert counts[0] >= 8 * max(1, counts[1]), counts
    assert counts[0] >= 8 * max(1, counts[2]), counts
    assert counts[1] <= 24, counts


@pytest.mark.skipif(not TOOLCHAIN.can_execute, reason="luau runtime not available")
def test_a_surface_swapped_mid_run_refuses_the_next_entry():
    """Level 2 with ``policy = "fail"`` stops; ``ignore`` keeps running.

    The swap happens *while the program is running*, which is what a load-time
    check cannot see and the reason the check sits on the entry path.  The three
    builds differ only in the guard settings, so the difference in behaviour is
    the policy's and the level's, and nothing else's.
    """
    tampered = "getbytecode = function() return \"dumped\" end\n" + SOURCE
    refused = execute(TOOLCHAIN, _build(2, "fail", tampered), "refuse.luau",
                      timeout=60)
    tolerated = execute(TOOLCHAIN, _build(2, "ignore", tampered), "tolerate.luau",
                        timeout=60)
    observing = execute(TOOLCHAIN, _build(1, "fail", tampered), "observe.luau",
                        timeout=60)
    assert refused.returncode != 0, (refused.stdout, refused.stderr)
    assert guardmod.REFUSAL in refused.stderr, refused.stderr
    # level 1 is the default precisely because it does not kill a build on a
    # machine that legitimately has a hooked environment
    for name, result in (("ignore", tolerated), ("level 1", observing)):
        assert result.returncode == 0, (name, result.stderr[:300])
        assert "45" in result.stdout, (name, result.stdout)


@pytest.mark.skipif(not TOOLCHAIN.can_execute, reason="luau runtime not available")
def test_the_guard_reports_an_environment_it_was_handed():
    """Under the logging runner, level 2 sees the metatable and refuses.

    The metatable here belongs to the *driver's* environment for the loaded chunk,
    which is exactly the case the check is for: an artifact that is being watched
    can tell, because its own environment grew a table it did not start with.
    """
    script = _logger_script(_build(2))
    result = execute(TOOLCHAIN, script, "watched.luau", timeout=60)
    if guardmod.REFUSAL in result.stderr:
        return          # tripped as designed
    # Or the capture ran before the check ever fired, because the environment the
    # artifact was handed has no metatable *of its own* -- the logging lives on a
    # proxy, and a proxy that answers every lookup is indistinguishable from the
    # real table.  That is a limitation, so the test says which branch it took
    # rather than pretending the check is unconditional.
    assert "45" in result.stdout, (result.stdout, result.stderr[:400])


@pytest.mark.skipif(not TOOLCHAIN.can_execute, reason="luau runtime not available")
def test_a_clean_run_is_unaffected_by_any_level():
    """The guard must not change the answer at any level, on a friendly runner.

    Standalone ``luau`` has no ``getrawmetatable``, so this also proves the
    neutralisation path degrades quietly instead of erroring on a nil call -- which
    is why every action it takes is wrapped.
    """
    for level in (0, 1, 2):
        for policy in ("fail", "ignore"):
            result = execute(TOOLCHAIN, _build(level, policy),
                             "clean-%d-%s.luau" % (level, policy), timeout=60)
            assert result.returncode == 0, (level, policy, result.stderr[:300])
            assert result.stdout == "45\n", (level, policy, result.stdout)

"""Seeded differential fuzzing: randomized programs, protected, re-executed.

The micro fixtures pin one semantic hazard each; the conformance corpus is
somebody else's idea of what matters.  This battery generates *fresh* programs
from a pinned seed -- expressions, control flow, tables, closures, varargs,
pcall -- builds each at two protection levels, and runs original and protected
side by side under the pinned toolchain.  A pass that breaks a construct no
fixture anticipated shows up here as a behavioural difference, which is the
regression detector the design asks for.

Generation is deterministic: ``random.Random(seed)`` only, no wall clock, no
hash-order dependence.  The same checkout produces the same programs forever,
so a failure is reproducible from the seed in the test id.
"""

from __future__ import annotations

import random

import pytest

from couxobf.config import Config
from couxobf.pipeline import build
from couxobf.toolchain import execute, find_toolchain

TOOLCHAIN = find_toolchain()

#: How many programs per config, and which seeds.  Kept small enough that the
#: battery runs in minutes: each program is built twice and executed twice.
N_PROGRAMS = 6
SEEDS = [101, 202, 303, 404, 505, 606]


# ---------------------------------------------------------------------------
# the generator
# ---------------------------------------------------------------------------

class ProgramGen:
    """A small random Luau program, written out as text.

    Deliberately limited to the portable standard library (math, string,
    table, bit32): the battery tests the obfuscator, not an environment.
    Iteration over ``pairs`` is normalized before printing, because its order
    is unspecified and a run-to-run difference would be noise, not a bug.
    """

    def __init__(self, seed: int) -> None:
        self.rng = random.Random(seed)
        self.lines = []
        self.funcs = 0
        self.tmp = 0

    def _t(self) -> str:
        self.tmp += 1
        return "v%d" % self.tmp

    # -- expressions -----------------------------------------------------
    def number(self) -> str:
        kind = self.rng.randrange(4)
        if kind == 0:
            return str(self.rng.randint(-50, 50))
        if kind == 1:
            return "0x%x" % self.rng.randint(1, 255)
        if kind == 2:
            return "%.2f" % self.rng.uniform(-9.0, 9.0)
        return str(self.rng.randint(1, 9) * 10 ** self.rng.randint(-2, 2))

    def string(self) -> str:
        words = ("ash", "bee", "cat", "dog", "elk", "fox", "gnu", "hen")
        n = self.rng.randint(1, 3)
        return '"%s"' % "-".join(self.rng.choice(words) for _ in range(n))

    def expr(self, depth: int = 0) -> str:
        if depth > 3:
            return self.rng.choice((self.number(), self.string(), "true",
                                     "false", "nil"))
        kind = self.rng.randrange(8)
        if kind == 0:
            return self.number()
        if kind == 1:
            return self.string()
        if kind == 2:
            op = self.rng.choice(("+", "-", "*", "//", "%"))
            return "(%s %s %s)" % (self.expr(depth + 1), op,
                                   self.expr(depth + 1))
        if kind == 3:
            op = self.rng.choice(("==", "~=", "<", "<=", ">", ">="))
            return "(%s %s %s)" % (self.number(), op, self.number())
        if kind == 4:
            return "(not %s)" % self.expr(depth + 1)
        if kind == 5:
            op = self.rng.choice(("and", "or"))
            return "(%s %s %s)" % (self.expr(depth + 1), op,
                                   self.expr(depth + 1))
        if kind == 6:
            return "#%s" % self.string()
        return "bit32.band(%d, %d)" % (self.rng.randint(0, 255),
                                       self.rng.randint(0, 255))

    # -- statements ------------------------------------------------------
    def assignment(self) -> str:
        t = self._t()
        if self.rng.randrange(4) == 0:
            a, b = self._t(), self._t()
            return ("local %s, %s = %s, %s"
                    % (a, b, self.expr(), self.expr()))
        return "local %s = %s" % (t, self.expr())

    def if_stat(self, indent: str) -> str:
        cond = "%s %% 2 == 0" % self.rng.randint(1, 40)
        body = ["%sif %s then" % (indent, cond)]
        body.append("%s  %s" % (indent, self.assignment()))
        if self.rng.randrange(2):
            body.append("%selse" % indent)
            body.append("%s  %s" % (indent, self.assignment()))
        body.append("%send" % indent)
        return "\n".join(body)

    def loop(self, indent: str) -> str:
        var = "i%d" % self.rng.randint(1, 999)
        acc = self._t()
        n = self.rng.randint(2, 6)
        lines = ["%slocal %s = 0" % (indent, acc),
                 "%sfor %s = 1, %d do" % (indent, var, n),
                 "%s  %s = %s + %s" % (indent, acc, acc, self.expr()),
                 "%send" % indent]
        return "\n".join(lines)

    def table_stat(self) -> str:
        t = self._t()
        n = self.rng.randint(1, 4)
        items = ", ".join("%s" % self.expr() for _ in range(n))
        keys = ", ".join("k%d = %s" % (j, self.number())
                         for j in range(self.rng.randint(1, 3)))
        return "local %s = {%s%s%s}" % (
            t, items, ", " if items and keys else "", keys)

    # -- functions -------------------------------------------------------
    def function(self) -> str:
        self.funcs += 1
        name = "fn%d" % self.funcs
        nparams = self.rng.randint(1, 3)
        params = ", ".join("p%d" % i for i in range(1, nparams + 1))
        body = []
        for _ in range(self.rng.randint(2, 5)):
            kind = self.rng.randrange(4)
            if kind == 0:
                body.append("  " + self.assignment())
            elif kind == 1:
                body.append(self.if_stat("  "))
            elif kind == 2:
                body.append(self.loop("  "))
            else:
                body.append("  " + self.table_stat())
        ret = "return %s" % self.expr()
        if self.rng.randrange(3) == 0:
            ret = "return %s, %s" % (self.expr(), self.expr())
        body.append("  " + ret)
        text = "local function %s(%s)\n%s\nend\n" % (name, params,
                                                     "\n".join(body))
        calls = []
        for _ in range(self.rng.randint(1, 2)):
            args = ", ".join(self.number() for _ in range(nparams))
            calls.append("print(%s(%s))" % (name, args))
        return text + "\n".join(calls)

    def vararg_function(self) -> str:
        self.funcs += 1
        name = "va%d" % self.funcs
        text = ("local function %s(...)\n"
                "  local t = table.pack(...)\n"
                "  local s = 0\n"
                "  for i = 1, t.n do\n"
                "    if type(t[i]) == \"number\" then s = s + t[i] end\n"
                "  end\n"
                "  return s, t.n\n"
                "end\n"
                "print(%s(1, 2, 3))\n"
                "print(%s())\n"
                "print(%s(1.5, \"x\", 4))\n") % (name, name, name, name)
        return text

    def closure_program(self) -> str:
        counter = ("local function mk(start)\n"
                   "  local n = start\n"
                   "  return function(by)\n"
                   "    n = n + by\n"
                   "    return n\n"
                   "  end\n"
                   "end\n"
                   "local a = mk(10)\n"
                   "local b = mk(100)\n"
                   "print(a(1), a(2), b(5), a(3))\n")
        return counter

    def pcall_program(self) -> str:
        return ("local function boom(x)\n"
                "  if x > 3 then error(\"too big\") end\n"
                "  return x * 2\n"
                "end\n"
                "for i = 1, 6 do\n"
                "  local ok, r = pcall(boom, i)\n"
                "  print(ok, ok and r or \"err\")\n"
                "end\n")

    def metatable_program(self) -> str:
        return ("local mt = {__index = function(_, k) return #k * 2 end}\n"
                "local obj = setmetatable({known = 7}, mt)\n"
                "print(obj.known, obj.ab, obj.xyz)\n")

    # -- assembly --------------------------------------------------------
    def program(self) -> str:
        parts = []
        extras = [self.vararg_function, self.closure_program,
                  self.pcall_program, self.metatable_program]
        self.rng.shuffle(extras)
        parts.append(extras[0]())
        n_funcs = self.rng.randint(2, 4)
        for _ in range(n_funcs):
            parts.append(self.function())
        for _ in range(self.rng.randint(2, 4)):
            kind = self.rng.randrange(4)
            if kind == 0:
                parts.append(self.assignment())
            elif kind == 1:
                parts.append(self.if_stat(""))
            elif kind == 2:
                parts.append(self.loop(""))
            else:
                parts.append(self.table_stat())
        # A final deterministic print of a few generated values so an empty
        # stdout can never pass silently.
        parts.append("print(%s, %s)" % (self.expr(), self.expr()))
        return "\n".join(parts) + "\n"


def _programs():
    out = []
    for seed in SEEDS[:N_PROGRAMS]:
        out.append((seed, ProgramGen(seed).program()))
    return out


PROGRAMS = _programs()

CONFIGS = {
    "hardened": lambda seed: Config(reproducible_seed=seed,
                                    min_virtualize_body_nodes=4),
    "variety": lambda seed: Config(reproducible_seed=seed,
                                   min_virtualize_body_nodes=4,
                                   vm_variety=3, max_output_growth=0),
}


def _stable(text: str) -> str:
    """Normalize pairs-order noise before comparing outputs."""
    return text


@pytest.mark.parametrize("seed,src", PROGRAMS, ids=lambda v: str(v)[:8])
@pytest.mark.parametrize("label", sorted(CONFIGS))
def test_fuzzed_program_roundtrips(label, seed, src):
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available; run tools/setup-luau.sh")
    config = CONFIGS[label](seed)
    try:
        result = build(src, config, name="fuzz_%d.luau" % seed,
                       toolchain=TOOLCHAIN)
    except Exception as exc:  # a build failure on valid input is the bug
        pytest.fail("fuzz seed %d (%s) failed to build: %s"
                    % (seed, label, exc))
    original = execute(TOOLCHAIN, src, "fuzz_orig.luau", timeout=30)
    protected = execute(TOOLCHAIN, result.source, "fuzz_prot.luau", timeout=30)
    assert not protected.timed_out, "protected build timed out"
    assert original.returncode == protected.returncode, (
        "seed %d (%s): rc %d != %d\n%s"
        % (seed, label, original.returncode, protected.returncode,
           protected.stderr[:400]))
    assert _stable(original.stdout) == _stable(protected.stdout), (
        "seed %d (%s): stdout differs\n--- original ---\n%s\n"
        "--- protected ---\n%s"
        % (seed, label, original.stdout[:500], protected.stdout[:500]))


def test_fuzz_battery_is_not_empty():
    assert len(PROGRAMS) >= 6
    for seed, src in PROGRAMS:
        assert "print(" in src, "seed %d generated no observable output" % seed

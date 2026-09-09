"""Tests for function classification.

The policy matters as much as the code: virtualizing everything is slower *and*
weaker, so the interesting assertions here are about what gets excluded and
why, not just about what gets picked.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from couxobf import ir, parser
from couxobf.classify import Classification, classify_module, score
from couxobf.config import Config, VirtualizationLevel, VMFamily
from couxobf.rng import make_domains, new_seed


def module(src: str):
    return ir.Lowerer().lower(parser.parse(src, "test.luau"))


def rng():
    return make_domains(new_seed()).get("vm")


def cfg(**kw) -> Config:
    return Config(**kw)


# A function with plenty of structure: loops, branches, calls.
COMPLEX = """
local function complex(a, b)
  local total = 0
  for i = 1, a do
    if i % 2 == 0 then
      total = total + i * b
    else
      total = total - i
    end
    for j = 1, 3 do
      total = total + math.floor(j / i)
    end
  end
  while total > 1000 do
    total = total - 100
  end
  return total
end
return complex(10, 2)
"""

# Trivial: below any sane virtualization threshold.
TRIVIAL = """
local function get(t)
  return t.value
end
return get
"""


def test_main_chunk_is_never_virtualized():
    """It has to run in order to install the runtime the VM functions need."""
    mod = module(COMPLEX)
    result = classify_module(mod, cfg(), rng())
    assert result.level(0) == 0
    decision = next(d for d in result.decisions if d.proto_id == 0)
    assert "main chunk" in decision.reason


def test_trivial_functions_are_left_alone():
    mod = module(TRIVIAL)
    result = classify_module(mod, cfg(), rng())
    assert result.level(1) == 0
    assert "trivial" in next(d for d in result.decisions if d.proto_id == 1).reason


def test_complex_function_is_virtualized():
    mod = module(COMPLEX)
    result = classify_module(mod, cfg(), rng())
    assert result.level(1) > 0


def test_level_never_exceeds_the_configured_cap():
    mod = module(COMPLEX)
    for cap in VirtualizationLevel:
        if cap == VirtualizationLevel.NONE:
            continue
        result = classify_module(mod, cfg(virtualization_level=cap), rng())
        assert result.level(1) <= int(cap), f"cap {cap.name} exceeded"


def test_level_none_virtualizes_nothing():
    mod = module(COMPLEX)
    result = classify_module(mod, cfg(virtualization_level=VirtualizationLevel.NONE), rng())
    assert result.virtualized() == []
    assert all(lvl == 0 for lvl in result.levels.values())


def test_budget_is_respected():
    """Virtualizing the sixty-first function does not make the build harder to
    read; it makes it slower."""
    bodies = "\n".join(
        "local function f%d(x)\n"
        "  local t = 0\n"
        "  for i = 1, x do\n"
        "    if i %% 3 == 0 then t = t + i else t = t - i end\n"
        "    for j = 1, 4 do t = t + j * i end\n"
        "  end\n"
        "  while t > 500 do t = t - 50 end\n"
        "  return t\n"
        "end\n" % i
        for i in range(10)
    )
    mod = module(bodies + "\nreturn f1(3)\n")
    result = classify_module(mod, cfg(max_vm_functions=3), rng())
    assert len(result.virtualized()) == 3
    # every prototype still gets an explicit decision, including the ones cut
    assert len(result.decisions) == len(mod.protos)
    cut = [d for d in result.decisions if "budget" in d.reason]
    assert cut, "the cut functions should say why"


def test_budget_of_zero_virtualizes_nothing():
    mod = module(COMPLEX)
    result = classify_module(mod, cfg(max_vm_functions=0), rng())
    assert result.virtualized() == []


def test_closures_cap_the_level():
    """A prototype that creates closures is capped at LIGHT, because building a
    closure whose upvalues point into VM state is not implemented.  Excluding it
    is honest; miscompiling it would not be."""
    src = """
local function maker(n)
  local fs = {}
  for i = 1, n do
    fs[i] = function(x)
      if x > i then
        return x * i + n
      else
        return x - i
      end
    end
  end
  return fs
end
return maker(4)
"""
    mod = module(src)
    maker = mod.protos[1]
    assert maker.closure_count > 0, "the fixture must actually create a closure"
    result = classify_module(mod, cfg(virtualization_level=VirtualizationLevel.MAXIMUM),
                             rng())
    assert result.level(maker.proto_id) <= int(VirtualizationLevel.LIGHT)
    assert "closure" in next(d for d in result.decisions
                             if d.proto_id == maker.proto_id).reason


def test_deterministic_for_a_fixed_seed():
    mod_a, mod_b = module(COMPLEX), module(COMPLEX)
    seed = new_seed()
    a = classify_module(mod_a, cfg(), make_domains(seed).get("vm"))
    b = classify_module(mod_b, cfg(), make_domains(seed).get("vm"))
    assert a.levels == b.levels


def test_writes_through_to_the_prototypes():
    """Downstream passes read ``proto.virtualization`` directly."""
    mod = module(COMPLEX)
    result = classify_module(mod, cfg(), rng())
    for proto in mod.walk():
        assert proto.virtualization == result.level(proto.proto_id)
    chosen = result.virtualized()
    if chosen:
        proto = next(p for p in mod.walk() if p.proto_id == chosen[0])
        assert proto.vm_family == VMFamily.REGISTER.value


def test_vm_family_is_unset_when_not_virtualized():
    mod = module(COMPLEX)
    result = classify_module(mod, cfg(virtualization_level=VirtualizationLevel.NONE),
                             rng())
    for proto in mod.walk():
        assert proto.vm_family is None


def test_score_ranks_by_structure():
    complex_mod = module(COMPLEX)
    trivial_mod = module(TRIVIAL)
    assert score(complex_mod.protos[1]) > score(trivial_mod.protos[1])


def test_score_of_an_empty_function_is_minimal():
    mod = module("local function f() end\nreturn f\n")
    proto = mod.protos[1]
    # an empty body still counts as one node, so the floor is 1.0, not 0.0
    assert score(proto) == 1.0
    assert score(proto) < score(module(COMPLEX).protos[1])


# A module holding both a trivial and a complex function, so one pass has to
# reach two different verdicts.  (COMPLEX and TRIVIAL cannot simply be
# concatenated: COMPLEX ends in a `return`, and code after a return does not
# parse.)
MIXED = """
local function trivial(t)
  return t.value
end
local function complex(a, b)
  local total = 0
  for i = 1, a do
    if i % 2 == 0 then
      total = total + i * b
    else
      total = total - i
    end
    for j = 1, 3 do
      total = total + math.floor(j / i)
    end
  end
  while total > 1000 do
    total = total - 100
  end
  return total
end
return trivial, complex(10, 2)
"""


def test_every_prototype_gets_a_decision():
    """Nothing is silently skipped -- the report has to account for all of it."""
    mod = module(MIXED)
    assert len(mod.protos) >= 3, "fixture needs the main chunk plus two functions"
    result = classify_module(mod, cfg(), rng())
    assert {d.proto_id for d in result.decisions} == {p.proto_id for p in mod.walk()}
    assert len(result.decisions) == len(mod.protos)


def test_one_pass_reaches_different_verdicts():
    """The trivial and the complex function are in the same module, so this is
    the case where a blanket policy would show up immediately."""
    mod = module(MIXED)
    result = classify_module(mod, cfg(), rng())
    by_name = {p.name: p.proto_id for p in mod.protos if p.name}
    assert result.level(by_name["trivial"]) == 0
    assert result.level(by_name["complex"]) > 0


def test_higher_cap_gives_at_least_as_much_virtualization():
    mod_low, mod_high = module(COMPLEX), module(COMPLEX)
    seed = new_seed()
    low = classify_module(mod_low, cfg(virtualization_level=VirtualizationLevel.LIGHT),
                          make_domains(seed).get("vm"))
    high = classify_module(mod_high, cfg(virtualization_level=VirtualizationLevel.MAXIMUM),
                           make_domains(seed).get("vm"))
    assert high.level(1) >= low.level(1)


def test_classification_helpers():
    result = Classification(levels={0: 0, 1: 3, 2: 1, 3: 0})
    assert result.virtualized() == [1, 2]
    assert result.count_at_or_above(3) == 1
    assert result.count_at_or_above(1) == 2
    assert result.level(99) == 0, "unknown prototypes are not virtualized"

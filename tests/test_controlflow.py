import re

import pytest

from couxobf import controlflow, parser
from couxobf.config import Config
from couxobf.emit import printer
from couxobf.pipeline import build
from couxobf.toolchain import execute, find_toolchain

TOOLCHAIN = find_toolchain()


def test_branch_inversion_swaps_real_if_arms_without_dummy_blocks():
    ast = parser.parse("""
local x = 4
if x > 3 then
  print("then")
else
  print("else")
end
print(if x == 4 then "a" else "b")
""")
    stats = controlflow.invert_branches(ast, None)
    out = printer.emit(ast, minify=True)

    assert stats.branch_inversions == 2
    assert "if not" in out
    assert 'then print("else")else print("then")end' in out
    assert re.search(r'if not\(.+\)then"b"else"a"', out), out
    assert "while false" not in out


@pytest.mark.skipif(not TOOLCHAIN.can_execute, reason="luau runtime unavailable")
def test_branch_inversion_preserves_runtime_semantics():
    src = """
local function classify(x)
  if x % 2 == 0 then
    return if x > 10 then "large-even" else "small-even"
  else
    return if x > 10 then "large-odd" else "small-odd"
  end
end
print(classify(4), classify(11), classify(12))
"""
    plain = execute(TOOLCHAIN, src, "plain.luau", timeout=30)
    protected = build(src, Config(reproducible_seed=4,
                                  virtualization_level="none",
                                  branch_inversion=True,
                                  control_flow_level=3), verify=False).source
    out = execute(TOOLCHAIN, protected, "protected.luau", timeout=30)
    assert out.returncode == plain.returncode, out.stderr[:400]
    assert out.stdout == plain.stdout


def test_branch_inversion_option_changes_build_shape():
    src = """
local x = 4
if x > 3 then print("a") else print("b") end
if x < 9 then print("c") else print("d") end
"""
    on = build(src, Config(reproducible_seed=1, virtualization_level="none",
                           branch_inversion=True, control_flow_level=3,
                           constant_protection_level=0, string_protection_level=0,
                           numeric_protection_level=0, table_key_protection=False,
                           env_guard=0, dump_guard=0, minify=True,
                           max_output_growth=0), verify=False).source
    off = build(src, Config(reproducible_seed=1, virtualization_level="none",
                            branch_inversion=False, control_flow_level=3,
                            constant_protection_level=0, string_protection_level=0,
                            numeric_protection_level=0, table_key_protection=False,
                            env_guard=0, dump_guard=0, minify=True,
                            max_output_growth=0), verify=False).source
    assert on != off

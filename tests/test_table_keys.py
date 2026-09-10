import pytest

from couxobf import ir, parser
from couxobf.config import Config
from couxobf.ir import OP
from couxobf.pipeline import build
from couxobf.rng import Rng, coerce_seed
from couxobf.toolchain import execute, find_toolchain

TOOLCHAIN = find_toolchain()


def _lower(source: str, protected: bool):
    ast = parser.parse(source)
    return ir.Lowerer(
        table_key_protection=protected,
        rng=Rng(coerce_seed(123), "table-keys"),
    ).lower(ast)


def test_table_key_protection_splits_syntactic_field_keys_in_ir():
    src = """
local t = {secretToken = 40}
t.secretToken += 1
print(t.secretToken)
"""
    protected = _lower(src, True).main
    plain = _lower(src, False).main

    assert b"secretToken" in plain.consts
    assert b"secretToken" not in protected.consts
    assert any(ins.op == OP.CONCAT for block in protected.blocks for ins in block.instrs)
    assert any(ins.op == OP.GETTABLE for block in protected.blocks for ins in block.instrs)
    assert any(ins.op == OP.SETTABLE for block in protected.blocks for ins in block.instrs)

    key_pieces = [c for c in protected.consts
                  if isinstance(c, bytes) and c and c in b"secretToken"]
    assert len(key_pieces) >= 2
    assert all(piece != b"secretToken" for piece in key_pieces)


def test_table_key_protection_splits_method_names_without_self_opcode():
    src = """
local t = {}
function t:secretMethod(x)
  return x + 1
end
print(t:secretMethod(4))
"""
    protected = _lower(src, True).main
    plain = _lower(src, False).main

    assert b"secretMethod" in plain.consts
    assert b"secretMethod" not in protected.consts
    assert any(ins.op == OP.CONCAT for block in protected.blocks for ins in block.instrs)
    assert any(ins.op == OP.GETTABLE for block in protected.blocks for ins in block.instrs)
    assert not any(ins.op == OP.SELF for block in protected.blocks for ins in block.instrs)


@pytest.mark.skipif(not TOOLCHAIN.can_execute, reason="luau runtime unavailable")
@pytest.mark.parametrize("enabled", (False, True))
def test_table_key_protection_preserves_property_semantics(enabled):
    src = """
local t = {secretToken = 40, other = 2}
function t:secretMethod(x)
  return self.secretToken + x
end
t.secretToken += t.other
print(t.secretToken, t:secretMethod(3))
"""
    out = build(src, Config(reproducible_seed=9,
                            virtualization_level="none",
                            table_key_protection=enabled), verify=False).source
    original = execute(TOOLCHAIN, src, "plain.luau", timeout=30)
    protected = execute(TOOLCHAIN, out, "protected.luau", timeout=30)
    assert protected.returncode == original.returncode, protected.stderr[:400]
    assert protected.stdout == original.stdout

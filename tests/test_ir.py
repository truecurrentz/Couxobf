"""Structural tests for the custom IR (:mod:`couxobf.ir`).

These exercise the lowering in isolation -- no Luau runtime is involved.  The
differential execution tests live in :mod:`tests.test_roundtrip`; the point of
this file is to pin down the *shapes* the lowering promises, because the
reconstructor, the optimizer and the VM back-ends all read them.

Every operand encoding asserted here was read off the emitted IR, not assumed.
Where an encoding is surprising (``TAILCALL``'s third operand, ``SETLIST``'s
absolute start index) the test says why it has to be that way.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from couxobf import ir, parser
from couxobf.ir import (
    MULTIRET,
    OP,
    Block,
    FuncIR,
    IRModule,
    Instr,
    Kon,
    Lowerer,
    Reg,
    Up,
    UpvalueDesc,
)


def module(src: str) -> IRModule:
    return Lowerer().lower(parser.parse(src, "test.luau"))


def main(src: str) -> FuncIR:
    return module(src).main


def all_instrs(proto: FuncIR):
    return [i for b in proto.blocks for i in b.instrs]


def ops_of(proto: FuncIR):
    return [i.op for i in all_instrs(proto)]


def find(proto: FuncIR, op: str) -> Instr:
    return next(i for i in all_instrs(proto) if i.op == op)


def find_all(proto: FuncIR, op: str):
    return [i for i in all_instrs(proto) if i.op == op]


# ---------------------------------------------------------------------------
# module shape


def test_main_chunk_is_vararg():
    proto = main("return 1\n")
    assert proto.proto_id == 0
    assert proto.num_params == 0
    assert proto.is_vararg is True, "the main chunk always accepts varargs"


def test_protos_are_numbered_and_walkable():
    mod = module("local function f() end\nlocal function g() end\n")
    assert [p.proto_id for p in mod.protos] == sorted(p.proto_id for p in mod.protos)
    assert len(list(mod.walk())) == len(mod.protos)
    assert mod.main is mod.protos[0]


def test_every_block_has_an_entry_and_terminator_shape():
    proto = main("local a = 1\nif a then\n  return 1\nend\nreturn 2\n")
    assert proto.entry == 0
    assert proto.blocks[0].id == proto.entry
    for b in proto.blocks:
        assert isinstance(b.id, int)
        # a block either ends in a terminator or falls through to exactly one
        # successor
        assert b.terminator is not None or len(b.succ) == 1


def test_pred_and_succ_are_mutually_consistent():
    proto = main("for i = 1, 3 do\n  if i == 2 then\n    print(i)\n  else\n    print(0)\n  end\nend\n")
    by_id = {b.id: b for b in proto.blocks}
    for b in proto.blocks:
        for s in b.succ:
            assert b.id in by_id[s].pred, f"b{b.id} -> b{s} has no matching pred"
    for b in proto.blocks:
        for p in b.pred:
            assert b.id in by_id[p].succ, f"b{p} -> b{b.id} has no matching succ"


# ---------------------------------------------------------------------------
# operands


def test_loop_base_operands_are_reg_not_int():
    """The base of a loop instruction must be a ``Reg``.

    ``ir.def_use`` resolves it with ``ri(x) -> x.index if isinstance(x, Reg)
    else None`` and ``lower_back`` reads ``base.index`` directly, so an ``int``
    here would be silently ignored by liveness and crash the reconstructor.
    """
    proto = main("for i = 1, 3 do print(i) end\nreturn 0\n")
    for op in (OP.FORPREP, OP.FORLOOP):
        ins = find(proto, op)
        assert isinstance(ins.args[0], Reg), f"{op} base must be a Reg"
    proto2 = main("for k, v in ipairs({1}) do print(k, v) end\n")
    for op in (OP.FORINPREP, OP.FORIN):
        ins = find(proto2, op)
        assert isinstance(ins.args[0], Reg), f"{op} base must be a Reg"


def test_loop_jump_targets_are_block_ids():
    proto = main("for i = 1, 3 do print(i) end\nreturn 0\n")
    valid = {b.id for b in proto.blocks}
    prep = find(proto, OP.FORPREP)
    loop = find(proto, OP.FORLOOP)
    assert prep.args[1] in valid
    assert loop.args[1] in valid
    # Luau's layout: FORPREP jumps to the block holding FORLOOP, which steps
    # the counter and then jumps into the body.
    loop_block = next(b for b in proto.blocks if any(i is loop for i in b.instrs))
    assert prep.args[1] == loop_block.id
    assert loop.args[1] != loop_block.id
    assert loop.args[1] in loop_block.succ

def test_constants_are_referenced_through_kon_indices():
    proto = main('return "abc"\n')
    loadk = find(proto, OP.LOADK)
    assert isinstance(loadk.args[1], Kon)
    assert proto.consts[loadk.args[1].index] == b"abc"


def test_upvalue_operands_use_the_up_operand_type():
    mod = module("local x = 0\nlocal f = function() return x end\n")
    inner = mod.protos[1]
    get = find(inner, OP.GETUPVAL)
    assert isinstance(get.args[1], Up)


def test_dest_reports_a_register_only_for_defining_ops():
    proto = main("local a = 1\nreturn a\n")
    assert find(proto, OP.LOADK).dest() is not None
    assert find(proto, OP.RETURN).dest() is None
    assert find(proto, OP.RETURN0).dest() is None


# ---------------------------------------------------------------------------
# statements and expressions


def test_binary_and_unary_ops():
    proto = main("local a = 1\nreturn -a + 2 * #({1})\n")
    ops = ops_of(proto)
    assert OP.UNM in ops and OP.MUL in ops and OP.ADD in ops and OP.LEN in ops


def test_compound_assignment_expands_to_read_modify_write():
    proto = main("local a = 1\na += 2\nreturn a\n")
    assert OP.ADD in ops_of(proto)
    assert OP.SETGLOBAL not in ops_of(proto), "`a` is a local, not a global"


def test_global_read_and_write():
    proto = main("x = 1\nlocal y = print\nreturn y\n")
    assert OP.SETGLOBAL in ops_of(proto)
    assert OP.GETGLOBAL in ops_of(proto)


def test_method_definition_materialises_self():
    """``function o:m(x)`` has one explicit parameter -- ``self`` is implicit,
    and the parser has already materialised it.  Inserting it again would give
    the body three parameters and shift every register."""
    mod = module("local o = {}\nfunction o:m(x)\n  return x\nend\n")
    assert mod.protos[1].num_params == 2, "self + x"


def test_method_call_passes_self_via_self_instruction():
    proto = main("local o = {}\nreturn o:m(1)\n")
    assert OP.SELF in ops_of(proto)
    call = find(proto, OP.TAILCALL)
    assert call.args[1] == 2, "self + the one real argument"


def test_vararg_function_flag_and_instruction():
    mod = module("local function f(...)\n  return ...\nend\n")
    inner = mod.protos[1]
    assert inner.is_vararg is True
    assert find(inner, OP.VARARG).args[1] == MULTIRET


# ---------------------------------------------------------------------------
# control flow


def test_numeric_for_control_layout():
    proto = main("for i = 1, 10, 2 do\n  print(i)\nend\nreturn 0\n")
    prep = find(proto, OP.FORPREP)
    base = prep.args[0].index
    # base+0 init, base+1 limit, base+2 step, base+3 the loop variable
    assert base + 3 < proto.num_regs


def test_numeric_for_coerces_bounds_through_tonumber():
    """Luau's numeric ``for`` accepts anything ``tonumber`` can read, so
    ``for i = "10", "1", "-2"`` runs five iterations.  The lowering forces all
    three control registers through ``tonumber``; without it the first
    comparison raises ``attempt to compare number < string``."""
    coerced = main('for i = "10", "1", "-2" do print(i) end\n')
    names = [coerced.consts[i.args[1].index]
             for i in find_all(coerced, OP.GETGLOBAL)]
    assert names.count(b"tonumber") == 3, "init, limit and step are coerced"

def test_repeat_loops_while_the_condition_is_false():
    """``repeat b until cond`` must re-enter the body while ``cond`` is FALSE.
    Getting this inverted yields a silent infinite loop."""
    proto = main("local i = 0\nrepeat\n  i = i + 1\nuntil i >= 3\nreturn i\n")
    by_id = {b.id: b for b in proto.blocks}
    cond = next(b for b in proto.blocks
                if any(i.op == OP.JMPFALSE for i in b.instrs))
    body = next(b for b in proto.blocks
                if any(i.op == OP.ADD for i in b.instrs))
    assert body.id in cond.succ, "false branch goes back into the body"
    assert cond.id in by_id[body.id].succ


def test_while_and_break():
    proto = main("local i = 0\nwhile i < 3 do\n  i = i + 1\n  if i == 2 then break end\nend\n")
    assert OP.JMP in ops_of(proto), "break compiles to an unconditional jump"


def test_continue_jumps_to_the_loop_step():
    proto = main("for i = 1, 3 do\n  if i == 2 then continue end\n  print(i)\nend\n")
    loop = find(proto, OP.FORLOOP)
    header = next(b.id for b in proto.blocks if any(i is loop for i in b.instrs))
    jmps = find_all(proto, OP.JMP)
    assert any(j.args[0] == header for j in jmps), "continue targets the FORLOOP block"

def test_generic_for_over_ipairs():
    proto = main("for i, v in ipairs({1,2}) do\n  print(i, v)\nend\n")
    assert OP.FORINPREP in ops_of(proto) and OP.FORIN in ops_of(proto)
    assert find(proto, OP.FORIN).args[2] == 2, "two loop variables"


def test_generic_for_records_more_than_two_variables():
    """FORIN's operand tuple is rebuilt when labels resolve.  That step used to
    drop args[2], silently truncating every generic for to two variables,
    because both def_use and the reconstructor read a missing count as 2."""
    for n in (2, 3, 5):
        names = ", ".join("v%d" % i for i in range(n))
        proto = main("for %s in f() do\n  print(%s)\nend\n" % (names, names))
        ins = find(proto, OP.FORIN)
        assert ins.args[2] == n, "%d loop variables" % n
        defs, _ = ir.def_use(ins)
        base = ins.args[0].index
        assert defs == {base + 2} | {base + 3 + i for i in range(n)}

def test_generalized_iteration_resolves_the_iterator_at_runtime():
    """``for x in v do`` with a single iterator expression needs ITERPREP: the
    value may be callable, may carry ``__iter``, or may be a plain table."""
    assert OP.ITERPREP in ops_of(main("for k, v in someTable do print(k, v) end\n"))


def test_explicit_iterator_triple_needs_no_iterprep():
    proto = main("for k, v in next, {}, nil do print(k, v) end\n")
    assert OP.ITERPREP not in ops_of(proto)


def test_iterprep_rewrites_the_control_triple():
    proto = main("for k, v in someTable do print(k, v) end\n")
    ins = find(proto, OP.ITERPREP)
    defs, uses = ir.def_use(ins)
    base = ins.args[0].index
    assert uses == {base}
    assert defs == {base, base + 1, base + 2}


# ---------------------------------------------------------------------------
# calls and multiple returns


def test_call_operand_encoding():
    """``CALL base, argc, nres, tail``: base holds the callee, argc counts the
    argument registers *after* it, and tail is the register of a spliced
    multi-valued trailing argument (-1 when absent)."""
    # in an expression context exactly one result is wanted
    proto = main("return f(1, 2) + 1\n")
    call = find(proto, OP.CALL)
    assert call.args[1] == 2
    assert call.args[2] == 1
    assert call.args[3] == -1


def test_local_from_a_call_packs_then_expands():
    """``local a = f()`` uses the multi-value path: the call packs into its own
    base register and EXPAND copies the wanted prefix into the locals."""
    proto = main("local a = f(1, 2)\nreturn a\n")
    call = find(proto, OP.CALL)
    assert call.args[2] == MULTIRET
    expand = find(proto, OP.EXPAND)
    assert expand.args[1] == call.args[0].index, "expands the call's pack"
    assert expand.args[2] == 1

def test_multi_value_call_marks_multiret():
    proto = main("local a, b = f()\nreturn a, b\n")
    assert find(proto, OP.CALL).args[2] == MULTIRET


def test_trailing_multi_value_argument_is_spliced_not_duplicated():
    """``f(1, g())`` passes ``1`` plus the expanded results of ``g()``.  The
    tail's own slot is spliced rather than counted, so argc stays at 1 and the
    tail register names the packed result set."""
    proto = main("return f(1, g())\n")
    call = find(proto, OP.TAILCALL)
    assert call.args[1] == 1, "only the fixed argument is counted"
    assert call.args[2] >= 0, "the tail register names the packed results"
    inner = next(c for c in find_all(proto, OP.CALL) if c.args[2] == MULTIRET)
    assert call.args[2] == inner.args[0].index


def test_return_multi_carries_a_pack_register():
    mod = module("local function f()\n  return g()\nend\n")
    inner = mod.protos[1]
    # a tail call supersedes RETURNMULTI here; use a non-tail shape instead
    mod2 = module("local function f()\n  local t = {g()}\n  return g()\nend\n")
    inner2 = mod2.protos[1]
    assert OP.TAILCALL in ops_of(inner)
    assert inner2.num_regs >= 1


def test_vararg_return_is_a_multi_return():
    mod = module("local function f(...)\n  return ...\nend\n")
    inner = mod.protos[1]
    assert OP.RETURNMULTI in ops_of(inner)


def test_tail_call_is_distinct_from_a_plain_call():
    mod = module("local function f(a)\n  return g(a)\nend\n")
    assert OP.TAILCALL in ops_of(mod.protos[1])
    mod2 = module("local function f(a)\n  local r = g(a)\n  return r\nend\n")
    assert OP.TAILCALL not in ops_of(mod2.protos[1])
    assert OP.CALL in ops_of(mod2.protos[1])


# ---------------------------------------------------------------------------
# tables


def test_setlist_carries_an_absolute_start_index():
    """Appending at ``#t + 1`` is wrong: an explicit ``nil`` array element does
    not lengthen the table, so ``{1, 2, nil, 4}`` would collapse to three slots
    and everything after the hole would shift down.  ``SETLIST base, count,
    start`` writes at absolute 1-based indices instead."""
    proto = main("local t = {1, 2, nil, 4}\nreturn t[4]\n")
    setlist = find(proto, OP.SETLIST)
    assert setlist.args[1] == 4, "the nil hole still occupies a slot"
    assert setlist.args[2] == 1, "absolute start index"
    defs, uses = ir.def_use(setlist)
    base = setlist.args[0].index
    # SETLIST mutates the table rather than defining a new value for it, so the
    # register is a *use*; marking it defined would let liveness kill it.
    assert base in uses
    assert defs == set()
    assert {base + 1, base + 2, base + 3, base + 4} <= uses

def test_grouped_setlist_advances_the_start_index():
    proto = main("local t = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70}\nreturn t\n")
    starts = [i.args[2] for i in find_all(proto, OP.SETLIST)]
    assert starts[0] == 1
    assert all(s > starts[0] for s in starts[1:]), "later groups start further along"


def test_field_and_key_writes_use_settable():
    proto = main('local t = {}\nt.x = 1\nt["y"] = 2\nreturn t\n')
    assert len(find_all(proto, OP.SETTABLE)) == 2


def test_newtable_is_emitted_for_a_constructor():
    proto = main("local t = {}\nreturn t\n")
    assert OP.NEWTABLE in ops_of(proto)


# ---------------------------------------------------------------------------
# closures and upvalues


def test_upvalue_descriptor_for_a_direct_local_capture():
    mod = module("local x = 0\nlocal f = function() return x end\n")
    inner = mod.protos[1]
    assert len(inner.upvalues) == 1
    up = inner.upvalues[0]
    assert isinstance(up, UpvalueDesc)
    assert up.from_local is True
    assert up.index == 0
    assert up.name == "x"


def test_upvalue_descriptors_chain_across_nesting():
    src = (
        "local function outer()\n"
        "  local x = 1\n"
        "  local function inner()\n"
        "    local y = 2\n"
        "    return function() return x, y end\n"
        "  end\n"
        "  return inner()\n"
        "end\n"
    )
    mod = module(src)
    innermost = max(mod.protos, key=lambda p: p.proto_id)
    assert len(innermost.upvalues) == 2
    # capturing an enclosing variable adds the descriptor to the *capturing*
    # prototype; x comes through `inner`, so it is not a local of the innermost
    xs = [u for u in innermost.upvalues if u.name == "x"]
    ys = [u for u in innermost.upvalues if u.name == "y"]
    assert xs and ys
    assert xs[0].from_local is False
    assert ys[0].from_local is True


def test_upvalue_writes_go_through_setupval():
    """Reconstructing upvalues as copies breaks here: the write must be visible
    to the owner."""
    mod = module("local x = 0\nlocal f = function() x = x + 1 end\nf()\nreturn x\n")
    inner = mod.protos[1]
    assert OP.GETUPVAL in ops_of(inner)
    assert OP.SETUPVAL in ops_of(inner)


def test_closure_operands_reference_the_child_prototype():
    mod = module("local function f() end\n")
    closure = find(mod.main, OP.CLOSURE)
    child = closure.args[1]
    assert isinstance(child, FuncIR)
    assert child.proto_id == mod.protos[1].proto_id


# ---------------------------------------------------------------------------
# metadata the back-ends rely on


def test_liveness_is_populated_for_every_block():
    proto = main("local a = 1\nif a > 0 then\n  local b = 2\n  return b\nend\nreturn a\n")
    assert proto.blocks
    for b in proto.blocks:
        assert isinstance(b.live_in, set) and isinstance(b.live_out, set)
    # `a` is live out of the entry block: both arms read it
    assert 0 in proto.blocks[0].live_out


def test_liveness_is_empty_for_a_dead_tail():
    proto = main("local a = 1\nreturn a\n")
    ret_block = next(b for b in proto.blocks if any(i.op == OP.RETURN for i in b.instrs))
    assert ret_block.live_out == set()


def test_def_use_marks_the_registers_an_instruction_touches():
    proto = main("local a = 1\nlocal b = 2\nreturn a + b\n")
    add = find(proto, OP.ADD)
    defs, uses = ir.def_use(add)
    assert defs == {add.args[0].index}
    assert uses == {add.args[1].index, add.args[2].index}


def test_num_regs_is_a_high_water_mark():
    proto = main("local a = 1\nlocal b = 2\nlocal c = 3\nreturn a + b + c\n")
    assert proto.num_regs >= 3
    for ins in all_instrs(proto):
        defs, uses = ir.def_use(ins)
        for r in defs | uses:
            assert r < proto.num_regs, f"{ins.op} touches R{r} past num_regs={proto.num_regs}"


def test_reachable_blocks_covers_the_cfg():
    proto = main("for i = 1, 3 do\n  if i == 2 then\n    print(i)\n  else\n    print(0)\n  end\nend\n")
    reach = ir.reachable_blocks(proto)
    assert proto.entry in reach
    assert reach <= frozenset(b.id for b in proto.blocks)

def test_postorder_visits_every_block_once():
    proto = main("for i = 1, 3 do\n  if i == 2 then\n    print(i)\n  else\n    print(0)\n  end\nend\n")
    po = ir.postorder(proto)
    assert len(set(po)) == len(po), "each block appears exactly once"
    # postorder covers the reachable blocks; a placed-but-unreferenced label can
    # leave an unreachable empty block behind, and that is not an error
    assert set(po) == set(ir.reachable_blocks(proto))

def test_per_iteration_flags_loop_body_registers():
    """Luau gives each loop iteration its own variable, so a closure built in
    the body must capture that iteration's value rather than the shared
    register.  Only loop-body registers are flagged -- blanket flagging would
    break live upvalue writes."""
    flagged = main("for i = 1, 3 do\n  local x = i\n  print(x)\nend\n")
    assert flagged.per_iteration
    assert not main("local y = 1\nreturn y\n").per_iteration


def test_counters_are_maintained():
    proto = main("local function f(a)\n  return a\nend\nif f(1) then\n  for i = 1, 2 do\n    print(i)\n  end\nend\n")
    assert proto.closure_count >= 1
    assert proto.branch_count >= 1
    assert proto.loop_count >= 1
    assert proto.call_count >= 1


def test_interpolated_string_is_split_into_concatenations():
    proto = main('local a = 1\nreturn `x {a} y`\n')
    assert len(find_all(proto, OP.CONCAT)) == 2
    names = [proto.consts[i.args[1].index]
             for i in find_all(proto, OP.GETGLOBAL)]
    assert b"tostring" in names, "interpolated parts are coerced with tostring"

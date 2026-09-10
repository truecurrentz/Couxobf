"""R6: one constant pool per VM group.

The pool is where every constant in the artifact lives, sealed.  Before R6 it
was exactly one pool per artifact -- native literals and every VM group's
bytecode alike -- so one recovered accessor yielded all of them (reviewer
point #19).  With more than one VM group the descriptors split: each group
seals its own pool with its own region key and an AAD bound to the group's
own fingerprint, so a blob lifted out of one group fails to open under
another group's runtime even inside the same artifact.  Native code keeps the
shared pool: it has no group to bind to, and splitting it would buy nothing
but decrypts.

These tests pin the split, its determinism, its blast radius, and -- by
differential execution -- that the program still computes what it did.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from couxobf import rng as rngmod
from couxobf.config import Config
from couxobf.constpool import ConstantPool
from couxobf.crypto.kdf import KeyMaterial
from couxobf.pipeline import build
from couxobf.runtime.constpool_runtime import (FAILURE_MESSAGE,
                                               ConstantPoolRuntime,
                                               default_names)
from couxobf.toolchain import execute, find_toolchain
from couxobf.vm import wiring

TOOLCHAIN = find_toolchain()

EXAMPLE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "examples", "inventory.luau")
with open(EXAMPLE, encoding="utf-8") as _fh:
    INVENTORY = _fh.read()

#: The inventory example is small, so three interpreters push it past the
#: default growth budget and the ladder trims the build back to one group.
#: The budget is not what this suite is testing -- lift it.
_CFG = dict(reproducible_seed=7, vm_variety=3, max_output_growth=400)


def _multi_group_build():
    out = build(INVENTORY, Config(**_CFG), name="inv.luau", verify=False)
    groups = out.runtime_names.get("vm_plan") or []
    assert len(groups) >= 2, (
        "expected several VM groups; the budget ladder or the classifier "
        "trimmed the build back to %d" % len(groups))
    return out


# ---------------------------------------------------------------------------
# the split
# ---------------------------------------------------------------------------

def test_a_single_group_build_keeps_one_shared_pool():
    """Default surface unchanged: one group means one pool and no group_pools
    entry, exactly as before R6."""
    src = ("local function f(a, b)\n"
           "  local x = a + b\n"
           "  local y = x * a\n"
           "  local z = y - b\n"
           "  local w = z // a\n"
           "  local v = w % b\n"
           "  return x + y + z + w + v\n"
           "end\n"
           "print(f(2, 3))\n")
    out = build(src, Config(reproducible_seed=7), name="one.luau", verify=False)
    assert "group_pools" not in out.runtime_names
    assert out.stats.virtualized >= 1


def test_each_group_seals_its_own_pool():
    out = _multi_group_build()
    rn = out.runtime_names
    gp = rn.get("group_pools")
    assert gp is not None, "multi-group build must report its group pools"
    assert sorted(gp) == [str(g["group"]) for g in rn["vm_plan"]], (
        "one pool per VM group, no more, no less")
    accessors = [gp[k]["get"] for k in sorted(gp)]
    # Distinct from each other and from the shared pool's accessor: one
    # recovered name must not read another group's blob.
    assert len(set(accessors)) == len(accessors)
    assert rn["pool"]["get"] not in accessors
    for accessor in accessors + [rn["pool"]["get"]]:
        assert accessor in out.source, accessor


def test_group_pools_are_deterministic():
    a = build(INVENTORY, Config(**_CFG), name="inv.luau", verify=False)
    b = build(INVENTORY, Config(**_CFG), name="inv.luau", verify=False)
    assert a.source == b.source


def test_group_fingerprints_distinguish_groups():
    """The AAD binding is only meaningful if the fingerprints are: same group
    twice gives the same digest, different groups give different ones."""
    dom = rngmod.make_domains(b"\x07" * 16)
    plan = wiring.make_plan(dom.get("vm"), {2, 3, 4}, variety=3)
    fps = [wiring.group_fingerprint(g) for g in plan.groups]
    assert len(set(fps)) == len(fps)
    again = [wiring.group_fingerprint(g) for g in plan.groups]
    assert fps == again


# ---------------------------------------------------------------------------
# the blast radius
# ---------------------------------------------------------------------------

def _two_group_pools():
    """Two pools sealed exactly the way the build seals group pools: same
    key material, same context shape, different group fingerprints."""
    dom = rngmod.make_domains(b"\x07" * 16)
    plan = wiring.make_plan(dom.get("vm"), {2, 3, 4}, variety=3)
    keys = KeyMaterial.from_seed(b"\x07" * 16)
    pools = []
    for group in plan.groups[:2]:
        pool = ConstantPool(
            keys, dom.get("vm").fork("vm-pool-%d" % group.index),
            b"ctx" + b"\xc1g" + wiring.group_fingerprint(group))
        for value in (b"alpha", 1, 2.5, True):
            pool.slot(value)
        pools.append(pool.seal())
    return pools


def test_a_blob_opens_under_its_own_group():
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    sealed, _ = _two_group_pools()
    rt = ConstantPoolRuntime(default_names())
    src = rt.emit(sealed.key, sealed.nonce, sealed.tag, sealed.ciphertext,
                  sealed.aad)
    src += "\nprint(%s(2))\n" % rt.accessor
    result = execute(TOOLCHAIN, src, "own.luau", timeout=30)
    assert result.returncode == 0, result.stderr[:200]
    assert result.stdout == "1\n"


def test_a_blob_moved_to_a_sibling_group_is_rejected():
    """Group 0's ciphertext, opened with group 1's key and AAD: the MAC must
    fail and the runtime must refuse with the neutral wording -- not hand back
    garbage constants."""
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    blob, sibling = _two_group_pools()
    assert blob.aad != sibling.aad
    rt = ConstantPoolRuntime(default_names())
    src = rt.emit(sibling.key, sibling.nonce, sibling.tag, blob.ciphertext,
                  sibling.aad)
    src += "\nprint(%s(1))\n" % rt.accessor
    result = execute(TOOLCHAIN, src, "swap.luau", timeout=30)
    assert result.returncode != 0, "a cross-group blob authenticated"
    assert FAILURE_MESSAGE in result.stderr, result.stderr[:200]


# ---------------------------------------------------------------------------
# behaviour
# ---------------------------------------------------------------------------

def test_a_multi_group_build_still_computes_what_the_source_does():
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available")
    out = build(INVENTORY, Config(**_CFG), name="inv.luau", verify=True)
    want = execute(TOOLCHAIN, INVENTORY, "want.luau", timeout=30)
    got = execute(TOOLCHAIN, out.source, "got.luau", timeout=120)
    assert got.returncode == want.returncode, got.stderr[:400]
    assert got.stdout == want.stdout

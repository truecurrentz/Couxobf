#!/usr/bin/env python3
"""Print what a build draws from the vm stream, so it can be checked.

The vm stream is the one place where adding a name to the runtime moves
every other name a build draws: a build's format, opcode map, cipher and
dispatch key are all drawn from it, and one extra draw shifts all of them.
Forking a role's name off the shared block is what keeps a new role from
doing that, and this is the check that says whether it worked.

    python tools/stream-check.py [program.luau] [--seed N]

It prints the prototype selection, the ``row_mask``, and each group's
format -- the fields a decoder has to know plus the arm seed -- for one
program at one seed. Two builds that print the same thing drew the same
stream; the numbers themselves mean nothing across a change of program or
seed, so the way to use it is to run it before and after a change.
"""

import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from couxobf import ir, parser                           # noqa: E402
from couxobf.config import Config                        # noqa: E402
from couxobf.pipeline import seed_from_config            # noqa: E402
from couxobf.rng import make_domains                     # noqa: E402
from couxobf.vm import encode, wiring                    # noqa: E402
from couxobf.vm.format import FormatPrefs, FormatSpec    # noqa: E402

DEFAULT = os.path.join(ROOT, "tests", "fixtures", "corpus", "loops.luau")

#: The format fields a decoder has to know.  Everything else about a group is
#: either named by its own role or derived from these.
FIELDS = ("op_bytes", "reg_bytes", "wide_bytes", "pad", "wides_first",
          "target_mode", "op_cipher", "arm_seed")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("program", nargs="?", default=DEFAULT)
    ap.add_argument("--seed", type=int, default=101)
    args = ap.parse_args(argv)

    name = os.path.basename(args.program)
    with open(args.program, encoding="utf-8", errors="surrogateescape") as fh:
        source = fh.read()

    # The pipeline's own front end, in the pipeline's order: the point of the
    # check is that a *build* draws what it draws, and a seed derived any
    # other way is a different build.
    config = Config.from_profile("maximum")
    config.reproducible_seed = args.seed
    module = ir.Lowerer().lower(parser.parse(source, name))
    rngs = make_domains(seed_from_config(config))
    protos = {p.proto_id: p for p in module.protos}
    probe = FormatSpec()
    selected = {pid for pid in wiring.select_protos(module,
                                                    config.virtualization_level)
                if encode.can_virtualize(protos[pid], probe)[0]}
    plan = wiring.make_plan(
        rngs.get("vm"), selected,
        family=config.vm_family, dispatcher=config.dispatcher_family,
        randomize_opcodes=bool(config.opcode_randomization),
        variety=int(config.vm_variety),
        alias_ratio=0.0, alias_chance=0.0,
        fmt_prefs=FormatPrefs.from_config(config),
        permute_blocks=False,
        protos_by_id=protos if config.vm_isa_subset else None,
        isa_subset=bool(config.vm_isa_subset))

    print("%s, seed %d" % (name, args.seed))
    print("  selected %d prototypes, row_mask %d"
          % (len(selected), plan.row_mask))
    for i, group in enumerate(plan.groups):
        print("  group %d: %s" % (i, " ".join(
            "%s=%s" % (f, getattr(group.fmt, f)) for f in FIELDS)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

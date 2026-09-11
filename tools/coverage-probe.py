#!/usr/bin/env python3
"""How much of a corpus the VM can run, under each capability flag setting.

The numbers the increments are argued with, reproducible: this walks the
pipeline's own front end -- same seed derivation, same preparation, same
classifier, same ``_select_for_vm`` -- and counts what the selection came to.
It stops before reconstruction because coverage is a question about the
selection, not about the bytes that come out of it, and because a full build
of the corpus takes minutes this probe does not need to spend.

    python tools/coverage-probe.py [file.luau ...]

No arguments means the repo corpus plus ``examples/``.  Three settings are
reported: neither capability flag, ``vm_upvalues`` alone, and both.  Each
cell is prototypes/instructions, where an instruction is one IR instruction
in a prototype the VM will run.
"""

import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from couxobf import classify as _classify          # noqa: E402
from couxobf import comments as _comments          # noqa: E402
from couxobf import index_to_num as _index_to_num  # noqa: E402
from couxobf import ir as _ir                      # noqa: E402
from couxobf import optimize as _optimize          # noqa: E402
from couxobf import parser as _parser              # noqa: E402
from couxobf import sema as _sema                  # noqa: E402
from couxobf.config import Config                  # noqa: E402
from couxobf.pipeline import _select_for_vm, seed_from_config  # noqa: E402
from couxobf.rng import make_domains               # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = sorted(glob.glob(os.path.join(ROOT, "tests", "fixtures", "corpus",
                                       "*.luau")))
EXAMPLES = sorted(glob.glob(os.path.join(ROOT, "examples", "*.luau")))

SETTINGS = (
    ("neither", {"vm_upvalues": False, "vm_closures": False}),
    ("upvalues", {"vm_upvalues": True, "vm_closures": False}),
    ("both", {"vm_upvalues": True, "vm_closures": True}),
)


def lower_and_select(source: str, name: str, config: Config):
    """The lowered module and the prototypes ``_select_for_vm`` keeps.

    The stages are the pipeline's, in the pipeline's order, because the
    classifier reads what they produce: a seed derived any other way gives
    different domains and therefore a different selection.
    """
    seed = seed_from_config(config)
    text = _comments.prepare(source, name, config.hash_comments,
                             _parser.parse)[0]
    ast = _parser.parse(text, name)
    domains = make_domains(seed)
    _sema.ScopeAnalyzer().analyze(ast)
    directives = [(d.line, d.name)
                  for d in _comments.find_directives(source)]
    if getattr(config, "index_to_num", False):
        _index_to_num.rewrite(ast, domains.get("index-to-num"),
                              directives=directives)
    module = _ir.Lowerer(
        table_key_protection=bool(config.table_key_protection),
        rng=domains.get("table-keys")).lower(ast)
    # What runs is what survives the optimiser, and the optimiser is where
    # the lowerer's scratch moves and dead stores go: counting before it
    # would credit the VM with instructions no artifact ever contains.
    _optimize.optimize_module(module)
    classification = _classify.classify_module(module, config,
                                               domains.get("vm"),
                                               directives=directives)
    chosen = _select_for_vm(module, classification,
                            upvalues_ok=bool(config.vm_upvalues),
                            closures_ok=bool(config.vm_closures))
    return module, chosen


def config_for(flags: dict) -> Config:
    config = Config.from_profile("maximum")
    config.reproducible_seed = 41
    for key, value in flags.items():
        setattr(config, key, value)
    return config


def main(argv):
    paths = argv[1:] or (CORPUS + EXAMPLES)
    rows = []
    totals = [(0, 0)] * len(SETTINGS)
    everything = 0          # instructions, all prototypes
    all_protos = 0          # prototypes, selected or not
    for path in paths:
        name = os.path.basename(path)
        with open(path, encoding="utf-8", errors="surrogateescape") as fh:
            source = fh.read()
        cells = []
        for index, (label, flags) in enumerate(SETTINGS):
            module, chosen = lower_and_select(source, name, config_for(flags))
            protos = instrs = 0
            for proto in module.walk():
                count = sum(len(b.instrs) for b in proto.blocks)
                if index == 0:
                    everything += count   # every prototype, selected or not
                    all_protos += 1
                if proto.proto_id in chosen:
                    protos += 1
                    instrs += count
            cells.append((protos, instrs))
        rows.append((name, cells))
        totals = [(t[0] + c[0], t[1] + c[1]) for t, c in zip(totals, cells)]

    width = max(len(r[0]) for r in rows)
    print("%-*s %12s %12s %12s" % (
        width, "file", *(label for label, _ in SETTINGS)))
    for name, cells in rows:
        print("%-*s %12s %12s %12s" % (
            width, name, *("%d/%d" % c for c in cells)))
    print("%-*s %12s %12s %12s" % (
        width, "total", *("%d/%d" % t for t in totals)))
    print("\n%d files, %d prototypes, %d IR instructions after "
          "optimisation. The last setting runs %d prototypes and %d "
          "instructions (%.1f%% of them)."
          % (len(paths), all_protos, everything, totals[-1][0],
             totals[-1][1], 100.0 * totals[-1][1] / max(1, everything)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

#!/usr/bin/env python3
"""Measure what an analyst can carry from one build to the next.

File size is not a protection metric, and neither is "the output differs".  The
question this project has to answer with a number is the one virtualization
research keeps returning to: *if someone recovers the opcode table, the handler
order and the instruction format of one artifact, how much of it still works on
the next one?*

So this is a matcher -- deliberately a weak one, because a weak attack with a
measured success rate is worth more here than a strong attack with an asserted
one.  It sweeps each prototype's payload from the entry offset the way the
interpreter walks straight-line code, taking the value at each instruction start
and looking it up in a table of "value means operation".  Truth for a build is
what that build's own map and format say, so nothing here needs the encoder's
answer sheet: the sweep and the table are built from the same two artifacts a
static tool would have.

Four things are compared between a pair of builds:

``numbering``
    the fraction of opcodes that kept the same dispatcher number;
``payload``
    the fraction of instructions in B whose *stored value* means the same thing
    in A's table as it does in B -- the number a devirtualizer actually cares
    about;
``shape``
    whether the format fields a decoder must know (field widths, masks, padding,
    operand order, jump-target mode, opcode cipher, header order) agree at all;
``arms``
    whether the handler arms appear in the same order, i.e. whether "the third arm
    is LOADK" survives from one build to the next.

Each is averaged over every ordered pair of builds, for three configurations of
one program: a protector that varies nothing, this tool with the numbering
shuffle only, and this tool as shipped.  The middle column is the interesting
one -- it separates "the numbers moved" from "the bytes stopped meaning anything".

The builds are made by driving the VM layer directly (lower, select, plan,
encode) rather than through the whole pipeline, so that one configuration flag
means one difference between the columns instead of also shifting the optimizer
and the pool.  That makes the numbers comparable to each other; it does not make
them the same as a shipped artifact's, and it is why this is a measurement tool
rather than a test.

Usage::

    python3 tools/reuse-audit.py [path/to/program.luau] [--seeds N] [--json]

Exit status is 0 whenever the audit runs; it measures, it does not pass a verdict.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from couxobf import ir, parser                         # noqa: E402
from couxobf.config import Config                      # noqa: E402
from couxobf.integrity.payload import _reader          # noqa: E402
from couxobf.rng import make_domains                   # noqa: E402
from couxobf.vm import encode, wiring                  # noqa: E402
from couxobf.vm.format import FormatPrefs, FormatSpec   # noqa: E402
from couxobf.vm.runtime import dispatch_entries        # noqa: E402


#: The three configurations, in the order that makes the table readable: a
#: protector that never varies anything, this tool with the opcode shuffle alone,
#: and this tool as shipped.
CASES: Tuple[Tuple[str, Dict[str, Any]], ...] = (
    ("stable", {"opcode_randomization": False, "operand_randomization": False,
                "block_permutation": False, "opcode_cipher": False,
                "vm_isa_subset": False}),
    ("numbered", {"opcode_randomization": True, "operand_randomization": False,
                  "block_permutation": False, "opcode_cipher": False,
                  "vm_isa_subset": False}),
    ("hardened", {}),
    # The shipped knob plus several VMs in one artifact: a matcher that has to
    # feed one recovered table into three interpreters scores zero on `shape` and
    # `arms` for a different reason -- there is more than one of each.
    ("polymorphic", {"vm_variety": 3, "dispatcher_family": "mixed"}),
)

SHAPE_FIELDS = ("op_bytes", "reg_bytes", "wide_bytes", "pad", "wides_first",
                "reg_mask", "wide_mask", "target_mode", "op_cipher",
                "dispatch_shape", "inline_reads", "key_taps")


def _sweep(code: bytes, fmt: FormatSpec, reader: Any,
           opmap: Any, start: int) -> List[Tuple[int, str]]:
    """(stored value, operation) for every instruction a linear walk reaches.

    Stops rather than wraps: an offset past the end, or a value the map does not
    answer to, means the walk has left the program, and continuing would score
    operand bytes as if they were opcodes -- which is exactly the mistake a
    real static matcher makes, and not one worth reproducing in a measurement.
    """
    out: List[Tuple[int, str]] = []
    at = start
    size_field = fmt.op_bytes
    while fmt.header_size <= at < len(code):
        stored = int.from_bytes(code[at:at + size_field], "little")
        number = reader.opcode_at(code, at)
        op = opmap.to_op.get(number)
        if op is None:
            break
        out.append((stored, op))
        at += reader.size(op)
    return out


def _facts(source: str, name: str = "audit.luau",
           seed: int = 1, **over: Any) -> Dict[str, Any]:
    module = ir.Lowerer().lower(parser.parse(source, name))
    config = Config.hardened()
    config.min_virtualize_body_nodes = 1
    for key, value in over.items():
        if not hasattr(config, key):
            raise SystemExit("%s is not a Config field" % key)
        setattr(config, key, value)

    rngs = make_domains(seed.to_bytes(16, "big"))
    protos = {p.proto_id: p for p in module.protos}
    selected = wiring.select_protos(module, config.virtualization_level)
    fmt_probe = FormatSpec()
    selected = {pid for pid in selected
                 if encode.can_virtualize(protos[pid], fmt_probe)[0]}
    plan = wiring.make_plan(
        rngs.get("vm"), selected,
        family=config.vm_family,
        dispatcher=config.dispatcher_family,
        randomize_opcodes=bool(config.opcode_randomization),
        variety=int(config.vm_variety),
        alias_ratio=0.0, alias_chance=0.0,
        fmt_prefs=FormatPrefs.from_config(config),
        permute_blocks=False,
        protos_by_id=protos if config.vm_isa_subset else None,
        isa_subset=bool(config.vm_isa_subset),
    )

    groups: List[Dict[str, Any]] = []
    for group in plan.groups:
        fmt: FormatSpec = group.fmt
        reader = _reader(fmt)
        pairs: List[Tuple[int, str]] = []
        for pid in sorted(group.protos):
            proto = protos.get(pid)
            if proto is None:
                continue
            enc = encode.encode_proto(proto, group.opmap, fmt=fmt)
            entry = reader.header(enc.code)["entry"]
            pairs += _sweep(enc.code, fmt, reader, group.opmap, entry)
        groups.append({
            "family": group.family,
            "dispatcher": group.dispatcher,
            "numbers": dict(group.opmap.to_byte),
            "opcodes": len(group.opmap.to_byte),
            "shape": {f: getattr(fmt, f) for f in SHAPE_FIELDS},
            "header": [n for n, _ in fmt.header.fields],
            "arms": [entry.numbers[0] for entry in dispatch_entries(group.opmap, fmt)],
            "pairs": pairs,
        })
    return {"virtualized": len(selected), "groups": groups,
            "bytes": sum(len(g["pairs"]) for g in groups)}


def compare(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """A's recovered knowledge, scored against B."""
    ga, gb = a["groups"], b["groups"]
    # Same program, same selection rule, so the same prototypes.  A build with a
    # different *number* of groups is zero transfer, not a partial match: an
    # analyst with three interpreters to feed and one recovered table has failed,
    # however neat each individual table looked.
    if len(ga) != len(gb):
        return {"groups_match": False, "numbering": 0.0, "payload": 0.0,
                "shape": 0.0, "arms": 0.0, "isa": 0.0}
    hits = total = payload_hits = payload_total = 0
    shape_same = arms_same = isa_same = 0
    for x, y in zip(ga, gb):
        isa_same += (x["opcodes"] == y["opcodes"])
        shape_same += (x["shape"] == y["shape"]
                       and x["header"] == y["header"])
        arms_same += (x["arms"] == y["arms"])
        learned = _table(x["pairs"])
        for stored, op_b in y["pairs"]:
            payload_total += 1
            payload_hits += (learned.get(stored) == op_b)
        for op in set(x["numbers"]) & set(y["numbers"]):
            total += 1
            hits += (x["numbers"][op] == y["numbers"][op])
    return {"groups_match": True,
            "numbering": (hits / total) if total else 0.0,
            "payload": (payload_hits / payload_total) if payload_total else 0.0,
            "shape": shape_same / len(ga),
            "arms": arms_same / len(ga),
            "isa": isa_same / len(ga)}


def _table(pairs: List[Tuple[int, str]]) -> Dict[int, str]:
    """A learned "value means operation" table, majority vote per value."""
    tally: Dict[int, Dict[str, int]] = {}
    for stored, op in pairs:
        counts = tally.setdefault(stored, {})
        counts[op] = counts.get(op, 0) + 1
    return {byte: max(counts, key=counts.get) for byte, counts in tally.items()}


def audit(path: str, seeds: int) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        source = handle.read()
    report: Dict[str, Any] = {"program": os.path.basename(path), "cases": {}}
    for label, over in CASES:
        facts = [_facts(source, name=os.path.basename(path), seed=101 + i, **over)
                 for i in range(seeds)]
        scored = [compare(facts[i], facts[j])
                  for i in range(len(facts)) for j in range(len(facts)) if i != j]
        pairs = [s for s in scored if s["groups_match"]] or scored
        report["cases"][label] = {
            "builds": len(facts),
            "virtualized": [f["virtualized"] for f in facts],
            "instructions": [f["bytes"] for f in facts],
            "groups": [len(f["groups"]) for f in facts],
            "isa_sizes": [[g["opcodes"] for g in f["groups"]] for f in facts],
            "transfer": {key: sum(p[key] for p in pairs) / len(pairs)
                         for key in ("numbering", "payload", "shape", "arms",
                                     "isa")},
        }
    return report


def print_report(report: Dict[str, Any]) -> None:
    print("cross-build knowledge transfer")
    print("program : %s" % report["program"])
    print("pairs   : every ordered pair of builds, so each figure is how much of")
    print("          one build's recovered knowledge still works on another's")
    print()
    header = "%-10s %8s  %8s  %8s  %7s  %6s  %5s" % (
        "config", "instrs", "numbering", "payload", "shape", "arms", "isa")
    print(header)
    print("-" * len(header))
    for label, case in report["cases"].items():
        t = case["transfer"]
        print("%-10s %8s  %7.0f%%  %7.0f%%  %6.0f%%  %5.0f%%  %4.0f%%" % (
            label, "%d" % (sum(case["instructions"]) / len(case["instructions"])),
            t["numbering"] * 100, t["payload"] * 100, t["shape"] * 100,
            t["arms"] * 100, t["isa"] * 100))
    print()
    for label, case in report["cases"].items():
        print("%-10s handlers per VM, per build: %s" % (label, case["isa_sizes"]))
    print()
    print("Read `payload` as 'would my tool still work'.  `stable` is what a")
    print("protector without polymorphism scores; `numbered` is opcode shuffling")
    print("alone; `hardened` is this tool as shipped.  None of it is a bound: a")
    print("matcher that reads the emitted interpreter instead of the payload")
    print("recovers a table for whatever build it is pointed at, and then what it")
    print("has to redo per build is the format -- which is why `shape` and `arms`")
    print("are in this table at all.")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("program", nargs="?",
                    default=os.path.join(ROOT, "examples", "maze.luau"))
    ap.add_argument("--seeds", type=int, default=3,
                    help="builds per configuration (default 3)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    report = audit(args.program, max(2, args.seeds))
    if args.json:
        print(json.dumps(report, indent=1, sort_keys=True))
    else:
        print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

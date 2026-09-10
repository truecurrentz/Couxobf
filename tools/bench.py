#!/usr/bin/env python3
"""Build-time and runtime overhead, measured rather than asserted.

The design's claim is "protected output stays reasonably close to the
original".  That is only a claim until somebody runs both sides and writes
the numbers down, which is what this tool does:

* build time and output size per example, per profile;
* runtime wall-time ratio (median of N) original vs protected, under the
  pinned Luau toolchain.

The results belong in ``docs/benchmarks.md`` with the commit that produced
them.  A change that moves the hardened runtime ratio or the output size by
more than a few tens of percent should explain itself there, the same way a
test failure explains itself.

Usage::

    python3 tools/bench.py [--runs N] [--examples a.luau b.luau]

Requires the toolchain from ``tools/setup-luau.sh`` for the runtime half;
the build half runs without it.
"""

from __future__ import annotations

import argparse
import os
import statistics
import sys
import time
from typing import List

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from couxobf.config import Config                                  # noqa: E402
from couxobf.pipeline import build                                 # noqa: E402
from couxobf.toolchain import execute, find_toolchain              # noqa: E402

DEFAULT_EXAMPLES = ("examples/hello.luau", "examples/inventory.luau",
                    "examples/maze.luau")
PROFILES = (("compact", Config.compact), ("hardened", Config.hardened),
            ("maximum", Config.maximum))


def _read(path: str) -> str:
    with open(path, encoding="utf-8", errors="surrogateescape") as fh:
        return fh.read()


def _median(values: List[float]) -> float:
    return statistics.median(values) if values else float("nan")


def bench_runtime(tc, src: str, protected: str, name: str, runs: int,
                  timeout: int) -> dict:
    def timed(code: str, label: str) -> List[float]:
        out = []
        for _ in range(runs):
            t0 = time.perf_counter()
            res = execute(tc, code, label, timeout=timeout)
            out.append(time.perf_counter() - t0)
            if res.returncode != 0 or res.timed_out:
                return []
        return out

    orig = timed(src, "orig_" + name)
    prot = timed(protected, "prot_" + name)
    if not orig or not prot:
        return {"ok": False}
    return {"ok": True, "original_ms": _median(orig) * 1000.0,
            "protected_ms": _median(prot) * 1000.0,
            "ratio": _median(prot) / max(1e-9, _median(orig))}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--examples", nargs="*", default=list(DEFAULT_EXAMPLES))
    args = ap.parse_args(argv)

    tc = find_toolchain()
    print("toolchain:", "present" if tc.can_execute else "MISSING "
          "(runtime half skipped; run tools/setup-luau.sh)")
    print()
    header = ("%-22s %-9s %8s %8s %7s %6s %10s %10s %7s"
              % ("example", "profile", "in_B", "out_B", "ratio", "vm",
                 "build_ms", "prot_ms", "slowdown"))
    print(header)
    print("-" * len(header))
    for path in args.examples:
        src = _read(os.path.join(ROOT, path))
        in_bytes = len(src.encode("utf-8"))
        for label, factory in PROFILES:
            config = factory()
            config.reproducible_seed = 42
            t0 = time.perf_counter()
            result = build(src, config, name=os.path.basename(path),
                           verify=False)
            build_ms = (time.perf_counter() - t0) * 1000.0
            out_bytes = result.stats.output_bytes
            rt = {"ok": False}
            if tc.can_execute and result.stats.virtualized + 1 > 0:
                rt = bench_runtime(tc, src, result.source,
                                   os.path.basename(path), args.runs,
                                   args.timeout)
            if rt["ok"]:
                print("%-22s %-9s %8d %8d %6.1fx %6d %10.0f %10.1f %6.1fx"
                      % (path, label, in_bytes, out_bytes,
                         out_bytes / max(1, in_bytes),
                         result.stats.virtualized, build_ms,
                         rt["protected_ms"],
                         rt["protected_ms"] / max(1e-9, rt["original_ms"])))
            else:
                print("%-22s %-9s %8d %8d %6.1fx %6d %10.0f %10s %7s"
                      % (path, label, in_bytes, out_bytes,
                         out_bytes / max(1, in_bytes),
                         result.stats.virtualized, build_ms, "-", "-"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

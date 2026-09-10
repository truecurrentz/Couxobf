# Benchmarks

Measured, not asserted. Everything below ran under the pinned toolchain
(`.luau-toolchain/`, Luau 0.700) on this repository's examples and corpus, via
`tools/bench.py` and the scripts noted inline. Numbers move with the machine
and the seed; what is pinned here is the *shape* of the cost and the
commit-relative deltas, so a regression has somewhere to be noticed.

## What a protected build costs, by profile

`tools/bench.py --runs 3`, seed 42, median of three:

```
example                profile       in_B    out_B   ratio     vm   build_ms    prot_ms slowdown
------------------------------------------------------------------------------------------------
examples/hello.luau    compact         24    16121  671.7x      0        591        6.4    1.6x
examples/hello.luau    hardened        24    17793  741.4x      0       1188        5.9    1.6x
examples/hello.luau    maximum         24    19805  825.2x      0         99        8.5    2.4x
examples/inventory.luau compact       2008    36209   18.0x      0        207       10.2    2.4x
examples/inventory.luau hardened      2008    44196   22.0x      3       2685       12.6    3.2x
examples/inventory.luau maximum       2008    65520   32.6x      3        349      115.9   29.4x
examples/maze.luau     compact       3484    53982   15.5x      0        318       29.1    6.2x
examples/maze.luau     hardened      3484    83363   23.9x      2        498     6357.3 1201.4x
examples/maze.luau     maximum       3484    91502   26.3x      2        524     6597.5 1364.3x
```

For the sub-10 ms originals the `slowdown` column amplifies baseline noise;
`prot_ms` is the honest column. On that column, the chain-dispatch work cut
the maze hardened build from ~9.0 s to ~6.4 s (~30%) relative to the
previous closure-bank interpreter, at ~1–3% output growth.

Read the table as three facts:

1. **`compact` never pays for the VM.** It virtualizes nothing, so its
   slowdown is the reconstruction and constant-pool overhead alone, and on
   trivial input that is a rounding error.
2. **`hardened`/`maximum` pay the interpreter.** The runtime ratio is the
   price of executing user code through the woven interpreter instead of the
   Luau VM. It is proportional to how much of the program is virtualized and
   how tight its loops are, not to the program's size.
3. **Build time is one-shot.** It grows with virtualized node count and stays
   in the hundreds of milliseconds for these examples; it is never on the
   user's runtime path.

## Where the runtime cost actually lives

Split of `tests/fixtures/corpus/buffers.luau` (numeric-heavy, one hot loop;
original 0.58 s, `reproducible_seed=42`):

| build                       | wall time | slowdown |
|-----------------------------|-----------|----------|
| original                    | 0.58 s    | 1x       |
| protected, `vm=none`        | ~97 s     | ~165x    |
| protected, default          | ~71 s     | ~123x    |
| protected, min-nodes=40     | ~74 s     | ~128x    |

The surprise in these numbers is the second row: with **no virtualization at
all**, the native multi-block reconstruction is already the dominant cost for
a loop-heavy program. The VM layer removes part of it (virtualized blocks
leave the affine-flattened native path) but replaces it with an interpreter
loop. Further wins therefore need both halves:

* VM side — dispatch shape and operand reads, measured below.
* Native side — the affine flattening of multi-block bodies (`lower_back`),
  which is where `vm=none` builds spend their time. Not addressed yet; see
  the roadmap in `research-comparison.md`.

## The cost of opaque split arms (native side)

R2's native half adds opaque `elseif` arms to the flattened drivers, keyed to
an encoded state the build proves unreachable. They are extra comparisons in
the dispatch chain and extra bytes in the artifact, so the cost is measured
rather than assumed — `examples/maze.luau`, `reproducible_seed=42`, median of
three protected runs (original 3.3 ms):

| build                          | wall time | Δ vs arms off | out size | split arms |
|--------------------------------|-----------|---------------|----------|------------|
| arms off (`control_flow_level=0`) | 5888 ms | —             | 77 916 B | 0          |
| arms on (`control_flow_level=2`)  | 6050 ms | +2.8 %        | 82 077 B | 33         |

The runtime price is the per-dispatch extra comparison a decoy arm adds while
the chain scans for the matching block — it never runs, but it is compared.
At the hardened default's 0.2 draw rate that is +2.8 % on the hot maze
program, comfortably inside the "a few tens of percent" bar this file holds
changes to. The size price is the arm's encoded-state comparison plus a deep
copy of the real block's tail statements (+5.3 %). Both scale with the rate
dial, so a build that wants less pays less: level 0 emits none, and the
`compact` profile (level 0) never sees them.

## Dispatch shape and operand reads (VM side)

Measured on `examples/maze.luau` with the format forced per shape (chain
forced via `draw` monkeypatch; `/tmp/chain_bench.py`), median of three:

| interpreter shape                        | wall time | vs bank |
|------------------------------------------|-----------|---------|
| bank (closure table dispatch)            | ~9.0 s    | 1.00x   |
| chain (scrambled if/elseif ladder)       | ~6.0 s    | ~0.67x  |
| chain + inline operand reads             | ~6.1 s    | ~0.68x  |

Chain dispatch is the one clear win: one scrambled compare ladder per
instruction instead of a hash-bucketed closure call. It is ~33% faster on the
hot loop and ships a smaller interpreter (no bank table), and both shapes are
drawn per group, so a build carries whichever the seed picks — the knob is
diversity, not a setting.

Inlining the operand reads at each read site (instead of calling the
generated readers) is within noise: Luau function calls are cheap and the
inlined expressions make each handler longer, so the two effects cancel. The
option stays as a per-build draw because it genuinely changes the artifact's
shape, not because it is faster.

What is *not* recoverable by these micro-means: the remaining ~6 s is the
per-instruction constant of any interpreter written in Luau — table-based
register file, operand decode, loop scaffolding, ~5.5 µs per virtualized
iteration (~20 instructions per loop pass). Closing that needs structural
change (e.g. register file as locals for small prototypes), which the roadmap
lists as follow-up work rather than promising it here.

## Sealed-blob spelling (dense vs hex)

Sealed material (pool ciphertext, string pages, ticket metadata) can ship as
base85 over a per-build alphabet (`blob_encoding = "dense"`, the default) or
in the historical escaped form (`hex`). Measured at equal protection, seed
42, hardened profile:

| example     | dense    | hex      | saving |
|-------------|----------|----------|--------|
| hello.luau  | 19 627 B | 19 809 B | 0.9 %  |
| inventory   | 54 874 B | 57 473 B | 4.5 %  |
| maze        | 78 673 B | 81 711 B | 3.7 %  |

The data literals themselves shrink by the expected ~3.2×, but sealed
material is only ~10 % of a hardened artifact; the interpreter, crypto module
and descriptor tables dominate. The honest takeaway: dense is a free win
(load-time decode only) but it is not *the* size lever. The decoder preamble
costs ~1 KB, so builds with < 512 bytes of sealed material keep hex and
report `dense-skipped` in the build report.

## The guard's cost

`env_guard`/`dump_guard` level 2 (`hardened` and `maximum`) re-checks the
execution environment from inside the dispatch loop, masked like an opaque
predicate. On the maze hot loop it is within the run-to-run noise of the
numbers above (~6.0–6.1 s either way): the check fires on a minority of
instructions and is a handful of identity compares. Level 1 (the default)
captures and snapshots only, and costs nothing at runtime.

## The differential tests and slow corpus programs

`tests/fixtures/corpus/buffers.luau` and `constructs.luau` virtualize to
roughly a minute of runtime under the aggressive test floor
(`min_virtualize_body_nodes=4`, chosen so the corpus actually exercises the
VM). Their outputs are byte-identical to the originals — the slowness is the
documented price of virtualizing tight loops — so the differential test gives
them a longer protected-side budget (`PROTECTED_TIMEOUT`) instead of
weakening the equivalence check. If a future change makes them materially
faster or slower, update `docs/benchmarks.md` and the timeout together.

## Reproducing

```
.venv/bin/python tools/bench.py --runs 3
```

A change that moves the hardened runtime ratio or the output size by more
than a few tens of percent should explain itself here, the same way a test
failure explains itself.

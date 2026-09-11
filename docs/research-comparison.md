# Reference study and architecture redesign

Studied references (cloned and read, not copied):

| Project | Language | Size | Model |
|---|---|---|---|
| [Prometheus](https://github.com/prometheus-lua/Prometheus) | pure Lua | ~10.8 kLOC | AST step pipeline; full custom-VM "Vmify" |
| [LuaObfuscatorV2](https://github.com/PY44N/LuaObfuscatorV2) | Rust | ~1.6 kLOC (+ deps) | bytecode-in → custom VM out |
| [Clyde](https://github.com/sfr-development/Lua-Obfuscator-Clyde-Protection) | TypeScript | ~12.7 kLOC | from-scratch Luau front end + dual VMs |
| [ScriptShield](https://github.com/skizap/ScriptShield) | Python | large, GUI-centric | third-party parser + AST passes + stack VM |
| [Hercules (fork)](https://github.com/AlephSc/Fork-Hercules-Obf) | Lua | ~0.6 kLOC | text-level regex modules |
| [Luaq](https://obfuscator.cfd/docs) | closed source | docs only | macro/directive surface |

This document records what each design does well, what fails in it, and what
we take into couxobf. Every recommendation states the problem, the inspiring
reference, why it beats our current state, the runtime cost, the compatibility
risk, the test plan, and whether it defaults on.

---

## 0. Reference notes (with weaknesses)

### Prometheus

**Architecture.** Parser → AST → configurable list of *steps* → unparser.
Steps (`ConstantArray`, `EncryptStrings`, `NumbersToExpressions`,
`SplitStrings`, `ProxifyLocals`, `AntiTamper`, `Vmify`, `WrapInFunction`,
`Watermark`, `AddVararg`) are independent AST-to-AST transforms with declared
settings descriptors. Seeded RNG; several name generators (mangled, Il,
number, confuse).

**Vmify.** Compiles the whole script to a custom register bytecode and emits a
VM as a "container function". Notably it *virtualizes closures and upvalues*:
upvalues are modelled with proxy objects (`newproxy`/metatable tricks) so
nested functions survive. Constant array with shuffle/rotate/wrapper
functions; string encryption (XOR variants); anti-tamper that hashes the VM
container via `debug.getinfo`/`string.dump` and traps edits in a
data-dependent sanity chain.

**Testing.** Differential tests: 16 semantic fixtures run through every preset
under lua5.1 *and* luau, N iterations, inside Docker (`scripts/run-tests.sh`).
That "same behaviour on two real interpreters" harness is the right shape.

**Weaknesses (do not copy).**
- Luau support is explicitly unfinished: no type annotations, partial modern
  syntax. A Roblox-first tool must not reuse that front end.
- The VM is *one fixed shape*: same opcode set, same dispatch, same container
  in every build. Only numbering/constant encoding moves. One devirtualizer
  covers every Prometheus artifact ever produced — the exact failure the
  reviewer pointed at us before we added formats.
- String/constant "encryption" is XOR/base64-class; recoverable mechanically.
- AntiTamper depends on `debug`/`string.dump`, absent or restricted on Roblox.
- Steps mutate one shared AST in sequence; a step that breaks an invariant
  fails late, in the unparser or at runtime.

**What we take.** Step/pipeline modularity with per-step settings and an
honest settings descriptor; the idea that *closure-capable virtualization* is
the coverage frontier; differential multi-interpreter testing; constant-array
rotation/wrapper diversity (we already have the pool equivalent, stronger).

### LuaObfuscatorV2

**Architecture.** Reads *Lua 5.1 bytecode* (via a deserializer), converts to a
custom VM IR, and emits the VM as Lua source assembled from per-opcode handler
*strings* with randomized opcode names; bytecode compression; string and
constant encryption; numeric mutations; an inliner.

**Strengths.** Letting the real compiler do the parsing is maximally robust on
syntax. Emitting handlers from string templates with per-build opcode names is
cheap polymorphism. Compressing bytecode before encryption shrinks payloads.

**Weaknesses (do not copy).**
- Lua 5.1 bytecode only — no Luau at all. Disqualifying for us.
- Work-in-progress; several passes are stubs.
- Operating on bytecode forfeits type annotations and source-level transforms
  (renaming is limited to what bytecode preserves).
- `load()`/`string.dump` reliance does not survive Roblox sandboxing.

**What we take.** Compress-before-encrypt as a payload-size habit; the idea
that numeric literals deserve per-build *arithmetic* encodings (we store
disguised doubles already; an exact integer split-and-fold path is still open
— see roadmap R7).

### Clyde

**Architecture.** TypeScript, from scratch: Lexer → Parser (full Luau grammar
incl. types, interpolation, compound assignment, `continue`) → AST passes
(rename, string encode, control-flow scramble) → **two** bytecode compilers
(stack VM and register VM) → generated interpreter + bootstrap template.
Payload: LZMA-compressed, base85-encoded, encrypted; per-proto keys
(`protoKeys`), S-box/helix/cascade custom ciphers, feature flags
(`opcodeShuffle`, `fakeHandlers`, `handlerNoise`, `antiDebug`, `antiTamper`,
`controlFlowFlattening`, `opcodeFusion`, `deadCodeInjection`, `customCipher`,
`stubCompression`, `vmNesting`), three levels, polymorphic seed.

**Strengths.** The register VM handles upvalues (`LOAD_UPVAL/STORE_UPVAL/
CLOSE_UPVAL`), varargs, tail calls, `NAMECALL`, `pcall` — full semantic
coverage inside the VM. The *feature-flag matrix with forced/disabled flags
per level* is a clean way to compose protection profiles. LZMA + base85 makes
payloads genuinely small.

**Weaknesses (do not copy).**
- Two parallel VMs double the implementation and the recognizable surface;
  one of them is always the weaker one.
- No test suite in the repository; correctness is asserted, not shown. For a
  tool whose only product is "same behaviour", that is disqualifying on its
  own — we keep our differential harness as the spine instead.
- Custom ciphers (S-box "helix/cascade") are home-brew stream ciphers layered
  on top of everything; none are authenticated. Tampering with the payload is
  detectable by nothing. Our AEAD pool is strictly stronger.
- Node/TS dependency and a bundled LZMA decoder in the artifact: heavy,
  fingerprintable, and a moving target for Roblox engine changes.
- `fakeHandlers`/`deadCodeInjection` are noise passes of exactly the kind our
  own design review rejected (dead arms are a fingerprint once a deobfuscator
  starts executing paths).

**What we take.** Closure/upvalue/vararg support *inside* the VM as the
coverage goal (R5); compression + dense textual encoding of sealed blobs
(R4); per-proto key separation (we already do per-region keys — extend the
AAD binding, R6); the flag-matrix idea maps onto our profiles.

### ScriptShield

**Architecture.** Python + PyQt GUI, orchestrator/plugin/profile machinery,
`luaparser` third-party AST, an 8 kLOC AST transformer (constant array, CFF,
dead-code injection, number obfuscation, string encryption, anti-debug, code
splitting), and a small **stack** VM with a *fixed* opcode numbering
(`LOAD_CONST = 0x01` …), emitted as a Lua runtime template.

**Strengths.** The best test culture of the five: one pytest file per
transformer, fixture-driven, plus integration tests. The plugin/dependency-
graph orchestrator is a real design for multi-file projects (checkpoints,
multiprocessing).

**Weaknesses (do not copy).**
- `luaparser` is Lua 5.1: Luau-only syntax breaks the tool, not the transform.
  Third-party parsers are a liability we already paid to avoid (our front end
  is ours).
- Fixed opcode numbers and a fixed stack VM: a deobfuscator written once works
  forever. The VM is the weakest of all references.
- Stack dispatch is also the slowest model; per-instruction table pushes
  dominate runtime.
- The GUI/orchestrator mass (checkpoint manager, stylesheets, dialogs) is
  scope that adds no protection.

**What we take.** Per-pass unit tests as a non-negotiable convention (we have
it; formalize pass-level golden tests in E2); per-transformer fixtures that
each pin one semantic hazard (we have the micro battery; extend it).

### Hercules (fork)

**Architecture.** ~620 lines of Lua text-processing modules: regex variable
renaming, pattern-injected "control flow", garbage insertion, opaque
predicates by template, `string.dump` + `load` bytecode wrapping.

**Weaknesses (all of it).** No AST: regex renaming breaks on shadowing,
strings, and `foo:bar()` sugar; `string.dump`/`load` do not exist for user
scripts on Roblox; injected garbage is pattern-recognizable instantly; no
tests. It exists in this study only as a negative example: *text-level
transforms and dump/load tricks are not an option.*

**What we take.** Nothing but the anti-example, recorded so nobody proposes
`load(string.dump(...))` "protection" later.

### Luaq (public docs only)

The documented surface is a **macro/directive layer**:
`LUAQ_OBFUSCATED` (compile-time flag + dead-branch removal), `LUAQ_INLINE`
(compile-time inlining, 256-node cap, then the body is protected like any
other code), `LUAQ_CRASH` (randomized crash paths), `LUAQ_ENCSTR/ENCNUM/
ENCFUNC` (per-literal compile-time encryption), `LUAQ_NO_VIRTUALIZE`
(per-function VM opt-out), `LUAQ_NO_UPVALUES`, `LUAQ_INDEX_TO_NUM`
(statically-known string keys → per-build random numeric keys), `LUAQ_LINE`,
comment directives (`--!luaq:no_virtualize` etc.), "aggressive optimizations"
(folding, DCE, simplification, register reuse) and "enhanced VM compression".

**What we take.**
- **Per-function annotations** (`--!couxobf: no_virtualize` / `virtualize`)
  are a direct, cheap usability win and a standard we should adopt (R8).
- **Index-to-number**: turning static table keys into per-build numeric keys
  is a real *structural* transform with zero runtime cost. We already protect
  keys by interning them into the sealed pool; the numeric-index variant is
  complementary for tables that must stay plain (serialization, iteration
  order visibility). Scoped carefully (only provably-static keys) — R9.
- Compile-time inlining before virtualization: small helpers inline into
  callers shrink glue code and make call graphs less obvious. Medium value,
  later phase (R10).
- Dead dev-branch removal keyed on a compile-time boolean: maps to our
  `strip_types`/optimizer story.

---

## A. Architecture comparison

Scored honestly: ✅ real and measured · ◐ partial/qualified · ✗ absent ·
n/a not applicable. "Us" is the state at commit `31b4843`.

| Axis | Prometheus | LuaObfV2 | Clyde | ScriptShield | Hercules | Luaq (docs) | **Us** |
|---|---|---|---|---|---|---|---|
| Lexer/parser | own, Lua5.1 (+◐Luau) | none (bytecode in) | own, full Luau | `luaparser` (5.1) | none (regex) | unknown, full Luau | **own, full Luau ✅** (types, interp, compound, continue) |
| AST transformations | step pipeline, 11 steps | few IR mutations | 3 passes | 1 transformer, ~10 passes | text templates | macros | **IR-level passes + AST branch inversion ◐** |
| Identifier renaming | 5 generators, scope-aware | via bytecode | rename pass | visitor mangling | regex (broken) | implied | **per-build stream, scope-aware ✅** |
| Constant protection | constant array + wrappers | constant encryption | per-proto keys | constant array | base64 strings | ENCSTR/ENCNUM macros | **AEAD pool + decoys + tickets ✅** |
| String protection | split + encrypt step | string encryption | string encoding pass | XOR/AES | base64 | ENCSTR | **sealed bank, per-occurrence tickets, cache policies ✅** |
| Number protection | NumbersToExpressions (AST) | numeric mutations | constant folding opt | number obfuscation | ✗ | ENCNUM | **pool disguises ✅; exact integer arithmetic encoding ✗** |
| Constant-pool design | one array, rotated/wrapped | encrypted table | K table per chunk | one array | n/a | n/a | **one sealed pool/artifact; per-group pools ✗** |
| Bytecode representation | custom byte stream | custom 32-bit instrs | number arrays (+LZMA) | int arrays | dumped Luau bytecode | custom (closed) | **per-group byte formats ✅** |
| VM architecture | register VM, closure-aware | register, template-built | stack + register | stack, fixed | n/a | custom (closed) | **register-based "woven", one shape ◐** |
| Opcode design | fixed set, shuffled numbers | per-build names | shuffled + fusion | **fixed numbers ✗** | n/a | closed | **permuted + aliases + cipher + per-group subset ✅** |
| Operand encoding | fixed widths | fixed | fixed | fixed | n/a | closed | **widths/masks/order/padding per group ✅ (best in class)** |
| Register/stack model | registers | registers | both | stack | n/a | closed | **registers (table `R`) ✅** |
| Control-flow flattening | VM dispatch only | ✗ | flag exists | CFF pass (AST) | fake blocks | not documented | **native funcs: always-on state machine ✅; VM: block permutation ✅; opaque arms ✗** |
| Opaque predicates | ✗ | ✗ | ✗ (dead code instead) | ✗ | templates | ✗ | **one tautology line ◐ (not a real predicate)** |
| Dead-code handling | ✗ | ✗ | deadCodeInjection (noise) | dead-code injection (noise) | garbage inserter | dev-branch removal | **decoy pool values ✅; no dead arms (deliberate)** |
| VM dispatch | while/if chain | if chain | switch/table | while/if | n/a | closed | **hashed bucket→closure call per instr ◐ (slow)** |
| Function/upvalue handling | proxies ✅ | via bytecode | in-VM upvalues ✅ | ✗ (no closures in VM) | n/a | NO_UPVALUES macro | **not virtualizable at all ✗ (biggest coverage gap)** |
| Metatable support | ◐ | ✅ (bytecode) | ✅ | ◐ | n/a | n/a | **✅ differential fixtures cover `__index` etc.** |
| Error handling | pcall passthrough | ◐ | pcall/xpcall opcodes | ◐ | n/a | CRASH macro | **✅ identical messages; pcall fixtures** |
| Luau compatibility | ◐ (stated unfinished) | ✗ | ✅ | ✗ (5.1 parser) | ✗ | ✅ | **✅ compile-validated per build** |
| Optimization passes | ✗ | constant mutation | folding flag | ✗ | ✗ | "aggressive optimizations" | **fold/copyprop/DSE/unreachable ✅** |
| Compression | ✗ | ✅ bytecode | LZMA+base85 ✅ | ✗ | ✗ | "enhanced VM compression" | **✗ (`\xHH` escapes, 4 chars/byte)** |
| Runtime overhead | high (table VM) | medium | high (stack)/med (reg) | very high | n/a | claims low | **high: 2 closure calls/instruction ◐** |
| Anti-tamper | debug.getinfo hash (Roblox-hostile) | ✗ | antiTamper flag | anti-debug | ✗ | CRASH | **AEAD tags + env/dump guards ✅ honest scope** |
| Build-time randomization | seed → names/encoding | per-build names | polymorphicSeed | ✗ mostly | ✗ | per-build indices | **17 domain-separated streams ✅ (best in class)** |
| Test coverage | Docker differential | run flag | none visible | strong pytest | none | n/a | **753 tests + differential corpus + reuse-audit ✅** |
| Failure modes | late unparser errors | WIP crashes | unknown | transform errors | silent breakage | n/a | **build-time validation + integrity walk + budget ✅** |

**Reading of the table.** We already lead on operand encoding, build-time
randomization, constant protection, and test culture. The references lead us
on four axes only: (1) in-VM closure/upvalue coverage, (2) payload density,
(3) dispatcher speed, (4) per-function user control. Everything else they do
we either do better or they should not be copied from (noise passes, home-brew
crypto, text-level hacks).

### Our current state, axis by axis (details the table compresses)

- **Pipeline.** `source → comments.prepare → parser → sema → ir.Lowerer →
  optimize (in lower_back) → classify → lower_back.reconstruct_protected →
  (VM plan/encode/integrity) → pool/bank seal → printer → verify (+ optional
  differential)`. Stages are modules; ordering and seeds live in `pipeline.py`.
- **VM.** One "woven" family, one dispatch shape: hashed-key bucket tables of
  handler closures; `op → key = f(op, seed, fmt) → bucket → closure()`.
  Per-group `FormatSpec` (op/reg/wide widths, padding, masks, field order,
  target mode abs/biased/rel/edges, opcode cipher, fusion rules, header
  layout). Per-group `OpcodeMap` with aliases and sparse numbering; per-group
  ISA subset from `required_ops`. Block permutation + in-block reorder.
  Build-time `integrity.payload` walk validates every payload against its own
  group's format.
- **Constants.** One sealed region per VM group plus one for the native code
  (R6), each with its own key, prefix, ticket mask, accessor and drawn decoder
  *shape* (R7), and each authenticated against the format that reads it.
  Strings that reach the bank are fragmented across shuffled pages and
  addressed per occurrence.
- **Native reconstruction.** Multi-block prototypes are emitted as a flattened
  state machine whose *shape* is drawn per function, not only its constants:
  the counter holds either a raw block id -- and arms compare one of five
  arithmetic images of it -- or an encoded image, in which case no encoding
  expression is emitted at all and arms compare the counter directly;
  dispatch is either a flat equality chain or a balanced binary search over
  the image; the driver loop is a `while` on the counter, an infinite loop
  exited with `break`, or a `repeat/until`. Arm order is shuffled on some
  functions. Single-block bodies stay straight-line.
- **Honest gaps (config-declared, not wired).** `opaque_predicates` emits one
  boundary tautology only; `vm_variety` is pinned to 1 in `pipeline.py` (the
  maximum profile's `vm_variety=3` is silently ignored — a real defect);
  pending fields today: `max_vm_depth, mixed_execution, handler_splitting,
  dispatcher_splitting, state_distribution, call_frame_obfuscation,
  encoded_pc, epoch_masks, chunking_level, lazy_decode, chunk_size,
  integrity_level, junk_level, identifier_polymorphism, fingerprint_reduction`.
- **Measurements (this checkout, seed 42).** hello.luau: 24 B → 17.7 KB
  (739×; fixed runtime floor dominates). inventory.luau: 22.2×. maze.luau:
  23.2×. reuse-audit hardened: numbering transfer 15 %, payload 0 %, shape
  0 %, arms 0 %; the `polymorphic` column is *identical* to `hardened`,
  proving `vm_variety` currently does nothing.

---

## B. Recommended unified architecture

Keep the pipeline skeleton — it is the right shape — and reorganize around
three principles the references demonstrate (and their failures reinforce):

1. **One IR, many backends.** Every protection decision operates on `FuncIR`,
   never on source text and never on Luau bytecode we do not own. Prometheus'
   late unparser failures, ScriptShield's parser ceiling and Hercules' regex
   damage are all consequences of violating this.

2. **A pass is a `(FuncIR, Rng, PassConfig) -> FuncIR` (or `FuncIR ->
   Bytecode`) with its own unit tests.** Nothing else touches randomness.
   This is what makes every transformation independently testable and every
   build structurally different.

3. **The VM is a family of interpreters generated from one template plus
   per-group descriptors — never several parallel VM implementations.**
   Clyde's dual VM shows the cost of the alternative. Structural variety must
   come from *descriptors* (formats, maps, keys, readers, dispatch keys), not
   from duplicated engines.

### Target pipeline

```
source
 ├─ comments.prepare (hash-comment policy)
 ├─ lexer/parser → AST                      [front end, ours]
 ├─ directives: --!couxobf: no_virtualize   [NEW R8, Luaq-inspired]
 ├─ sema (scopes, upvalues, used-globals)
 ├─ AST passes: branch_inversion, inline-small-helpers [R10, opt-in]
 ├─ ir.Lowerer → IRModule
 ├─ optimize (fold, copyprop, DSE, unreachable)   [exists]
 ├─ NEW pass slots, each unit-tested:
 │    pass.controlflow   (state-machine shaping, opaque arms, arm order)
 │    pass.predicates    (build-keyed opaque predicates, native + VM)
 │    pass.indexnum      (static table keys → per-build numeric keys, opt-in)
 ├─ classify (per-prototype decision, now honoring directives)
 ├─ vm.wiring.make_plan  (groups ≥1 again — R1)
 ├─ vm.encode            (exists; + closure-capable lowering later — R5)
 ├─ pool/bank seal       (exists; + dense blob encoding — R4, per-group AAD)
 ├─ lower_back           (native reconstruction + VM closures + guards)
 ├─ printer (+ optional minify)
 └─ verify: parse-back, forbidden APIs, integrity walk,
            differential execution, reuse-audit thresholds [R3]
```

### Structural-variety budget

"Every build different" is spent from a fixed budget of *independent* axes.
The current spend, measured by reuse-audit, is: numbering, payload encoding,
shape, arms, ISA subset, block order, reader geometry, pool/bank prefixes,
all names. The plan adds: group count, per-group dispatch keying, state
encoding per native function (exists), opaque-arm selection, blob alphabet.
Each new axis must show ≤ its predecessor's transfer score in reuse-audit
before it ships — that is the regression bar (E2).

---

## C. Prioritized improvement roadmap

P0 = correctness/honesty, P1 = highest protection-per-effort, P2 = coverage,
P3 = polish. Each item names the axes above.

| # | Item | Problem solved | Priority |
|---|---|---|---|
| R0 | Green baseline everywhere: test corpus must not require an external Luau checkout; add repo-local conformance fixtures | failing/erroring tests hide regressions | **P0** |
| R1 | Restore multi-group VMs: `vm_variety` actually drives `make_plan`; report and docs reflect it | dead knob, dishonest `maximum` profile, single recognizable VM pattern | **P0** |
| R2 | Real opaque predicates + opaque dispatch arms (build-keyed, never foldable, never dead) | `opaque_predicates` is a tautology today; docs admit the gap | **P1 — done** (VM tap + native split arms) |
| R3 | Regression automation: reuse-audit thresholds as a test; seeded differential fuzz battery | "detect and prevent regressions automatically" | **P0/P1** |
| R4 | Dense blob encoding: per-build 85-alphabet encoder for pool/bank/payload literals | `\xHH` = 4 chars/byte; hello.luau at 739×; size ceiling forces dropping real protection | **P1 — done** |
| R5 | Closure-capable virtualization (upvalues via accessor closures behind `vm_upvalues`; varargs via frame field; nested closures behind `vm_closures`) | our biggest coverage gap vs Prometheus/Clyde | **P2 — done: varargs, upvalues, and nested closures whether or not the children capture (151 of 201 corpus prototypes, up from 88)** |
| R6 | Per-group constant pools with group-format AAD binding | one recovered accessor currently yields all constants | **P2 — done** |
| R7 | Exact integer arithmetic number encoding (split/add/fold) behind `numeric_protection_level=2` | numbers currently only get float-safe disguises | **P2 — done** |
| R8 | `--!couxobf:` directives (`no_virtualize`, `virtualize`) | per-function user control, Luaq parity | **P2 — done** |
| R9 | Index-to-number pass for provably-static table keys (opt-in) | structural transform at zero runtime cost | **P3 — done** |
| R10 | Inline-small-helpers AST pass (opt-in, node cap) | glue-code reduction, Luaq parity | **P3** |
| R11 | Dispatcher speed option: inlined-chain dispatch for small groups | 2 closure calls/instruction is slow | **P2 — done** |
| R12 | Remove dead config surface; every remaining field either wired or gone (see G) | 15 pending fields erode trust in the report | **P1 — done** |
| R13 | Per-region pool decoder shape: draw how the decoder finds an entry, folds a ticket and dispatches a type byte | R6 gave every region its own key but the same decoder code, so one pattern-match gets them all | **P2 — done** |

Status: R0, R1, R2, R3, R4, R6, R7, R8, R9, R11, R12 and R13 are implemented and measured
(see `docs/benchmarks.md`); the fuzz battery is in
`tests/test_fuzz_differential.py`, and the reuse-audit's verdict is pinned
as a regression test in `tests/test_reuse_regression.py`.  Everything else
is as listed.  R12 removed thirteen inert fields (`junk_level`, `encoded_pc`,
`epoch_masks`, `max_vm_depth`, `mixed_execution`, `handler_splitting`,
`call_frame_obfuscation`, `dispatcher_splitting`, `state_distribution`,
`chunking_level`, `lazy_decode`, `chunk_size`, `integrity_level`), shrank the
VM-family and dispatcher selectors to what the tool actually emits, and wired
`opaque_predicates` to the R2 tap — so the default pending list is now
`identifier_polymorphism, fingerprint_reduction` only.

Deliberately **not** on the roadmap, with reasons (these are reference
techniques we reject): dead-code/fake-handler injection (Clyde/ScriptShield/
Hercules) — unreachable arms are a deobfuscation *aid* and a fingerprint, and
our decoy-pool approach buys the same confusion without emitting branches that
can never run; home-brew stream ciphers (Clyde) — unauthenticated, weaker than
our AEAD; `load(string.dump(...))` wrapping (Hercules) — unavailable on
Roblox; third-party parsers (ScriptShield) — Luau ceiling; anti-debug as
prevention — our docs already scope guards as detection/cost.

---

## D. Detailed implementation plan

### R0 — Self-contained test corpus (P0)

*Problem.* `tests/test_layout.py` errors without
`/tmp/luau-src-0.700/tests/conformance/*.luau`; 406 tests skip without the
toolchain. A checkout with no external state must run green.

*Reference.* ScriptShield's fixture-per-transformer convention; our own micro
battery already does this for semantics.

*Change.* Vendor a small `tests/fixtures/corpus/*.luau` set derived from our
examples plus hand-written multi-block/closure/vararg programs (written by
us, not copied from Luau). Test modules fall back to it when the external
corpus is absent.

*Cost/risk.* None. *Test.* `pytest` green in a clean checkout. *Default.*
n/a.

### R1 — Multi-group VMs again (P0)

*Problem.* `pipeline.py` pins `vm_variety=1`; the `maximum` profile's
`vm_variety=3` is silently ignored; reuse-audit shows `polymorphic == hardened`.

*Reference.* Our own earlier design (reviewer-analysis #3 measured groups of
19/10/7 handlers); Clyde's per-proto keying argues for per-group separation.

*Why better.* One interpreter per artifact means one recovered format reads
the whole file. N groups with distinct formats/opmaps/ciphers/readers force N
reconstructions and break "the VM pattern" as a single recognizable object —
the user's explicit goal.

*Change.* Pass `vm_variety` through `_build_once`; keep the single woven
family (the consolidation argument about duplicated handler surfaces still
holds — variety comes from descriptors, not engine clones). Budget guard:
each group costs ~10–19 KB, so the existing size-budget ladder already pays
for it (`vm_variety` is in `_BUDGET_TRIMS`). Update report lines and
SECURITY.md's stale "four state models" paragraph.

*Cost.* Output size +10–19 KB per extra group; build time linear.
*Compatibility.* None — groups are internal.
*Test.* `test_vm_variety_emits_n_groups` (assert N distinct format
descriptors, N readers, N entry names); reuse-audit polymorphic column must
stop matching hardened; differential fixture suite at variety=2,3.
*Default.* On at `maximum` (as the profile already promises); 1 at
hardened/balanced/compact.

### R2 — Real opaque predicates and opaque arms (P1) — **implemented**

*Problem.* Today's `opaque_predicates` emits
`if not ((op == op) and (pc >= 1) and (#code >= pc))` — a boundary check, not
a predicate. The review point #14 refused *provable* predicates ("anything we
can fold, a deobfuscator can fold"). The sound version is a predicate whose
truth the build knows from its own sealed data, evaluated at runtime from that
data.

*Reference.* ScriptShield/Hercules use opaque predicates as noise — rejected
in that form. The technique itself is standard; our version keys it to the
AEAD material so it cannot be constant-folded from source alone.

*As built (VM side).* The per-group format draws a **key tap**: a byte at a
build-known offset in the payload header's filler region (a byte the encoder
writes identically into every payload of the group). The dispatch key folds
that byte in — `band(bxor(op, salt, _pt), mask)` for the chain,
`band(bxor(bxor(op, salt), _pt) + bias, mask)` for the bank — where `_pt` is
read from the payload once per call. Because the tap value lives inside the
encrypted pool, the ladder/bank constants in the interpreter's text are an
image of the numbering under a salt the text does not carry: lifting the
interpreter alone no longer decodes the arms, and a matcher has to decrypt
the payload to recover the table. `bxor` stays bijective in `op`, so an
unassigned number still cannot collide with a real arm, and the tap costs one
byte read per call rather than per instruction. Drawn per group (~1 in 10
formats, whenever the header is a renumbered one), keyed into the reuse-audit
`shape` and the structural fingerprint, so a recovered tapped table does not
score as reuse of an untapped group.

*Native side (also built).* The flattened native driver gains *split arms*
at the same knob (`opaque_predicates`, rate-limited by
`control_flow_level`: 0.12 / 0.2 / 0.3 at levels 1–3, none at 0).  For a
drawn block, a second `elseif` joins the arm whose encoded state lies
outside the affine encoding's image of the block ids: the counter is only
ever assigned a block id, so the build can prove the arm unreachable while
a reader can only show it by solving the flattened CFG.  The decoy arm
carries a deep copy of the real block's last one-to-three statements,
drawn from the same IR — even under a bug that reached it, it executes
the same tail semantics and lands on the same successor.  No dead branch
ever exists; only a branch whose unreachability is work to prove.  The
drawn encoding (mode/salt/mul/modulus), the real states and the decoy
states are logged per prototype (`Reconstructor.split_log`) so the
exactly-one-satisfiable invariant is unit-proven symbolically over the
affine forms rather than asserted (`tests/test_split_arms.py`).

*Why better.* First genuine opaque predicate in the tool; keyed to sealed
data instead of algebraic identities; structurally per-build.

*Cost.* VM: one header byte read per call plus one extra `bxor` term in the
key (negligible — measured within the per-iteration noise band). Native (when
built): ≤ 2× size on the drawn arms only, rate-limited by `control_flow_level`.
*Compatibility.* None — the tap is inside the authenticated blob, so a tamper
of it is already a MAC failure.
*Test.* `tests/test_vm_dispatch.py` pins the tapped ladder/bank: the scramble
folds the payload term, the constants are the tapped image of the numbering
and not the salt-only image, and a forced-tap build executes byte-identical to
its source under the pinned toolchain.
*Default.* On (drawn) for renumbered headers.

### R3 — Regression automation (P0/P1)

*Problem.* Diversity can silently regress (it did: `vm_variety` was pinned
and nothing noticed until this study).

*Reference.* Our own `tools/reuse-audit.py` — promote it; ScriptShield's
per-transformer pytest convention.

*Change.*
- `tests/test_reuse_audit.py`: run the audit on `maze.luau`, assert hardened
  payload/shape/arms transfer ≤ 5 %, numbering ≤ 25 %; assert `polymorphic`
  (variety=3) differs from `hardened` in handler-count sequence.
- `tests/test_fuzz_differential.py`: seeded generator emitting randomized
  programs (arith exprs, if/while/for/repeat, tables, varargs, closures over
  locals via the native path, `pcall`, metatables) — build at hardened +
  maximum, run both sides, compare. 20 programs × 3 seeds, deterministic.
  Skips cleanly without the toolchain (like the rest).
- CI workflow (`.github/workflows/test.yml`): pytest matrix; a job that runs
  the differential battery with the pinned Luau tag via `setup-luau.sh`
  cache.

*Cost.* Test time only. *Risk.* None.
*Default.* n/a.

### R4 — Dense blob encoding (P1) — **implemented**

*Problem.* Sealed blobs ship as `\xHH` escapes (4 source chars per byte).
hello.luau grows 739×; the size ceiling makes the budget ladder drop real
protection on larger inputs.

*Reference.* Clyde (LZMA+base85) and Luaq ("enhanced VM compression"). We
take base85-class density, skip LZMA: a Luau LZMA decoder is large and
fingerprintable, while an alphabet decoder is ~12 lines.

*Design.* Per build, draw a permutation of an 85-char printable-safe alphabet
(no quote/backslash/newline, ASCII to stay `\xHH`-free). Emit blobs as
base85 over the alphabet (5 chars per 4 bytes: 1.25 chars/byte vs 4). The
alphabet is emitted as escaped chunks whose locals are declared in a
build-shuffled order and concatenated back in alphabet order, so the base
never appears contiguously and the declaration order carries no information.
Blobs covered: pool ciphertext, bank pages, VM payloads, edge tables -- all
of them ride the pool/bank runtimes, so the single decoder preamble serves
every blob.

*As built, and what the measurement corrected.* The data literals do shrink
by the expected ~3.2×, but sealed material is only ~10 % of a hardened
artifact -- the interpreter, the crypto module and the descriptor tables are
the other 90 %. Measured end-to-end saving is therefore ~1–4.5 % of total
size (hello 0.9 %, inventory 4.5 %, maze 3.7 % at equal protection), not the
45 % this section once hoped for. The decoder preamble costs a fixed ~1 KB,
so builds with < 512 bytes of sealed material keep hex and report
"dense-skipped" -- the draw happens, the overhead does not. The size target
the original estimate pointed at is really the *fixed* runtime costs, which
is a different (larger) piece of work.

*Cost.* Decode is one indexing pass per blob at load; load-time only.
*Compatibility.* None (pure data layer). *Tests.* `tests/test_dense.py`:
round trips per group shape, alphabet hygiene, the emitted decoder executed
under the pinned toolchain on odd lengths and 1 KB of random bytes, the
skip-threshold behaviour, and dense-vs-hex differential on a real example.
*Default.* On, with the threshold escape above; `Config.blob_encoding =
"dense" | "hex"` is wired through the API option surface and the web form.

### R5 — Closure-capable virtualization (P2 — varargs, upvalues and nested closures done)

*Problem.* `can_virtualize` refuses any prototype with upvalues, varargs, or
nested closures — i.e. most real Roblox code (callbacks, state objects).
Prometheus and Clyde both cross this line.

*As built (vararg increment).* The vararg refusal is gone. The entry point
already packed every argument the caller sent; it now stashes that pack in
the frame (one table write, the named-parameter count riding it as a field),
and the VM grows a `VARARG` handler that is just a slice of the pack —
`count < 0` packs every vararg into one register, exactly like CALL's
MULTIRET, with which it shares the biased-count encoding. Nothing outside the
call can observe the stash, which is precisely why varargs could cross the
boundary while upvalues — visible to real Luau closures outside the call —
still cannot. Coverage is measured in `tests/test_vm_varargs.py` (fixed reads
and nil padding, splice into calls and returns, `table.pack(...).n` bit-exact
including trailing nils, tail calls, multi-group, maximum profile, native↔VM
callers). The one honesty note it surfaced is pre-existing and documented:
`#` on a table with nil holes is undefined in Luau itself, and a table the VM
fills sequentially can report a different length than one the native compiler
builds with a size hint — the content is exact, the holey length is not
pinned, and code that needs the true count should use `table.pack(...).n`.

*As built (upvalue increment).* Upvalue reads and writes cross the boundary
behind `vm_upvalues` (default off), and not by the cell-table design sketched
below — a simpler mechanism subsumed it. The stub the entry point replaces a
capturing function with is emitted at the closure site, which puts it
lexically inside the scope owning the captured variables. It builds, per
upvalue, a getter and a setter closure over the same expression the native
reconstruction uses to reach that variable (the owner's register slot, or the
local holding that iteration's value or cell where Luau's semantics demand
one) and passes
the list as a third `enter` argument; `GETUPVAL`/`SETUPVAL` call through it.
Because the accessors target the very storage native siblings use, reads and
writes are live and consistent by construction — including a native write
landing between two of the child's reads, and two VM siblings sharing one
counter. The cell-table design would have rewritten the parent's accesses to
go through a cell; the accessor design needs no parent rewrite at all, and
per-iteration capture comes free because the stub is created per iteration
and captures the snapshot local -- or, where the closure writes the variable,
the cell the parent allocated at the declaration, which is what that local
holds. The one line that does not move: an upvalue
whose home prototype is itself virtualized has storage no Luau closure can
see, so the selector removes such prototypes — a fixpoint, since the relation
is circular. Today the fixpoint cannot fire (a home creates a closure, which
the encoder refuses); it is the guard for the closure increment. Coverage is
measured in `tests/test_vm_upvalues.py`: read-only capture, VM child writes
read by the native parent and the reverse, shared counter across a VM/native
sibling pair, per-iteration capture of a loop variable, two upvalues with a
local, capture composed with varargs, `pcall` through a VM closure,
relay-chained captures through native scopes, and the refusal paths.

*As built (nested closure increment).* A virtualized prototype may now create
closures of its own -- when the children it creates capture nothing. A child
with no upvalues needs nothing from the frame it was born in, so the
interpreter can hand out its entry stub itself: `CLOSURE d, pid` stores
`stubs[pid ^ row_mask]` in a register, and the stub is the same plain Luau
function the native reconstruction would have emitted at the closure site.
Two constraints come with it, and both are the point rather than the price.

The first: the children have to come into the VM with their parent. The
interpreter can name a descriptor row or nothing -- it has no function value
for a child left native -- so a virtualized prototype takes its whole
virtualizable subtree in with it, however small the children are. Refusing
the parent instead was the first implementation, and measuring it is what
changed the rule: a nested helper is almost always below the classifier's
size floor *on its own*, so "every child must already be selected" left the
flag able to prove itself only on functions whose helpers were large -- and a
comparator, a callback or a helper beside the loop that calls it is exactly
the small case. The other half of the rule is the refusal: a child that
cannot be built in the VM at all (it captures something a virtualized
ancestor owns) unselects its parent, and that unravels upwards from the
leaves, so a tree is all-or-nothing and the report prints the *child's*
refusal as the parent's reason. Deciding it takes no fixpoint, because
everything a prototype's decision depends on is a fact about its ancestors:
encodability is computed bottom-up, then the set is decided top-down. The second: a child
belongs to its parent's
*group*, because the parent's CLOSURE arm names this interpreter's entry
point, and the artifact carries no map from prototype to interpreter. With
`vm_variety > 1` a closure tree is therefore one indivisible unit, and the
group count is capped by the number of trees rather than the number of
prototypes: a request for three VMs against one tree is really a request for
one, and emitting two interpreters for one tree would be dead weight an
analyst could read for free.

One thing this increment had to get right that is not about closures at all.
Luau hoists a closure that captures nothing: `f == f` holds across iterations
of the loop that declares it, and across calls of the function containing it.
A stub built per execution answers that differently and silently -- nothing
raises, the comparison is simply false -- and the old code built one per
closure site for *every* virtualized prototype, including a leaf declared
inside a native loop. The stubs are now built once per prototype in the
prelude and keyed by descriptor row, so both paths agree with plain Luau.
Capturing prototypes are excluded from the table on purpose: their stub closes
over accessor closures built at the site, and Luau gives those a fresh closure
per execution anyway. That divergence predates this increment; sharing the
stub is what closes it.

*As built (the capturing half).* The line the increment above drew was "a
child that captures nothing", and the reason for it was sound: the variables a
capturing child names would have to live in a VM frame, which is a table no
Luau closure can see. What that argument missed is that one place *can* see
the frame -- the interpreter running the parent, which owns it. So the
accessor is built there instead of at a native closure site: `CLOSURE` looks
the child up in a capture table and, when it finds one, builds a getter and a
setter closing over `R[slot]` and hands the pair to the interpreter as the
child's upvalue list, exactly the list the native path builds. Three ways a
capture is served, because three things can be captured:

*a plain local of the parent's* -- live, not a copy. Both closures close over
the frame, so a write by either side is seen by the other, which is what a
captured variable means and what the accessor design already did for reads and
writes across the native boundary.

*a loop variable* -- Luau gives every iteration its own, so a closure declared
in the body captures *that* iteration's value while the frame slot keeps
moving. The accessor therefore closes over a cell holding a snapshot taken at
the moment the closure is created. This is the per-iteration cell, and it
lands exactly where the old sketch put it.

*an upvalue of the parent's* -- relayed, not re-derived. The interpreter hands
the child the parent's own accessor pair, so a chain of captures ends where
the native site built it however deep it started.

Two consequences worth stating. The stub is born inside the interpreter, whose
environment is not the parent's, so it is `setfenv`'d to the environment the
parent's frame was entered with. And it is built fresh every time `CLOSURE`
runs, where the non-capturing case hands out one shared stub: Luau gives a
capturing closure a new identity per evaluation and hoists a non-capturing
one, so the two paths have to differ or `f == f` starts lying.

One shape the snapshot does *not* reach, and the reason the cell exists: a
closure that *writes* the loop-body local it captured. Reading and writing
pull in opposite directions here -- a per-iteration copy is right for a
reader, and wrong for two closures sharing a counter within one iteration --
so a captured loop-body local is not represented by its register at all. It
becomes a cell: one table allocated at the declaration, which is the one place
that runs exactly once per iteration, whose single field is the variable, and
through which every access goes, the loop body's own included. A reader gets
the iteration's value because the table is the iteration's; a writer shares it
with every other closure of that iteration because they all captured the same
table. Both halves of the rule the old sketch had to choose between, from one
representation.

The rewrite is a pass over the finished body, because which locals a closure
captured is only known once it is finished, and it is confined to the range
where the register *is* the variable: a register is scratch before the
declaration -- a numeric `for` spends its preheader calling the coercion
helper with the register its body's first local is about to be handed -- and
scratch again after the block closes, when a call may use it as an argument
slot, which no rewrite can follow because the slot is a number in the operand
list rather than an operand.

`can_virtualize` grew two capability flags (`upvalues_ok`, `closures_ok`)
instead of a blanket refusal; the classifier still keeps its size floor for a
prototype standing on its own -- a child comes in under its parent rather than
scoring its way in -- and the cap that held every closure-creating prototype at
LIGHT now lifts with the flag. The one rule this increment had to *remove* is
the upvalue-home fixpoint: it existed because a closure capturing a
virtualized prototype's variable had nowhere to point, and the interpreter is
now somewhere to point it. R5b on its own keeps the rule.

*Measured.* Coverage on the repo corpus plus the examples -- 28 files, 201
prototypes, 7 693 IR instructions -- `maximum` profile, seed 41: 88 prototypes
(45.6 % of instructions) with both capability flags off, 118 (64.1 %) with
`vm_upvalues`, and 151 (69.2 %) with `vm_upvalues` *and* `vm_closures`. The
capturing half is worth more than the non-capturing one, which is the opposite
of what the ordering suggests -- `vm_closures` alone moved the corpus 117 ->
119 prototypes, because almost every closure in real code captures something.
The files that move are the ones written around callbacks: `closures.luau` 2 ->
9 prototypes (50 -> 148 instructions), `queue.luau` 6 -> 10, `parse.luau` 8 ->
10, `errors.luau` 4 -> 6, `inventory.luau` 4 -> 6.

One number in that table needed a fixture before it could be measured at all:
the corpus had no non-capturing nested helpers in it -- `closures.luau` is
deliberately a file of *capturing* closures -- so `tests/fixtures/corpus/helpers.luau`
was added as the other half of the pair, and on it alone the VM goes from 1
prototype (18 instructions) to 17 of 18 (225 of 363). Without that file the
corpus moves 117 -> 119, which is what the third increment measured on the day
it was written and why its selection rule changed the next day.

`tests/test_vm_closures.py` is the differential gate, 27 tests: a nested
helper, a comparator handed to `table.sort`, three levels of nesting, several
children from one parent, a loop-declared closure, a self-calling one,
multi-group and the `maximum` profile across seeds -- and for the capturing
half, a live read, a write the parent sees, two children sharing one variable,
per-iteration capture, a relay through a virtualized parent, a capture two
frames down, a closure that outlives the frame that built it, a fresh identity
per evaluation, a comparator called back from C, and the one refusal that is
left (`vm_closures` without `vm_upvalues`).

*Reference.* Prometheus' upvalue proxies; Clyde's `LOAD_UPVAL/STORE_UPVAL/
CLOSE_UPVAL` with an `openUVs` table. We did it our way, at the IR level, and
the accessors replaced both the proxies and the cells for reads/writes.

*Why better.* Virtualization coverage jumps from "leaf numeric code" to
"most application code" — the single largest protection gain available.

*Cost.* Two accessor closures per upvalue per call of a capturing stub, and
each upvalue access is an indirect call; prototypes without captures pass
`false` and pay nothing. That cost is why the flag defaults off.
*Compatibility risk.* Low for what ships — the fixture list above is the
gate — but the loop-body-local cell limitation (documented in SECURITY.md)
bounds which captures are safe. The frame holds no captured state, so there
is no second copy of an upvalue anywhere in the artifact for a dumper to find
or for semantics to disagree with.
*Test.* `tests/test_vm_upvalues.py`, differential against the source itself.

### R6 — Per-group pools (P2) — **implemented**

*Problem.* One pool per artifact: recovering one accessor yields every
constant (reviewer point #19).

*Reference.* Clyde's per-proto keys; reviewer-analysis #19 already scoped it.

*Change.* Each VM group seals its own pool with its own region key and AAD =
context + group fingerprint; the pool descriptor tables are fragmented per
group (we already fragment metadata). Native code keeps one shared pool.

*As built.* One sealed region per VM group plus one for everything that stayed
native, each with its own prefix, its own ticket mask and its own accessor, so
the regions are not visibly one runtime declared twice. Which region a constant
is interned into is decided by the prototype it belongs to, and the VM's own
payload reads go through the region that owns the prototype -- `prelude_source`
hands its expression callbacks the prototype id for exactly that. Every region
shares the one crypto module, so the split does not put a second decrypt
routine in the artifact.

*Measured.* `examples/maze.luau`, seed 41, `vm_variety=2`: three regions
(native, group 0, group 1) holding 32, 26 and 22 constants, +13 KB over the
single-pool build. The size ceiling (24x) gives up the second group on this
example, so multi-group builds are rarer in default configurations than the
knob suggests — which is a real limitation, not something the report hides.

*Cost.* +1 decrypt per group at load. *Risk.* Low — pool code is unit-tested.
*Test.* `test_a_blob_lifted_from_one_region_does_not_open_in_another` seals one
pool per region context and cross-opens every pair; the build-level test pins
that a `vm_variety=2` build really seals one region per group, that the
accessors and AADs differ, and that the report says how many there are.
*Default.* On when the artifact carries more than one VM group.  Splitting a
single group's constants out costs a whole runtime (~5 KB on `maze.luau`), and
the size ceiling pays for it by giving up the split arms, control-flow
flattening and edge indirection -- measured, that trade is a loss, so one
group keeps one pool and the split waits until there is something to split
between.

### R13 — Per-region pool decoder shape (P2) — **implemented**

*Problem.* R6 gave each region its own key, prefix, ticket mask and accessor,
but every region still ran *the same decoder code*: one offset table built in
`load()` from a walking `q`, one `bit32.bxor` against one 4-byte mask literal,
one if-chain on the type byte. Identifiers are drawn per build; the structure
is not. So an artifact with three regions carries three copies of one decoder
under different names, and a single pattern-match — or a single
deobfuscation script written against any artifact we have shipped — gets all
of them. That is the technique checklist's #24 ("different helper
implementations for equivalent operations", scored ⬜ — one implementation
each) landing on the pool, with reviewer point #19's split already in place
and the names already drawn: what is left is the shape.

*Reference.* The reference tools are worse here, not better: Prometheus,
Ironbrew-ish derivatives and Clyde each ship one decoder shape for everyone,
which is why "unpack the constants" scripts exist for them at all. The idea of
drawing a shape comes from our own R11 dispatcher work and from the driver
shapes in `lower_back.driver_shape_counts()` — the same reasoning, now applied
to the constant pool instead of the state machine: two artifacts should not
share recognisable machinery even when they share a design.

*Change.* Three axes, drawn per region from that region's own forked RNG, and
declared in one place (`ConstantPoolRuntime.SHAPES`) so the menu is auditable:

| axis | choices | what actually differs |
|---|---|---|
| `offsets` | `eager` / `scan` | `eager` builds the whole entry-offset table during `load()`, as before. `scan` keeps a cursor and walks the stream forward on demand, remembering each offset as it passes it — so the artifact never holds a table of every entry position, and `load()` no longer touches the whole blob. |
| `deticket` | `xor` / `split` / `sum` | All three are the same XOR of the same 32-bit mask. `xor` keeps the mask as one 4-byte literal (as before); `split` does two XORs with two literals whose XOR is the mask; `sum` does one XOR with the sum of two literals whose masked sum is the mask. In the last two the mask never appears as a literal at all. |
| `material` | `chain` / `table` | `chain` dispatches the type byte through the if-chain (as before); `table` dispatches it through a table of per-type reader closures, so the decoder body carries no type tests. |

Twelve combinations, all decoding the same pool. They are structural, not
cosmetic: two of them remove the mask literal, one removes the eager offset
table, one removes the type tests.

*As built.* The shape is drawn per region where the region's RNG is already
forked (`rng.fork("pool:" + tag)`), stored on the region, passed to
`ConstantPoolRuntime.emit()`, and printed per region in the report — a build
that drew `native (sum/table/eager), vm group 0 (sum/table/scan), vm group 1
(split/table/eager)` says so. Every region still shares the one crypto module,
so the split still does not put a second decrypt routine in the artifact.

*Measured.* All twelve shapes are checked against one sealed pool in Luau,
reading the slots forwards *and* backwards — the reverse order is the case the
`scan` shape has to get right, since it can only walk forward and must have
remembered a slot it already passed
(`test_every_drawn_decoder_shape_decodes_the_same_pool`).
`test_the_shape_draw_really_varies` pins that every axis really is drawn:
across 24 seeds, each of the three axes takes every value it can take. Size on
`examples/maze.luau` (seed 41, default profile): the twelve shapes span under
1 KB, which is inside the noise of the drawn identifier lengths — the draw is
free. Runtime: `scan` walks each entry once and memoises it, so it is O(1)
amortised per lookup and strictly less work up front than `eager`; `table`
trades the if-chain's average three compares for one index.

*What it does not buy.* The menu is fixed at twelve and it is written down in
this document, so an analyst who has read it knows the shapes exist. Varying
the shape does not raise the cost of the underlying attack — find the `load()`
call, dump the plaintext at its end — by one step; what it raises is the cost
of writing *one* script that works against two artifacts, and the probability
that a bytestream signature matches the family. The security still rests on
the AEAD and on R6's per-region binding, not here. The string bank's reader is
still one implementation (checklist #24 stays 🔶 for it), and the handlers are
still one implementation each.

*Cost.* None measurable. *Risk.* Low — the axis code is a pure restructuring
of one emitter and every combination is differentially tested. *Default.* On,
always: unlike R6's region split there is nothing to pay for it.
*Test.* `tests/test_constpool.py` (the two above) plus every existing pool
test, which now runs with a drawn shape rather than a fixed one.

### R7 — Exact integer arithmetic encoding (P2) — **implemented**

*Problem.* `numeric_protection_level=2` masked double bytes today; integers
can do better than storage-level disguise.

*Reference.* LuaObfuscatorV2 numeric mutations; Prometheus
NumbersToExpressions. Their versions rewrite AST expressions (visible,
foldable); ours stays in the pool layer.

*As built.* A pool entry for an exact-integer double with `|v| <= 2**53`
stores two 32-bit halves (`TAG_NUM_SPLIT`: signed hi, unsigned lo, 8 bytes
— the same footprint as the double) and the runtime rebuilds the value as
`hi * 2**32 + lo`. Every term is an exact double and the sum stays under
2^54, so the reconstruction is bit-exact by construction; the eligibility
rule (`_split_halves`) is what proves it, refusing non-integers, the
infinities, NaN, `|v| > 2**53` and negative zero (arithmetic cannot carry
the sign bit — `-0.0 + 0.0` is `+0.0`). Everything refused falls through
to the masked-double path, so level 2 is strictly stronger than level 1,
never weaker. A decoder that scans the blob for `string.unpack(">d")`
finds no bytes for split constants at all.

*Cost.* One extra unpack, one multiply and one add per split constant,
load-time only (the materializer path); zero runtime on cached policies.
*Compatibility.* None — exactness is unit-proven across the edge values
(2**53, 2**32 boundaries, negatives, ±0, NaN, 1e300) and by running a
protected build that prints every split constant under the pinned
toolchain (`tests/test_numeric_split.py`).
*Default.* On at level 2 (the `maximum` profile sets it).

### R8 — Directives (P2 — done)

*Problem.* Users cannot exempt a hot callback or force-protect one function.

*Reference.* Luaq `--!luaq:no_virtualize` / `LUAQ_NO_VIRTUALIZE`.

*Design.* A `--!couxobf:no_virtualize` or `--!couxobf:virtualize` comment
names the first function declared after it. `comments.find_directives`
scans with the same string-aware pass the rest of the module uses, so a
directive-shaped string or long comment is not a directive; the classifier
binds each one to a prototype and overrides the score. `no_virtualize`
keeps the function native whatever its score; `virtualize` ranks the
function ahead of the budget so an explicit request is the last thing the
budget gives up, and lifts a trivial function past the node floor.

Two honesty rules, because a directive that quietly did nothing is the same
dead knob the rest of this tool removes:

* An unknown `--!couxobf:<name>` fails the build and names the valid
  spellings (Luaq's reserved-prefix lesson).
* A directive the config or the VM overrode is reported as ignored, not
  implied to have run: a `virtualize` with virtualization disabled, on the
  main chunk, on a function that captures upvalues (the VM has no closure
  support yet — R5), or with no function after it all lands under
  `ignored` in the report's `source directives` line.

The directive never lifts what the VM cannot represent — the closure cap
and the configured level ceiling still stand — because it is a request
about *which* functions run in the VM, not a licence to ignore the VM's
limits.

*Cost.* Zero runtime. *Risk.* Directive extraction never touches string
contents — the scanner is string-aware, and the build re-parses the prepared
source anyway. Tests: `tests/test_directives.py`.
*Default.* On (directives are read whenever present; no config needed).

### R9 — Index-to-number (P3 — done)

*Problem.* Table keys are protected by interning, but the key strings still
ride the encrypted constant pool: break the pool once and the shape of every
local record comes with it.

*Reference.* Luaq `LUAQ_INDEX_TO_NUM`.

*As built.* `index_to_num` (opt-in, CLI `--index-to-num`) rewrites the keys
of provably-static local tables to per-build numeric handles, before lowering
-- so the keys are small integers and the strings never reach the pool at
all.  `couxobf/index_to_num.py` owns the pass.  The safety rule is a strict
whitelist, not a heuristic: the table must be a plain local bound once to
a literal-string-key constructor (no array part, no computed keys), never
reassigned, never captured as an upvalue, and every use of it anywhere in the
program must be `t.name` or `t["literal"]` -- checked by resolving every
`Name` node to its symbol and inspecting the parent node.  Any other parent
(a call argument, a return, an aliasing assignment, a dynamic index, a method
call, an operator operand) declines the table.  Because the pass only accepts
tables whose whole shape it can see, the key set is exactly the union of the
constructor's keys and the access sites' keys, and the per-build bijection
covers all of it.  A table bows out with `--!couxobf:no_index_to_num` above
its declaration (R8 directive syntax).

*Cost.* Zero at runtime -- numeric indexing is if anything marginally faster
than string indexing, and the pass removes work from table-key interning.
*Risk.* Contained by the whitelist and by being opt-in: the default build is
byte-for-byte what it was before (a corpus-wide run rewrote 0 tables and
declined 7, with every build still verifying).  Tests: `tests/
test_index_to_num.py` (23), including the discriminating check that the keys
leave the lowered constant pool and per-seed handle agreement/disagreement.
*Default.* Off (`index_to_num = false`).

### R10 — Inline small helpers (P3)

*Reference.* Luaq `LUAQ_INLINE`, 256-node cap.

*Design.* AST pass before lowering: `local function` used only in call
positions, body ≤ 64 nodes, no upvalue writes, gets inlined at call sites
with fresh registers; the original is dropped. Opt-in.

*Cost.* Code size up where inlined; call graph less obvious.
*Default.* Off initially.

### R11 — Inlined-chain dispatch for small groups (P2) — **implemented**

*Problem.* The woven dispatcher calls a closure per instruction (bucket
lookup + call + `_pack` on returns). That is the dominant VM overhead.

*Reference.* The historical `nested_if` shape we removed was fast but
recognizable; the fix is to keep it unrecognizable.

*Design.* For groups with ≤ 24 arms, emit the dispatch as a permuted
`if/elseif` chain with handler bodies *inlined* (no closure bank), keeping
the per-build keying, arm order, and reader. Larger groups keep the bank.
Which shape a group gets is drawn, so the artifact can hold both.

*As built.* `FormatSpec.dispatch_shape ∈ {bank, chain}` is drawn per group.
The chain decodes one scramble key per instruction
(`band(bxor(op, salt), mask)`; `bxor` is a bijection, so an unassigned opcode
number can never collide with a real arm) and walks a permuted ladder with
the handler bodies inlined, falling through to the same neutral error the
bank uses. Bank and chain share the handler bodies, the readers, the opaque
tripwire and the entry-guard injection, so the two are genuinely the same VM
behind two dispatch front-ends. A companion axis,
`FormatSpec.inline_reads`, spells the operand arithmetic at each read site
instead of calling the generated readers; it measures within noise (Luau
calls are cheap; longer handlers cost what the calls saved) and is kept for
the structural variety, drawn 50/50.

*Measured.* maze hardened 9.0 s → 6.4 s (≈30 %) against the closure bank, at
≈1–3 % output growth; see `docs/benchmarks.md`. `test_vm_dispatch` runs both
shapes through the routing and trace machinery; the reuse-audit keys on
`dispatch_shape` and `inline_reads` so a recovered table from one shape does
not score as reuse of the other.

### R12 — Dead-config cleanup (P1)

See section G. Every field either gets wired (R1/R2 cover
`state_distribution` semantics, `opaque_predicates`, `vm_variety`) or leaves
the dataclass, CLI and docs together, in one commit, with the report's
pending list shrinking to empty.

---

## E. Test and benchmark plan

### E1. Semantic fixtures (grow the micro battery)

Add, each pinning one hazard the new work touches:
closure-over-loop-local, two closures sharing an upvalue, VM child writing an
upvalue read by native parent, varargs through a VM function
(`select('#')` and table.pack shapes), numeric-for with float step through a
flattened native function, state-machine function raising through `pcall`,
directive-bound functions, base85 blobs at lengths 1..7, per-group pool swap
(negative test), index-to-num negative cases (table escapes via call).

### E2. Diversity regression (the reuse-audit contract)

`tests/test_reuse_audit.py` pins: hardened vs hardened transfers — payload
≤ 5 %, shape ≤ 5 %, arms ≤ 5 %, numbering ≤ 25 %; polymorphic (variety 3)
must additionally differ from hardened in per-build handler-count sequence.
Any future change that makes builds more similar fails CI with a number in
the assertion message. This is the automatic regression detector the request
asks for.

### E3. Benchmarks

`tools/bench.py` (new): for each example, run original vs protected
(profiles compact/hardened/maximum) under the pinned toolchain, median of 5,
report: wall time ratio, output bytes, pool decrypt ms. Baseline recorded in
`docs/benchmarks.md` before each P-wave lands; a change that moves the
hardened time ratio by > 15 % or output size by > 10 % must be explained in
the commit.

### E4. Build-time budget

`pytest` wall time stays under ~6 min on 2 cores; differential fuzz battery
capped at 60 runs; fuzz seeds pinned.

### E5. Validation hooks already in place (kept)

parse-back, forbidden-API check, helper uniqueness, integrity walk, AEAD
tags, uniform error messages, no-marker assertions (no `pc`, `R`, `K`,
`stack`, `opcode`, `_k` prefixes, or old helper names in output).

---

## F. Changes to existing modules (concrete)

| Module | Change | Wave |
|---|---|---|
| `pipeline.py` | stop pinning `vm_variety`; pass config value; report N groups honestly; docstring fixes | W1 (R1) |
| `vm/wiring.py` | already group-capable; add per-group pool hooks (R6), dispatch-shape draw for R11 | W1/W3 |
| `vm/runtime.py` | payload-header key taps folded into the ladder/bank dispatch key (R2 VM side, done); inlined-chain emitter (R11) | W2/W3 |
| `lower_back.py` | split-arm emission in `_proto_body` (R2 native side); directive bindings threaded to classifier; per-group pool wiring | W2 |
| `comments.py` | `--!couxobf:` directive extraction (R8) | W2 |
| `classify.py` | honor directives; capability-set aware (R5) | W2/W3 |
| `constpool.py`, `runtime/constpool_runtime.py`, `strings/bank.py`, `runtime/stringbank_runtime.py` | dense alphabet blob layer behind one shared encoder module `couxobf/encode85.py` (R4); exact-int numeric path (R7) | W2 |
| `vm/encode.py`, `vm/isa.py` | upvalue/vararg opcodes + cell lowering (R5) | W3 |
| `config.py` | ~~wire or delete (R12)~~ done: 13 inert fields removed, selectors shrunk, `opaque_predicates` wired to the R2 tap; add `vm_closures`, `index_to_num`, `inline_helpers` | W1–W3 |
| `docs/SECURITY.md` | fix stale "four state models / three dispatch shapes" paragraph once R1 lands | W1 |
| `tests/` | corpus fixtures (R0), reuse-audit contract (R3), fuzz battery (R3), new micro fixtures (E1) | W0–W3 |
| `tools/bench.py` | new (E3) | W1 |
| `.github/workflows/test.yml` | new CI (R3) | W1 |

Waves: **W0** baseline + R0; **W1** R1+R12a+benchmarks; **W2** R2+R4+R3;
**W3** R5+R6+R11; **W4** R7–R10. Each wave ends with the full suite green
and the reuse-audit contract passing.

---

## G. Parts to remove

Removed because they add surface without protection, each with the reason.
**All of items 1–3 below are now implemented (R12):** the fields left the
dataclass, the CLI choice lists, the web option surface and the profile
constructors in one commit, and the pending list dropped from fifteen names
to two (`identifier_polymorphism`, `fingerprint_reduction` — genuinely
unbuilt).

1. **`Config.junk_level`, `encoded_pc`, `epoch_masks`** — declared since the
   first design, never wired, and the project's own review concluded junk
   arms and dead padding are fingerprints, not protection (review points #14,
   #15). Remove from config/CLI/docs. (If a future need appears it gets
   designed as live-arm variety, which R2/R11 provide.)
2. **`Config.max_vm_depth`, `mixed_execution`, `handler_splitting`,
   `call_frame_obfuscation`, `dispatcher_splitting`, `state_distribution`** —
   semantics absorbed: there is one interpreter family, one artifact-level
   mix, and splitting concepts that presuppose multiple engine clones we
   deliberately do not build. Removing them empties the pending list along
   with `chunking_level/lazy_decode/chunk_size` (lazy decode is already what
   the pool does; "chunking" has no design behind it) and `integrity_level`
   (the AEAD tag/hash choice is not a user-facing safety dial — the tag is
   always verified).
3. **The `VMFamily`/`DispatcherFamily` multi-member enums shrink** to what
   exists (`woven` + `mixed`-as-don't-care), kept loadable for saved configs
   but no longer advertised as choices; the CLI `--vm-family/--dispatcher`
   choice lists shrink to match. This is honest surface reduction — the
   alternative is ten names for one thing.
4. **`interpreter_source`'s `trace` plumbing stays** (tests use it) — listed
   here only because it looks removable and is not.
5. **Hercules-style and dump/load patterns** — not in the code, but recorded
   as rejected so they are never added.

What we explicitly keep although it looks redundant: the decoy pool entries
(they are data, not dead code, and are measured), the fingerprint AAD binding
(it is authenticated, not cosmetic), the single-tautology "opaque" line (it
doubles as a pc/op tripwire; it is replaced, not merely deleted, by R2).

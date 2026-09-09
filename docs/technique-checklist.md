# Technique checklist

All 80 points, each checked against what this build actually does. Every claim
below was measured on the artifact or read out of the code at commit `609c9e1`
— not inferred from intent. Where the measurement contradicted an earlier
assumption, the measurement is what is written here.

**Legend**

| Mark | Meaning |
| --- | --- |
| ✅ | Implemented, and verified to have an effect |
| ⭐ | Implemented *and improved beyond the point as written* |
| 🔶 | Partially implemented — the gap is stated |
| ⬜ | Not implemented |

**Tally: 26 done · 20 partial · 34 not built.** Of the 26 done, 16 are ✅ and 10 are ⭐ (implemented and improved beyond the point as written). All 80 points are scored exactly once.

Two standing caveats that apply to the whole document. Client-side
obfuscation raises the cost of reversing; it does not make reversing
impossible, and nothing here should be read as claiming otherwise. And
"verified" means a test or a measurement exists — it never means the technique
is unbreakable.

---

## 1. Selective virtualization

| # | Technique | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Virtualize only selected high-value functions | ⭐ | Five levels (`none`/`light`/`medium`/`heavy`/`maximum`) with size floors, plus per-function refusals for upvalues, closures, the main chunk and varargs. `max_vm_functions` caps the total — measured on `inventory.luau`: uncapped 3/7, capped at 1 → 1/7, capped at 0 → 0/7. Improved beyond the point: selection is not merely "high-value functions", it is a per-function decision with a size floor and an explicit refusal reason recorded in the report. |
| 22 | Never recursively virtualize generated VM code | ✅ | The interpreter is emitted as plain Luau source; the main chunk is never virtualized, so generated code cannot re-enter the lowering path. |
| 80 | Hybrid native/virtual execution | ⬜ | `mixed_execution` is declared but inert. A function is either wholly native or wholly in the VM. |
| 77 | Randomize whether an operation is native, VM, or hybrid | ⬜ | No per-operation boundary exists to randomize. |

## 2. VM encoding and dispatch

| # | Technique | Status | Evidence |
| --- | --- | --- | --- |
| 3 | Separate bytecode from the dispatcher | ✅ | The payload is a sealed, MAC'd blob; the interpreter is emitted separately with this build's opcode numbers inlined. Nothing in the interpreter reveals the wire format. |
| 5 | Randomize opcode semantics every build | ⭐ | `OpcodeMap.shuffled` per build from the `opcodes` stream. Measured: 60 seeds → 60 distinct bytecodes, 0 integrity failures. Improved: the permutation comes from a domain-separated stream, not a shared one. |
| 8 | Multiple dispatcher styles | ⭐ | `nested_if`, `decision_tree`, `bucket`, plus `mixed` which draws per build. Measured interpreter sizes on one opcode map: 9680 / 18819 / 10294 bytes. Improved: bucket geometry is per-build too (`buckets = 4 + seed%5`, odd multiplier), so two bucket dispatchers are not structurally identical. |
| 76 | Randomize dispatch strategy per function | ✅ | `dispatcher_family="mixed"` resolves through the `dispatch` stream. |
| 78 | Several VM families | ✅ | `register`, `accumulator`, `stack`, `hybrid`. Measured output sizes with `--min-nodes 1`: 18705 / 19155 / 22678 / 21016 bytes. |
| 79 | Select family per build/function using the build RNG | 🔶 | Per build, but by user choice. Only the *dispatcher* is drawn from the RNG; the family is not. |
| 75 | Randomize register-vs-stack decisions | 🔶 | Four families exist; the choice is not randomized per build. |
| 2 | Multiple VM instruction encodings per build | ⬜ | One family per build. A devirtualizer written for that build's family generalizes across the whole artifact. |
| 70 | No permanent VM ABI | 🔶 | Opcode numbering permutes per build, but the bytecode header (`<BBHHH`, 8 bytes) and the register/wide ordering are fixed across every build. |
| 71 | Randomize opcode count | ⬜ | 47 opcodes, fixed. Only their numbering moves. |
| 72 | Randomize instruction width | ⬜ | Widths are fixed per opcode (1, 2, 3, 4, 5, 6 and 8 bytes across the ISA) and identical in every build. |
| 73 | Randomize operand width | ⬜ | Registers are always 1 byte, wides always 2. |
| 74 | Randomize operand ordering | ⬜ | `operand_randomization` is declared but inert. Operands are emitted in `FORMATS[op].regs` order. |
| 6 | Split into micro-ops, then randomly fuse | ⬜ | `instruction_fusion` and `super_instructions` are inert. |
| 4 | Encrypt/encode operands independently | ⬜ | Operands are plain bytes inside the sealed blob. The blob is authenticated as a whole; operands are not individually encoded. |
| 7 | Relative/indirect instruction addressing | ⬜ | `entry` and jump targets are absolute, including the 8-byte header. |
| 9 | Periodically mutate VM state representation | ⬜ | `state_distribution` is inert. |
| 10 | Avoid a single central VM state table | ⬜ | One register file per frame. |
| 33 | Randomize instruction ordering where dependencies permit | 🔶 | Block *layout* is permuted (60 permutations → 60 distinct bytecodes, +141 bytes, 28/28 corpus files still correct). Instructions within a block are not reordered. |
| 18 | Encode control-flow edges separately from instruction data | ⬜ | Jump targets live inside the instruction stream. |

## 3. Constants, strings, keys

| # | Technique | Status | Evidence |
| --- | --- | --- | --- |
| 11 | Hide constants behind the vault; don't assume encryption prevents runtime extraction | ⭐ | ChaCha20-Poly1305 sealed pool. Improved: the limitation is stated rather than glossed — the report and docs both say a determined analyst can hook the accessor at runtime, because confidentiality and tamper-resistance are different properties. |
| 12 | Per-function / per-region keys | ⭐ | `KeyMaterial.region_key(purpose, region)` over six purposes, with 17 domain-separated streams behind it. Improved this build: the emitted *names* are now per-build too (see #16). |
| 13 | Per-literal handles and randomized reconstruction order | ✅ | Per-occurrence tickets, a page permutation, and an LCG mask applied before encryption. Measured on `inventory.luau`: 13/13 source string literals absent from the output. |
| 42 | Decode only the currently needed region | ✅ | Strings resolve per occurrence through a ticket; the VM blob is the exception (see #41). |
| 43 | Keep plaintext lifetime short | ✅ | Default cache policy is `none`, so a decoded string is not retained. |
| 44 | none / bounded plaintext caching | ⭐ | Three policies. Improved: `bounded_cache_size` is now reachable from the UI and was previously a knob with no control. |
| 26 | Randomize table layouts and index mappings | 🔶 | Pool layout and string pages are keyed and permuted; the descriptor table shape is not. |
| 27 | Several equivalent arithmetic encodings for numbers | ⬜ | `numeric_protection_level` is inert. Numbers are stored in the pool as-is. |
| 28 | Don't encode everything | 🔶 | Constants are interned selectively and most code is left untouched, but which values are protected is not itself randomized. |
| 29 | Randomize which values receive protection | ⬜ | The selection is deterministic given the source. |
| 49 | Don't put all integrity constants together | ⬜ | Key, nonce and tag are emitted adjacent in the pool runtime. |

## 4. Names, helpers, fingerprints

| # | Technique | Status | Evidence |
| --- | --- | --- | --- |
| 16 | Break obvious names (`R0`, `R1`, `stack`, `pc`, `opcode`) | 🔶 | `stack`, `sp`, `acc`, `code`, `exec`, `enter`, `call`, `getfenv` are per-build. **Measured gap:** `pc` appears 228 times in a maximum-profile build, and `R`/`K`/`E` are literal inside the interpreter. `R0`/`R1` appear 0 times. |
| 39 | Build-specific structural fingerprint | 🔶 | Per-build name prefixes now exist (see #69), but there is no deliberate marker that lets our own tooling recognize its output. |
| 69 | Continuously change the generated format | ⭐ | **Improved this build.** The pool and bank prefixes were the constants `_kQ` and `_kS`, identical in every build ever produced — `_kQ` alone appears 115 times in a typical output. Each build now draws its own: 12 builds produced 24 prefixes, all distinct, none stable. |
| 25 | Avoid repeated decoder boilerplate | ✅ | Measured on a maximum build: 30 long string literals, 30 distinct, 0 repeated. |
| 23 | Randomize helper placement | ⬜ | **Known remaining fingerprint.** `_kpack`, `_kunpk`, `_kapp`, `_kiter`, `_kiterpack`, `_kitercheck` are fixed in every build and always sit in the same position in the prelude. They are tracked in `lower_back.EMITTED_HELPERS`, which is what randomizing them needs. |
| 24 | Different helper implementations for equivalent operations | ⬜ | One implementation each. |
| 40 | Avoid a recognizable VM → decrypt → execute sequence | ⬜ | The prelude order is fixed: crypto runtime, constant pool, helpers, body. |

## 5. Control flow

| # | Technique | Status | Evidence |
| --- | --- | --- | --- |
| 20 | Control-flow flattening around VM boundaries | ⬜ | `control_flow_level` is inert. |
| 19 | Opaque predicates, used sparingly | ⬜ | The capability does not exist, so neither does the over-use the point warns about. `predicates` has its own randomness stream ready for it. |
| 34 | Generate equivalent AST forms before the main pass | ⬜ | No pre-pass rewriting. |
| 35 | Randomize boolean / control-flow formulations | ⬜ | Conditions are emitted as parsed. |
| 14 | Decoy constants and instructions | ⬜ | `decoys` and `junk_level` are inert — deliberately, since §13.1 of the spec forbids padding output with dead code as a substitute for structural diversity. |
| 15 | Randomize register allocation independently from source renaming | ⬜ | Registers are allocated deterministically; renaming is separate but registers are not permuted. |
| 17 | Split VM metadata among several structures | 🔶 | The descriptor was reduced to `{code, consts}` — `entry` and `nparams` are gone from the plaintext (`grep -c 'entry=\|nparams='` → 0) and now live inside the MAC'd blob. |

## 6. Integrity

| # | Technique | Status | Evidence |
| --- | --- | --- | --- |
| 45 | Don't claim anti-tamper from hashing alone | ✅ | Documented, not faked. Data tamper-resistance is real and measured; **code** tamper-resistance is not achievable in client-side Luau and the docs say so rather than implying otherwise. |
| 47 | Make integrity failures indistinguishable from ordinary failures | ✅ | **Fixed this build.** All five `error()` sites across both runtimes now raise one identical message. A test asserts the set of distinct `error(...)` call sites has size 1. |
| 48 | Avoid obvious strings (`"integrity"`, `"invalid instruction"`, `"VM error"`) | ✅ | **Fixed this build.** Measured on production output, all zero: `integrity`, `invalid instruction`, `VM error`, `failed authentication`, `authentication`, `tamper`, `checksum`, `constant pool`, `string bank`, `protected payload`. Three of those previously said "failed authentication", which named the check and confirmed the edit had been noticed. |
| 46 | Integrity checks at multiple semantic boundaries | ⬜ | One MAC per blob, verified once on first load. |
| 50 | Differential tests against unprotected execution | ⭐ | 18 differential tests, plus the web suite executing all four VM families × three dispatcher shapes and comparing to the original. Measured: 12/12 builds of `inventory.luau` byte-identical in output. |

## 7. Semantics coverage

| # | Technique | Status | Evidence | Test count |
| --- | --- | --- | --- | --- |
| 21 | Preserve native Luau semantics | ✅ | Full lexer → parser → sema → IR pipeline; 1240 passing tests. | — |
| 51 | Test closures heavily | 🔶 | Present, not heavy. | 8 |
| 52 | Test upvalues heavily | 🔶 | Same 8. | (shared) |
| 53 | Test multiple returns | 🔶 | `RETURNMULTI` semantics are covered, including the splice. | 7 |
| 54 | Test varargs | 🔶 | Covered, though vararg functions are refused for virtualization. | (shared) |
| 55 | Test `break`, `continue`, `return`, nested loops | 🔶 | Present. | 8 |
| 56 | Test metamethods | 🔶 | Present. | 5 |
| 57 | Test method calls and `NAMECALL` | 🔶 | `SELF` semantics mirrored from `lower_back`. | (shared) |
| 58 | Test coroutine / yield behaviour | ⬜ | **Zero tests.** `coroutine` appears in the codebase only as an entry in the globals whitelist in `sema.py`. Not VM-supported, not tested. | 0 |
| 59 | Test `nil`, `false`, `0`, `NaN`, infinities, int/float edges | 🔶 | Fold rules are careful (no folding of CONCAT/LEN/comparisons, `bool` excluded, `-0.0` not merged into `0.0`), but only one named edge-case test. | 1 |
| 60 | Test Roblox APIs without executing untrusted source | ⬜ | `roblox_mode` is inert. Compile-only validation is in place, which is the part that matters for safety. | — |

## 8. Measurement and self-attack

| # | Technique | Status | Evidence |
| --- | --- | --- | --- |
| 61 | Benchmark every protection individually | 🔶 | The cost report gives per-technique sizes and counts (67 lines for a maximum build). Runtime overhead is measured for some — VM dispatch is ~10× on 400k instructions — but not for each technique. |
| 63 | Don't blindly maximize output size | 🔶 | The principle is followed and documented, but nothing enforces it. `hello.luau` currently grows 515×, which is its own fingerprint. |
| 62 | Reject transformations with disproportionate overhead | ⬜ | `max_output_growth` is inert. |
| 64 | Mutation testing against our own deobfuscator | ⬜ | No deobfuscator exists to mutate against. |
| 65 | Automated deobfuscation benchmark | ⬜ | — |
| 66 | Measure recoverability of identifiers, strings, constants, CFGs, opcodes | ⬜ | The report measures sizes and counts, not recoverability. |
| 67 | Multiple independent deobfuscators attacking each build | ⬜ | — |
| 68 | Regression tests when a tool recovers something | ⬜ | The practice exists — every defect found by measurement became a test — but there is no analysis tool yet to drive it. |

## 9. Randomness and pipeline discipline

| # | Technique | Status | Evidence |
| --- | --- | --- | --- |
| 30 | Separate randomness domain per transformation stage | ⭐ | **17 domains**, not the 12 previously recorded: `identifiers`, `names-final`, `cfg`, `predicates`, `constants`, `strings`, `vm`, `opcodes`, `operands`, `registers`, `handlers`, `dispatch`, `chunks`, `integrity`, `decoys`, `emission`, `pc`. Improved: five of these (`operands`, `registers`, `predicates`, `chunks`, `names-final`) are reserved for techniques that do not exist yet, so adding them will not require reusing a stream. |
| 31 | Never reuse release seeds | ✅ | A fresh 128-bit `secrets.token_bytes(16)` per request; a pinned seed is hashed through SHA-256 rather than packed, so seeds differing by one bit diverge completely. |
| 32 | Seed influences structure, not just constants | ⭐ | Measured: four seeds on `maze.luau` gave 27537 / 27452 / 27586 / 30575 bytes, four distinct sha256, and different dispatcher shapes (`nested_if`/`bucket`/`bucket`/`nested_if`). Improved this build: names are structural too. |
| 36 | Normalize first, then transform the AST | ✅ | No regex-based source transformation anywhere in the pipeline. |
| 37 | Reparse after major transformations | ✅ | `validate_output` reparses the emitted source and counts AST nodes before anything else. |
| 38 | Final lexical renaming last | ✅ | Renaming happens at emission through `NameGenerator`, after all structural work. |
| 41 | Interleave decoding with execution | 🔶 | True for strings (per-occurrence tickets, lazily resolved). Not for the VM blob, which is decrypted in full on first entry. |

---

## The 18-stage pipeline

What the requested pipeline maps to, stage by stage.

| Stage | State |
| --- | --- |
| Source | ✅ `couxobf/parser.py` |
| AST normalization | ✅ `couxobf/sema.py` |
| Semantic-preserving transforms | 🔶 optimization only; no equivalent-form rewriting (#34, #35) |
| Identifier / register randomization | 🔶 identifiers yes (#38), registers no (#15) |
| CFG transformation | 🔶 block layout permutation only (#33); no flattening (#20), no edge indirection (#18) |
| Select high-value functions | ✅ #1 |
| AST → custom IR | ✅ `couxobf/ir.py` — blocks with ids, preds/succs, liveness |
| IR optimization | ✅ `couxobf/optimize.py` |
| Instruction fusion | ⬜ #6 |
| Per-build opcode permutation | ✅ #5 |
| Per-function VM encoding | ⬜ #2 — one family per build |
| VM bytecode packing | ✅ sealed + MAC'd blob |
| Operand encryption / encoding | ⬜ #4 |
| Fragment scattering | ✅ #13 |
| Runtime VM | ✅ four families |
| Native Luau operations | ✅ #21 |
| Integrity / consistency checks | 🔶 #45, #47, #48 done; #46, #49 not |
| Final AST reparse | ✅ #37 |
| Final randomized emission | ✅ #38, and per-build names since #69 |

## The polymorphic hybrid VM

What each build can currently change, against the eleven axes requested.

| Axis | Per-build? |
| --- | --- |
| Opcode numbering | ✅ |
| Instruction format | ⬜ |
| Register layout | ⬜ |
| Operand encoding | ⬜ |
| Dispatcher structure | ✅ |
| VM state layout | ⬜ |
| Instruction fusion | ⬜ |
| Constant representation | 🔶 layout keyed, values not |
| Control-flow representation | 🔶 block order only |
| Helper implementation | ⬜ |
| VM / native boundary | ⬜ |

**4 of 11 axes are genuinely per-build.** That is the honest state of the
"polymorphic hybrid VM", and it is the single largest gap between the design
and the implementation.

---

## Checklist example

How to read this document against a real artifact. This is a live measurement
of one build, not an illustration.

```
BUILD     examples/maze.luau
PROFILE   maximum | virtualization maximum | vm_family stack | dispatcher mixed
SEED      00000000000000000000000000c0ffee
RESULT    3484 B -> 52412 B  (15.0x)
          8 prototypes, 3 virtualized
          sha256 86b25338391ace7dee5d1181...
          executes byte-identically to the original under the Luau runtime
```

These are the numbers the command at the end of this section produces, so
re-running it should reproduce them exactly — a pinned seed is the whole point.

Scoring that build against the checklist:

| Question | Result | Point |
| --- | --- | --- |
| Did it VM everything? | No — 3 of 8 prototypes | ✅ #1 |
| Are source string literals recoverable? | 0 of the 9 distinct literals in the source appear in the output | ✅ #13 |
| Are source identifiers present? | 13 substrings match, all accounted for: Luau keywords (`local`, `function`, `return`, `while`, `elseif`, `false`), builtins (`string`, `table`, `print`, `ipairs`, `setmetatable`, `concat`), and `state` — which is only the five `error("invalid state")` sites, not the source's `state` local (that was renamed). A naive substring check reports this as a leak; it is not one. | ✅ #38 |
| Any diagnostic vocabulary? | 0 hits across 10 phrases | ✅ #48 |
| Any repeated decoder boilerplate? | 29 long literals in the output, 0 repeats | ✅ #25 |
| Does the seed change the shape? | Yes — different dispatcher across seeds | ✅ #32 |
| Is the helper block a stable signature? | **Yes** — `_kiterpack` and friends are identical in every build | ⬜ #23 |
| Is `pc` an obvious name? | **Yes** — 228 occurrences | 🔶 #16 |
| Would a devirtualizer for this build generalize? | **Yes** — one family, one instruction format | ⬜ #2, #72 |
| Is output growth bounded? | **No** — 15.0× here, 515× on `hello.luau` | ⬜ #62 |

Six passes, four fails. The four failures are the next four items of work, in
the order they should be done:

1. **#23 + #16** — randomize helper names and the interpreter's `pc`/`R`/`K`/`E`.
   Cheapest of the four and it removes the last stable identifiers.
   `EMITTED_HELPERS` already tracks what needs renaming.
2. **#62** — enforce `max_output_growth`. A 515× expansion is a fingerprint on
   its own, independent of anything inside it.
3. **#4** — per-operand encoding. The blob is authenticated as a whole today;
   operands inside it are plain.
4. **#2 + #72** — a second encoding per build, and randomized instruction
   width. This is the expensive one and the one that actually defeats a generic
   devirtualizer.

### Re-running this measurement

```bash
# the whole checklist's testable half
python3 -m pytest tests/ -q          # 1240 passed, 99 skipped

# a single build, scored
python3 -m couxobf protect examples/maze.luau --profile maximum \
  --vm-level maximum --min-nodes 1 --vm-family stack --dispatcher mixed \
  --string-level 3 --cache-policy none --seed 0xC0FFEE -o /tmp/out.luau

# the report, including which techniques were configured but not applied
python3 -m couxobf report examples/maze.luau --profile maximum
```

The `pending` list in the API response is the machine-readable form of every ⬜
and 🔶 in this document: 32 techniques are declared in `Config` and reported as
not applied rather than being silently ignored.

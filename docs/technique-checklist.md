# Technique checklist

All 80 points, each checked against what this build actually does. Every claim
below was measured on the artifact this tree produces or read out of the code —
not inferred from intent. Measured 2026-09-09 on Python 3.11 with the pinned Luau
toolchain in `.luau-toolchain/`, against the tree at `a9f4ef8` plus the per-group
reporting, the pool-binding gate, and the per-build-diversity round since it --
`opcode_cipher`, `vm_isa_subset`, seed-permuted dispatch arms, and
`tools/reuse-audit.py`, which is where the cross-build numbers in the measurement
rows come from. Sizes, opcode counts and hashes in this document move when the
emitter moves, so they were re-run for this revision rather than copied. Where a
measurement contradicted an earlier assumption, the measurement is what is
written here; where a capability turned out not to exist, the row says so and
`Config` reports the field as pending rather than letting it look implemented.

**Legend**

| Mark | Meaning |
| --- | --- |
| ✅ | Implemented, and verified to have an effect |
| ⭐ | Implemented *and improved beyond the point as written* |
| 🔶 | Partially implemented — the gap is stated |
| ⬜ | Not implemented |

**Tally: 45 done · 23 partial · 11 not built · 1 deliberately not emitted
(#60).** Of the 45 done, 26 are ✅ and 19 are ⭐ (implemented and improved
beyond the point as written). All 80 points are scored exactly once; the tally
is recomputed from the table itself rather than carried forward. The round that produced the two new VM options moved four
rows: #71 from ✅ to ⭐ (the handler count is now derived from the code rather than
only randomized), #68 from ⬜ to ⭐ (there is an extractor whose findings become
tests), and #65 and #66 from ⬜ to 🔶 (a real cross-build measurement exists; a
recovery-time study and a CFG-reconstruction number do not).

This document scores the tool against the 80 techniques. The 29 points of the
architecture review that prompted this round -- per-build VM diversity, partition
diversity, and reducing single points of extraction -- are answered point by point
in [`reviewer-analysis.md`](reviewer-analysis.md), which also records what the
review asked for that this project will not build, and why.

Two standing caveats that apply to the whole document. Client-side
obfuscation raises the cost of reversing; it does not make reversing
impossible, and nothing here should be read as claiming otherwise. And
"verified" means a test or a measurement exists — it never means the technique
is unbreakable.

---

## 1. Selective virtualization

| # | Technique | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Virtualize only selected high-value functions | ⭐ | Five levels (`none`/`light`/`medium`/`heavy`/`maximum`) with size floors, plus per-function refusals for upvalues, capturing closures, the main chunk and varargs -- **and, since R5's third and fourth increments, no refusal at all for a function that creates nested closures, capturing or not**: `vm_closures` lets the interpreter hand out a child's entry stub and, for one that captures, build its accessors over the parent's frame -- the one place the frame is visible -- so a helper, a comparator or a callback no longer drags its parent out of the VM (the child comes into the VM with its parent -- the whole subtree, however small -- and shares its parent's group). `max_vm_functions` caps the total — measured on `inventory.luau`: uncapped 3/7, capped at 1 → 1/7, capped at 0 → 0/7. Improved beyond the point: selection is not merely "high-value functions", it is a per-function decision with a size floor and an explicit refusal reason recorded in the report. |
| 22 | Never recursively virtualize generated VM code | ✅ | The interpreter is emitted as plain Luau source; the main chunk is never virtualized, so generated code cannot re-enter the lowering path. |
| 80 | Hybrid native/virtual execution | ⬜ | A function is either wholly native or wholly in the VM. The `mixed_execution` knob that claimed otherwise was removed in R12. |
| 77 | Randomize whether an operation is native, VM, or hybrid | ⬜ | No per-operation boundary exists to randomize. |

## 2. VM encoding and dispatch

| # | Technique | Status | Evidence |
| --- | --- | --- | --- |
| 3 | Separate bytecode from the dispatcher | ✅ | The payload is a sealed, MAC'd blob; the interpreter is emitted separately with this build's opcode numbers inlined. Nothing in the interpreter reveals the wire format. |
| 5 | Randomize opcode semantics every build | ⭐ | `OpcodeMap.shuffled` per build from the `opcodes` stream. Measured: 60 seeds → 60 distinct bytecodes, 0 integrity failures. Improved: the permutation comes from a domain-separated stream, not a shared one, **and the payload no longer carries the permutation's output directly** -- `opcode_cipher` draws `none`/`add`/`affine`/`swap` per group, so the bytes in the stream are a bijective image of the number the dispatcher branches on and the two are separated by a decoder. At `maximum`: 19 affine, 12 add, 9 swap and no `none` across 40 draws; at `compact`: `none` 40/40 and unpermuted arms, because both cost zero bytes and a build that advertises readability should not pay them. |
| 8 | Multiple dispatcher styles | ⭐ | `nested_if`, `decision_tree`, `bucket`, plus `mixed` which draws per build. Measured interpreter sizes on one opcode map: 9680 / 18819 / 10294 bytes. Improved: bucket geometry is per-build too (`buckets = 4 + seed%5`, odd multiplier), so two bucket dispatchers are not structurally identical. |
| 76 | Randomize dispatch strategy per function | 🔶 | Each VM group draws its own dispatch shape (chain ladder or bank) and its own key salt/tap from the format, so the per-group dispatch is a draw, not a constant. But there is one guarded dispatcher family, not several strategies: R12 removed `dispatcher_splitting` and the legacy shape names (`bucket`, `nested_if`, ...) from the CLI — saved configs naming them still load and normalize. |
| 78 | Several VM families | ✅ | `register`, `accumulator`, `stack`, `hybrid`. Measured output sizes with `--min-nodes 1`: 18705 / 19155 / 22678 / 21016 bytes. |
| 79 | Select family per build/function using the build RNG | 🔶 | There is one operand family (woven); R12 removed the dead rotation and `state_distribution`, and the CLI no longer offers family choices. Legacy family names remain loadable in saved configs and normalize to `woven`. What varies per group is the format, the opcode map and the dispatch keying, all drawn from the build RNG. |
| 75 | Randomize register-vs-stack decisions | 🔶 | Which family a prototype runs on is decided per group by round-robin over the sorted prototype ids, and the family pool is a rotation starting at the pinned one - so the spread is even and the user's choice survives. It is deterministic: a draw from the build RNG per group is the remaining half of the point. |
| 2 | Multiple VM instruction encodings per build | ⭐ | Five axes vary per VM *group*, not per build: `vm_variety` emits 1-4 interpreters and `_make_groups` gives each its own family, dispatcher, opcode map and instruction format; `vm_isa_subset` narrows each map to the operations that group's protos were lowered to; `opcode_cipher` decides whether the stream carries the dispatcher's number or an image of it; and `arm_seed` reorders the arms inside the interpreter. Measured over 6 seeds at variety=2 (12 groups): 12 distinct opcode counts, 14-67, against 10 distinct counts 98-118 with the subset off -- the count stopped being a property of the ISA and became one of the code. 12 distinct field layouts, all four target modes (`abs`/`biased`/`rel`/`edges`). The report prints a line per group (`vm 1 : register decision_tree 1 protos, 31 opcodes, 1B op + 1B reg + 2B wide, targets rel, opcode cipher add, 10 fused`), so what is described is what the artifact contains, not what was requested. |
| 70 | No permanent VM ABI | ⭐ | The header is part of the format, not a constant of the tool: `HeaderLayout` renumbers and reorders its fields per group, `op_bytes`/`reg_bytes`/`wide_bytes` change the unit size, and `pad` adds bytes a reader has to know about. `size`/`body_size`/`max_wide` are derived from the same descriptor. Improved: there is no second ABI description to keep in sync - `LEGACY_SPEC` exists so the historical shape stays testable. |
| 71 | Randomize opcode count | ⭐ | The handler count is a build-time variable: aliases give one opcode several numbers, `sparse` spaces the numbering so gaps appear, and fused pairs add super-op numbers the map may or may not fit. Measured over 12 groups from 6 seeds: 9 distinct counts, 91 to 124, printed per group. The ISA's 47 operations are fixed; the number of arms the dispatcher branches on - the thing a matcher counts - is not. Improved this build: the count is also *derived*, not just randomized -- `vm_isa_subset` runs `encode.required_ops(proto, fmt)` over the group's own protos and unions their operations, plus both halves of every fused pair the numbering fits, plus `JMP` when block permutation needs a filler. Same 12 groups, subset on: 12 distinct counts, 14 to 67. It is fail-safe in one direction only, deliberately: a proto containing an operation the lowerer could not name makes `required_ops` return `None` and the group falls back to the full ISA, so a classification bug costs bytes and never correctness. |
| 72 | Randomize instruction width | ✅ | `allow_op_widen`/`allow_wide_widen`/`allow_pad` are drawn per group: across 12 groups the layouts include `op` 1 and 2 bytes, `wide` 2 and 3, `pad` 0-2, `wides_first` both ways - 12 distinct layouts in 6 seeds. A wider instruction is wider in the encoder, the validator and the generated reader by the same arithmetic. Improved: the same draw now also picks `op_swap_bits` and the affine cipher for the opcode field, which are format decisions rather than numbering decisions -- a 2-byte affine image of a value under 43 never has a zero high byte, so the field stops being identifiable by its padding as well as by its permutation. |
| 73 | Randomize operand width | ✅ | `reg_bytes` is drawn per group (measured 1 and 2) and masked by `reg_mask`, with `wides_first` putting the wide operand on either side of it. `pack`'s raw 0-based index goes through `_rp` and the biased fields through `_biased`, so the two conventions cannot be mixed by accident. |
| 74 | Randomize operand ordering | ⭐ | Field offsets belong to the format (`fields`/`offsets`), `wides_first` flips the order, `pad` puts bytes between operands, and per-field masks mean the same operand shows up as different bytes. Improved beyond the wording: the reader is generated from the same descriptor, so "operand order is randomized" and "it still decodes" are one property rather than two that have to be kept aligned by hand. |
| 6 | Split into micro-ops, then randomly fuse | ✅ | `instruction_fusion` + `super_instructions` are wired: `_fusion_plan` pairs only `FUSABLE` opcode pairs the group's numbering can fit, `EncodedProto.fused` carries the halves, and `_fused_handler` emits one arm for both. The per-group report line counts them (`4 fused`, `5 fused`, or nothing when the map could not fit a pair). Both flags have to be on, and an `identity()` opcode map allocates no fused numbers on purpose. |
| 4 | Encrypt/encode operands independently | ✅ | Each field of an instruction is encoded through its own width and mask (`FormatSpec.fields/offsets/width/mask/store`), so the register field of one group is 1 byte and of another 2, `wides_first` moves the wide operand before or after the registers, and `pad` inserts filler between them. The interpreter's reader is generated from the same descriptor (`reader_source`), which is what keeps a per-field mask from becoming a mismatch. The descriptor covers the selector field too -- `op_bytes`, `op_mask` and the drawn `opcode_cipher` are read through `fields()`/`encode_op` exactly as the register fields are, so an artifact where the operands are masked and the opcode is raw does not exist. (Scored against technique #5, where the cipher is the point, rather than promoted here.) |
| 7 | Relative/indirect instruction addressing | ⭐ | `target_mode` chooses per group between `abs`, `biased`, `rel` and `edges`, and `_target_jump(fmt, travel)` computes the advance from the format: relative targets are deltas measured from the pc the emitted arm leaves behind, which for a non-advancing arm (`JMP`, `RETURN0`) is one operand earlier - an asymmetry that was a real bug, found by running artifacts rather than by reading the encoder. Improved beyond the point: `edges` is a fourth mode, and the geometry is pinned by `test_a_jump_leaves_pc_where_its_own_mode_measures_from`. |
| 9 | Periodically mutate VM state representation | 🔶 | VM state differs per group — each group draws its own format, opcode numbering, readers and dispatch keying — but it is one operand family, and R12 removed the `state_distribution` knob that claimed otherwise. "Periodically" is not what happens: nothing mutates the state representation while it runs. |
| 10 | Avoid a single central VM state table | ✅ | There is no artifact-wide state table: each group's interpreter declares its own register file, stack and `sp` locals (names drawn per build), and the metadata each frame is handed is assembled from three separate tables (#17) rather than read out of one object. |
| 33 | Randomize instruction ordering where dependencies permit | ⭐ | Blocks are permuted (`_layout.permuted_order`: 60 permutations -> 60 distinct bytecodes, +141 bytes, 28/28 corpus files still correct) and, since `control_flow_level` feeds the format, instructions inside a block are reordered when the group's format allows it. Improved: the reorder is a property of the descriptor, so the encoder and the validator agree by construction rather than by convention. |
| 18 | Encode control-flow edges separately from instruction data | ✅ | `edge_indirection` moves destinations into their own blob, keyed per prototype and passed through the same pool accessor as the payload: the instruction stream carries an ordinal, and the generated reader resolves it (`local q = 1 + _rk(a) * 4`). The mode is chosen per group, so a build can hold a VM with edges and one without. |

## 3. Constants, strings, keys

| # | Technique | Status | Evidence |
| --- | --- | --- | --- |
| 11 | Hide constants behind the vault; don't assume encryption prevents runtime extraction | ⭐ | ChaCha20-Poly1305 sealed pool. Improved: the limitation is stated rather than glossed — the report and docs both say a determined analyst can hook the accessor at runtime, because confidentiality and tamper-resistance are different properties. |
| 12 | Per-function / per-region keys | ⭐ | `KeyMaterial.region_key(purpose, region)` over six purposes, with 17 domain-separated streams behind it. Improved this build: the emitted *names* are now per-build too (see #16). |
| 13 | Per-literal handles and randomized reconstruction order | ✅ | Per-occurrence tickets, a page permutation, and an LCG mask applied before encryption. Measured on `inventory.luau`: 13/13 source string literals absent from the output. |
| 42 | Decode only the currently needed region | ✅ | Strings resolve per occurrence through a ticket; the VM blob is the exception (see #41). |
| 43 | Keep plaintext lifetime short | ✅ | Default cache policy is `none`, so a decoded string is not retained. |
| 44 | none / bounded plaintext caching | ⭐ | Three policies. Improved: `bounded_cache_size` is now reachable from the UI and was previously a knob with no control. |
| 26 | Randomize table layouts and index mappings | ✅ | Three mechanisms move the layout now: the split descriptor tables (#17), the edge blob (#18) and per-group field widths and masks (#4), on top of the keyed pool and permuted string pages that were already there. The index mapping is per build because the opcode map and the field offsets are. |
| 27 | Several equivalent arithmetic encodings for numbers | 🔶 | `numeric_protection_level` is wired: level 1 stores each number as a masked double (seed + XOR keystream, still bit-exact), level 2 additionally rebuilds exact-integer constants (`abs(v) <= 2**53`) from two 32-bit halves at runtime, so no double bytes for them exist in the blob (R7). The exactness rule in `constpool._split_halves` is what keeps this safe where #11's warning applies: NaN, ±inf, non-integers and negative zero keep the masked-double path, so the encoding is never "sometimes disguised" — every entry's tag says exactly how it decodes. |
| 28 | Don't encode everything | 🔶 | Constants are interned selectively and most code is left untouched, but which values are protected is not itself randomized. Improved this build in the other direction, which is the one the point is really about: the *interpreter* does not encode everything either -- `vm_isa_subset` gives a VM only the operations its own protos need, so a handler set that published 43 numbers carries 31, and the artifact gets smaller as it gets less analyzable (90,523 -> 67,411 B at the pinned example command). |
| 29 | Randomize which values receive protection | ⬜ | The selection is deterministic given the source. |
| 49 | Don't put all integrity constants together | ⬜ | Key, nonce and tag are emitted adjacent in the pool runtime. |

## 4. Names, helpers, fingerprints

| # | Technique | Status | Evidence |
| --- | --- | --- | --- |
| 16 | Break obvious names (`R0`, `R1`, `stack`, `pc`, `opcode`) | ✅ | **Fixed.** `pc`, `R`, `K`, `E`, `stack`, `opcode` and the six helper names now all count **0** in the output, down from 228 / 111 / 7 / 5 / 0 / 1 plus six fixed helper names. Each build draws its own from the `vm` stream. |
| 39 | Build-specific structural fingerprint | ✅ | `wiring.structural_fingerprint(plan)` digests each group's family, dispatcher, opcode count and instruction format -- and, since the count became a function of the code (`vm_isa_subset`) rather than of the ISA, that digest changes for free when a build narrows a VM. `lower_back` appends it to the constant pool's AAD before sealing, so a pool lifted into a build with different decisions fails authentication, and the report prints the 8-byte digest. Measured: 6 seeds -> 6 distinct digests, and the same seed and config reproduce it. No marker string is emitted: the point is our tooling recognizing the format, and a digest of decisions does that without anything in the file saying so. |
| 69 | Continuously change the generated format | ⭐ | **Improved this build.** The pool and bank prefixes were the constants `_kQ` and `_kS`, identical in every build ever produced — `_kQ` alone appears 115 times in a typical output. Each build now draws its own: 12 builds produced 24 prefixes, all distinct, none stable. |
| 25 | Avoid repeated decoder boilerplate | ✅ | Measured on a maximum build: 30 long string literals, 30 distinct, 0 repeated. |
| 23 | Randomize helper placement | 🔶 | **Names and blocks yes, one contiguous preamble no.** The six bit/table helpers used to be `_kpack`/`_kunpk`/`_kiter`/`_kiterpack`/`_kitercheck`/`_kapp` in every build; each build now draws its own names, and the runtime is no longer a single preamble — measured in a maximum build of `maze.luau`, the guard locals land at lines 9-12, the bit-op destructure at 39 and the pool blobs at 239+. What the point still asks for and does not get: the six helpers are one statement, and which of the four runtime blocks goes where is fixed by the emitter, not drawn. |
| 24 | Different helper implementations for equivalent operations | 🔶 | **The constant pool's decoder is no longer one implementation (R13).** Each region draws a shape on three axes -- whether entry offsets are built eagerly at load or scanned forward on demand and memoised, whether the ticket mask is folded in as one literal, as two XORs of two literals, or as one XOR of their sum, and whether a type byte dispatches through an if-chain or a table of per-type readers -- so twelve structurally different decoders open the same pool, two of which drop the mask literal entirely. Measured: all twelve verified against one sealed pool in Luau, reading slots forwards and backwards; the spread across shapes is under 1 KB on `maze.luau`, inside the noise of the drawn identifier lengths. What is still one implementation: the string bank's reader, the crypto module, and each handler body. |
| 40 | Avoid a recognizable VM → decrypt → execute sequence | ⬜ | The prelude order is fixed: crypto runtime, constant pool, helpers, body. |

## 5. Control flow

| # | Technique | Status | Evidence |
| --- | --- | --- | --- |
| 20 | Control-flow flattening around VM boundaries | 🔶 | `control_flow_level` is read - it gates `allow_instruction_reorder` - and block layout is permuted. What the point asks for, flattening *around the VM boundary* with dispatcher states that outlive one instruction, does not exist. |
| 19 | Opaque predicates, used sparingly | ✅ | **Built in R2, and keyed so they cannot be constant-folded.** VM side: the dispatch key folds a build-known payload-header byte (`FormatSpec.key_taps`), so the ladder/bank constants are an image of the numbering under a salt only the encrypted pool carries. Native side: flattened drivers gain split `elseif` arms keyed to an encoded state the build proves no reachable counter takes (`Reconstructor.split_log` records the draw so the exactly-one-satisfiable invariant is unit-proven). Both ride `opaque_predicates` and are rate-limited by `control_flow_level` — the sparingly part is a dial, not an accident. |
| 34 | Generate equivalent AST forms before the main pass | ⬜ | No pre-pass rewriting. |
| 35 | Randomize boolean / control-flow formulations | ⬜ | Conditions are emitted as parsed. |
| 14 | Decoy constants and instructions | 🔶 | **Partly built.** `decoys`/`decoy_constants` are live: the pool plants unreferenced entries as it interns (a maximum build of `maze.luau` carries 24), derived from values already in the pool, scattered rather than tacked on, and the report prints the count. The dispatch-chain half is not built, and R12 removed `junk_level` outright: unreachable arms are a deobfuscation aid and a fingerprint, so junk stays out by design. So the decoys are constants only. |
| 15 | Randomize register allocation independently from source renaming | ⬜ | Registers are allocated deterministically; renaming is separate but registers are not permuted. |
| 17 | Split VM metadata among several structures | ✅ | `metadata_fragmentation` decides whether the split happens: on, `prelude_source` emits a payload table, a constants table and an edge table and assembles the rows table from all three (`code = T[3]`); off, one table whose rows carry the payload inline (`code = get(47)`). `entry` and `nparams` are in neither - they live in the MAC'd header, where editing them invalidates a tag. |

## 6. Integrity

| # | Technique | Status | Evidence |
| --- | --- | --- | --- |
| 45 | Don't claim anti-tamper from hashing alone | ✅ | Documented, not faked. Data tamper-resistance is real and measured; **code** tamper-resistance is not achievable in client-side Luau and the docs say so rather than implying otherwise. |
| 47 | Make integrity failures indistinguishable from ordinary failures | ✅ | **Fixed this build.** All five `error()` sites across both runtimes now raise one identical message. A test asserts the set of distinct `error(...)` call sites has size 1. |
| 48 | Avoid obvious strings (`"integrity"`, `"invalid instruction"`, `"VM error"`) | ⭐ | **Fixed, then fixed again.** Measured on production output, all zero: `integrity`, `invalid instruction`, `VM error`, `failed authentication`, `authentication`, `tamper`, `checksum`, `constant pool`, `string bank`, `protected payload`. Three sites said "failed authentication", naming the check and confirming the edit had been noticed. Improved further: the dispatcher fallthrough said `"unknown opcode "` — literally the "invalid instruction" phrasing this point calls out, and the last place `opcode` reached the artifact. All three sites now raise the neutral message. |
| 46 | Integrity checks at multiple semantic boundaries | 🔶 | At build time: one AEAD tag per pool, per bank and per payload, plus header/opcode-count/entry-start validation of every prototype against its own group's format (`validate_proto`, `validate_module`), so an encoder/validator disagreement fails the build instead of shipping. At run time: the tag, and the guard's re-check of the dump surfaces at every VM entry. Not there: a per-block or per-instruction check - `self_test` stays declared and inert, and R12 removed `integrity_level` because the AEAD tag is always verified; it was never a user-facing safety dial. |
| 50 | Differential tests against unprotected execution | ⭐ | 18 differential tests in `tests/test_roundtrip.py` over 40 micro fixtures (`tests/fixtures/micro/*.luau`) and the 4 `examples/*.luau`, plus the web suite executing all four VM families × three dispatcher shapes and comparing to the original. Measured: 12/12 builds of `inventory.luau` byte-identical in output, and 40/40 builds of a seeded loop battery (`/tmp/diffloop.sh`) running clean. |

## 7. Semantics coverage

| # | Technique | Status | Evidence | Test count |
| --- | --- | --- | --- | --- |
| 21 | Preserve native Luau semantics | ✅ | Full lexer → parser → sema → IR pipeline; 1964 passing tests, 99 skipped with the toolchain on `PATH`. The skips are the upstream conformance files this tree documents as excluded -- each needs the vector type, native-code support or the debug library, or asserts on source line numbers a source-to-source compiler cannot preserve -- not a missing runtime: without `.luau-toolchain/bin` on `PATH` the execution-backed tests skip on top of those. | — |
| 51 | Test closures heavily | 🔶 | Present, not heavy. | 8 |
| 52 | Test upvalues heavily | 🔶 | Same 8. | (shared) |
| 53 | Test multiple returns | 🔶 | `RETURNMULTI` semantics are covered, including the splice. | 7 |
| 54 | Test varargs | 🔶 | Covered, though vararg functions are refused for virtualization. | (shared) |
| 55 | Test `break`, `continue`, `return`, nested loops | 🔶 | Present. | 8 |
| 56 | Test metamethods | 🔶 | Present. | 5 |
| 57 | Test method calls and `NAMECALL` | 🔶 | `SELF` semantics mirrored from `lower_back`. | (shared) |
| 58 | Test coroutine / yield behaviour | ⬜ | **Zero tests.** `coroutine` appears in the codebase only as an entry in the globals whitelist in `sema.py`. Not VM-supported, not tested. | 0 |
| 59 | Test `nil`, `false`, `0`, `NaN`, infinities, int/float edges | 🔶 | Fold rules are careful (no folding of CONCAT/LEN/comparisons, `bool` excluded, `-0.0` not merged into `0.0`), but only one named edge-case test. | 1 |
| 60 | Executor-specific guard APIs | — | Deliberately not emitted. The project is free for everyone, so guards stay on portable Luau dump/debug surfaces and do not call executor-only APIs. | — |

## 8. Measurement and self-attack

| # | Technique | Status | Evidence |
| --- | --- | --- | --- |
| 61 | Benchmark every protection individually | 🔶 | The cost report gives per-technique sizes and counts (67 lines for a maximum build). Runtime overhead is measured for some — VM dispatch is ~10× on 400k instructions — but not for each technique. |
| 63 | Don't blindly maximize output size | ✅ | The ceiling is the enforcement, and the ladder's order is the judgement: decoys and padding go first, interpreters and dispatch shapes last. The honest limit, measured: `hello.luau` is 24 bytes, so no trimming reaches 24x - the crypto runtime, the pool decoder and one interpreter are an ~11 KB floor. After giving up all nine groups it sits at 464x, and the report lists what was lost. A ceiling that cannot be met still costs the passes and still tells you; it does not invent a ratio it did not achieve. |
| 62 | Reject transformations with disproportionate overhead | ⭐ | `max_output_growth` is enforced by rebuilding: `_within_budget` walks a ladder of optional-pass groups, cheapest-per-byte first, and stops as soon as the ratio fits - then reports every group it gave up, so a trimmed build does not read as a build that was configured less. Measured on `maze.luau`: 27.0x with the ceiling off, 19.4x under a 24x ceiling with three passes dropped. Improved beyond the point: the give-up is *named*, which is the difference between a bound and a surprise. |
| 64 | Mutation testing against our own deobfuscator | ⬜ | No deobfuscator exists to mutate against. The nearest thing is a test suite that *behaves* like one -- `tests/test_integrity.py` flips bits in the sealed payload and expects the runtime to refuse -- but that mutates the artifact, not the analysis. |
| 65 | Automated deobfuscation benchmark | 🔶 | `tools/reuse-audit.py` runs a real static extractor over every build of a program -- it sweeps each payload through the emitted reader, learns a "stored value means operation" table by majority vote, and scores that table against the truth of every *other* build. That is the cross-build half of the benchmark, which is the quantity the review asked for; the recovery-time half, and an extractor that reads the interpreter's source instead of its data, are not built. Pinned by `tests/test_reuse.py`, with a `stable` control that must score 100% so a metric which quietly measured nothing fails the suite. |
| 66 | Measure recoverability of identifiers, strings, constants, CFGs, opcodes | 🔶 | Measured, four of five: identifiers (substring oracle over 40 corpus files and 4 examples, with the keyword and builtin matches accounted for rather than waved away), strings (0 of 9 source literals recoverable in the pinned build), constants (0 of 9, plus 24 planted decoys that a dumper cannot tell from live entries), opcodes (1% of payload values transfer between builds). Not measured: CFG reconstruction -- there is no tool that tries it, so there is no number for it. |
| 67 | Multiple independent deobfuscators attacking each build | ⬜ | Two readers of the format exist (`vm/runtime.py` for the emitted interpreter, `integrity/payload.py` for the validator) and the suite requires them to agree, but they are two implementations of one design, not two attacks: a bug that makes both wrong is invisible. One of them is even load-bearing for the product, which is the opposite of independence. A second, adversarial extractor -- built to fail -- is the real answer, and it is the reason `tools/reuse-audit.py` refuses to call its 1% a bound. |
| 68 | Regression tests when a tool recovers something | ⭐ | **Improved beyond the point as written.** The practice always existed -- every defect found by measurement became a test -- and now there is a tool to drive it: what `reuse-audit` finds is asserted in `tests/test_reuse.py`, and the pipeline test that pins the cipher into the reader (`tests/test_pipeline.py: test_the_opcode_cipher_is_in_the_reader_not_only_in_the_config`) exists because the audit's own first draft found a knob that lived only in the config. A finding that is not written down as a failing test is a finding that gets forgotten. |

## 9. Randomness and pipeline discipline

| # | Technique | Status | Evidence |
| --- | --- | --- | --- |
| 30 | Separate randomness domain per transformation stage | ⭐ | **17 domains**, not the 12 previously recorded: `identifiers`, `names-final`, `cfg`, `predicates`, `constants`, `strings`, `vm`, `opcodes`, `operands`, `registers`, `handlers`, `dispatch`, `chunks`, `integrity`, `decoys`, `emission`, `pc`. Improved: five of these (`operands`, `registers`, `predicates`, `chunks`, `names-final`) are reserved for techniques that do not exist yet, so adding them will not require reusing a stream. |
| 31 | Never reuse release seeds | ✅ | A fresh 128-bit `secrets.token_bytes(16)` per request; a pinned seed is hashed through SHA-256 rather than packed, so seeds differing by one bit diverge completely. |
| 32 | Seed influences structure, not just constants | ⭐ | Measured: four seeds on `maze.luau` at `maximum` gave 65095 / 67218 / 71136 / 73434 bytes and four distinct fingerprints, and the two interpreters in each of those builds differ from the next build's in family pair, opcode count (53/37, 56/37, 65/41, 50/57), cipher (`add`/`affine`, `add`/`add`, `swap`/`swap`, `swap`/`swap`), field widths, jump-target mode (`rel`, `abs`, `biased`, `edges` all appear) and fused-pair count. Improved this build: names are structural too, and so is which *instructions exist*. |
| 36 | Normalize first, then transform the AST | ✅ | No regex-based source transformation anywhere in the pipeline. |
| 37 | Reparse after major transformations | ✅ | `validate_output` reparses the emitted source and counts AST nodes before anything else. |
| 38 | Final lexical renaming last | ✅ | Renaming happens at emission through `NameGenerator`, after all structural work. |
| 41 | Interleave decoding with execution | 🔶 | True for strings (per-occurrence tickets, resolved lazily) and for the pool's plaintext (one constant materialized per read). Not true for the pool blob or the VM payload, both opened in full on first use. R12 removed `chunking_level`, `chunk_size` and `lazy_decode` — "chunking" had no design behind it, and lazy decode is already what the pool does per constant. Per-chunk keys plus lazy chunk opening remain the gap, and the runtime half - chunk table, per-chunk offsets, the lifetime policy - is where the work is. |

---

## The 18-stage pipeline

What the requested pipeline maps to, stage by stage.

| Stage | State |
| --- | --- |
| Source | ✅ `couxobf/parser.py` |
| AST normalization | ✅ `couxobf/sema.py` |
| Semantic-preserving transforms | 🔶 `couxobf/optimize.py` only; no equivalent-form rewriting (#34, #35) |
| Identifier / register randomization | 🔶 identifiers yes (#38); the register *field* is widened, masked and permuted per group (#73, `_rp`), the register *allocation* is still deterministic (#15) |
| CFG transformation | ✅ for what exists: block permutation plus within-block instruction reorder, both driven by the format descriptor (#33, #20's gate) — and edge indirection moves a jump's destination out of the stream (#18). Still no graph flattening with dispatcher states that outlive an instruction (#20) |
| Select high-value functions | ✅ #1 |
| AST → custom IR | ✅ `couxobf/ir.py` — blocks with ids, preds/succs, liveness |
| IR optimization | ✅ `couxobf/optimize.py` |
| Instruction fusion | ✅ #6 — `FUSABLE` pairs the group's numbering can fit become one handler arm |
| Per-build opcode permutation | ✅ #5 |
| Per-function VM encoding | ✅ #2 — 1-4 groups via `vm_variety`, each with its own family, dispatcher, opcode map and format |
| VM bytecode packing | ✅ sealed + MAC'd blob, sizes derived from the format (`FormatSpec.size`) |
| Operand encryption / encoding | ✅ #4 for encoding (per-field width, mask, offset, `wides_first`); operands are not individually encrypted — the unit of authentication is the blob |
| Fragment scattering | ✅ #13 |
| Runtime VM | ✅ four families |
| Native Luau operations | ✅ #21 |
| Integrity / consistency checks | 🔶 #45, #47, #48 done; #46 partly (per-blob tags, per-prototype validation at build, guard re-check at each entry — no per-block check); #49 not — key, nonce and tag are still adjacent in the emitted runtime |
| Final AST reparse | ✅ #37 |
| Final randomized emission | ✅ #38, and per-build names since #69 |

## The polymorphic hybrid VM

What each build can currently change, against the eleven axes requested.

| Axis | Per-build? |
| --- | --- |
| Opcode numbering | ✅ — permuted, sparsely spaced, aliased, narrowed to the group's own operations, and stored as an image of itself rather than the number (`opcode_cipher`): `14` to `67` dispatch numbers per VM at `maximum` (#71, #5) |
| Instruction format | ✅ — `op`/`reg`/`wide` widths, `pad`, `wides_first`, target mode and arm order drawn per group: 12 distinct layouts in 6 seeds (#72, #74, #79) |
| Register layout | ✅ — `reg_bytes` and `reg_mask` per group, biased fields through `_biased`, raw through `_rp` (#73) |
| Operand encoding | ✅ — per-field width, mask and offset from one descriptor the reader shares (#4) |
| Dispatcher structure | 🔶 — one guarded woven dispatcher; per-group dispatch *shape* (chain ladder or bank) and keying drawn with the format (#76) |
| VM state layout | ✅ — register, stack, accumulator and hybrid interpreters coexist in one artifact (#75, #79) |
| Instruction fusion | ✅ — `FUSABLE` pairs the numbering can fit become one arm (`2 fused`, `5 fused` in the report) (#6) |
| Constant representation | 🔶 — pool layout keyed, decoys planted, plaintext materialized per read; per-chunk keys unbuilt, and R12 removed the chunking knobs that claimed them (#14, #41) |
| Control-flow representation | ✅ — block permutation, within-block reorder, and jump targets in `abs`/`biased`/`rel`/`edges` form (#7, #18, #33) |
| Helper implementation | 🔶 — the constant pool's decoder is drawn per region on three axes (how an entry offset is found, how a ticket is folded back into a slot, how a type byte dispatches), so twelve structurally different decoders open the same pool (R13); the crypto module, the string bank's reader and each handler body are still one implementation each, and placement is spread by emitter structure rather than by choice (#23, #24) |
| VM / native boundary | ⬜ — a function is wholly native or wholly virtual; the inert `mixed_execution` knob was removed in R12 (#80) |

**8 of 11 axes are genuinely per-build and a ninth is partly.** That is the
honest state of the "polymorphic hybrid VM": what a build varies is the *shape*
it decodes with, and it varies it per group rather than once per build. Helper
implementation now varies for one helper — the pool decoder — and not for the
rest. The two it does not vary at all are chunked constant representation and a
per-operation native/virtual boundary.

---

## Beyond the 80: three things asked for alongside them

These are not numbered points, so they are not scored above. They are documented
here because they change what the artifact does and what the site exposes.

### Environment-logging and dump resistance

`env_guard`, `dump_guard` and `guard_policy` (live fields, all three). The intent
is narrow and stated as such in the artifact's own report: make the usual ways of
watching a scripted environment *cost something*, not make them impossible.

| Level | What the build does |
| --- | --- |
| **Level 0** | Nothing. The environment is left exactly as it arrived. |
| **Level 1** | Capture what is worth capturing at load (`debug`, `error`, `getfenv`, `getmetatable`, `next`, `rawget`, `string`, `table`, `type` — nine names in a maximum build) and read the locals thereafter, so an `__index` logger installed on `_G` after load never sees the reads. Dump surfaces (`string.dump`, `getbytecode`, `getscriptbytecode`, `debug.getinfo`, `debug.gethook`) are checked at load and at every VM entry. |
| **Level 2** | As level 1, plus the policy: `neutralise` replaces the logging metamethods with ones that return the value without telling anyone, and `fail` raises through the captured `error` when a surface has been swapped underneath the build. |

Measured on one program at three levels: 19427 B, 21036 B and 21652 B, all three
printing `3 6 9 12 15`; at level 2 with `getbytecode` swapped for a trapping stub
mid-run, the artifact exits non-zero instead of handing over a proto. The five
surfaces are re-checked per VM entry, not once, because a dumper's whole trick is
installing itself after the preamble.

What this does **not** do, said plainly because the tempting framing is a lie: it
cannot stop anything. A dumper that patches the in-memory proto never asks for a
dump; a hook installed before the artifact's own load runs sees the capture; a
runtime with no `bit32` silently degrades the crypto, which is why the guard binds
after the scaffolding exists rather than before. `Guard.summary()` reports what
was captured, which surfaces were re-checked, whether it neutralised anything and
whether it refused — and the report line is generated from that, so the artifact
says what it did rather than what was requested.

### Source and output comments

`hash_comments` is `auto`, `strip` or `strict` (live). On the way in, a leading
`#!` line is dropped and any remaining `#` comment is removed by the lexer-aware
stripper, so hash-style comments never reach the parser as tokens; `strict`
refuses to build a file that has them anywhere but line start, because silently
eating a `#` inside a string is how a source-level transform earns a wrong-answer
bug. On the way out the invariant is that an artifact contains zero `#` and zero
`--` comments, which is tested rather than asserted in a comment:
`test_no_artifact_contains_a_comment` builds every `examples/*.luau` at both
`compact` and `maximum` and scans the result with the independent scanner from
`couxobf.comments` — a re-parse check would not catch a stray banner, because Luau
accepts comments.

### Every option reachable from the site

36 live fields are reachable from `web/` → `api/obfuscate.py` → `Config`, and the
list is not hand-maintained: `describe()` emits the option table (label, help,
type, choices, range, gate), `web/app.js` renders that and nothing else, and
`tests/test_web.py` asserts the rendered form covers exactly the live fields.
Gating is expressed once in Python (`FIELD_REQUIRES`) and read by the UI, so
`bounded_cache_size` appearing or disappearing is not a second implementation of
a rule. Fields that exist in `Config` and are read by nothing are (a) omitted from
the form, (b) listed in `describe()["pending"]` and in the report's "requested but
not applied" section, and (c) **refused** by the endpoint:

```
"identifier_polymorphism" -- that field exists but the pipeline does not read it yet, and this
endpoint will not pretend otherwise
```

That is the whole point of the demotion batch: an inert knob on a UI is a claim
about protection that was not delivered, which is worse than an absent one.

---

## Checklist example

How to read this document against a real artifact. This is a live measurement of
one build, not an illustration, and every number below came from running it.

```
BUILD      examples/maze.luau
PROFILE    maximum | virtualization maximum | min_nodes 1 | vm_family stack
           dispatcher mixed | string level 3 | cache none | pool decoys 24
SEED       00000000000000000000000000c0ffee
RESULT     3484 B -> 67411 B  (19.3x, ceiling 24x, no pass trimmed to fit)
           8 prototypes, 3 virtualized
           sha256 f48c0e9a02a43f192456f065...
           executes byte-identically to the original under the Luau runtime
           0 `#` comments, 0 `--` comments, 0 diagnostic phrases
           guard: env level 1, dump level 1, policy fail, 5 surfaces re-checked
                  at each VM entry
           fingerprint 25e155d53cd98cba -- the pool is authenticated against it
           vm 0 : stack     nested_if      2 protos,  67 opcodes,
                            2B op + 1B reg + 2B wide, targets abs,
                            opcode cipher affine, 16 fused
           vm 1 : register  decision_tree  1 protos,  31 opcodes,
                            1B op + 1B reg + 2B wide, targets rel,
                            opcode cipher add, 10 fused
```

Scoring that build against the checklist:

| Question | Result | Point |
| --- | --- | --- |
| Did it VM everything? | No — 3 of 8 prototypes; the main chunk is never virtualized | ✅ #1, #22 |
| Are source string literals recoverable? | 0 of the 9 distinct literals in the source appear in the output | ✅ #13 |
| Are source identifiers present? | 13 substrings match, all accounted for: Luau keywords (`local`, `function`, `return`, `while`, `elseif`, `false`), builtins (`string`, `table`, `print`, `ipairs`, `setmetatable`, `concat`), and `state` — which is only the `error("invalid state")` sites, not the source's `state` local (that was renamed). A naive substring check reports this as a leak; it is not one. | ✅ #38 |
| Any diagnostic vocabulary? | 0 hits across 10 phrases | ✅ #48 |
| Any repeated decoder boilerplate? | 82 distinct long literals in the output, 0 repeats | ✅ #25 |
| Does the seed change the shape? | Yes — 6 seeds at `vm_variety=2` give 6 distinct sizes (58,147–69,417 B), 6 distinct fingerprints, 12 distinct opcode counts (14–67) and 12 distinct field layouts | ✅ #32 |
| Is the helper block a stable signature? | **Names no** — per build. **Placement partly** — guard locals, the bit destructure and the pool blobs land in different regions; the six helpers are still one statement | 🔶 #23 |
| Any recognisable VM identifier left? | **No** — `pc`, `R`, `stack`, `opcode` count 0, and the lone `K` and `E` matches are bytes inside escaped ciphertext, not identifiers | ✅ #16 |
| Would a devirtualizer for this build generalize? | **No** — two interpreters with different families, dispatchers, opcode *counts*, register widths, jump-target modes and opcode ciphers, so a recovery tool handles each separately; a table learned from this build's payload matches another build's payload 1% of the time. Handler *bodies* are still plain Luau, so step 4 of the report stays the real cost. | ✅ #2, #72 |
| Is output growth bounded? | **Yes** — 19.3x under a 24x ceiling, and if it had not fit the report would name the passes it gave up. The same command with `vm_isa_subset` off builds 90,523 B against this 67,411 B — 25.5% bigger for *less* per-build variation, because narrowing a VM removes handlers rather than adding obfuscation | ✅ #62, #63 |
| Can the pool be lifted into another build? | **No** — the AAD carries the format digest, so a foreign pool fails authentication on first read | ✅ #39 |
| Are there constants in the pool the program never reads? | **Yes** — 24 planted, encoded identically, scattered by value derivation rather than appended | ✅ #14 (constants only) |

Ten passes, one partial. What is left, in the order it should be done:

1. **#41, and the per-group pools it enables** — one pool per VM group, each keyed
   and AAD-bound to that group's format, then chunking with per-chunk keys inside
   it. R12 removed the inert `chunking_level`/`chunk_size`/`lazy_decode` knobs;
   if this lands it lands as a designed feature, and the runtime half (chunk
   table, per-chunk offsets, a lifetime policy) is where the work is. This is
   the item that answers the sharpest
   criticism in the review: there is currently one accessor for all constant data
   in an artifact, and recovers-then-walks-it tooling needs it only once.
2. **#24, #23** — several implementations per helper, then the freedom to put
   them anywhere in the artifact.
3. **#19, #34, #35, #40** — native-path variants: the native half of a hybrid
   build is more legible than the virtual half.
4. **#64, #67** — a second, adversarial extractor, so the cross-build numbers
   above are not measured by a tool that shares our reader design. The
   recoverability side (#65, #66) and the test that keeps it honest (#68) now
   have a real harness in `tools/reuse-audit.py`; CFG reconstruction and a
   matcher that reads emitted Lua rather than payload bytes do not.
5. **#27** — arithmetic encodings for numbers, which is also the row where a
   half-implementation would be worse than none (see #11).

### Re-running this measurement

```bash
# the whole checklist's testable half
# the whole checklist's testable half; the PATH prefix is what un-skips every
# test that has to run Luau rather than only emit it
PATH="$PWD/.luau-toolchain/bin:$PATH" python3 -m pytest tests/ -q
                                     # 1964 passed, 99 skipped

# a single build, scored
python3 -m couxobf protect examples/maze.luau --profile maximum \
  --vm-level maximum --min-nodes 1 --vm-family stack --dispatcher mixed \
  --string-level 3 --cache-policy none --seed 0xC0FFEE -o /tmp/out.luau

# the report, including the per-group VM table and which fields were not applied
python3 -m couxobf report examples/maze.luau --profile maximum

# how much of one build's recovered opcode table transfers to the next
python3 tools/reuse-audit.py examples/maze.luau --seeds 3
```

The `pending` list in the API response and the "requested but not applied"
section of the report are the machine-readable form of every ⬜ in this
document: 20 fields are declared in `Config` for a maximum build and are named as
not applied rather than being silently accepted. The endpoint will refuse an
option nothing reads, which is the same rule enforced from the other side. The
result panel shows the outcome rather than the request: a table with one row per
interpreter the build actually emitted (`vm 1 · register · decision_tree · 1
prototype · 31 opcodes · 1B op + 1B reg + 2B wide · targets rel · opcode cipher
add · 10 fused`), taken from the plan and cross-checked against the report text by
`tests/test_web.py` -- including the cipher, whose row reads `none (raw numbers)`
when a build leaves the numbers alone.

# couxobf security model

## The one thing to read first

**Obfuscation raises the cost of reading code. It does not make anything secret.**

Anything this tool produces runs on a machine an attacker controls, with a
debugger attached, in an interpreter whose every value they can print. If a
value reaches the client, the attacker can obtain it. No arrangement of
bytecode, encryption, or control flow changes that, and any tool that implies
otherwise is selling something.

So the honest question is never "is this secure?" but **"what does it now cost
to read this, and was that cost worth paying?"** This document answers that
question and states the limits plainly.

Two corollaries that follow directly:

- **Never put a genuine secret in protected client code.** Not an API key, not
  a signing key, not an authorization rule, not the answer to a validation
  check. Server-side enforcement is the only mechanism that works, and it works
  whether or not the client is obfuscated. See "Roblox specifics" below.
- **This tool is not a security mechanism.** It is a cost multiplier applied on
  top of one. If removing the obfuscation would let someone do something they
  should not be able to do, the design is wrong, not the obfuscation.

## Threat model

### What the attacker has

Assume the strongest realistic position:

- The protected artifact, in full, as many copies as they want.
- A working Luau/Roblox runtime, with the ability to run the artifact under a
  debugger, hook any global, and dump memory.
- Time. They are not racing a deadline unless you impose one, and you cannot
  impose one on a client.
- Standard tooling: disassemblers, decompilers, symbolic execution, and
  increasingly, language models that read transformed code competently.

### What the attacker wants

Three distinct goals, which the design treats differently because they have
different answers:

| Goal | Achievable? | What the tool does |
|---|---|---|
| Understand the program's structure and logic | Yes, given enough effort | Raises the effort |
| Extract embedded constants and strings | Yes, trivially, by running it | Raises the effort of *static* reading only |
| Recover a genuine secret | Yes | **Nothing. Do not embed secrets.** |

### What is out of scope

This tool does not attempt, and cannot provide: anti-tampering that survives a
determined attacker, anti-debugging, detection of analysis environments,
license enforcement, or protection of server-side logic. Anything claiming
those properties from client-side code alone is theater.

## What the transformations actually cost an analyst

Qualitative, and deliberately so. A "security percentage" would be a number
with no referent: cost depends on the analyst's skill, tooling, and patience,
none of which the build controls.

### Virtualization and dispatch (implemented)

A selected prototype is lowered to a register file driven by a generated
interpreter, with no lexical blocks and no visible loop structure. Four state
models (`register`, `accumulator`, `stack`, `hybrid`) and three dispatch shapes
(`nested_if`, `decision_tree`, `bucket`) are drawn per VM group, and `vm_variety`
means one artifact can hold two or three of them at once, each with its own opcode
map, field widths, jump-target mode and handler fusion. The report prints one line
per group so the claim is checkable rather than asserted.

(The heading used to read "control-flow flattening". It was a misnomer: what is
implemented is dispatch, not flattening -- there is no threaded code and no
dispatcher state that outlives one instruction. `control_flow_level` feeds
instruction reordering, which is real; graph flattening is not claimed.)

**Cost added:** an analyst must reconstruct a CFG per group, under a numbering
and an instruction geometry that exist only in this file, before they can reason
about the program at all. A tool written against `nested_if` with 1-byte operands
and absolute jump targets does not read a group that chose `decision_tree`, 2-byte
operands and an edge table. This is the single largest cost multiplier in the
current build, because it attacks *structure*, which is what a human reads first.

**Cost not added:** handler bodies are plain Luau, and permuting opcode *numbers*
does not change what a handler does -- step 4 of the build report is unaffected by
every setting in the tool. The `nested_if` shape is a linear `if`/`elseif` chain on
a plaintext counter; instrumenting the interpreter to log that counter recovers the
execution order mechanically. `encoded_pc` would have hidden the counter and is
declared-but-not-read, so the report lists it as pending rather than pretending.

### Constant pool encryption (implemented)

Literals do not appear in the artifact. They live in one ChaCha20-sealed blob
with a 32-byte authentication tag, decrypted once at runtime.

**Cost added:** static reading yields no string *values*, numbers, table keys,
or method names. An analyst grepping for a URL, an error message, or a table
key gets no hits. Measured on the upstream `stringinterp.luau`: of 32 string
literals in the source, none appear in the protected output.

**But not zero.** `strings(1)` still finds the global names the program uses --
`string`, `print`, `table` -- because those are visible by design (see "Known
limitations"). So the artifact still says which libraries it touches; it no
longer says what it does with them.

**Cost not added:** essentially none at runtime. The key is in the artifact --
it has to be, or the program could not run -- so the blob is decryptable by
anyone holding the file, with no execution required. Decrypting it is a script,
not a debug session; and the pool's *plaintext* is in the heap the moment a
constant is read, so a breakpoint on the accessor yields that constant. What it
no longer yields is the whole pool for free: one read gives one value, so
enumerating means driving reads, and any build with `decoys` on will collect
planted entries that the program never touches and cannot tell from the encoded
form. That is a cost, not a barrier -- the blob as a whole is recoverable.

Treat this as *removing the easy static signal*, not as confidentiality. That
is a real and useful property; it is not secrecy. The distinction matters
because the failure mode of confusing them is putting a secret in the pool.

The cryptographic choices are deliberately uninteresting: ChaCha20 for
confidentiality, HMAC-SHA-256 for integrity, HKDF-SHA256 for key derivation,
all with published test vectors, all cross-checked between the Python
implementation and the generated Luau. Nothing here is invented, because an
invented primitive is the one part of a system like this that is likely to be
actually broken rather than merely bypassable. Confidentiality, integrity and
obfuscation are kept separate: the tag detects tampering, the cipher hides
bytes, and neither one obscures program structure.

### Per-build variation (implemented)

Key material, nonces, and name assignments derive from a 128-bit build seed
through domain-separated streams. The same source under two seeds produces
structurally different output; the same source, seed and version produce
byte-identical output.

**Cost added:** defeats copy-paste analysis. A deobfuscator written against one
build does not transfer to the next, and diffing two builds of the same source
does not isolate the change.

**Cost not added:** nothing against an analyst working on the single build they
care about, which is the usual case.

Alongside the shape changes, a build digests its own format decisions -- the
family, dispatcher, opcode count and instruction format of each group -- and folds
that 8-byte digest into the constant pool's additional authenticated data. The
digest is printed in the report, so a pool lifted out of one artifact fails
authentication in another whose config happens to match, without anything in the
file advertising that it is Couxobf output. A build with nothing virtualized
reports the digest as drawn-but-unbound, because there would be no running format
to key anything to.

## Known limitations

Stated explicitly, because an undocumented limitation is worse than a
documented one.

**Global names stay visible.** `print`, `game`, `workspace` and every other
global appear in the output by name. Hiding them requires reading through an
environment table, and Luau resolves a global against the *calling function's*
environment -- so an environment captured at load time silently breaks
`setfenv`. That indirection was implemented, broke the upstream `locals.luau`
conformance test, and was reverted. A test asserts the behaviour so it is not
quietly reintroduced.

**The VM is Luau source, not bytecode.** The dispatcher and register file are
readable Luau. A Luau-level VM cannot hide from a Luau-level debugger, because
the debugger is running the same language.

**Helpers are recognizable scaffolding.** The six runtime helpers used to be
named `_kpack`, `_kunpk`, `_kiter`, `_kiterpack`, `_kitercheck` and `_kapp` in
every artifact ever produced; their names are now drawn per build (a fixed string
appearing a hundred-odd times is a signature by itself). What is unchanged: there
is one implementation per operation, they are emitted as one statement, and their
position in the file is decided by the emitter rather than by the build seed.
Diversifying the implementations is on the roadmap and is not done (#23, #24).

**The environment guard raises cost and prevents nothing.** `env_guard` and
`dump_guard` capture the interesting library names at load and re-check five
surfaces (`string.dump`, `getbytecode`, `getscriptbytecode`, `debug.getinfo`,
`debug.gethook`) at every VM entry; at level 2 the build can neutralize a logging
`__index` or refuse once a surface has been swapped. None of that is a boundary.
A dumper that patches the in-memory proto never calls any of those functions; a
hook installed before the artifact loads sees the capture happen; and a debugger
runs the same language the guard is written in. The artifact's own report states
what the guard captured and whether it tripped, because a build should not claim
more than it did.

**Semantic fidelity constrains transformation.** The tool must preserve Luau
semantics exactly, including observable error messages (user code matches on
them with `pcall`), `setfenv` behaviour, per-iteration loop variable capture,
and numeric-for coercion through `tonumber`. Every one of those is a place a
more aggressive transformation would be wrong. Correctness is not negotiable
here, which caps how far obfuscation can go.

## Verification

Every claim above is checked by execution, not asserted:

- `tests/test_roundtrip.py` runs the original source and the reconstruction
  under the pinned Luau 0.700 toolchain and requires identical stdout and exit
  status. 40 hand-written fixtures, each targeting one semantic hazard, plus
  the upstream conformance corpus.
- `tests/test_constpool.py` runs the same 40 fixtures through the *protected*
  path, and verifies the pool bit-exactly -- NaN, signed zero, infinities,
  values above 2^53, and strings containing every byte value -- against two
  independent decoders. It also verifies that flipping a bit in the sealed blob
  stops the runtime rather than yielding wrong constants.
- `tests/test_luau_crypto.py` cross-checks the generated Luau crypto against
  Python's `hashlib`/`hmac` and a Python ChaCha20, in both directions.

- `tests/test_guard.py` builds the same program at all three guard levels and
  requires the same stdout from all of them, then runs it under a hostile
  environment: a `_G` with a logging `__index`/`__newindex`, and `getbytecode`
  swapped for a trapping stub mid-run. Level 0 prints and exits 0; level 2 with
  `policy=fail` exits non-zero. A defence test that only inspects emitted text
  would pass on a build that does nothing.
- `tests/test_config.py` greps the tree for reads of every field in
  `Config.IMPLEMENTED` and fails on a field nothing consumes; `tests/test_web.py`
  renders the generated form against a stub DOM and fails if a live field is
  missing from it or a pending one is present in it. Those two are what keep the
  site's option list honest as the pipeline changes underneath it -- the grep is
  on attribute reads, which is why `FormatPrefs.from_config` reads its fields as
  attributes rather than through `getattr(config, "name", default)`.
- The build report's own "requested but not applied" section is the artifact-level
  view of the same rule, and `api/obfuscate.py` refuses to accept a pending
  field. A claim and a knob have to be backed by a read.

The conformance corpus has two documented exclusions, each replaced by a narrow
test covering the behaviour it also exercises: `calls.luau` asserts on *which*
resource limit trips first (the original exhausts Luau's unpack limit; a
lowering that uses more memory per frame hits the allocator first), and
`iter.luau` asserts on Luau's specialized global-`next` loop, which is a
bytecode detail rather than a semantic one. Excluding a test is how a real bug
hides, so anything added to that list has to justify itself in a comment.

## Roblox specifics

Obfuscation is not access control, and in a Roblox game the gap is widest,
because the client is fully attacker-controlled by design.

- **Server-side secret separation.** Anything genuinely secret stays on the
  server. Protected client code is still client code.
- **Validate every argument.** The server must not trust a value because the
  client computed it. Assume every remote payload is forged.
- **No generic execution remotes.** A remote that takes a path and arguments
  and runs them is arbitrary remote code execution with a UI. Bind remotes to
  specific, individually validated actions.
- **Rate limit per player and per action,** with cooldowns, server-side.
- **Never trust client physics or `Touched` state.** A client that reports it
  touched the coin is reporting a wish.
- **Use network ownership deliberately.** Owning a part means the client
  authoritatively simulates it; that is a performance decision with security
  consequences.

If the client can be modified to gain an advantage, and the server does not
independently check, the advantage is available. Obfuscating the client changes
how long it takes to find, not whether it exists.

## Reporting

Build reports describe reverse-engineering *cost* in qualitative terms -- what
an analyst must do, in what order, and which steps are automatable. They do not
report a security percentage, a score, or a grade, because those numbers have
no referent and imply a guarantee the tool cannot make.

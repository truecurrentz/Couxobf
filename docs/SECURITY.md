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

### Control-flow flattening (implemented)

Every prototype is lowered to a table-backed register file driven by a
`while true do if pc == K then ... end` dispatcher. There are no lexical
blocks, no visible loop structure, and no `if`/`else` nesting to read.

**Cost added:** an analyst must reconstruct the CFG by hand before they can
reason about the program at all. This is the single largest cost multiplier in
the current build, because it attacks *structure*, which is what a human reads
first.

**Cost not added:** the dispatcher is a linear `if`/`elseif` chain on a
plaintext counter. Symbolically executing it, or just instrumenting the
interpreter to log `pc`, recovers the CFG mechanically. This is
straightforward to automate and someone will.

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
anyone holding the file, with no execution required. And the plaintext is in
the heap the moment any constant is read, so a single breakpoint on the
accessor function dumps the entire pool.

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

**Helpers are shared across prototypes.** `_kpack`, `_kunpk`, `_kiter`,
`_kiterpack`, `_kitercheck`, `_kapp` appear once, with fixed shapes. They are
immediately recognizable as scaffolding and are the obvious place to start
reading. Diversifying them is on the roadmap and is not done yet.

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

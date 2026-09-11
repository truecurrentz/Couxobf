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
interpreter, with no lexical blocks and no visible loop structure. The
interpreter itself is one deliberately consolidated design -- a single register
discipline with a guarded, table-indexed dispatch -- because shipping four
parallel interpreter shapes put four recognizable surfaces in every artifact and
gave a deobfuscator four times the targets. What varies is everything *around*
that one shape, and it varies per VM group: `vm_variety` lets one artifact hold
several interpreters at once, and each group draws its own opcode numbering,
instruction format (field widths, operand masks, padding, field order,
jump-target mode and opcode cipher), instruction subset and dispatch-key
mixing. Two more axes are per group as well: `vm_isa_subset` gives a VM only
the operations its own protos were lowered to, and `opcode_cipher` stores a
bijective image of the dispatcher's number in the bytecode, with the order of
the dispatch arms drawn alongside it. The report prints one line per group so
the claim is checkable rather than asserted, and the web result panel shows the
same table, cipher included. The earlier multi-family/multi-dispatcher names
still load for saved configs, but they normalize to this one interpreter.

(The heading used to read "control-flow flattening". It was a misnomer: what is
implemented is dispatch, not flattening -- there is no threaded code and no
dispatcher state that outlives one instruction. `control_flow_level` feeds
instruction reordering, which is real; graph flattening is not claimed.)

**Cost added:** an analyst must reconstruct a CFG per group, under a numbering
and an instruction geometry that exist only in this file, before they can reason
about the program at all. A tool written against one group's 1-byte operands,
biased jump targets and additive register mask does not read a sibling group
with 2-byte operands, an edge table and a different mask -- the recovered
format is per group, not per artifact. A group that narrowed its instruction
set also has fewer arms than the tool expects, and its payload numbers have to
pass through that build's reader before they mean anything. This is the single
largest cost multiplier in the current build, because it attacks *structure*,
which is what a human reads first.

**What that cost is, measured.** `tools/reuse-audit.py` builds the same program
under several configurations, learns a "stored value means operation" table from
each build the way a static tool would, and scores it against every other build.
Across two seeds of `examples/maze.luau`: numbering transfers 12% of the time, the
payload table 1%, instruction layout 0%, arm order 0%. A protector that varies
nothing scores 100% on all four, which is what makes those numbers mean something.
The measurement is one weak matcher over straight-line sweeps, so it is a floor on
the analyst's work rather than a ceiling on it: the *number of handlers per group*
does transfer (100%), because how many operations a function needs is a property
of the function, not a secret.

**Cost not added:** handler bodies are plain Luau, and permuting or re-encoding
opcode *numbers* does not change what a handler does -- step 4 of the build report
is unaffected by every setting in the tool. The `nested_if` shape is a linear
`if`/`elseif` chain on a plaintext counter: after the reader decodes the field, the
comparison is on an ordinary local, so instrumenting the interpreter to log that
local recovers the execution order mechanically. The fetch itself is no longer
`byte(code, pc)` written at the dispatch site -- it is a generated per-group reader
whose offsets, widths and masks come from the same descriptor as the encoder, which
means a grep for the fetch misses, and a recovered reader is per-group rather than
one per artifact. The `encoded_pc` knob that once claimed to hide the program
counter was removed in R12: pc protection is what `pc_protection` (biased and
relative jump targets) actually delivers, and a dead knob is not how the tool
talks about protection.

### Varargs and upvalues at the VM boundary (implemented, R5)

The VM frame is an ordinary table, so the boundary for joining it is: nothing
a real Luau closure must be able to see may live in the frame. Varargs
crossed first (R5): call arguments are private to the call, so the entry point
stashes the caller's packed arguments in the frame and `VARARG` is a slice of
them. Upvalue *reads and writes* cross with `vm_upvalues` (R5's second
increment, off by default), and they cross differently: the frame still holds
no captured state. The stub replacing a capturing function is emitted at the
closure site, so it is lexically inside the scope that owns the variables; it
builds, per upvalue, a getter and a setter closure over the very expression
the native reconstruction uses -- the owner's register slot, or the local
holding that iteration's value or cell where Luau's semantics demand one -- and
hands
the list to the interpreter as a third entry argument. `GETUPVAL` and
`SETUPVAL` call through it, which keeps reads and writes live and consistent
with any native sibling sharing the variable, including writes that land
between two of the child's reads. One line does not move even with the flag:
a capture whose owning prototype is itself virtualized has its storage inside
a frame no closure can see, so the selector unselects such a prototype (a
fixpoint, since the ownership relation is circular). That rule is what R5's
fourth increment removes *for builds that turn closures on*: the interpreter
builds the accessor, and it can see the frame it owns. With `vm_upvalues`
alone -- the configuration this paragraph describes -- the rule still stands,
because there the accessors are emitted at a native closure site and no
virtualized owner's frame is reachable from one.

### Nested closures that capture nothing (implemented, R5's third increment)

With `vm_closures` (off by default, like `vm_upvalues`) a virtualized
prototype may create closures of its own, provided the children it creates
capture nothing. A child with no upvalues needs no state from the frame it was
born in, so the interpreter can hand out its entry stub itself: `CLOSURE`
stores `stubs[pid ^ row_mask]` in a register, and that stub is the same plain
Luau function the native reconstruction would have emitted at the closure
site. Two obligations come with it. The children have to come into the VM with
their parent -- the interpreter has no function value for a child left native
-- so a virtualized prototype takes its virtualizable subtree in with it,
however small the children are, and a child that cannot be built in the VM at
all unselects the parent, which unravels upwards to the root of the tree. And a child belongs to its parent's
VM *group*, because the parent's CLOSURE arm names this interpreter's entry
point; the artifact carries no table mapping prototypes to interpreters, and a
closure tree is one indivisible unit when a build asks for more than one VM.

**Cost added:** none measurable. Each stub is built once at load rather than
once per closure creation, so the common case allocates *less* than before.

**What it did not cover, and now does:** a child that captures -- the case
real callbacks are made of. The fourth increment builds the accessor inside
the interpreter, which is the one place that can see the frame: a getter and a
setter closing over the parent's slot, or over the cell the parent made when
the variable is a loop-body local that Luau gives every iteration its own, and
the parent's own accessor pair relayed for an upvalue the parent carries. The stub
is `setfenv`'d to the parent's environment, since a closure born inside the
interpreter would otherwise inherit the interpreter's. Prototype count on the
corpus goes 118 -> 151. Both flags are still new machinery behind a default of
off rather than a change to what every build does.

**Cost added:** a capturing stub allocates two closures per upvalue per call
and every `GETUPVAL`/`SETUPVAL` is two indirect calls. That is real, and it is
why the flag defaults off; the common case (no captures) passes `false` and
allocates nothing. What it buys is structural: upvalue-heavy code -- state
machines, iterators with retained closures, module patterns -- used to be
exactly the code the VM could not take, and leaving it native left a
recognizable shape in every artifact.

### Directives: per-function control (implemented, R8)

A `--!couxobf:no_virtualize` or `--!couxobf:virtualize` comment names the
first function declared after it, so the user can exempt a hot callback from
the VM or force-protect a function the score would skip. The directive is a
request about *which* functions run in the VM, not a licence to ignore what
the VM cannot represent: a `virtualize` on a function the selected VM cannot
take -- with `vm_upvalues` off, that still includes functions capturing
upvalues -- on the main chunk, or under `virtualization_level = none` is
reported as ignored rather than implied to have run, and an unknown
`--!couxobf:` spelling fails the build instead of silently doing nothing. See
`docs/research-comparison.md` § R8.

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

### Index-to-number table keys (implemented, R9, opt-in)

The pool hides key *strings*, but breaking the pool once yields the shape of
every record. `index_to_num` (CLI `--index-to-num`, off by default) goes a
step further for tables it can prove safe: it rewrites the keys to per-build
numeric handles *before lowering*, so the key strings never enter the pool at
all. The safety rule is a strict whitelist -- the table must be a plain local
bound once to a literal-string-key constructor, never reassigned, never captured
as an upvalue, and used only as `t.name` or `t["literal"]`. Any value-flow
(passing, returning, aliasing, dynamic indexing, method call, operator operand)
declines the table, and a table can opt out with
`--!couxobf:no_index_to_num` above its declaration. Runtime cost is zero
(numeric indexing is marginally faster); a corpus-wide run rewrote 0 tables and
declined 7, with every build still verifying, which is the point of a
whitelist: it is allowed to do nothing, it is never allowed to change behaviour.

### Per-build variation (implemented)

Key material, nonces, and name assignments derive from a 128-bit build seed
through domain-separated streams. The same source under two seeds produces
structurally different output; the same source, seed and version produce
byte-identical output.

**Cost added:** defeats copy-paste analysis. A deobfuscator written against one
build does not transfer to the next -- see the measured transfer rates under
*Virtualization and dispatch* above -- and diffing two builds of the same source
does not isolate the change, because the diff is most of the file.

**Cost not added:** nothing against an analyst working on the single build they
care about, which is the usual case. Per-build variation is a *reusability* tax:
it makes a tool, a script or a note expensive to write once and reuse, and it
buys an attacker who intends to read one artifact a directory of the same file in
a different order.

Alongside the shape changes, a build digests its own format decisions -- the
family, dispatcher, opcode count (each group's own narrowed set, not the published
ISA) and instruction format of each group -- and folds
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
`dump_guard` capture the interesting library names at load and re-check the
watched surfaces (`string.dump`, `getbytecode`, `getscriptbytecode`,
`debug.getinfo`, `debug.gethook`) from inside the dispatch loop, masked the
way an opaque predicate is -- a mid-run swap of a surface is caught within a
handful of instructions rather than at a greppable entry point; at level 2
the build refuses with the dispatcher's own fallthrough wording, assembled at
runtime so the phrase never appears in the artifact. None of that is a boundary.
A dumper that patches the in-memory proto never calls any of those functions; a
hook installed before the artifact loads sees the capture happen; and a debugger
runs the same language the guard is written in. The artifact's own report states
what the guard captured and whether it tripped, because a build should not claim
more than it did.

**A closure that captures a local declared in a loop body costs one table per
iteration.** Luau gives every iteration its own copy of such a local, and a
closure built in the body captures that iteration's. Reading and writing pull
in opposite directions -- a per-iteration copy is right for a reader, and
wrong for two closures of one iteration sharing a counter -- so the
representation is a cell: one table allocated at the declaration, whose single
field is the variable, and through which every access goes, the loop body's
own included. Both directions then agree, at every profile, native or
virtualized:

```lua
local makers = {}
for i = 1, 3 do
    local n = i * 2
    makers[i] = function()
        n += 1
        return n
    end
end
print(makers[1](), makers[1](), makers[2](), makers[3]())
-- 3 4 5 7, protected and not
```

What that leaves is cost and recognisability rather than behaviour: a captured
loop-body local becomes a `GETTABLE`/`SETTABLE` pair per access and a
`NEWTABLE` per iteration, and the field is a constant. A local no closure
captures is untouched, so the shape appears only where a program already
captures one.

**One pool and one bank per artifact.** Constant data lives in exactly two places
-- the sealed pool and the string bank -- each authenticated as a whole. So the
"single point of extraction" criticism is only half answered: there is one reader
per interpreter for *code*, and one for *data* for the entire program. Per-VM-group
pools, each keyed and AAD-bound to the format of the interpreter that reads it, are
the next structural change and are not built; until then a dumper who recovers the
pool accessor has every literal in the program, decoys included.

**One function, one interpreter.** `vm_variety` gives a program several VMs and
`vm_isa_subset` gives each one its own instruction set, but a prototype belongs to
exactly one group. Nothing splits a single function across two VM families: that
means moving a live frame -- registers, program counter, open upvalues, yield state
-- between interpreters mid-function, which the lowering cannot express yet. The
same missing prerequisite is why there is no per-region data representation and no
run-time rescheduling of work between interpreters.

**The string system varies its order, not its structure.** Fragments are packed
into 512-byte pages with shuffled page order and per-occurrence tickets instead of
ids, and each page's keystream is separately addressed. Page size is fixed -- it is
a `StringBank` constructor argument constrained to multiples of 64, not a `Config`
field, so there is no knob to advertise and no diversity to claim -- and there is
one implementation of the bank reader. `numeric_protection_level`,
`constant_protection_level` and `table_key_protection` are wired; the
`chunking_level` knob was removed in R12 (per-chunk keys remain unbuilt and are
not advertised as if they existed).

**Semantic fidelity constrains transformation.** The tool must preserve Luau
semantics exactly, including observable error messages (user code matches on
them with `pcall`), `setfenv` behaviour, per-iteration loop variable capture,
and numeric-for coercion through `tonumber`. Every one of those is a place a
more aggressive transformation would be wrong. Correctness is not negotiable
here, which caps how far obfuscation can go.

**A captured loop-body local is a cell now, and what is left is cost rather
than constraint.** Luau gives every iteration of a loop its own cell for a
local declared in the body, and a retained closure must keep seeing that
iteration's. The reconstruction models registers as shared slots, so a
captured loop-body local is no longer one of them: it becomes a table
allocated at the declaration -- the one site that runs once per iteration --
and every access goes through it, the loop body's own included, native and
virtualized alike. Both directions of the old tension then hold at once: a
reader sees the iteration it was built in, and two closures of one iteration
sharing a counter share that counter. What the representation costs, and the
shape it leaves in the output, are written up under the limitations above.

**`#` on a table with nil holes is reproduced in content, not in length.**
When a multi-value result -- a call return, a vararg list (R5) -- is appended
into a table, the VM copies all `n` values including trailing nils, so every
*element* is present and correctly placed. But `#t` on a table containing nil
holes is undefined in Luau itself: the result depends on the internal
array/hash split, which depends on how the table was built. The native
compiler builds `{ ... }` with a size hint; the VM fills the table
sequentially. For a holey table the two can report different lengths. This is
undefined-behaviour territory the language itself does not pin down (the same
source rebuilt with different allocation could move it), and it predates R5 --
the call-return path has always had it. Code that needs the true count of a
possibly-holey pack should use `table.pack(...).n`, which is exact and which
the VM reproduces bit-for-bit.

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

- `tests/test_reuse.py` runs `tools/reuse-audit.py` over a four-function program
  and asserts what the audit measures: a `stable` configuration must transfer 100%
  on all five metrics -- a positive control, so an audit that quietly stopped
  extracting reads as perfect diversity and fails the suite instead -- while a
  hardened build must transfer under 5% of its payload table, 0% of its
  instruction layouts and 0% of its arm orders, with per-group handler counts that
  differ from each other and stay stable across seeds.
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

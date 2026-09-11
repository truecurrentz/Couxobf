/* couxobf web UI. No framework, no build step, no dependencies.
 *
 * The option form is built from two tables that have to agree:
 *
 *   SPEC   -- the curated structure: which groups exist, which field goes in
 *             each, what a control is called and what it does.
 *   surface -- kinds, choices, ranges and defaults, fetched from the endpoint.
 *
 * Only the second one decides what a build accepts, so the form is not allowed to
 * contain a field the endpoint has never heard of; `tests/test_web.py` asserts the
 * two cover the same set.  Fetching `surface` is an enhancement, not a dependency:
 * opening this file straight from the filesystem still gives a working form, built
 * from the fallback copy at the bottom of the file, which the same test keeps from
 * drifting.
 */

const $ = (id) => document.getElementById(id);

/* The curated part: order, grouping, labels, help. */
const SPEC = [
  {
    id: "core",
    title: "What gets hidden",
    help: "Everything below decides how much of the program is turned into bytecode " +
          "for a private interpreter, and how that interpreter is shaped.",
    fields: [
      ["profile", "Preset", "select",
       "Sets every option below. Change it any time; a control you have moved by " +
       "hand keeps its value until you press the preset again."],
      ["virtualization_level", "Virtualization", "select",
       "How many functions go into the VM. `none` leaves a native build with " +
       "renaming, string protection and integrity only."],
      ["min_virtualize_body_nodes", "Body size floor", "int",
       "Functions smaller than this stay native: below about eight AST nodes a VM " +
       "frame costs more than it hides."],
      ["max_vm_functions", "Max virtualized functions", "int",
       "A cap, not a target. 0 means no limit."],
      ["vm_polymorphism", "Woven VM", "bool",
       "Uses the single hardened VM: mixed operand data paths inside one shared " +
       "interpreter and one guarded dispatch loop, avoiding multiple attack surfaces."],
      ["vm_variety", "VM compatibility", "int",
       "Legacy compatibility field. Builds now normalize to one shared VM per artifact."],
      ["vm_isa_subset", "Per-VM instruction set", "bool",
       "Each interpreter carries only the opcodes the functions on it need, so the " +
       "handler count follows the code instead of being the whole ISA in every " +
       "build. It also shrinks the artifact; a VM running three numeric helpers " +
       "does not need forty arms."],
      ["vm_upvalues", "Virtualize capturing functions", "bool",
       "Lets functions that capture upvalues run in the VM. The stub replacing " +
       "such a function builds getter and setter closures over the same storage " +
       "the native code uses, so reads and writes stay live and shared with any " +
       "native sibling. A capture whose owner is itself virtualized still keeps " +
       "the function native. Off by default."],
      ["vm_closures", "Virtualize functions that build closures", "bool",
       "Lets a virtualized function create closures of its own, when the " +
       "children it creates capture nothing: the interpreter hands out the " +
       "child's entry point instead of the source declaring it. The children " +
       "run in the VM too, and stay in their parent's group, so the artifact " +
       "carries no table mapping functions to interpreters. A child that " +
       "captures still keeps its parent native. Off by default."],
    ],
  },
  {
    id: "format",
    title: "Instruction format",
    help: "What one instruction looks like on the wire: which fields, how wide, in " +
          "what order, and what the numbers in them mean. A devirtualizer written " +
          "against one artifact stops transferring here.",
    fields: [
      ["operand_randomization", "Operand layout", "bool",
       "Field widths, order, padding and masks are drawn per build."],
      ["instruction_formats", "Format variety", "select",
       "0 keeps the historical layout, 1 mixes, 2 spends every knob. A level " +
       "because the size cost is real and per-group."],
      ["pc_protection", "Encoded targets", "bool",
       "Jump targets are biased or relative rather than raw positions, so the " +
       "numbers in the stream mean nothing without the format."],
      ["edge_indirection", "Edge table", "bool",
       "Control-flow edges leave the instruction stream: a payload carries an " +
       "ordinal and the destinations live in their own blob."],
      ["opcode_randomization", "Opcode randomization", "bool",
       "Number opcodes per build rather than following Luau's order."],
      ["opcode_cipher", "Opcode cipher", "bool",
       "The payload carries a disguised image of the opcode number -- a rotation, " +
       "an affine map, or a halves swap -- while the interpreter branches on the " +
       "number its own map assigned. Costs no bytes, and it is what makes a table " +
       "of \"byte 7 means ADD\" from one build say nothing about another."],
      ["opcode_aliases", "Opcode aliases", "select",
       "How many numbers can reach one instruction: 0 one number per opcode, 1 " +
       "some opcodes get a second alias, 2 widens both the alias set and the " +
       "numbering space."],
      ["register_randomization", "Register numbering", "bool",
       "Register fields are widened and masked. A full permutation is not " +
       "implemented: FORLOOP, CALL and SETLIST address base+1..+3."],
      ["control_flow_level", "Control flow", "select",
       "How far blocks are rearranged, from reordering up to flattening."],
      ["opaque_predicates", "Opaque predicates", "bool",
       "Add short validity predicates whose truth depends on the current decoded " +
       "VM state, not repeated arithmetic identities a simplifier can delete."],
      ["branch_inversion", "Invert branches", "bool",
       "Randomly flip eligible if/else branches and their conditions before lowering, " +
       "without adding dummy blocks or changing evaluation order."],
      ["block_permutation", "Permute blocks", "bool",
       "Emit basic blocks in an order that is not the source order."],
    ],
  },
  {
    id: "data",
    title: "Data protection",
    help: "Literals are not stored as literals. Numbers keep their exact IEEE-754 " +
          "value -- precision, signed zero and NaN included -- but not their shape.",
    fields: [
      ["string_protection_level", "Strings", "select",
       "0 off, 1 encoded, 2/3 fragmented, ChaCha20 encrypted, HMAC-SHA256 checked, " +
       "lazy, ticketed and indirectly referenced through randomized string IDs."],
      ["constant_protection_level", "Constant pool", "select",
       "0 disables the pool, 1 uses the verified encrypted pool. Higher experimental " +
       "modes are withheld until differential execution is clean across runtimes."],
      ["numeric_protection_level", "Numbers", "select",
       "Masks IEEE-754 double bytes inside the encrypted pool so number materializing " +
       "is generated dynamically while preserving exact Luau float semantics."],
      ["table_key_protection", "Table keys", "bool",
       "Assemble syntactic property names from protected fragments so field access " +
       "does not expose a stable GETTABLEK/SETTABLEK key vocabulary."],
      ["index_to_num", "Table keys to numbers", "bool",
       "Rewrite the keys of provably-static local tables to per-build numeric " +
       "handles, so the key strings never enter the constant pool at all. " +
       "Opt-in whitelist; a table can bow out with --!couxobf:no_index_to_num above it."],
      ["cache_policy", "Decoded-string cache", "select",
       "How much plaintext sits in the heap: `none` re-materialises on every read, " +
       "`full` keeps everything, `bounded` keeps a rolling window."],
      ["bounded_cache_size", "Cache window", "int",
       "How many entries the bounded cache holds before it drops them."],
      ["decoys", "Decoy entries", "bool",
       "Real pool entries and dispatch numbers the program never uses, with no " +
       "recognisable pattern in which ones they are."],
      ["decoy_constants", "Decoy count", "int",
       "Per build. Scales with the real pool so a small file does not gain a " +
       "conspicuous block of noise."],
      ["metadata_fragmentation", "Split descriptor tables", "bool",
       "Keep the payload, the constants and the edge table in three locals instead " +
       "of one record per prototype, so there is no single object to dump."],
    ],
  },
  {
    id: "guards",
    title: "Environment and dump guards",
    help: "These do not prevent a dump; nothing in a Lua VM can. They remove the " +
          "free look at which globals the artifact touches, and they notice a " +
          "replaced dump surface. Both are drawn from the runtime's own snapshot of " +
          "the environment before any hook is in place.",
    fields: [
      ["env_guard", "Anti environment logging", "select",
       "0 off, 1 snapshot, 2 snapshot plus refusing to run when the environment has " +
       "been given a logging __index/__newindex pair. At 1 and above the runtime's " +
       "own library lookups become chunk locals, so an __index logger does not see " +
       "them at all."],
      ["dump_guard", "Anti dump", "select",
       "Checks portable Luau dump/introspection surfaces such as debug.info, " +
       "debug.getinfo, debug.traceback, debug.gethook and string.dump, then " +
       "refuses before plaintext access at level 2."],
      ["guard_policy", "When a guard fires", "select",
       "`fail` refuses the same way a corrupt payload does, so the trip is not a " +
       "message that names the check. `ignore` keeps running, which is how you " +
       "measure the checks on a machine that legitimately has a hooked " +
       "environment."],
    ],
  },
  {
    id: "output",
    title: "Output",
    help: "How the artifact is written and how much it is allowed to grow.",
    fields: [
      ["minify", "Minify", "bool",
       "No newlines or indentation. Harder to read; also harder for you to diff " +
       "against a previous build."],
      ["strip_types", "Strip type annotations", "bool",
       "Luau type syntax is erased either way; this drops it before lowering rather " +
       "than carrying it."],
      ["hash_comments", "# comments", "select",
       "`auto` strips a leading # (the `#!` shebang and the convention some " +
       "tooling uses), `strip` always, `strict` refuses the input. A # inside a " +
       "string or an operator like #t is never touched, and the stripped source is " +
       "re-parsed to prove nothing was cut through."],
      ["blob_encoding", "Blob spelling", "select",
       "How sealed blobs (pool ciphertext, string pages) are written. `dense` " +
       "ships base85 over a per-build alphabet (~1.25 chars per byte, decoded " +
       "once at load); `hex` keeps the escaped form (~4 chars per byte) for " +
       "debugging. Same protection either way, and tiny builds keep `hex` " +
       "automatically when the decoder would cost more than it saves."],
      ["max_output_growth", "Size budget", "float",
       "Above this ratio the pipeline gives up the most expensive optional passes " +
       "and rebuilds, then reports what it dropped. 0 disables the check. A maximum " +
       "build of a small file runs 12-16x, so the default is 24."],
      ["fingerprint", "Format fingerprint", "bool",
       "Record a structural digest of what this build decided in the report, and " +
       "bind the constant pool to it. No marker string ends up in the artifact."],
      ["seed", "Seed", "seed",
       "Empty draws a fresh 128-bit seed per build, which is the point: a fixed seed " +
       "means a fixed artifact."],
    ],
  },
];

/* Fields the endpoint accepts that this page does not have a control for. The
   form generator refuses to build one, and the banner below says so, because a
   knob can only be offered once the pipeline reads it. */
const EXTRA_WIDGET = {
  kind: "text",
};

const PRESET_BLURB = {
  compact: "Renaming and string protection, no VM. Smallest output.",
  balanced: "One VM, common settings, moderate growth.",
  hardened: "Several formats, integrity checks, bigger.",
  maximum: "Every pass, including the ones that cost 12-16× in size.",
};

const GROUPS = SPEC.map((g) => g.fields.map((f) => f[0]));
const FIELD_NAMES = GROUPS.flat();

/* Widgets that are not Config fields. */
const SYNTH = {
  profile: { kind: "enum", choices: ["compact", "balanced", "hardened", "maximum"],
             default: "maximum" },
  seed: { kind: "text" },
};

const PRESET_LABELS = {
  compact: "Compact",
  balanced: "Balanced",
  hardened: "Hardened",
  maximum: "Maximum",
};

/* ---------- option state ---------- */

/* A program worth obfuscating: a metatable, a closure, loops, numeric formatting.
   Small enough that a build finishes in about a second, and it prints something,
   so a user can compare the original output with the protected one. */
const EXAMPLE = `-- inventory.luau
local Catalog = {}
Catalog.__index = Catalog

function Catalog.new(name)
  local self = setmetatable({}, Catalog)
  self.name = name
  self.items = {}
  return self
end

function Catalog:add(sku, label, unitPrice, stock)
  self.items[sku] = { label = label, unitPrice = unitPrice, stock = stock }
end

function Catalog:discountFor(quantity)
  if quantity >= 100 then return 0.25
  elseif quantity >= 25 then return 0.10
  elseif quantity >= 5 then return 0.05 end
  return 0
end

function Catalog:totalFor(sku, quantity)
  local item = self.items[sku]
  if item == nil then return nil, "unknown sku" end
  if item.stock < quantity then return nil, "insufficient stock" end
  local rate = self:discountFor(quantity)
  return item.unitPrice * quantity * (1 - rate), rate
end

local function buildCounter(start)
  local count = start
  return function()
    count = count + 1
    return count
  end
end

local shop = Catalog.new("Taytay Hardware")
shop:add("NAIL-3", "3-inch nails", 0.15, 5000)
shop:add("PLANK-8", "8ft plank", 4.75, 240)
shop:add("SCREW-BOX", "Screw box (500)", 12.5, 60)

local receipts = {}
local nextLine = buildCounter(0)

for _, sku in ipairs({ "NAIL-3", "PLANK-8", "SCREW-BOX", "NAIL-3" }) do
  local quantity = ({ 200, 30, 4, 3 })[nextLine()]
  local net, rate = shop:totalFor(sku, quantity)
  if net then
    table.insert(receipts, string.format("%s x%d = %.2f", sku, quantity, net))
  else
    table.insert(receipts, string.format("%s: %s", sku, rate))
  end
end

local grand = 0
for i = 1, #receipts do
  print(i .. ". " .. receipts[i])
  for token in receipts[i]:gmatch("= (%d+%.%d+)") do grand = grand + tonumber(token) end
end

print(string.format("%s: %d lines, total %.2f", shop.name, #receipts, grand))
`;

const HONESTY = `What this does, and what it does not.

It raises the cost of reading the program. It does not make the program unreadable.

- The output is Luau source. Anyone who can run it can run it, and anything that
  can run can be observed while it runs. A dumper attached to a real VM can read
  the constant pool after the runtime decrypts it, because decrypting it is the
  runtime's job.
- The key material is inside the artifact. So is the interpreter, so is the format
  description. Each of those is findable by someone determined enough; what they
  cannot do cheaply is find them in a build whose instruction format, opcode
  numbering, pool layout and helper names differ from the last build's.
- The environment and dump guards remove a free look and notice a replaced
  surface. A runner that never touches string.dump, keeps its own VM, and does not
  install a logging metatable trips nothing at all -- that is a dump no guard could
  see, and pretending otherwise is how tools get trusted to do more than they do.
- Roblox's own protections are not part of this. Output is checked against the API
  surface, not run inside an executor.

The useful model is cost, not secrecy. docs/SECURITY.md in the repository has the
whole version of this.`;

let surface = {};       // from the endpoint: {name: {kind, choices, min, max, ...}}
let profileValues = {}; // from the endpoint: {profile: {name: value}}
let pendingFields = []; // from the endpoint: config fields nothing reads yet

function specFor(name) {
  return surface[name] || SYNTH[name] || { kind: name };
}

function widgetFor(name) {
  const el = $(`opt-${name}`);
  return el ? el.querySelector("input, select") : null;
}

function currentValue(name) {
  const el = widgetFor(name);
  if (!el) return undefined;
  if (el.type === "checkbox") return el.checked;
  if (el.type === "range" || el.dataset.kind === "int") {
    const n = parseInt(el.value, 10);
    return Number.isNaN(n) ? undefined : n;
  }
  if (el.dataset.kind === "float") {
    const n = parseFloat(el.value);
    return Number.isNaN(n) ? undefined : n;
  }
  if (el.dataset.number) {
    const n = parseInt(el.value, 10);
    return Number.isNaN(n) ? undefined : n;
  }
  return el.value;
}

/* A control whose field only has an effect alongside another setting is shown,
   marked, and left out of the request: sending it would make the response claim
   an option was applied when the build ignored it. */
function gateState(name) {
  const gate = specFor(name).requires;
  if (!gate) return { live: true, note: "" };
  if (gate.any_of) {
    const on = gate.any_of.some((f) => {
      const v = currentValue(f);
      return typeof v === "number" ? v > 0 : !!v;
    });
    return { live: on, note: specFor(name).gate || "needs one of those on" };
  }
  const value = currentValue(gate.field);
  let ok = false;
  if (gate.op === "==") ok = value === gate.value;
  else if (gate.op === "!=") ok = value !== gate.value;
  else if (gate.op === ">=") ok = Number(value) >= gate.value;
  else if (gate.op === "<=") ok = Number(value) <= gate.value;
  return { live: ok, note: specFor(name).gate || `${gate.field} ${gate.op} ${gate.value}` };
}

function readOptions() {
  const options = {};
  for (const name of FIELD_NAMES) {
    const el = widgetFor(name);
    if (!el) continue;
    if (name !== "profile" && !gateState(name).live) continue;
    const value = currentValue(name);
    if (value === undefined || value === "") continue;
    if (name === "profile") {
      options.profile = value;
    } else if (name === "seed") {
      const text = String(value).trim();
      if (!text) continue;
      if (/^0x[0-9a-fA-F_]+$/.test(text) || /^\d[\d_]*$/.test(text)) {
        options.reproducible_seed = text.replace(/_/g, "");
      }
    } else {
      // A dropdown or a text box hands back a string even for a numeric field, and
      // the endpoint refuses a string where it declared an integer -- which is the
      // right thing for it to do, so the conversion happens here instead.
      const kind = specFor(name).kind;
      if (kind === "int" || kind === "float" || kind === "wide") {
        const n = Number(value);
        if (Number.isNaN(n)) continue;
        options[name] = n;
      } else {
        options[name] = value;
      }
    }
  }
  return options;
}

/* ---------- form building ---------- */

/* The config's own declared-but-unread fields, as chips the page cannot do more
   with than name. Rendered from the endpoint's answer so the list is the config's
   and not a copy that has to be remembered. */
function renderPendingFields(list) {
  const box = $("declaredBox");
  if (!list || !list.length) { box.hidden = true; return; }
  $("declaredSummary").textContent =
    `${list.length} field${list.length === 1 ? "" : "s"} in the config that this build will not read`;
  $("declaredList").innerHTML = list
    .map((n) => `<span class="chip dim" title="accepted by Config, ignored by the pipeline">${n}</span>`)
    .join("");
  box.hidden = false;
}

function buildForm() {
  const root = $("options");
  root.innerHTML = "";
  for (const group of SPEC) {
    const section = document.createElement("section");
    section.className = "group";
    section.id = `group-${group.id}`;
    section.innerHTML =
      `<h3>${group.title}</h3><p class="group-help">${group.help}</p>` +
      `<div class="rows"></div>`;
    const rows = section.querySelector(".rows");
    for (const [name, label, kind, help] of group.fields) {
      rows.appendChild(buildRow(name, label, kind, help));
    }
    root.appendChild(section);
  }
  const unknown = unknownFields();
  $("missing").hidden = !unknown.length;
  renderPendingFields(pendingFields);
  $("missing").textContent = unknown.length
    ? `The endpoint accepts options this page has no control for: ${unknown.join(", ")}.`
    : "";
  syncGates();
}

function unknownFields() {
  const visible = new Set(FIELD_NAMES);
  return Object.keys(surface)
    .filter((n) => n !== "reproducible_seed" && !visible.has(n));
}

function buildRow(name, label, kind, help) {
  const spec = specFor(name);
  const row = document.createElement("div");
  row.className = "row";
  row.dataset.field = name;

  const head = document.createElement("div");
  head.className = "row-label";
  head.innerHTML =
    `<label for="opt-${name}"><code>${name}</code><span>${label}</span></label>` +
    `<p class="help">${help}</p>`;
  row.appendChild(head);

  const box = document.createElement("div");
  box.className = "row-control";
  box.id = `opt-${name}`;
  box.appendChild(buildControl(name, kind, spec));
  row.appendChild(box);
  return row;
}

/* A dropdown of small integers, for the level-shaped fields the config types as
   int.  The values come from the endpoint's own min/max, so this page cannot
   offer a level the config would refuse; when the range is too wide to be a menu
   the caller gets a slider instead (`selectChoices` returns null). */
function selectChoices(name, spec) {
  if (spec.choices && spec.choices.length) return spec.choices;
  if (spec.min == null || spec.max == null) return null;
  const low = Math.floor(spec.min), high = Math.floor(spec.max);
  if (high - low > 8) return null;
  const out = [];
  for (let v = low; v <= high; v += 1) out.push(String(v));
  return out;
}

function buildControl(name, kind, spec) {
  if (kind === "bool") {
    const label = document.createElement("label");
    label.className = "switch";
    const input = document.createElement("input");
    input.type = "checkbox";
    input.checked = spec.default !== false;
    input.dataset.kind = "bool";
    input.id = `control-${name}`;
    label.appendChild(input);
    label.appendChild(document.createTextNode("on"));
    input.addEventListener("change", () => {
      label.classList.toggle("off", !input.checked);
      syncGates();
    });
    label.classList.toggle("off", !input.checked);
    return label;
  }
  if (kind === "select" && selectChoices(name, spec)) {
    const select = document.createElement("select");
    select.id = `control-${name}`;
    for (const choice of selectChoices(name, spec)) {
      const option = document.createElement("option");
      option.value = choice;
      option.textContent = choice;
      select.appendChild(option);
    }
    if (spec.default != null) select.value = String(spec.default);
    select.addEventListener("change", syncGates);
    return select;
  }
  if (kind === "int" && (spec.kind === "wide" || WIDE_INTS.has(name))) kind = "number";
  if (kind === "int" || kind === "float") {
    const wrap = document.createElement("div");
    wrap.className = "slider";
    const low = kind === "int" ? (spec.min ?? 0) : (spec.min ?? 1);
    const high = kind === "int" ? (spec.max ?? 64) : (spec.max ?? 40);
    const input = document.createElement("input");
    input.type = "range";
    input.min = String(low);
    input.max = String(high);
    input.step = kind === "int" ? "1" : "0.5";
    input.value = String(spec.default ?? low);
    input.id = `control-${name}`;
    input.dataset.kind = kind;
    const out = document.createElement("output");
    out.textContent = input.value;
    input.addEventListener("input", () => {
      out.textContent = input.value;
      syncGates();
    });
    wrap.appendChild(input);
    wrap.appendChild(out);
    return wrap;
  }
  if (kind === "number") {
    const input = document.createElement("input");
    input.type = "number";
    input.id = `control-${name}`;
    input.dataset.kind = "text";
    input.dataset.number = "1";
    if (spec.min != null) input.min = String(spec.min);
    if (spec.max != null) input.max = String(spec.max);
    if (spec.default != null) input.value = String(spec.default);
    input.addEventListener("input", syncGates);
    return input;
  }
  const text = document.createElement("input");
  text.type = "text";
  text.id = `control-${name}`;
  text.dataset.kind = "text";
  text.placeholder = "fresh per build";
  text.spellcheck = false;
  return text;
}

/* Grey out controls that are gated off, and say why. */
function syncGates() {
  for (const name of FIELD_NAMES) {
    const row = document.querySelector(`.row[data-field="${name}"]`);
    if (!row) continue;
    const { live, note } = gateState(name);
    row.classList.toggle("gated", !live);
    let flag = row.querySelector(".gate");
    if (!live) {
      if (!flag) {
        flag = document.createElement("p");
        flag.className = "gate";
        row.querySelector(".row-label").appendChild(flag);
      }
      flag.textContent = `unused unless ${note}`;
    } else if (flag) {
      flag.remove();
    }
  }
}

function applyProfile(name) {
  document.querySelectorAll("#presetBar button[data-profile]").forEach((btn) => {
    btn.setAttribute("aria-pressed", String(btn.dataset.profile === name));
  });
  const values = profileValues[name];
  if (!values) return;
  for (const [field, value] of Object.entries(values)) {
    const el = widgetFor(field);
    if (!el) continue;
    if (el.type === "checkbox") {
      el.checked = !!value;
      el.closest(".switch")?.classList.toggle("off", !value);
    } else if (el.tagName === "SELECT") {
      el.value = String(value);
    } else if (el.dataset.kind === "int" || el.dataset.kind === "float") {
      el.value = String(value);
      const out = el.parentNode.querySelector("output");
      if (out) out.textContent = String(value);
    }
  }
  syncGates();
}

/* After a build: mark any control the response reported as not applied. It is a
   real option of the config, and this page says so rather than implying it did
   something. */
function markPending(list) {
  for (const name of FIELD_NAMES) {
    document.querySelector(`.row[data-field="${name}"]`)
      ?.classList.remove("inert");
  }
  for (const item of list || []) {
    document.querySelector(`.row[data-field="${item.name}"]`)
      ?.classList.add("inert");
  }
}

/* ---------- results ---------- */

function bytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / 1024 / 1024).toFixed(2)} MiB`;
}

function setStatus(text, kind) {
  const el = $("status");
  el.textContent = text || "";
  el.className = "status" + (kind ? " " + kind : "");
}

function renderMetrics(data) {
  const growth = (data.output_bytes / Math.max(data.input_bytes, 1)).toFixed(1);
  const cards = [
    ["in", bytes(data.input_bytes)],
    ["out", bytes(data.output_bytes)],
    ["growth", `${growth}×`],
    ["prototypes", String(data.prototypes)],
    ["virtualized", String(data.virtualized)],
    ["vm groups", String((data.vm_groups || []).length)],
  ];
  $("metrics").innerHTML = cards
    .map(([label, value]) => `<div class="metric"><b>${value}</b><span>${label}</span></div>`)
    .join("");
  $("metrics").hidden = false;
}

/* The interpreters, as the build made them.  The site exposes one polymorphism
   switch, but the artifact can hold stack/register/hybrid/accumulator machines
   with different dispatchers in the same file; this panel reports the result. */
function renderVms(groups) {
  const box = $("vmBox");
  if (!groups || !groups.length) { box.hidden = true; return; }
  const head = "<tr><td>vm</td><td>family / dispatch</td></tr>";
  const rows = groups.map((g) => {
    const opCipher = g.op_cipher === "none" ? "none (raw numbers)" : g.op_cipher;
    return `<tr><td><code>vm ${g.group}</code></td>` +
    `<td>${g.family} · ${g.dispatcher} · ${g.prototypes} ` +
    `${g.prototypes === 1 ? "prototype" : "prototypes"} · ${g.opcodes} opcodes · ` +
    `${g.op_bytes}B op + ${g.reg_bytes}B reg + ${g.wide_bytes}B wide · ` +
    `targets ${g.target_mode} · opcode cipher ${opCipher}` +
    `${g.arm_seed ? " · shuffled arms" : ""}` +
    `${g.fused ? ` · ${g.fused} fused` : ""}</td></tr>`;
  }).join("");
  $("vmBody").innerHTML = head + rows;
  box.hidden = false;
}

function renderApplied(applied) {
  const rows = Object.entries(applied || {}).map(([name, value]) =>
    `<tr><td><code>${name}</code></td><td>${fmtValue(value)}</td></tr>`).join("");
  $("appliedBody").innerHTML = rows;
  $("appliedBox").hidden = false;
}

function fmtValue(value) {
  if (value === true) return '<span class="yes">on</span>';
  if (value === false) return '<span class="no">off</span>';
  if (value === null || value === undefined) return '<span class="no">—</span>';
  return String(value);
}

function renderNotes(list) {
  const box = $("notesBox");
  if (!list || !list.length) { box.hidden = true; return; }
  $("notesList").innerHTML = list.map((n) => `<li>${n}</li>`).join("");
  box.hidden = false;
}

function renderPending(list) {
  const box = $("pendingBox");
  if (!list || !list.length) { box.hidden = true; return; }
  $("pendingSummary").innerHTML =
    `${list.length} configured ${list.length === 1 ? "option was" : "options were"} ` +
    `<em>not</em> applied by this build`;
  $("pendingList").innerHTML = list
    .map((p) => `<span class="chip" title="set to ${String(p.value)}">${p.name}</span>`)
    .join("");
  box.hidden = false;
}

/* ---------- the build ---------- */

let lastOutput = "";
let lastFilename = "protected.luau";

async function run() {
  const source = $("source").value;
  if (!source.trim()) { setStatus("Paste some Luau first.", "err"); return; }

  $("run").disabled = true;
  setStatus("Building…");
  $("output").textContent = "";
  $("metrics").hidden = true;
  $("pendingBox").hidden = true;
  $("notesBox").hidden = true;
  $("appliedBox").hidden = true;

  try {
    const res = await fetch(API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source, options: readOptions() }),
    });
    const data = await res.json().catch(() => ({}));

    if (!res.ok || data.error) {
      $("output").textContent = data.error || `HTTP ${res.status}`;
      setStatus(data.error ? "The build was refused." : "The build failed.", "err");
      renderPending(data.pending);
      return;
    }

    lastOutput = data.output;
    $("output").textContent = data.output;
    renderMetrics(data);
    renderApplied(data.applied);
    renderNotes(data.notes);
    renderVms(data.vm_groups);
    renderPending(data.pending);
    markPending(data.pending);
    $("report").textContent = data.report || "";
    $("copy").disabled = false;
    $("download").disabled = false;

    const seed = data.seed_hex.slice(0, 12);
    setStatus(`Built — seed ${seed}… · ${data.virtualized} of ${data.prototypes} ` +
              `prototypes virtualized · ${bytes(data.output_bytes)}`, "ok");
  } catch (err) {
    $("output").textContent = String(err);
    setStatus("Could not reach the build service.", "err");
  } finally {
    $("run").disabled = false;
  }
}

/* ---------- copy / download ---------- */

async function copy() {
  if (!lastOutput) return;
  try {
    await navigator.clipboard.writeText(lastOutput);
  } catch {
    // Clipboard API needs a secure context; fall back for file:// and http.
    const ta = document.createElement("textarea");
    ta.value = lastOutput;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); } catch { /* nothing left to try */ }
    ta.remove();
  }
  const btn = $("copy");
  const label = btn.textContent;
  btn.textContent = "Copied";
  setTimeout(() => { btn.textContent = label; }, 1400);
}

function download() {
  if (!lastOutput) return;
  const url = URL.createObjectURL(new Blob([lastOutput], { type: "text/plain" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = lastFilename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

/* ---------- file loading ---------- */

function updateInputStats() {
  const text = $("source").value;
  const size = new Blob([text]).size;
  const lines = text.split("\n").length;
  const comments = (text.match(/^\s*#/gm) || []).length;
  $("inputStats").textContent =
    `${bytes(size)} · ${lines} lines` + (comments ? ` · ${comments} # line(s)` : "");
}

function loadFile(file) {
  if (!file) return;
  if (file.size > 512 * 1024) {
    setStatus("That file is larger than the 512 KiB limit.", "err");
    return;
  }
  const reader = new FileReader();
  reader.onload = () => {
    $("source").value = String(reader.result || "");
    lastFilename = file.name.replace(/\.(luau|lua|txt)$/i, "") + ".protected.luau";
    updateInputStats();
    setStatus(`Loaded ${file.name}.`);
  };
  reader.onerror = () => setStatus("Could not read that file.", "err");
  reader.readAsText(file);
}

/* ---------- options surface ---------- */

const API = "api/obfuscate";

async function loadSurface() {
  try {
    const res = await fetch(API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode: "options" }),
    });
    if (!res.ok) return false;
    const data = await res.json();
    // An empty surface is not a surface: `OPTIONS` with no keys would build a form
    // of empty menus that all validate, which is worse than the fallback copy.
    if (!data || !data.options || !Object.keys(data.options).length) return false;
    surface = data.options;
    profileValues = data.profile_values || {};
    pendingFields = data.pending || [];
    return true;
  } catch {
    return false;           // opened without a backend: use the fallback copy
  }
}

/* Fallback surface, mirroring the endpoint for the handful of fields whose
   choices or ranges the form needs. `tests/test_web.py` compares this against
   `option_surface()`, so an update to one has to update the other. */
const FALLBACK = {
  virtualization_level: { kind: "enum", choices: ["none", "light", "medium", "heavy", "maximum"], default: "heavy" },
  vm_polymorphism: { kind: "bool", default: true },
  cache_policy: { kind: "enum", choices: ["none", "bounded", "full"], default: "none" },
  guard_policy: { kind: "choice", choices: ["fail", "ignore"], default: "fail" },
  hash_comments: { kind: "choice", choices: ["auto", "strip", "strict"], default: "auto" },
  blob_encoding: { kind: "choice", choices: ["dense", "hex"], default: "dense" },
  instruction_formats: { kind: "int", min: 0, max: 2, default: 1 },
  opcode_aliases: { kind: "int", min: 0, max: 4, default: 1 },
  string_protection_level: { kind: "int", min: 0, max: 3, default: 2 },
  constant_protection_level: { kind: "int", min: 0, max: 1, default: 1 },
  numeric_protection_level: { kind: "int", min: 0, max: 2, default: 1 },
  table_key_protection: { kind: "bool", default: true },
  index_to_num: { kind: "bool", default: false },
  control_flow_level: { kind: "int", min: 0, max: 3, default: 2 },
  branch_inversion: { kind: "bool", default: true },
  env_guard: { kind: "int", min: 0, max: 2, default: 1 },
  dump_guard: { kind: "int", min: 0, max: 2, default: 1 },
  decoy_constants: { kind: "int", min: 0, max: 256, default: 12 },
  bounded_cache_size: { kind: "int", min: 1, max: 4096, default: 16 },
  max_vm_functions: { kind: "int", min: 0, max: 4096, default: 64 },
  min_virtualize_body_nodes: { kind: "int", min: 0, max: 4096, default: 12 },
  vm_variety: { kind: "int", min: 1, max: 4, default: 1 },
  max_output_growth: { kind: "float", min: 0, max: 1000, default: 24 },
};

/* The int fields a slider can represent: the endpoint allows up to 4096, which a
   range input would turn into a lottery.  Those get a number box instead. */
const WIDE_INTS = new Set(["bounded_cache_size", "max_vm_functions",
                           "min_virtualize_body_nodes", "decoy_constants"]);

function useFallback() {
  for (const group of SPEC) {
    for (const entry of group.fields) {
      const name = entry[0];
      if (surface[name] || SYNTH[name]) continue;
      let fallback = FALLBACK[name];
      if (fallback && WIDE_INTS.has(name)) fallback = { ...fallback, kind: "wide" };
      if (fallback) surface[name] = fallback;
      else if (entry[2] === "int") {
        surface[name] = WIDE_INTS.has(name)
          ? { kind: "wide", default: 0 }
          : { kind: "int", min: 0, max: 8, default: 0 };
      }
    }
  }
}

/* ---------- wiring ---------- */

function init() {
  $("run").addEventListener("click", run);
  $("copy").addEventListener("click", copy);
  $("download").addEventListener("click", download);
  $("clearInput").addEventListener("click", () => {
    $("source").value = "";
    updateInputStats();
    setStatus("");
  });
  $("loadExample").addEventListener("click", () => {
    $("source").value = EXAMPLE;
    lastFilename = "inventory.protected.luau";
    updateInputStats();
    setStatus("Loaded the example.");
  });

  $("presetBar").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-profile]");
    if (!btn) return;
    const select = widgetFor("profile");
    if (select) select.value = btn.dataset.profile;
    applyProfile(btn.dataset.profile);
    setStatus(`Applied the ${btn.dataset.profile} preset.`);
  });

  const profileSelect = widgetFor("profile");
  if (profileSelect) profileSelect.addEventListener("change", () => {
    applyProfile(profileSelect.value);
    setStatus(`Applied the ${profileSelect.value} preset.`);
  });

  $("honestyLink").addEventListener("click", (e) => {
    e.preventDefault();
    $("output").textContent = HONESTY;
    setStatus("The limits of what this does, in its own words.");
  });

  $("filter").addEventListener("input", () => {
    const needle = $("filter").value.trim().toLowerCase();
    document.querySelectorAll(".row").forEach((row) => {
      const text = row.textContent.toLowerCase();
      row.hidden = !!needle && !text.includes(needle);
    });
    document.querySelectorAll(".group").forEach((group) => {
      const any = [...group.querySelectorAll(".row")].some((r) => !r.hidden);
      group.hidden = !!needle && !any;
    });
  });

  $("fileInput").addEventListener("change", (e) => loadFile(e.target.files[0]));

  // Ctrl/Cmd+Enter builds, which is what you reach for after editing.
  $("source").addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") { e.preventDefault(); run(); }
  });
  $("source").addEventListener("input", updateInputStats);

  const drop = $("drop");
  const hint = $("dropHint");
  ["dragenter", "dragover"].forEach((ev) =>
    drop.addEventListener(ev, (e) => {
      e.preventDefault();
      $("source").classList.add("dragover");
      hint.hidden = false;
    }));
  ["dragleave", "drop"].forEach((ev) =>
    drop.addEventListener(ev, (e) => {
      e.preventDefault();
      $("source").classList.remove("dragover");
      hint.hidden = true;
      if (ev === "drop") loadFile(e.dataTransfer.files[0]);
    }));

  const toggle = $("optionsToggle");
  toggle.addEventListener("click", () => {
    const open = $("options").classList.toggle("open");
    toggle.setAttribute("aria-expanded", String(open));
  });
  // On desktop the panel is always visible; make sure resizing back up does not
  // leave it hidden behind the mobile toggle state.
  const mq = window.matchMedia("(min-width: 900px)");
  const sync = (e) => { if (e.matches) $("options").classList.remove("open"); };
  mq.addEventListener ? mq.addEventListener("change", sync) : mq.addListener(sync);

  updateInputStats();
}

function renderPresets() {
  const bar = $("presetBar");
  const names = Object.keys(profileValues).length
    ? Object.keys(profileValues)
    : ["compact", "balanced", "hardened", "maximum"];
  bar.innerHTML = names
    .map((n) => `<button type="button" data-profile="${n}" title="${PRESET_BLURB[n] || ""}">${PRESET_LABELS[n] || n}</button>`)
    .join("");
}

async function boot() {
  const fresh = await loadSurface();
  if (!fresh) $("surfaceState").textContent =
    "ranges and vocabularies from the page's own copy";
  else $("surfaceState").textContent = "ranges and vocabularies from the endpoint";
  useFallback();
  buildForm();
  renderPresets();
  if (profileValues.maximum) applyProfile("maximum");
  init();
}

if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", boot);
}

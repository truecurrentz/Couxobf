/* couxobf web UI. No framework, no build step, no dependencies. */

const $ = (id) => document.getElementById(id);

const FIELDS = {
  profile: { kind: "select" },
  virtualization_level: { kind: "select" },
  vm_family: { kind: "select" },
  dispatcher_family: { kind: "select" },
  string_protection_level: { kind: "int" },
  cache_policy: { kind: "select" },
  min_virtualize_body_nodes: { kind: "int" },
  block_permutation: { kind: "bool" },
  opcode_randomization: { kind: "bool" },
  minify: { kind: "bool" },
  strip_types: { kind: "bool" },
  identifier_polymorphism: { kind: "bool" },
};

/* Profiles, mirrored from couxobf.config.Config. Kept here so the buttons do
   something visible instead of only changing a dropdown the user then has to
   inspect. */
const PRESETS = {
  maximum:  { profile: "maximum",  virtualization_level: "maximum", string_protection_level: 3,
              min_virtualize_body_nodes: 1,  vm_family: "stack", minify: true,
              block_permutation: true, opcode_randomization: true, cache_policy: "none" },
  balanced: { profile: "balanced", virtualization_level: "heavy",  string_protection_level: 2,
              min_virtualize_body_nodes: 12, vm_family: "hybrid", minify: false,
              block_permutation: true, opcode_randomization: true, cache_policy: "none" },
  compact:  { profile: "compact",  virtualization_level: "medium", string_protection_level: 1,
              min_virtualize_body_nodes: 24, vm_family: "register", minify: true,
              block_permutation: false, opcode_randomization: true, cache_policy: "bounded" },
};

const EXAMPLE = `-- inventory.lua
-- A small shop: tiered discounts, a counter closure, and a summary line.

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

/* ---------- options ---------- */

function readOptions() {
  const options = {};
  for (const [name, spec] of Object.entries(FIELDS)) {
    const el = $(name);
    if (!el) continue;
    if (spec.kind === "bool") options[name] = el.checked;
    else if (spec.kind === "int") options[name] = parseInt(el.value, 10) || 0;
    else options[name] = el.value;
  }
  const seed = $("seed").value.trim();
  if (seed) {
    const n = seed.toLowerCase().startsWith("0x")
      ? parseInt(seed.slice(2), 16) : parseInt(seed, 10);
    if (!Number.isNaN(n)) options.reproducible_seed = n;
  }
  return options;
}

function applyPreset(preset) {
  for (const [name, value] of Object.entries(preset)) {
    const el = $(name);
    if (!el) continue;
    if (el.type === "checkbox") el.checked = value;
    else el.value = String(value);
  }
}

/* ---------- formatting ---------- */

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
    ["growth", growth + "×"],
    ["prototypes", String(data.prototypes)],
    ["virtualized", String(data.virtualized)],
  ];
  $("metrics").innerHTML = cards
    .map(([label, value]) => `<div class="metric"><b>${value}</b><span>${label}</span></div>`)
    .join("");
  $("metrics").hidden = false;
}

function renderPending(list) {
  const box = $("pendingBox");
  if (!list || !list.length) { box.hidden = true; return; }
  $("pendingSummary").innerHTML =
    `${list.length} configured techniques were <em>not</em> applied`;
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

  try {
    const res = await fetch("api/obfuscate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source, options: readOptions() }),
    });
    const data = await res.json().catch(() => ({}));

    if (!res.ok || data.error) {
      $("output").textContent = data.error || `HTTP ${res.status}`;
      setStatus("The build failed.", "err");
      return;
    }

    lastOutput = data.output;
    $("output").textContent = data.output;
    renderMetrics(data);
    renderPending(data.pending);
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
  $("inputStats").textContent =
    `${bytes(size)} · ${text.split("\n").length} lines`;
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

  $("presetMaximum").addEventListener("click", () => applyPreset(PRESETS.maximum));
  $("presetBalanced").addEventListener("click", () => applyPreset(PRESETS.balanced));
  $("presetCompact").addEventListener("click", () => applyPreset(PRESETS.compact));

  $("rollSeed").addEventListener("click", () => {
    const buf = new Uint8Array(8);
    crypto.getRandomValues(buf);
    $("seed").value = "0x" + [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
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
  const mq = window.matchMedia("(min-width: 761px)");
  const sync = (e) => { if (e.matches) $("options").classList.remove("open"); };
  mq.addEventListener ? mq.addEventListener("change", sync) : mq.addListener(sync);

  updateInputStats();
}

document.addEventListener("DOMContentLoaded", init);

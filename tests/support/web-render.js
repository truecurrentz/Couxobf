/* Render web/app.js against a stub DOM and print what the page would send.

   This exists because the option form is generated: nothing in index.html names a
   control any more, so "the UI and the endpoint agree" cannot be checked by grepping
   markup. It is checked by running the page. The stub is the smallest DOM that
   app.js can build a form into -- elements, ids, classes, a recursive
   querySelector -- and it fails loudly: an element the script looks up that is not
   in index.html throws, which is exactly the class of bug a generated form can grow.

   Usage: node web-render.js <app.js> <comma,separated,ids> <describe.json>

   The third argument is the payload the page fetches; when it is missing the page
   falls back to the table copied into app.js, which is what happens when somebody
   opens index.html straight from a filesystem.
*/
const fs = require("fs");

const registry = new Map();

class Node {
  constructor(tag) {
    this.tagName = String(tag).toUpperCase();
    this.children = [];
    this.dataset = {};
    this.style = {};
    this.hidden = false;
    this.disabled = false;
    this.checked = false;
    this.type = "";
    this.value = "";
    this.spellcheck = true;
    this.attributes = {};
    this._classes = new Set();
    this._text = "";
    this._html = "";
    const self = this;
    this.classList = {
      add: (c) => self._classes.add(c),
      remove: (c) => self._classes.delete(c),
      toggle: (c, on) => (on === undefined ? self._classes.has(c) ? self._classes.delete(c) : self._classes.add(c) : (on ? self._classes.add(c) : self._classes.delete(c))),
      contains: (c) => self._classes.has(c),
    };
  }
  set className(v) { this._classes = new Set(String(v).split(/\s+/).filter(Boolean)); }
  get className() { return this._classes ? [...this._classes].join(" ") : ""; }
  set id(v) { this._id = v; registry.set(v, this); }
  get id() { return this._id; }
  set innerHTML(v) {
    this._html = String(v);
    this.children = [];
    // Enough of a parser for this page: app.js only ever asks for the elements it
    // puts class names on, so a flat list of them is a faithful enough DOM.
    const tag = /<(\w+)([^>]*)>/g;
    let m;
    while ((m = tag.exec(this._html))) {
      if (["html", "body"].includes(m[1].toLowerCase())) continue;
      const child = new Node(m[1]);
      const cls = /class="([^"]*)"/.exec(m[2]);
      if (cls) child.className = cls[1];
      const id = /id="([^"]*)"/.exec(m[2]);
      if (id) child.id = id[1];
      child.parentNode = this;
      this.children.push(child);
    }
  }
  get innerHTML() { return this._html; }
  set textContent(v) { this._text = String(v); }
  get textContent() { return this._text; }
  setAttribute(k, v) { this.attributes[k] = String(v); }
  appendChild(c) { this.children.push(c); if (c) c.parentNode = this; return c; }
  addEventListener() {}
  remove() {}
  closest() { return null; }
  querySelector(sel) {
    const list = sel.split(",").map((s) => s.trim());
    let found = null;
    const walk = (n) => {
      for (const c of n.children || []) {
        if (found) return;
        if (list.some((s) => matches(c, s))) { found = c; return; }
        walk(c);
      }
    };
    walk(this);
    return found;
  }
  querySelectorAll(sel) {
    const out = [];
    const walk = (n) => { for (const c of (n.children || [])) { if (matches(c, sel)) out.push(c); walk(c); } };
    walk(this);
    return out;
  }
}

function matches(node, sel) {
  if (sel.startsWith(".")) return !!node._classes && node._classes.has(sel.slice(1));
  if (sel.startsWith("#")) return node._id === sel.slice(1);
  const attr = sel.match(/^(\w+)\[data-field="([^"]+)"\]$/);
  if (attr) return node.tagName.toLowerCase() === attr[1] && node.dataset.field === attr[2];
  const tagAttr = sel.match(/^(\w+)\[([^=]+)="([^"]+)"\]$/);
  if (tagAttr) {
    return node.tagName.toLowerCase() === tagAttr[1] &&
           (node.attributes[tagAttr[2]] === tagAttr[3] || node[tagAttr[2]] === tagAttr[3]);
  }
  return node.tagName.toLowerCase() === sel.toLowerCase();
}

global.document = {
  getElementById: (id) => registry.get(id) || null,
  createElement: (tag) => new Node(tag),
  createTextNode: (t) => ({ text: String(t) }),
  addEventListener: (ev, fn) => { if (ev === "DOMContentLoaded") global.__ready = fn; },
  querySelector: (sel) => root.querySelector(sel),
  querySelectorAll: (sel) => root.querySelectorAll(sel),
  body: new Node("body"),
};
const root = new Node("html");

const ids = process.argv[3].split(",").filter(Boolean);
for (const id of ids) { const n = new Node("div"); n.id = id; }

global.window = { matchMedia: () => ({ matches: false, addEventListener() {} }) };
global.navigator = {};
global.crypto = { getRandomValues: () => {} };
global.setTimeout = (f) => { f(); return 0; };
global.Blob = class { constructor(parts) { this.size = String(parts.join("")).length; } };
global.URL = { createObjectURL: () => "", revokeObjectURL: () => {} };
global.FileReader = class {};

const payload = process.argv[4] && fs.existsSync(process.argv[4])
  ? fs.readFileSync(process.argv[4], "utf8") : null;
global.fetch = async (url, init) => {
  const body = init && init.body ? JSON.parse(init.body) : {};
  if (body.mode === "options") {
    if (!payload) throw new Error("no backend");
    return { ok: true, status: 200, json: async () => JSON.parse(payload) };
  }
  return {
    ok: true, status: 200,
    json: async () => ({ output: "", input_bytes: 1, output_bytes: 2, prototypes: 1,
                         virtualized: 1, seed_hex: "00".repeat(16), applied: {}, notes: [],
                         pending: [], report: "r", options: {} }),
  };
};

const source = fs.readFileSync(process.argv[2], "utf8").replace(
  'document.addEventListener("DOMContentLoaded", boot);', "");

async function main() {
  // eslint-disable-next-line no-eval
  eval(source);
  await boot();
  const options = document.getElementById("options");
  const groups = options.children.map((g) => ({
    title: g.innerHTML.match(/<h3>([^<]+)/) ? g.innerHTML.match(/<h3>([^<]+)/)[1] : "?",
    rows: g.querySelectorAll(".row").map((r) => r.dataset.field),
  }));
  const controls = {};
  for (const g of groups) {
    for (const field of g.rows) {
      const box = document.getElementById(`opt-${field}`);
      const el = box && box.querySelector("input") ? box.querySelector("input") : box.querySelector("select");
      controls[field] = el ? (el.tagName === "SELECT" ? "select" : el.type) : "none";
      if (el && el.dataset && el.dataset.kind) controls[field] += ":" + el.dataset.kind;
    }
  }
  const out = {
    groups: groups.map((g) => [g.title, g.rows.length]),
    fields: groups.flatMap((g) => g.rows),
    controls,
    presets: document.getElementById("presetBar")._html,
    surfaceState: document.getElementById("surfaceState")._text,
    missing: document.getElementById("missing")._text,
    readOptions: readOptions(),
  };
  process.stdout.write(JSON.stringify(out));
}

main().catch((e) => { process.stdout.write(JSON.stringify({ error: String(e.stack || e) })); process.exit(2); });

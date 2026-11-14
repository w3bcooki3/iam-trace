// iam-trace web app.
//
// Loads Pyodide, unpacks the iamtrace package (and the action catalog when the site was built
// with one) and calls iamtrace.web_api. Every result on screen comes from the same Python engine
// the CLI and the test suite run.
//
// Network use: only this site. The published build bundles Pyodide, the package, the catalog,
// fonts and the example account; the Content-Security-Policy in index.html blocks everything else.
// Inline style attributes are blocked too, so styling goes through classes and element.style.

import { Graph, ICON, KIND_COLOR, KIND_NAME } from "./graph.js";
import { EVALUATE_EXAMPLES, DIFF_EXAMPLE, ATTACK_POLICY_EXAMPLE } from "./examples.js";

const PYODIDE_URL = new URL(document.querySelector('meta[name="pyodide-url"]').content, location.href).href;
const root = document.documentElement;
const $ = (id) => document.getElementById(id);

// ------------------------------------------------------------------------------------- helpers

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}
function short(arn) {
  const s = String(arn ?? "");
  return s.startsWith("arn:") ? s.split(":").slice(5).join(":") || s : s;
}
function nameOf(arn) {
  const s = String(arn ?? "");
  return s.startsWith("arn:") ? s.split("/").pop() : s;
}
function plural(n, word, many) {
  return `${n.toLocaleString()} ${n === 1 ? word : many || word + "s"}`;
}
function sentence(s) {
  const t = String(s ?? "").trim();
  if (!t) return "";
  const c = t.charAt(0).toUpperCase() + t.slice(1);
  return /[.!?]$/.test(c) ? c : c + ".";
}
function kindOf(arn) {
  const s = String(arn);
  if (s === "admin") return "admin";
  if (s.includes(":user/") || / user/.test(s)) return "user";
  if (s.includes(":group/")) return "group";
  if (s.includes(":role/") || / role/.test(s)) return "role";
  return "resource";
}
function bytes(n) {
  return n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;
}
let toastTimer = null;
function toast(text) {
  const t = $("toast");
  t.textContent = text;
  t.classList.add("on");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("on"), 2200);
}
function overlay(text) {
  $("overlay-text").textContent = text || "";
  $("overlay").classList.toggle("on", Boolean(text));
}
// Let the browser paint (for example the "working" overlay) before a long synchronous call.
const nextFrame = () => new Promise((r) => requestAnimationFrame(() => setTimeout(r, 30)));
function download(name, text, type = "application/json") {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function copy(text) {
  if (!navigator.clipboard) return toast("Copying is not available in this browser");
  navigator.clipboard.writeText(text).then(() => toast("Copied"), () => toast("Could not copy"));
}
// Widths for bars, set through the CSSOM after rendering (style attributes are blocked).
function applyWidths(el) {
  el.querySelectorAll("[data-w]").forEach((x) => { x.style.width = `${x.dataset.w}%`; });
  el.querySelectorAll("[data-flex]").forEach((x) => { x.style.flex = x.dataset.flex; });
}
const IC = {
  warn: '<svg class="i" viewBox="0 0 24 24"><path d="M12 3l9 16H3z"/><path d="M12 10v4M12 17v.5"/></svg>',
  ok: '<svg class="i" viewBox="0 0 24 24"><path d="M5 12l4 4 10-10"/></svg>',
  x: '<svg class="i" viewBox="0 0 24 24"><path d="M6 6l12 12M18 6L6 18"/></svg>',
  arrow: '<svg class="i" viewBox="0 0 24 24"><path d="M5 12h14M13 6l6 6-6 6"/></svg>',
  info: '<svg class="i" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8v.5"/></svg>',
  upload: '<svg class="i" viewBox="0 0 24 24"><path d="M12 15V3M7 8l5-5 5 5"/><path d="M4 15v4a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-4"/></svg>',
  file: '<svg class="i" viewBox="0 0 24 24"><path d="M7 3h7l5 5v13H7z"/><path d="M14 3v5h5"/></svg>',
};

// ------------------------------------------------------------------------------------- settings

const store = {
  get(k, d) { try { return localStorage.getItem("iam-trace-" + k) ?? d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem("iam-trace-" + k, v); } catch { /* storage unavailable */ } },
  clear() { try { Object.keys(localStorage).filter((k) => k.startsWith("iam-trace-")).forEach((k) => localStorage.removeItem(k)); } catch { /* ignore */ } },
};
const DEFAULTS = { mode: "light", style: "bold", nodes: "card", brand: "#19b6a4" };
const prefs = { ...DEFAULTS };
for (const k of Object.keys(DEFAULTS)) prefs[k] = store.get(k, DEFAULTS[k]);
const systemDark = window.matchMedia("(prefers-color-scheme: dark)");

function applyPrefs() {
  root.dataset.mode = prefs.mode === "system" ? (systemDark.matches ? "dark" : "light") : prefs.mode;
  root.dataset.style = prefs.style;
  root.dataset.nodes = prefs.nodes;
  if (prefs.style === "brand") root.style.setProperty("--accent", prefs.brand);
  else root.style.removeProperty("--accent");
  root.style.setProperty("--brand-c", prefs.brand);
  for (const key of ["mode", "style", "nodes"]) {
    document.querySelectorAll(`[data-set="${key}"] .opt`).forEach((o) => o.classList.toggle("on", o.dataset.v === prefs[key]));
  }
  $("brand-color").value = prefs.brand;
  $("brand-hex").textContent = prefs.brand;
  document.querySelectorAll(".sw").forEach((s) => s.classList.toggle("on", s.dataset.c === prefs.brand));
  graphs.forEach((g) => g.render());
}
function setPref(key, value) {
  prefs[key] = value;
  store.set(key, value);
  applyPrefs();
}
document.querySelectorAll("[data-set] .opt").forEach((o) => o.addEventListener("click", () => setPref(o.parentElement.dataset.set, o.dataset.v)));
document.querySelectorAll(".sw").forEach((s) => s.addEventListener("click", () => { prefs.brand = s.dataset.c; store.set("brand", s.dataset.c); setPref("style", "brand"); }));
$("brand-color").addEventListener("input", (e) => { prefs.brand = e.target.value; store.set("brand", e.target.value); setPref("style", "brand"); });
systemDark.addEventListener("change", () => { if (prefs.mode === "system") applyPrefs(); });
$("opt-anim").checked = store.get("anim", "1") !== "0";
$("opt-anim").addEventListener("change", (e) => { root.classList.toggle("no-anim", !e.target.checked); store.set("anim", e.target.checked ? "1" : "0"); });
$("reset-settings").addEventListener("click", () => {
  store.clear();
  Object.assign(prefs, DEFAULTS);
  $("opt-anim").checked = true;
  root.classList.remove("no-anim", "no-labels");
  applyPrefs();
  toast("Settings reset");
});
$("focus-btn").addEventListener("click", () => {
  root.classList.toggle("focus");
  $("focus-btn").classList.toggle("on");
  setTimeout(() => graphs.forEach((g) => g.fit()), 30);
});
$("menu-btn").addEventListener("click", () => root.classList.toggle("nav-open"));

// ------------------------------------------------------------------------------------- navigation

const VIEWS = {
  overview: ["Attack paths", "Overview"], graph: ["Attack paths", "Attack graph"], findings: ["Attack paths", "Findings"],
  input: ["Attack paths", "Data input"], evaluate: ["Tools", "Evaluate a request"], diff: ["Tools", "Policy diff"],
  docs: ["Help", "Documentation"], changelog: ["Help", "Changelog"], settings: ["App", "Settings"],
};
function go(view) {
  if (!VIEWS[view]) view = "overview";
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("on", v.id === "v-" + view));
  document.querySelectorAll(".nav-item[data-go]").forEach((n) => n.classList.toggle("on", n.dataset.go === view));
  $("crumb-group").textContent = VIEWS[view][0];
  $("crumb-view").textContent = VIEWS[view][1];
  if (location.hash !== "#" + view) history.replaceState(null, "", "#" + view);
  root.classList.remove("nav-open");
  requestAnimationFrame(() => graphs.forEach((g) => g.fit()));
}
document.addEventListener("click", (e) => {
  const b = e.target.closest("[data-go]");
  if (b) go(b.dataset.go);
});
window.addEventListener("hashchange", () => go(location.hash.slice(1)));

// ------------------------------------------------------------------------------------- engine

let api = null;
let hasCatalog = false;
const ready = [];

function chip(id, state, text) {
  const el = $(id);
  el.querySelector("i").className = state;
  el.querySelector("span").textContent = text;
}
function call(fn, ...args) {
  return JSON.parse(api[fn](...args));
}
async function fetchArchive(name) {
  const resp = await fetch(name);
  return resp.ok ? await resp.arrayBuffer() : null;
}
async function boot() {
  const { loadPyodide } = await import(PYODIDE_URL + "pyodide.mjs");
  const pyodide = await loadPyodide({ indexURL: PYODIDE_URL });
  const pkg = await fetchArchive("iamtrace.zip");
  if (!pkg) throw new Error("iamtrace.zip is missing from this site");
  pyodide.FS.mkdirTree("/home/pyodide/lib");
  pyodide.unpackArchive(pkg, "zip", { extractDir: "/home/pyodide/lib" });
  const catalog = await fetchArchive("catalog.zip");
  if (catalog) {
    pyodide.FS.mkdirTree("/home/pyodide/catalog");
    pyodide.unpackArchive(catalog, "zip", { extractDir: "/home/pyodide/catalog" });
  }
  pyodide.runPython("import sys; sys.path.insert(0, '/home/pyodide/lib')");
  api = pyodide.pyimport("iamtrace.web_api");
  const summary = JSON.parse(api.catalog_summary());
  hasCatalog = Boolean(summary);
  chip("engine-chip", "", "Engine ready");
  chip("catalog-chip", hasCatalog ? "" : "off", hasCatalog ? `${summary.actions.toLocaleString()} actions` : "No action catalog");
  $("about-catalog").textContent = hasCatalog ? `${summary.actions.toLocaleString()} actions in ${summary.services} services` : "Not included in this build";
  $("ev-run").disabled = false;
  $("d-run").disabled = !hasCatalog;
  $("d-note").textContent = hasCatalog ? `Compares using the action catalog: ${summary.actions.toLocaleString()} actions in ${summary.services} services.` : "Diff needs the action catalog, which this build of the site does not include.";
  $("opt-blast").disabled = !hasCatalog;
  ready.splice(0).forEach((f) => f());
}
function whenReady(f) {
  if (api) f();
  else ready.push(f);
}
boot().catch((e) => {
  chip("engine-chip", "error", "Engine failed to start");
  chip("catalog-chip", "off", "Catalog unavailable");
  overlay("");
  console.error(e);
  toast("The analysis engine could not start. Reload the page to try again.");
});

// ------------------------------------------------------------------------------------- data input

const input = { src: "account", account: "", policy: "", scp: "", file: null, start: "", principals: [], example: false, accountValid: false };
let lastValid = null;

function setEditor(text) {
  $("editor").value = text;
  drawGutter();
}
function drawGutter() {
  const n = $("editor").value.split("\n").length;
  $("gutter").textContent = Array.from({ length: Math.min(n, 20000) }, (_, i) => i + 1).join("\n");
  $("ed-lines").textContent = plural(n, "line");
}
$("editor").addEventListener("scroll", () => { $("gutter").scrollTop = $("editor").scrollTop; });
let validateTimer = null;
$("editor").addEventListener("input", () => {
  input[input.src] = $("editor").value;
  if (input.src === "account" && input.file) { input.file = null; input.example = false; showFileRow(); }
  drawGutter();
  clearTimeout(validateTimer);
  validateTimer = setTimeout(validate, 250);
});

const SRC_TEXT = {
  account: ["Drop the account export here", "A .json file from aws iam get-account-authorization-details. Or paste it into the editor below.", "auth-details.json"],
  policy: ["Drop a policy file here", "One identity-based policy document. It is analysed as the only policy of a role.", "policy.json"],
  scp: ["Drop SCP files here", "One SCP document, or a JSON array of them. They apply to every principal in the account export.", "scps.json"],
};
function setSource(src) {
  input.src = src;
  document.querySelectorAll(".src").forEach((b) => b.classList.toggle("on", b.dataset.src === src));
  const [t, s, f] = SRC_TEXT[src];
  $("dz-title").textContent = t;
  $("dz-sub").textContent = s;
  $("ed-name").textContent = src === "account" && input.file ? input.file.name : f;
  $("pick-card").hidden = src === "policy";
  setEditor(input[src]);
  showFileRow();
  validate();
}
document.querySelectorAll(".src").forEach((b) => b.addEventListener("click", () => setSource(b.dataset.src)));

function showFileRow() {
  const f = input.src === "account" ? input.file : null;
  $("file-row").hidden = !f;
  if (f) {
    $("file-name").textContent = f.name;
    $("file-meta").textContent = `${bytes(f.size)}, loaded ${f.when.toLocaleTimeString()}`;
  }
}
$("file-clear").addEventListener("click", () => {
  input.account = "";
  input.file = null;
  input.example = false;
  setEditor("");
  showFileRow();
  validate();
});
$("run-reset").addEventListener("click", () => {
  input[input.src] = "";
  if (input.src === "account") { input.file = null; input.example = false; }
  setEditor("");
  showFileRow();
  validate();
});

const MAX_BYTES = 50 * 1024 * 1024;
function readFile(file) {
  if (file.size > MAX_BYTES) return toast("That file is larger than 50 MB");
  const reader = new FileReader();
  reader.onload = () => {
    const text = String(reader.result);
    input[input.src] = text;
    if (input.src === "account") {
      input.file = { name: file.name, size: file.size, when: new Date() };
      input.example = false;
    }
    $("ed-name").textContent = file.name;
    setEditor(text);
    showFileRow();
    validate();
    toast(`Loaded ${file.name}`);
  };
  reader.onerror = () => toast("The file could not be read");
  reader.readAsText(file);
}
$("choose-file").addEventListener("click", () => $("file-input").click());
$("file-input").addEventListener("change", (e) => { if (e.target.files[0]) readFile(e.target.files[0]); e.target.value = ""; });
const dz = $("dropzone");
["dragenter", "dragover"].forEach((t) => dz.addEventListener(t, (e) => { e.preventDefault(); dz.classList.add("over"); }));
["dragleave", "drop"].forEach((t) => dz.addEventListener(t, () => dz.classList.remove("over")));
dz.addEventListener("drop", (e) => { e.preventDefault(); if (e.dataTransfer.files[0]) readFile(e.dataTransfer.files[0]); });
// Dropping a file anywhere else on the page should not navigate away from it.
window.addEventListener("dragover", (e) => e.preventDefault());
window.addEventListener("drop", (e) => e.preventDefault());

let exampleText = null;
async function loadExampleAccount() {
  if (!exampleText) {
    const r = await fetch("examples/auth-details.json");
    if (!r.ok) throw new Error("the example account is missing from this site");
    exampleText = await r.text();
  }
  input.account = exampleText;
  input.file = { name: "example-account.json", size: exampleText.length, when: new Date() };
  input.example = true;
}
$("ed-example").addEventListener("click", async () => {
  if (input.src === "account") await loadExampleAccount();
  else if (input.src === "policy") input.policy = JSON.stringify(ATTACK_POLICY_EXAMPLE, null, 2);
  else input.scp = JSON.stringify([{ Version: "2012-10-17", Statement: [{ Sid: "AllowAll", Effect: "Allow", Action: "*", Resource: "*" }] },
    { Version: "2012-10-17", Statement: [{ Sid: "DenyLeavingOrg", Effect: "Deny", Action: "organizations:LeaveOrganization", Resource: "*" }] }], null, 2);
  setSource(input.src);
});

// Where a JSON parse error is, as "line X, column Y", from the browser's error message.
function jsonError(text, e) {
  const m = /position (\d+)/.exec(e.message);
  if (!m) return e.message;
  const pos = Number(m[1]);
  const before = text.slice(0, pos).split("\n");
  return `${e.message.replace(/ in JSON at position \d+.*$/, "").replace(/^JSON\.parse: /, "")} at line ${before.length}, column ${before[before.length - 1].length + 1}`;
}

function countStatements(doc) {
  if (!doc || typeof doc !== "object") return 0;
  const st = doc.Statement;
  return Array.isArray(st) ? st.length : st ? 1 : 0;
}
function inventoryOf(data) {
  const list = (k) => (Array.isArray(data[k]) ? data[k] : []);
  let statements = 0;
  for (const u of list("UserDetailList")) for (const p of u.UserPolicyList || []) statements += countStatements(p.PolicyDocument);
  for (const g of list("GroupDetailList")) for (const p of g.GroupPolicyList || []) statements += countStatements(p.PolicyDocument);
  for (const r of list("RoleDetailList")) for (const p of r.RolePolicyList || []) statements += countStatements(p.PolicyDocument);
  for (const p of list("Policies")) {
    const v = (p.PolicyVersionList || []).find((x) => x.IsDefaultVersion) || (p.PolicyVersionList || [])[0];
    statements += countStatements(v && v.Document);
  }
  return { users: list("UserDetailList").length, groups: list("GroupDetailList").length, roles: list("RoleDetailList").length, policies: list("Policies").length, statements };
}

function validate() {
  const text = input[input.src].trim();
  const box = $("validation");
  if (input.src === "account") input.accountValid = false;
  const tag = $("val-tag");
  lastValid = null;
  const set = (cls, label) => { tag.className = `tag ${cls}`; tag.textContent = label; };
  if (!text) {
    set("plain", "Waiting");
    box.innerHTML = `<p class="muted">${input.src === "scp" ? "Optional. Leave empty if the account is not in AWS Organizations." : "Nothing loaded yet. Drop a file, paste JSON, or press Load example."}</p>`;
    if (input.src !== "policy") renderPicker([]);
    updateRun();
    return;
  }
  let data;
  try {
    data = JSON.parse(text);
  } catch (e) {
    set("crit", "Not valid JSON");
    box.innerHTML = `<div class="check bad">${IC.x}<div>The text is not valid JSON<small>${esc(jsonError(text, e))}</small></div></div>`;
    if (input.src === "account") { input.principals = []; renderPicker([]); }
    updateRun();
    return;
  }
  const checks = [];
  if (input.src === "account") {
    const keys = ["UserDetailList", "GroupDetailList", "RoleDetailList", "Policies"];
    const present = keys.filter((k) => Array.isArray(data?.[k]));
    if (!data || typeof data !== "object" || Array.isArray(data) || !present.length) {
      set("crit", "Not an export");
      box.innerHTML = `<div class="check bad">${IC.x}<div>This is not an account export<small>Expected the output of aws iam get-account-authorization-details, with UserDetailList, RoleDetailList and the other lists.</small></div></div>`;
      renderPicker([]);
      updateRun();
      return;
    }
    const inv = inventoryOf(data);
    checks.push(`<div class="counts"><div><b>${inv.users}</b>users</div><div><b>${inv.groups}</b>groups</div><div><b>${inv.roles}</b>roles</div><div><b>${inv.policies}</b>policies</div></div>`);
    checks.push(present.length === 4
      ? `<div class="check ok">${IC.ok}<div>Recognised as get-account-authorization-details<small>All four lists present</small></div></div>`
      : `<div class="check warn">${IC.warn}<div>Some lists are missing<small>Missing: ${keys.filter((k) => !present.includes(k)).join(", ")}. Results may be incomplete.</small></div></div>`);
    checks.push(`<div class="check ok">${IC.ok}<div>${plural(inv.statements, "policy statement")} found</div></div>`);
    if (!input.scp.trim()) checks.push(`<div class="check warn">${IC.warn}<div>No SCPs supplied<small>If the account is in AWS Organizations, add its SCPs for a stricter result.</small></div></div>`);
    else checks.push(`<div class="check ok">${IC.ok}<div>SCPs will be applied<small>From the Organization SCPs tab</small></div></div>`);
    box.innerHTML = checks.join("");
    lastValid = { kind: "account" };
    whenReady(() => {
      const out = JSON.parse(api.account_principals(input.account));
      if (out.error) {
        set("crit", "Problem");
        box.insertAdjacentHTML("beforeend", `<div class="err">${IC.x}<div>${esc(sentence(out.error))}</div></div>`);
        lastValid = null;
        renderPicker([]);
      } else {
        set("ok", "Ready");
        input.accountValid = true;
        input.principals = out.principals;
        if (!out.principals.includes(input.start)) input.start = out.principals.find((p) => p.includes(":user/")) || out.principals[0] || "";
        renderPicker(out.principals);
      }
      updateRun();
    });
    if (!api) set("warn", "Checking");
  } else if (input.src === "policy") {
    if (!data || typeof data !== "object" || Array.isArray(data) || !("Statement" in data)) {
      set("crit", "Not a policy");
      box.innerHTML = `<div class="check bad">${IC.x}<div>This is not a policy document<small>Expected a JSON object with a Statement.</small></div></div>`;
    } else {
      set("ok", "Ready");
      box.innerHTML = `<div class="check ok">${IC.ok}<div>Policy document with ${plural(countStatements(data), "statement")}</div></div>
        <div class="check ok">${IC.info}<div>Analysed as the only policy of a role<small>Techniques that need other principals are reported as possible.</small></div></div>`;
      lastValid = { kind: "policy" };
    }
  } else {
    const docs = Array.isArray(data) ? data : [data];
    const bad = docs.filter((d) => !d || typeof d !== "object" || !("Statement" in d));
    if (bad.length) {
      set("crit", "Not SCPs");
      box.innerHTML = `<div class="check bad">${IC.x}<div>Expected SCP documents<small>Give one policy document or a JSON array of them.</small></div></div>`;
    } else {
      set("ok", "Ready");
      box.innerHTML = `<div class="check ok">${IC.ok}<div>${plural(docs.length, "SCP")}, ${plural(docs.reduce((a, d) => a + countStatements(d), 0), "statement")}<small>Applied the next time you run an account analysis.</small></div></div>`;
    }
  }
  updateRun();
}

function renderPicker(list) {
  const q = $("pick-search").value.trim().toLowerCase();
  const shown = list.filter((p) => p.toLowerCase().includes(q));
  if (!list.length) {
    $("pick").innerHTML = '<p class="list-empty">Principals appear here once an export is loaded.</p>';
    return;
  }
  $("pick").innerHTML = shown.slice(0, 300).map((p) => {
    const k = kindOf(p);
    return `<button class="pick-item ${p === input.start ? "on" : ""}" data-arn="${esc(p)}"><div class="who" data-kind="${k}"><span class="wi">${ICON[k] || ICON.resource}</span><div><b>${esc(nameOf(p))}</b><small>${esc(short(p))}</small></div></div><span class="radio"></span></button>`;
  }).join("") + (shown.length > 300 ? `<p class="list-empty">${shown.length - 300} more. Refine the search.</p>` : "") + (!shown.length ? '<p class="list-empty">No principal matches.</p>' : "");
  $("pick").querySelectorAll(".who").forEach((w) => w.style.setProperty("--kind", KIND_COLOR[w.dataset.kind] || KIND_COLOR.resource));
  $("pick").querySelectorAll(".pick-item").forEach((b) => b.addEventListener("click", () => { input.start = b.dataset.arn; renderPicker(list); updateRun(); }));
}
$("pick-search").addEventListener("input", () => renderPicker(input.principals));

function updateRun() {
  const accountReady = input.account.trim() && input.start && input.accountValid;
  let can = false;
  let note = "";
  if (input.src === "policy") {
    can = lastValid?.kind === "policy";
    note = can ? "Checks this policy against 92 techniques." : "Load a policy document to begin.";
  } else {
    can = Boolean(accountReady && api);
    note = !input.account.trim() ? "Load an account export to begin." : !input.start ? "Choose who the attacker starts as." : `Starts from ${nameOf(input.start)}. Checks every principal against 92 techniques.`;
  }
  if (!api) note = "Starting the analysis engine.";
  $("run").disabled = !can;
  $("run-note").textContent = note;
}

$("run").addEventListener("click", runAnalysis);
async function runAnalysis() {
  if (!api) return;
  overlay(input.src === "policy" ? "Checking the policy" : "Analysing the account");
  await nextFrame();
  try {
    if (input.src === "policy") {
      const out = call("escalate", input.policy);
      if (out.error) throw new Error(out.error);
      setModel(fromPolicy(out));
    } else {
      const out = call("analyze_account", input.account, input.start, input.scp, $("opt-blast").checked);
      if (out.error) throw new Error(out.error);
      setModel(fromAccount(out));
    }
    go("overview");
  } catch (e) {
    toast("The analysis failed");
    $("validation").insertAdjacentHTML("beforeend", `<div class="err">${IC.x}<div>${esc(sentence(e.message))}</div></div>`);
  } finally {
    overlay("");
  }
}

// ------------------------------------------------------------------------------------- result model

let model = null;

function fromAccount(out) {
  return {
    mode: "account",
    source: input.file ? input.file.name : "pasted export",
    example: input.example,
    start: out.result.start,
    report: out.result,
    graph: out.graph,
    principals: out.account.principals,
    allPaths: out.account.paths,
    inventory: out.inventory,
    scps: out.scps,
    text: out.text,
    sarif: out.sarif,
  };
}
function fromPolicy(out) {
  const r = out.result;
  return {
    mode: "policy",
    source: "single policy",
    example: false,
    start: r.start,
    report: r,
    graph: out.graph,
    principals: r.principals.map((p) => ({
      arn: p.arn, kind: p.kind, admin_equivalent: p.admin_equivalent, admin_reason: p.admin_reason,
      confirmed: p.techniques.filter((t) => t.confidence === "confirmed").length,
      possible: p.techniques.filter((t) => t.confidence === "possible").length,
      policies: p.arn === r.start ? 1 : null, groups: [], techniques: p.techniques,
      path: r.paths.filter((x) => x.start === p.arn).sort((a, b) => a.steps.length - b.steps.length)[0] || null,
    })),
    allPaths: r.paths,
    inventory: null,
    scps: 0,
    text: out.text,
    sarif: null,
  };
}

function setModel(m) {
  model = m;
  const acct = String(m.start || "").split(":")[4];
  $("scope-text").textContent = m.mode === "policy" ? "Single policy" : acct ? `Account ${acct}` : "Account";
  const startPaths = m.report.paths.filter((p) => p.start === m.start);
  const navPaths = $("nav-paths");
  navPaths.hidden = !startPaths.length;
  navPaths.textContent = startPaths.length;
  const findings = m.principals.reduce((a, p) => a + p.confirmed, 0);
  $("nav-findings").hidden = !findings;
  $("nav-findings").textContent = findings;
  renderOverview();
  renderGraphView();
  renderFindings();
}

const CATEGORY = {
  "principal-access": "Use another principal (assume a role, create keys)",
  "new-passrole": "Pass a role to a new resource",
  "existing-passrole": "Change an existing resource that has a role",
  "self-escalation": "Grant itself more permissions",
};

function chainHtml(path) {
  const parts = [`<span class="st">${esc(short(path.start))}</span>`];
  for (const s of path.steps) parts.push(`<span class="via">${IC.arrow}${esc(s.technique)}</span><span class="st">${esc(short(s.to))}</span>`);
  return parts.join("");
}

// Which permission changes break the most paths: each (principal, technique) on any path.
function recommendedFixes(m) {
  const counts = new Map();
  for (const path of m.allPaths) {
    for (const s of path.steps) {
      const key = `${s.from}|${s.technique}`;
      const e = counts.get(key) || { from: s.from, technique: s.technique, name: s.name, paths: 0, starts: new Set() };
      e.paths += 1;
      e.starts.add(path.start);
      counts.set(key, e);
    }
  }
  const byArn = new Map(m.principals.map((p) => [p.arn, p]));
  return [...counts.values()].sort((a, b) => b.paths - a.paths || a.technique.localeCompare(b.technique)).slice(0, 5).map((e) => {
    const t = byArn.get(e.from)?.techniques.find((x) => x.id === e.technique);
    return { ...e, permissions: t ? t.permissions : [e.name] };
  });
}

// ------------------------------------------------------------------------------------- overview

function emptyOverview() {
  return `<div class="glass empty-state"><span class="es-ic">${IC.upload}</span>
    <h2>No account analysed yet</h2>
    <p>Load the output of <span class="mono">aws iam get-account-authorization-details</span>, pick who the attacker starts as, and iam-trace shows every path to admin.</p>
    <div class="row"><button class="btn primary lg" data-go="input">Load your data</button><button class="btn lg" id="try-example">Try the example account</button></div></div>`;
}

function renderOverview() {
  const el = $("overview");
  if (!model) {
    el.innerHTML = emptyOverview();
    $("try-example")?.addEventListener("click", runExample);
    return;
  }
  const m = model;
  const startP = m.principals.find((p) => p.arn === m.start);
  const startPaths = m.report.paths.filter((p) => p.start === m.start).sort((a, b) => a.steps.length - b.steps.length);
  const startTech = (m.report.principals.find((p) => p.arn === m.start)?.techniques) || [];
  const confirmed = startTech.filter((t) => t.confidence === "confirmed");
  const possible = startTech.filter((t) => t.confidence === "possible");
  const who = esc(short(m.start));
  let tone;
  let head;
  let body;
  if (startP?.admin_equivalent) {
    tone = "crit";
    head = `<span>Critical:</span> ${who} is already admin-equivalent`;
    body = `This principal ${esc(startP.admin_reason || "has full control")}. Anyone with its credentials controls the account.`;
  } else if (startPaths.length) {
    tone = "crit";
    head = `<span>Critical:</span> ${who} can take over the account`;
    body = `Starting from ${who}, an attacker reaches an admin-equivalent principal in ${plural(startPaths[0].steps.length, "step")}, using only permissions your policies allow.${startPaths.length > 1 ? ` There are ${startPaths.length} paths in total.` : ""}`;
  } else if (confirmed.length) {
    tone = "warn";
    head = `<span>Review:</span> ${who} can escalate, but not to admin`;
    body = `${plural(confirmed.length, "technique")} let it become other principals, but none of them leads to full control in this ${m.mode === "policy" ? "policy" : "account"}.`;
  } else if (possible.length) {
    tone = "warn";
    head = `<span>Review:</span> ${plural(possible.length, "possible technique")} for ${who}`;
    body = "They depend on resources the input does not describe, such as existing Lambda functions or EC2 instances. Check those resources.";
  } else {
    tone = "ok";
    head = `<span>No path found:</span> ${who} cannot escalate`;
    body = `None of the 92 known techniques is allowed for this principal${m.scps ? ", with your SCPs applied" : ""}.`;
  }
  const reaches = startP?.admin_equivalent ? '<span class="tag crit">Already admin</span>' : startPaths.length ? '<span class="tag crit">Full control</span>' : '<span class="tag ok">No admin path</span>';
  const atRisk = m.principals.filter((p) => p.admin_equivalent || p.path);
  const admins = m.principals.filter((p) => p.admin_equivalent);
  const fixes = recommendedFixes(m);
  const inv = m.inventory;
  const blast = m.report.blast_radius;

  const banner = m.example ? `<div class="banner">${IC.info}<span>You are looking at the example account. Load your own export to analyse your account.</span><button class="btn" data-go="input">Load your data</button></div>` : "";

  const kpi = (cls, icon, label, value, sub, stack, key) => `<div class="kpi glass ${cls}"><div class="kh"><span class="ki">${icon}</span>${label}</div>
    <div class="kv"><b>${value}</b><span>${sub}</span></div>${stack ? `<div class="stack">${stack}</div>` : ""}${key ? `<div class="stack-key">${key}</div>` : ""}</div>`;
  const total = m.principals.length;
  const kpis = [
    kpi(startPaths.length ? "k-crit" : "k-ok", '<svg class="i" viewBox="0 0 24 24"><circle cx="5" cy="12" r="2.5"/><circle cx="19" cy="12" r="2.5"/><path d="M7.5 12h9"/></svg>', "Paths to admin", startPaths.length,
      startPaths.length ? `shortest ${plural(startPaths[0].steps.length, "step")}` : `from ${esc(nameOf(m.start))}`),
    kpi(atRisk.length ? "k-high" : "k-ok", '<svg class="i" viewBox="0 0 24 24"><path d="M12 3l8 4v5c0 4.4-3.4 8-8 9-4.6-1-8-4.6-8-9V7z"/></svg>', "Principals that reach admin", atRisk.length, `of ${plural(total, "principal")}`,
      total ? `<i class="c-crit" data-flex="${admins.length}"></i><i class="c-high" data-flex="${atRisk.length - admins.length}"></i><i class="c-faint" data-flex="${total - atRisk.length}"></i>` : "",
      `<span><i class="c-crit"></i>${admins.length} admin-equivalent</span><span><i class="c-high"></i>${atRisk.length - admins.length} with a path</span>`),
    kpi(confirmed.length ? "k-warn" : "k-ok", '<svg class="i" viewBox="0 0 24 24"><path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.5 2.5-2.4-.6-.6-2.4z"/></svg>', `Techniques for ${esc(nameOf(m.start))}`, startTech.length, "of 92 checked",
      startTech.length ? `<i class="c-crit" data-flex="${confirmed.length}"></i><i class="c-warn" data-flex="${possible.length}"></i><i class="c-faint" data-flex="${Math.max(0, 92 - startTech.length)}"></i>` : "",
      `<span><i class="c-crit"></i>${confirmed.length} confirmed</span><span><i class="c-warn"></i>${possible.length} possible</span>`),
    inv
      ? kpi("k-acc", '<svg class="i" viewBox="0 0 24 24"><circle cx="9" cy="8" r="3.2"/><circle cx="17" cy="9.5" r="2.6"/><path d="M3 20c1-3.4 3.4-5.2 6-5.2s5 1.8 6 5.2"/></svg>', "Principals analysed", total, `${plural(inv.managed_policies, "managed policy", "managed policies")}, ${plural(inv.inline_policies, "inline policy", "inline policies")}`,
        `<i class="c-acc" data-flex="${inv.users}"></i><i class="c-acc2" data-flex="${inv.roles}"></i><i class="c-muted" data-flex="${inv.groups}"></i>`,
        `<span><i class="c-acc"></i>${plural(inv.users, "user")}</span><span><i class="c-acc2"></i>${plural(inv.roles, "role")}</span><span><i class="c-muted"></i>${plural(inv.groups, "group")}</span>`)
      : kpi("k-acc", '<svg class="i" viewBox="0 0 24 24"><path d="M7 3h7l5 5v13H7z"/><path d="M14 3v5h5"/></svg>', "Input", "1", "identity policy, analysed as a role"),
  ].join("");

  const pathItems = startPaths.length
    ? startPaths.slice(0, 6).map((p, i) => `<div class="path-item" data-path="${m.report.paths.indexOf(p)}"><div class="ph"><b>${esc(nameOf(p.start))} to ${esc(nameOf(p.end))}</b><span class="tag crit">${plural(p.steps.length, "step")}</span></div>
        <div class="chain">${chainHtml(p)}</div><div class="pmeta"><span>${esc(sentence(p.why))}</span></div></div>`).join("")
    : `<p class="list-empty">No path to admin from ${who}.${possible.length ? " Possible techniques are listed in Findings." : ""}</p>`;

  const fixHtml = fixes.length
    ? fixes.map((f, i) => `<div class="fix"><span class="num">${i + 1}</span><span class="t">Narrow <span class="mono">${esc(f.permissions.join(", "))}</span> for ${esc(short(f.from))}</span><span class="tag crit imp">${plural(f.paths, "path")}</span>
        <span class="d">Removes ${esc(f.technique)} (${esc(f.name)}). ${f.starts.size > 1 ? `Used by ${plural(f.starts.size, "starting principal")}.` : ""}</span></div>`).join("")
    : '<p class="list-empty">No paths to break.</p>';

  const cats = {};
  for (const t of startTech) {
    cats[t.category] = cats[t.category] || { c: 0, p: 0 };
    cats[t.category][t.confidence === "confirmed" ? "c" : "p"] += 1;
  }
  const catMax = Math.max(1, ...Object.values(cats).map((x) => x.c + x.p));
  const catHtml = Object.keys(CATEGORY).map((k) => {
    const v = cats[k] || { c: 0, p: 0 };
    return `<div class="row"><span class="name">${CATEGORY[k]}</span><span class="bn">${v.c + v.p}</span><div class="track"><i class="${v.c ? "c-crit" : "c-warn"}" data-w="${((v.c + v.p) / catMax) * 100}"></i></div></div>`;
  }).join("");

  const blastHtml = blast
    ? (() => {
      const entries = Object.entries(blast.actions_by_access_level || {});
      const max = Math.max(1, ...entries.map(([, n]) => n));
      return `<p class="muted small-p">${plural(blast.total_actions, "action")} allowed on every resource, across ${plural(blast.principals.length, "reachable principal")}.</p>` +
        entries.map(([k, n]) => `<div class="row"><span class="name">${esc(k)}</span><span class="bn">${n.toLocaleString()}</span><div class="track"><i class="c-high" data-w="${(n / max) * 100}"></i></div></div>`).join("");
    })()
    : `<p class="list-empty">Not counted. Turn on <b>Count blast radius</b> in Data input to see how many AWS actions the attacker gains.</p><button class="btn" data-go="input">Open Data input</button>`;

  const ranked = [...m.principals].sort((a, b) => (b.admin_equivalent - a.admin_equivalent) || ((a.path ? a.path.steps.length : 99) - (b.path ? b.path.steps.length : 99)) || (b.confirmed - a.confirmed) || a.arn.localeCompare(b.arn));
  const riskRows = ranked.slice(0, 12).map((p) => principalRow(p)).join("");

  el.innerHTML = `${banner}
    <div class="page-head"><div><h1>Overview</h1><p>Analysed <span class="mono">${esc(m.source)}</span> from <span class="mono">${who}</span> against 92 privilege-escalation techniques from pathfinding.cloud${m.scps ? `, with ${plural(m.scps, "SCP")} applied` : ""}.</p></div>
      <div class="actions"><button class="btn" data-go="input">Change input</button><button class="btn primary" data-go="graph">Open attack graph</button></div></div>
    <div class="posture glass p-${tone}"><div class="posture-main"><span class="sev-badge">${tone === "ok" ? IC.ok : IC.warn}</span><div><h2>${head}</h2><p>${body}</p>${startPaths.length ? `<div class="chain">${chainHtml(startPaths[0])}</div>` : ""}</div></div>
      <div class="posture-side"><div class="ps-item"><div class="l">Starting principal</div><div class="v mono">${who}</div></div><div class="ps-item"><div class="l">Reaches</div><div class="v">${reaches}</div></div>
        <div class="ps-item"><div class="l">Shortest path</div><div class="v">${startPaths.length ? plural(startPaths[0].steps.length, "step") : "None"}</div></div><div class="ps-item"><div class="l">SCPs applied</div><div class="v">${m.scps || "None"}</div></div></div></div>
    <div class="kpis">${kpis}</div>
    <div class="grid-2">
      <div class="glass"><div class="card-h"><h3>Attack graph</h3><span class="sub">Who the attacker can become</span><div class="right"><button class="btn" data-go="graph">Open full screen</button></div></div>
        <div class="preview" id="preview" title="Open the attack graph"><div class="surface" id="psurface"><div class="world" id="pworld"><svg></svg></div></div></div></div>
      <div class="glass"><div class="card-h"><h3>Paths to admin</h3><span class="sub">Select one to view it on the graph</span></div><div class="card-b" id="ov-paths">${pathItems}</div></div>
    </div>
    <div class="grid-3">
      <div class="glass"><div class="card-h"><h3>Recommended fixes</h3><span class="sub">Ordered by paths broken</span></div><div class="card-b">${fixHtml}</div></div>
      <div class="glass"><div class="card-h"><h3>Technique categories</h3><span class="sub">Allowed for ${esc(nameOf(m.start))}</span></div><div class="card-b bars">${catHtml}</div></div>
      <div class="glass"><div class="card-h"><h3>Blast radius</h3><span class="sub">What the attacker can do</span></div><div class="card-b bars">${blastHtml}</div></div>
    </div>
    <div class="glass"><div class="card-h"><h3>Principals at risk</h3><span class="sub">Every principal, most exposed first</span><div class="right"><button class="btn" data-go="findings">All findings</button></div></div>
      <table><thead><tr><th>Principal</th><th>Status</th><th>Shortest path to admin</th><th>Confirmed</th><th>Possible</th><th>Policies</th></tr></thead><tbody>${riskRows}</tbody></table>
      ${ranked.length > 12 ? `<div class="more"><button class="btn" data-go="findings">Show all ${ranked.length} principals in Findings</button></div>` : ""}</div>`;
  applyWidths(el);
  hydrateWho(el);
  el.querySelectorAll("#ov-paths .path-item").forEach((p) => p.addEventListener("click", () => { go("graph"); focusPath(Number(p.dataset.path)); }));
  $("preview").addEventListener("click", () => go("graph"));
  preview = new Graph($("psurface"), $("pworld"), { interactive: false, pad: 24, maxScale: 0.85, markerPrefix: "p" });
  graphs[1] = preview;
  preview.setData(graphData(m));
}

function statusOf(p) {
  if (p.admin_equivalent) return ['<span class="sev c-crit"><i></i>Admin-equivalent</span>', p.admin_reason || ""];
  if (p.path) return ['<span class="sev c-high"><i></i>Can reach admin</span>', ""];
  if (p.confirmed) return ['<span class="sev c-warn"><i></i>Can escalate</span>', ""];
  if (p.possible) return ['<span class="sev c-warn"><i></i>Possible only</span>', ""];
  return ['<span class="sev c-ok"><i></i>No known technique</span>', ""];
}
function principalRow(p) {
  const [status] = statusOf(p);
  const k = kindOf(p.arn);
  return `<tr><td><div class="who" data-kind="${k}"><span class="wi">${ICON[k] || ICON.resource}</span><div><b>${esc(nameOf(p.arn))}</b><small>${esc(short(p.arn))}</small></div></div></td>
    <td>${status}</td><td>${p.admin_equivalent ? '<span class="t-faint">Is admin</span>' : p.path ? `${plural(p.path.steps.length, "step")}: <span class="mono">${p.path.steps.map((s) => esc(s.technique)).join(", ")}</span>` : '<span class="t-faint">None</span>'}</td>
    <td>${p.confirmed}</td><td>${p.possible}</td><td>${p.policies ?? "-"}</td></tr>`;
}
function hydrateWho(el) {
  el.querySelectorAll(".who[data-kind], .d-head[data-kind]").forEach((w) => w.style.setProperty("--kind", KIND_COLOR[w.dataset.kind] || KIND_COLOR.resource));
}

async function runExample() {
  await loadExampleAccount();
  setSource("account");
  whenReady(async () => {
    const out = JSON.parse(api.account_principals(input.account));
    input.principals = out.principals || [];
    input.start = input.principals.find((p) => p.endsWith(":user/dev")) || input.principals[0];
    renderPicker(input.principals);
    updateRun();
    await runAnalysis();
  });
  if (!api) overlay("Starting the analysis engine");
}

// ------------------------------------------------------------------------------------- graph

function graphData(m) {
  const byArn = new Map(m.principals.map((p) => [p.arn, p]));
  const pathsOf = new Map();
  const edgePaths = new Map();
  m.report.paths.forEach((path, i) => {
    if (path.start !== m.start) return;
    const ids = [path.start, ...path.steps.map((s) => s.to), "admin"];
    ids.forEach((id) => { if (!pathsOf.has(id)) pathsOf.set(id, new Set()); pathsOf.get(id).add(i); });
    path.steps.forEach((s) => { const k = `${s.from}|${s.to}`; if (!edgePaths.has(k)) edgePaths.set(k, new Set()); edgePaths.get(k).add(i); });
    const k = `${path.end}|admin`;
    if (!edgePaths.has(k)) edgePaths.set(k, new Set());
    edgePaths.get(k).add(i);
  });
  const anyPath = m.report.paths.some((p) => p.start === m.start);
  const nodes = m.graph.nodes.map((n) => ({
    ...n,
    kind: n.kind === "resource" ? kindOf(n.id) : n.kind,
    policies: byArn.get(n.id)?.policies ?? null,
    paths: pathsOf.get(n.id) || new Set(),
    notSpecific: !n.id.startsWith("arn:") && n.id !== "admin",
    reachesAdmin: anyPath,
  }));
  const edges = m.graph.edges.map((e) => ({ ...e, paths: edgePaths.get(`${e.from}|${e.to}`) || new Set() }));
  return { nodes, edges, start: m.start };
}

let selectedLabel = null;
const main = new Graph($("gsurface"), $("gworld"), {
  pad: 40,
  maxScale: 1.05,
  // Keep the graph clear of the paths panel on wide screens; on phones the panel overlays it.
  insets: () => ({ l: $("g-paths-panel").classList.contains("closed") || window.innerWidth < 860 ? 0 : 320, r: 0, t: 50, b: 50 }),
  onSelect: (n) => showNode(n),
  onEdge: (e, el) => showEdge(e, el),
});
let preview = null;
const graphs = [main];

function renderGraphView() {
  if (!model) return;
  const m = model;
  main.setData(graphData(m));
  const startPaths = m.report.paths.map((p, i) => [p, i]).filter(([p]) => p.start === m.start);
  $("g-head").innerHTML = startPaths.length
    ? `<span class="verdict-pill"><span class="dot">${IC.warn}</span><b>${plural(startPaths.length, "path")} to admin</b><span class="muted">from ${esc(short(m.start))}, shortest ${plural(Math.min(...startPaths.map(([p]) => p.steps.length)), "step")}</span></span>`
    : `<span class="verdict-pill ok-pill"><span class="dot">${IC.ok}</span><b>No path to admin</b><span class="muted">from ${esc(short(m.start))}</span></span>`;
  $("g-paths").innerHTML = startPaths.length
    ? startPaths.map(([p, i]) => `<div class="path-item" data-path="${i}"><div class="ph"><b>${esc(nameOf(p.start))} to ${esc(nameOf(p.end))}</b><span class="tag crit">${plural(p.steps.length, "step")}</span></div><div class="chain">${chainHtml(p)}</div></div>`).join("")
    : '<p class="list-empty">No path to admin. Possible techniques, if any, are drawn as dashed lines.</p>';
  $("g-paths").querySelectorAll(".path-item").forEach((el) => el.addEventListener("click", () => focusPath(Number(el.dataset.path))));
  if (window.innerWidth < 860) $("g-paths-panel").classList.add("closed");
  closeDetails();
}
function focusPath(i) {
  main.focus = main.focus === i ? null : i;
  main.render();
  $("g-paths").querySelectorAll(".path-item").forEach((el) => el.classList.toggle("on", Number(el.dataset.path) === main.focus));
}
$("f-poss").addEventListener("change", (e) => { main.hidePossible = !e.target.checked; main.render(); });
$("z-in").addEventListener("click", () => main.zoom(1.2));
$("z-out").addEventListener("click", () => main.zoom(1 / 1.2));
$("z-fit").addEventListener("click", () => main.fit());
$("g-hide-paths").addEventListener("click", () => { $("g-paths-panel").classList.add("closed"); main.fit(); });
$("g-show-paths").addEventListener("click", () => { $("g-paths-panel").classList.remove("closed"); main.fit(); });
$("g-export").addEventListener("click", () => {
  if (!model) return toast("Run an analysis first");
  download(`iam-trace-${nameOf(model.start)}.json`, JSON.stringify(model.report, null, 2));
});
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDetails(); });

function closeDetails() {
  $("g-details").classList.add("closed");
  main.selected = null;
  main.mark();
  if (selectedLabel) selectedLabel.classList.remove("sel");
  selectedLabel = null;
}
function techCard(t) {
  const src = t.source || {};
  return `<div class="tech"><div class="th"><a class="id" href="${esc(src.pathfinding || t.pathfinding_url || "#")}" target="_blank" rel="noopener">${esc(t.id)}</a><span class="tag ${t.confidence === "confirmed" ? "crit" : "warn"}">${t.confidence === "confirmed" ? "Confirmed" : "Possible"}</span></div>
    <div class="nm">${esc(t.name)}</div><div class="why">Leads to ${t.targets.map((x) => esc(short(x))).join(", ")}.${src.author ? ` First documented by ${src.first_documented ? `<a href="${esc(src.first_documented)}" target="_blank" rel="noopener">${esc(src.author)}</a>` : esc(src.author)}.` : ""}</div></div>`;
}
function showNode(n) {
  main.selected = n.id;
  main.mark();
  const m = model;
  const p = m.principals.find((x) => x.arn === n.id);
  const techs = (m.report.principals.find((x) => x.arn === n.id)?.techniques) || [];
  const sorted = [...techs].sort((a, b) => (a.confidence === "confirmed" ? 0 : 1) - (b.confidence === "confirmed" ? 0 : 1));
  const tags = [];
  if (n.start) tags.push('<span class="tag acc">Attacker starts here</span>');
  if (n.admin && n.kind !== "admin") tags.push('<span class="tag crit">Admin-equivalent</span>');
  let about;
  if (n.kind === "admin") about = "Reaching this node means the attacker can grant themselves any permission, read any data and delete any resource.";
  else if (n.admin) about = `Admin-equivalent: ${esc(n.admin_reason || "")}.`;
  else if (!n.id.startsWith("arn:")) about = "Not a specific principal: any role the policy can pass to a service. Which roles qualify depends on resources the input does not list.";
  else if (n.start) about = "The attacker controls this principal's credentials.";
  else about = "The attacker can become this principal.";
  $("g-details").innerHTML = `<div class="d-head" data-kind="${n.kind}"><div class="d-top"><span class="d-ic">${ICON[n.kind] || ICON.resource}</span><div><div class="d-name">${esc(n.label)}</div><div class="d-kind">${KIND_NAME[n.kind] || "Principal"}</div></div><button class="icon-btn" id="d-close" aria-label="Close">${IC.x}</button></div>
      ${n.id.startsWith("arn:") ? `<div class="d-arn">${esc(n.id)}</div>` : ""}${tags.length ? `<div class="d-tags">${tags.join("")}</div>` : ""}</div>
    ${n.kind !== "admin" && p ? `<div class="d-stats"><div><b>${p.confirmed}</b>confirmed</div><div><b>${p.possible}</b>possible</div><div><b>${p.policies ?? "-"}</b>policies</div></div>` : ""}
    <div class="d-sec"><h4>What this means</h4><p>${about}</p></div>
    ${p && p.groups && p.groups.length ? `<div class="d-sec"><h4>Groups</h4>${p.groups.map((g) => `<div class="policy-line"><span class="mono">${esc(short(g))}</span></div>`).join("")}</div>` : ""}
    ${sorted.length && !n.admin ? `<div class="d-sec"><h4>Techniques from here</h4>${sorted.slice(0, 15).map(techCard).join("")}${sorted.length > 15 ? `<p class="muted">and ${sorted.length - 15} more in Findings.</p>` : ""}</div>` : ""}
    ${n.admin && sorted.length ? `<div class="d-sec"><h4>Techniques</h4><p>Being admin-equivalent, every one of its ${sorted.length} allowed techniques applies. See Findings for the list.</p></div>` : ""}`;
  hydrateWho($("g-details"));
  $("g-details").classList.remove("closed");
  $("d-close").addEventListener("click", closeDetails);
}
function showEdge(e, el) {
  if (selectedLabel) selectedLabel.classList.remove("sel");
  selectedLabel = el;
  el.classList.add("sel");
  const m = model;
  const ids = e.name.split(/,\s*/);
  const from = m.report.principals.find((x) => x.arn === e.from);
  const techs = from ? from.techniques.filter((t) => ids.includes(t.id) || t.id === e.label) : [];
  $("g-details").innerHTML = `<div class="d-head"><div class="d-top"><div><div class="d-name mono">${esc(e.label)}</div><div class="d-kind">${esc(nameOf(e.from))} to ${esc(nameOf(e.to))}</div></div><button class="icon-btn" id="d-close" aria-label="Close">${IC.x}</button></div></div>
    <div class="d-sec">${techs.length ? techs.map(techCard).join("") : `<p>${esc(sentence(e.name))}</p>`}</div>
    ${techs.length ? `<div class="d-sec"><h4>Permissions involved</h4>${[...new Set(techs.flatMap((t) => t.permissions))].map((x) => `<div class="policy-line"><span class="mono">${esc(x)}</span></div>`).join("")}</div>` : ""}`;
  $("g-details").classList.remove("closed");
  $("d-close").addEventListener("click", closeDetails);
}

// ------------------------------------------------------------------------------------- findings

const findState = { filter: "confirmed", q: "", limit: 100 };
function renderFindings() {
  const el = $("findings");
  if (!model) {
    el.innerHTML = emptyOverview().replace("No account analysed yet", "No findings yet");
    $("try-example")?.addEventListener("click", runExample);
    return;
  }
  const rows = [];
  for (const p of model.principals) {
    for (const t of p.techniques) rows.push({ p, t });
  }
  const conf = rows.filter((r) => r.t.confidence === "confirmed").length;
  el.innerHTML = `<div class="page-head"><div><h1>Findings</h1><p>Every technique allowed for every principal, with links to how each one works.</p></div>
      <div class="actions"><button class="btn" id="dl-text">Download text</button>${model.sarif ? '<button class="btn" id="dl-sarif">Download SARIF</button>' : ""}<button class="btn" id="dl-json">Download JSON</button></div></div>
    <div class="glass"><div class="table-tools">
      <div class="seg-chips">${[["confirmed", `Confirmed (${conf})`], ["possible", `Possible (${rows.length - conf})`], ["all", `All (${rows.length})`], ["principals", `Principals (${model.principals.length})`]].map(([k, l]) => `<button class="chipf ${findState.filter === k ? "on" : ""}" data-f="${k}">${l}</button>`).join(" ")}</div>
      <label class="search"><svg class="i" viewBox="0 0 24 24"><circle cx="11" cy="11" r="6"/><path d="M20 20l-4.5-4.5"/></svg><input id="find-q" placeholder="Search principal, technique or permission" value="${esc(findState.q)}" aria-label="Search findings"></label>
      <span class="right" id="find-count"></span></div>
      <div id="find-body"></div></div>`;
  el.querySelectorAll(".chipf").forEach((c) => c.addEventListener("click", () => { findState.filter = c.dataset.f; findState.limit = 100; renderFindings(); }));
  $("find-q").addEventListener("input", (e) => { findState.q = e.target.value; findState.limit = 100; drawFindings(rows); });
  $("dl-json").addEventListener("click", () => download(`iam-trace-${nameOf(model.start)}.json`, JSON.stringify({ start: model.start, report: model.report, principals: model.principals }, null, 2)));
  $("dl-text").addEventListener("click", () => download(`iam-trace-${nameOf(model.start)}.txt`, model.text, "text/plain"));
  $("dl-sarif")?.addEventListener("click", () => download(`iam-trace-${nameOf(model.start)}.sarif`, model.sarif));
  drawFindings(rows);
}
function drawFindings(rows) {
  const q = findState.q.trim().toLowerCase();
  const body = $("find-body");
  if (findState.filter === "principals") {
    const list = model.principals.filter((p) => !q || p.arn.toLowerCase().includes(q));
    body.innerHTML = `<div class="ptable-wrap"><table><thead><tr><th>Principal</th><th>Status</th><th>Shortest path to admin</th><th>Confirmed</th><th>Possible</th><th>Policies</th></tr></thead><tbody>${list.slice(0, findState.limit).map(principalRow).join("")}</tbody></table></div>`;
    $("find-count").textContent = plural(list.length, "principal");
  } else {
    const list = rows.filter((r) => (findState.filter === "all" || r.t.confidence === findState.filter) &&
      (!q || r.p.arn.toLowerCase().includes(q) || r.t.id.includes(q) || r.t.name.toLowerCase().includes(q) || r.t.permissions.some((x) => x.toLowerCase().includes(q))))
      .sort((a, b) => (a.t.confidence === "confirmed" ? 0 : 1) - (b.t.confidence === "confirmed" ? 0 : 1) || a.p.arn.localeCompare(b.p.arn));
    const k = (arn) => kindOf(arn);
    body.innerHTML = list.length
      ? `<div class="ptable-wrap"><table><thead><tr><th>Confidence</th><th>Technique</th><th>Principal</th><th>Leads to</th><th>Permissions</th><th>Reference</th></tr></thead><tbody>${list.slice(0, findState.limit).map(({ p, t }) => `<tr>
          <td><span class="sev ${t.confidence === "confirmed" ? "c-crit" : "c-warn"}"><i></i>${t.confidence === "confirmed" ? "Confirmed" : "Possible"}</span></td>
          <td><b class="mono">${esc(t.id)}</b><div class="cat-note">${esc(CATEGORY[t.category] || t.category)}</div></td>
          <td><div class="who" data-kind="${k(p.arn)}"><span class="wi">${ICON[k(p.arn)] || ICON.resource}</span><div><b>${esc(nameOf(p.arn))}</b><small>${esc(short(p.arn))}</small></div></div></td>
          <td class="td-mono">${t.targets.map((x) => esc(short(x))).join("<br>")}</td>
          <td class="td-mono">${t.permissions.map(esc).join("<br>")}</td>
          <td><a href="${esc(t.source?.pathfinding || "#")}" target="_blank" rel="noopener">pathfinding.cloud</a></td></tr>`).join("")}</tbody></table></div>`
      : '<p class="list-empty">Nothing matches.</p>';
    $("find-count").textContent = plural(list.length, "finding");
    if (list.length > findState.limit) body.insertAdjacentHTML("beforeend", `<div class="more"><button class="btn" id="find-more">Show ${Math.min(100, list.length - findState.limit)} more</button></div>`);
  }
  hydrateWho(body);
  $("find-more")?.addEventListener("click", () => { findState.limit += 100; drawFindings(rows); });
}

// ------------------------------------------------------------------------------------- evaluate

const POLICY_TYPES = [
  ["identity", "Identity-based policy", "Attached to the user or role"],
  ["resource_policy", "Resource-based policy", "Bucket, key, queue or trust policy"],
  ["boundary", "Permissions boundary", "Caps the identity policies"],
  ["session", "Session policy", "Passed when the session started"],
  ["scp", "Service control policy", "Organization guardrail on principals"],
  ["rcp", "Resource control policy", "Organization guardrail on resources"],
];
const STEPS = [
  ["explicit_deny", "Explicit deny", "Explicit deny in any policy", '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8"/><path d="M7 17L17 7"/></svg>'],
  ["rcp", "RCPs", "Resource control policies", '<svg viewBox="0 0 24 24"><rect x="9" y="3" width="6" height="5" rx="1"/><rect x="3" y="16" width="6" height="5" rx="1"/><rect x="15" y="16" width="6" height="5" rx="1"/><path d="M12 8v4M6 16v-4h12v4"/></svg>'],
  ["scp", "SCPs", "Service control policies", '<svg viewBox="0 0 24 24"><rect x="9" y="3" width="6" height="5" rx="1"/><rect x="3" y="16" width="6" height="5" rx="1"/><rect x="15" y="16" width="6" height="5" rx="1"/><path d="M12 8v4M6 16v-4h12v4"/></svg>'],
  ["resource_policy", "Resource policy", "Resource-based policy", '<svg viewBox="0 0 24 24"><ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3"/></svg>'],
  ["identity_policy", "Identity", "Identity-based policies", '<svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6"/></svg>'],
  ["permissions_boundary", "Boundary", "Permissions boundary", '<svg viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2" stroke-dasharray="3 3"/><rect x="8" y="8" width="8" height="8" rx="1"/></svg>'],
  ["session_policy", "Session", "Session policies", '<svg viewBox="0 0 24 24"><circle cx="12" cy="13" r="8"/><path d="M12 9v4l3 2M9 2h6"/></svg>'],
];
const OUTCOME = { pass: ["ok", "Passes"], allow: ["ok", "Allows"], deny: ["crit", "Denies"], "no match": ["neutral", "No match"], "not applicable": ["idle", "Not applicable"] };
const evPolicies = Object.fromEntries(POLICY_TYPES.map(([k]) => [k, ""]));
const evOpen = new Set();

function policyState(text) {
  if (!text.trim()) return ["", "Not set"];
  try {
    const d = JSON.parse(text);
    return ["set", plural(countStatements(d), "statement")];
  } catch {
    return ["bad", "Invalid JSON"];
  }
}
function renderEvPolicies() {
  $("ev-policies").innerHTML = POLICY_TYPES.map(([k, name, note]) => {
    const [st, label] = policyState(evPolicies[k]);
    const open = evOpen.has(k);
    return `<div class="policy-ed" data-k="${k}"><button class="prow ${st}" aria-expanded="${open}"><span class="pi">${IC.file}</span><div><b>${name}</b><small>${note}</small></div><span class="pst">${label}</span><span class="lnk">${open ? "Close" : st ? "Edit" : "Add"}</span></button>
      ${open ? `<div class="ped-body"><textarea spellcheck="false" aria-label="${name} JSON" placeholder='{"Version": "2012-10-17", "Statement": [ ... ]}'></textarea>${st === "bad" ? '<p class="ped-err">This is not valid JSON.</p>' : ""}</div>` : ""}</div>`;
  }).join("");
  $("ev-policies").querySelectorAll(".policy-ed").forEach((row) => {
    const k = row.dataset.k;
    row.querySelector(".prow").addEventListener("click", () => { if (evOpen.has(k)) evOpen.delete(k); else evOpen.add(k); renderEvPolicies(); });
    const ta = row.querySelector("textarea");
    if (ta) {
      ta.value = evPolicies[k];
      ta.addEventListener("input", () => { evPolicies[k] = ta.value; refreshEvCounts(); });
      ta.addEventListener("blur", () => renderEvPoliciesKeepFocus());
    }
  });
  refreshEvCounts();
}
function renderEvPoliciesKeepFocus() {
  // Re-render on blur so the status labels update without stealing focus while typing.
  if (!document.activeElement || !document.activeElement.closest || !document.activeElement.closest("#ev-policies")) renderEvPolicies();
}
function refreshEvCounts() {
  const n = POLICY_TYPES.filter(([k]) => evPolicies[k].trim()).length;
  $("ev-pcount").textContent = `${n} of 6 supplied`;
}
EVALUATE_EXAMPLES.forEach((ex, i) => $("ev-scenario").add(new Option(ex.title, String(i))));
$("ev-scenario").addEventListener("change", () => loadEvExample(EVALUATE_EXAMPLES[Number($("ev-scenario").value)]));
function loadEvExample(ex) {
  $("ev-principal").value = ex.principal;
  $("ev-action").value = ex.action;
  $("ev-resource").value = ex.resource;
  $("ev-account").value = ex.account || "";
  $("ev-context").value = ex.context || "";
  evOpen.clear();
  for (const [k] of POLICY_TYPES) evPolicies[k] = ex.policies[k] ? JSON.stringify(ex.policies[k], null, 2) : "";
  const first = Object.keys(ex.policies)[0];
  if (first) evOpen.add(first);
  renderEvPolicies();
  $("ev-result").innerHTML = `<div class="glass empty-state"><span class="es-ic">${IC.info}</span><h2>Ready to evaluate</h2><p>Press Evaluate to see the decision, every step AWS checks, and the statement that decided it.</p></div>`;
}
$("ev-clear").addEventListener("click", () => { for (const [k] of POLICY_TYPES) evPolicies[k] = ""; evOpen.clear(); renderEvPolicies(); });
$("ev-run").addEventListener("click", () => {
  const req = {
    principal: $("ev-principal").value, action: $("ev-action").value, resource: $("ev-resource").value,
    resource_account: $("ev-account").value, context: $("ev-context").value,
    identity: [evPolicies.identity], resource_policy: evPolicies.resource_policy, boundary: evPolicies.boundary,
    session: [evPolicies.session], scp: [evPolicies.scp], rcp: [evPolicies.rcp],
  };
  const out = call("can", JSON.stringify(req));
  renderEvResult(out, req);
});

function renderEvResult(out, req) {
  const el = $("ev-result");
  if (out.error) {
    el.innerHTML = `<div class="verdict glass v-warn"><span class="vb">${IC.warn}</span><div><h2>Could not evaluate</h2><p>${esc(sentence(out.error))}</p></div></div>`;
    return;
  }
  const r = out.result;
  const allowed = r.decision === "Allow";
  const decided = STEPS.findIndex(([k]) => k === r.deciding_step);
  const last = r.trace[r.trace.length - 1];
  const where = [...new Set(last.matches.map((m) => m.policy))].map((x) => `<b>${esc(x)}</b>`).join(", ");
  const stepName = (STEPS[decided]?.[2] || r.deciding_step).toLowerCase();
  const why = { Allow: `Granted by the ${stepName}${where ? ` (${where})` : ""}, and no policy denies it.`, ExplicitDeny: `An explicit deny in ${where || "a policy"} overrides every allow.`, ImplicitDeny: `Nothing allows it at the ${stepName} step, so AWS denies it by default.` }[r.decision];
  const states = STEPS.map(([key], i) => {
    const t = r.trace.find((x) => x.step === key);
    if (t) return { t, tone: (OUTCOME[t.outcome] || ["neutral"])[0], label: (OUTCOME[t.outcome] || [null, sentence(t.outcome)])[1] };
    const reached = allowed || i < decided;
    return { t: null, tone: "idle", label: reached ? "Not supplied" : "Not reached", skipped: !reached };
  });
  const stopAt = allowed ? STEPS.length : decided;
  const pipe = STEPS.map(([key, shortName, , icon], i) => {
    const s = states[i];
    const link = i === 0 ? "" : i <= stopAt ? "lit" : "dim";
    return `<li class="ps" data-step="${key}" data-tone="${s.tone}" ${link ? `data-link="${link}"` : ""} ${s.skipped ? "data-skip" : ""}><span class="t">${icon}<span class="no">${i + 1}</span></span><span class="l">${shortName}</span><span class="o">${s.label}</span></li>`;
  }).join("") + `<li class="ps dec" data-tone="${allowed ? "ok" : "crit"}" data-link="${allowed ? "ok" : "crit"}"><span class="t"><svg viewBox="0 0 24 24">${allowed ? '<path d="M5 12l4 4 10-10"/>' : '<path d="M6 6l12 12M18 6L6 18"/>'}</svg></span><span class="l ${allowed ? "l-ok" : "l-crit"}">${allowed ? "Allowed" : "Denied"}</span><span class="o">${{ Allow: "Allow", ExplicitDeny: "Explicit deny", ImplicitDeny: "Implicit deny" }[r.decision]}</span></li>`;
  const rows = STEPS.map(([key, , name], i) => {
    const s = states[i];
    const tone = { ok: "t-ok", crit: "t-crit", neutral: "t-muted" }[s.tone] || "t-faint";
    const stm = s.t && s.t.matches.length ? s.t.matches.map((m) => `<div class="stmt"><span class="eff ${m.effect === "Deny" ? "d" : "a"}">${esc(m.effect)}</span><span class="w">${esc(m.policy)} / ${esc(m.statement)}</span>${m.conditions && m.conditions.length ? `<span class="cnd">${m.conditions.map(esc).join("<br>")}</span>` : ""}</div>`).join("") : "";
    return `<tr data-step="${key}" class="${s.skipped ? "skipped" : ""}"><td class="mono t-faint">${i + 1}</td><td class="fw5 td-nowrap">${name}</td><td><span class="${tone} fw5 td-nowrap">${s.label}</span></td>
      <td class="t-muted">${s.t ? esc(sentence(s.t.detail)) : s.skipped ? "Skipped: an earlier step decided." : "No policy of this type was supplied."}</td><td>${stm}</td></tr>`;
  }).join("");
  const warn = r.warnings && r.warnings.length ? `<div class="notice">${IC.warn}<div><b>Check these assumptions</b><ul>${r.warnings.map((w) => `<li>${esc(sentence(w))}</li>`).join("")}</ul></div></div>` : "";
  el.innerHTML = `<div class="verdict glass ${allowed ? "v-ok" : "v-crit"}"><span class="vb">${allowed ? IC.ok : IC.x}</span><div><h2>${allowed ? "Allowed" : "Denied"}</h2><p>${why}</p></div>
      <div class="vreq">${esc(short(req.principal))}<br>${esc(req.action)}<br>${esc(short(req.resource))}</div></div>${warn}
    <div class="glass ev-block"><div class="card-h"><h3>Evaluation path</h3><span class="sub">AWS checks these steps in order. Select one to see what it matched.</span></div><ol class="pipe" id="ev-pipe">${pipe}</ol></div>
    <div class="glass"><div class="card-h"><h3>Trace</h3></div><table><thead><tr><th>Step</th><th>Check</th><th>Result</th><th class="w28">Reason</th><th>Matching statements</th></tr></thead><tbody id="ev-trace">${rows}</tbody></table></div>`;
  const pick = (key) => {
    el.querySelectorAll(".ps").forEach((li) => li.classList.toggle("sel", li.dataset.step === key && !li.classList.contains("dec")));
    el.querySelectorAll("#ev-trace tr").forEach((tr) => tr.classList.toggle("sel", tr.dataset.step === key));
  };
  el.querySelectorAll(".ps:not(.dec)").forEach((li) => li.addEventListener("click", () => pick(li.dataset.step)));
  el.querySelectorAll("#ev-trace tr").forEach((tr) => tr.addEventListener("click", () => pick(tr.dataset.step)));
  pick(r.deciding_step);
}

// ------------------------------------------------------------------------------------- diff

function editorWith(ta, gut, text) {
  ta.value = text;
  const draw = () => { gut.textContent = Array.from({ length: ta.value.split("\n").length }, (_, i) => i + 1).join("\n"); };
  ta.addEventListener("input", draw);
  ta.addEventListener("scroll", () => { gut.scrollTop = ta.scrollTop; });
  draw();
  return draw;
}
const drawOld = editorWith($("d-old"), $("dg1"), JSON.stringify(DIFF_EXAMPLE.before, null, 2));
const drawNew = editorWith($("d-new"), $("dg2"), JSON.stringify(DIFF_EXAMPLE.after, null, 2));
$("d-swap").addEventListener("click", () => { const a = $("d-old").value; $("d-old").value = $("d-new").value; $("d-new").value = a; drawOld(); drawNew(); });
const KINDS = [["newly_allowed", "Newly allowed", "crit"], ["deny_removed", "Deny removed", "warn"], ["no_longer_allowed", "No longer allowed", "ok"], ["newly_denied", "Newly denied", "ok"]];
const LEVELS = ["Permissions management", "Write", "Tagging", "Read", "List", "Unknown"];
$("d-run").addEventListener("click", () => {
  const out = call("diff", $("d-old").value, $("d-new").value);
  const el = $("d-result");
  if (out.error) {
    el.innerHTML = `<div class="verdict glass v-warn"><span class="vb">${IC.warn}</span><div><h2>Could not compare</h2><p>${esc(sentence(out.error))}</p></div></div>`;
    return;
  }
  const d = out.result;
  const n = Object.fromEntries(KINDS.map(([k]) => [k, d.changes[k].length]));
  const sensitive = d.changes.newly_allowed.filter((e) => e.highlight);
  let v;
  if (d.unchanged) v = ["v-neutral", IC.ok, "No change", "Both versions allow and deny exactly the same requests."];
  else if (sensitive.length) v = ["v-crit", IC.warn, "Review required", `This change grants ${plural(sensitive.length, "sensitive action")}: permissions management or a step in a known escalation technique. ${n.newly_allowed} newly allowed in total.`];
  else if (n.newly_allowed || n.deny_removed) v = ["v-warn", IC.info, "Broadens access", `${n.newly_allowed} newly allowed and ${n.deny_removed} ${n.deny_removed === 1 ? "deny" : "denies"} removed. Nothing sensitive.`];
  else v = ["v-ok", IC.ok, "Narrows access", `${n.no_longer_allowed} no longer allowed and ${n.newly_denied} newly denied. Nothing new is granted.`];
  const kp = KINDS.map(([k, label, tone]) => `<div class="kpi glass ${n[k] ? `k-${tone}` : "k-plain"}"><div class="kh">${label}</div><div class="kv"><b>${n[k]}</b>${k === "newly_allowed" && sensitive.length ? `<span>${sensitive.length} sensitive</span>` : ""}</div></div>`).join("");
  const perLevel = LEVELS.map((lvl) => [lvl, KINDS.reduce((a, [k]) => a + d.changes[k].filter((e) => e.access_level === lvl).length, 0)]);
  const max = Math.max(1, ...perLevel.map(([, c]) => c));
  const bars = perLevel.map(([lvl, c]) => `<div class="row"><span class="name">${lvl}</span><span class="bn">${c}</span><div class="track"><i class="c-crit" data-w="${(c / max) * 100}"></i></div></div>`).join("");
  const rows = KINDS.filter(([k]) => n[k]).flatMap(([k, label, tone]) => [`<tr class="group-row g-${tone}"><td colspan="4">${label} (${n[k]})</td></tr>`,
    ...d.changes[k].map((e) => `<tr><td class="td-mono td-nowrap">${esc(e.action)}${e.highlight && k === "newly_allowed" ? `<span class="tag crit sens">Sensitive</span><span class="why-sens">${esc(sentence(e.highlight_reason))}</span>` : ""}</td><td>${esc(e.access_level)}</td>
      <td class="td-mono td-break">${e.resources.map(esc).join("<br>")}${e.principals && e.principals.length ? `<div class="t-muted">for ${e.principals.map(esc).join(", ")}</div>` : ""}</td><td class="td-mono">${e.conditions && Object.keys(e.conditions).length ? esc(JSON.stringify(e.conditions)) : '<span class="t-faint">None</span>'}</td></tr>`)]).join("");
  el.innerHTML = `<div class="verdict glass ${v[0]}"><span class="vb">${v[1]}</span><div><h2>${v[2]}</h2><p>${v[3]}</p></div></div>
    <div class="kpis">${kp}</div>${d.unchanged ? "" : `<div class="grid-2"><div class="glass"><div class="card-h"><h3>Every change</h3><span class="sub">Grouped by kind, then access level</span></div>
      <table><thead><tr><th>Action</th><th>Access level</th><th>Resources</th><th>Condition</th></tr></thead><tbody>${rows}</tbody></table></div>
      <div class="glass"><div class="card-h"><h3>By access level</h3></div><div class="card-b bars">${bars}</div></div></div>`}`;
  applyWidths(el);
});

// ------------------------------------------------------------------------------------- changelog

const CHANGES = [
  { v: "0.2.0", status: ["acc", "Latest"], date: "Unreleased", sum: "A new web app, the rename to iam-trace, and security hardening after a full review.", groups: [
    ["Added", ["A complete web app: an Overview dashboard with the verdict, metrics, paths to admin, recommended fixes and principals at risk.",
      "Full-screen attack graph with three node styles, a paths panel and a details panel for every principal and technique.",
      "Data input with file drop, validation, a searchable principal picker, organization SCPs and an optional blast-radius count.",
      "Findings with search, filters and downloads (text, SARIF, JSON); documentation and this changelog inside the app.",
      "Settings: light, dark or system mode; bold, restrained or brand-colour style; graph node style.",
      "<code class='c'>web_api.analyze_account</code>: one call returns the analysis from a starting principal, a summary of every principal, and supports SCPs."]],
    ["Changed", ["Renamed from IAM Lens to iam-trace. Install <code class='c'>iam-trace</code>, import <code class='c'>iamtrace</code>, catalog variable <code class='c'>IAMTRACE_CATALOG</code>.",
      "Escalation analysis skips techniques a principal cannot allow before evaluating them fully. Same results; 400 principals in 3 s instead of 24 s."]],
    ["Security", ["Wildcard matching runs in linear time. A crafted pattern could previously stall a CI job for minutes.",
      "Malformed input gives a clear error instead of crashing. Added a fuzz suite.",
      "The GitHub Action escapes text from pull requests before writing its comment.",
      "Workflows pin third-party actions to commit SHAs and pass inputs through environment variables.",
      "<code class='c'>catalog refresh</code> refuses to replace a directory holding anything but catalog files.",
      "The web app bundles its Python runtime, loads nothing from third parties, and allows neither eval nor inline styles."]],
    ["Fixed", ["The access-level check accepts actions listed under several levels. Against AWS's reference: 21,484 actions, 0 mismatches."]],
  ] },
  { v: "0.1.0", status: ["ok", "First version"], date: "November 2026", sum: "The engine, the command line, the GitHub Action and the first web page.", groups: [
    ["Added", ["<b>Evaluation engine</b> and <code class='c'>can</code>: identity, resource-based, boundary, session, SCP and RCP policies in AWS's order, every condition operator, policy variables, and a trace for every decision.",
      "<b>Action catalog</b> from AWS's machine-readable Service Authorization Reference, refreshed weekly; <code class='c'>expand</code> lists what a wildcard covers.",
      "<b>Semantic diff</b>: newly allowed, no longer allowed, newly denied and deny removed, grouped by access level, with sensitive actions marked.",
      "<b>Escalation analysis</b>: 92 techniques from pathfinding.cloud, multi-step paths to admin, blast radius and baselines.",
      "<b>GitHub Action</b> that reviews pull requests, and a <b>web page</b> running the same engine in the browser.",
      "Tests: the worked examples from AWS's documentation, hand-written cases for what the simulator cannot model, and a 228-case differential generator."]],
  ] },
];
const CT = { Added: "c-ok", Changed: "c-acc", Security: "c-crit", Fixed: "c-warn" };
function renderChangelog(filter) {
  $("timeline").innerHTML = CHANGES.map((r, i) => {
    const groups = r.groups.filter(([t]) => filter === "all" || t === filter);
    if (!groups.length) return "";
    return `<div class="rel glass ${i ? "muted-dot" : ""}"><div class="rel-h"><h2>${r.v}</h2><span class="tag ${r.status[0]}">${r.status[1]}</span><span class="date">${r.date}</span></div>
      <p class="rel-sum">${r.sum}</p>${groups.map(([t, items]) => `<div class="rel-group"><span class="ctype ${CT[t]}">${t}</span><ul>${items.map((x) => `<li>${x}</li>`).join("")}</ul></div>`).join("")}</div>`;
  }).join("");
}
document.querySelectorAll("#cl-filters .chipf").forEach((c) => c.addEventListener("click", () => {
  document.querySelectorAll("#cl-filters .chipf").forEach((x) => x.classList.toggle("on", x === c));
  renderChangelog(c.dataset.f);
}));

// ------------------------------------------------------------------------------------- docs

const docsView = $("v-docs");
function docTo(id) {
  const el = $(id);
  if (el) docsView.scrollTo({ top: el.offsetTop - 10, behavior: "smooth" });
}
document.querySelectorAll("#toc a, .dsec a[href^='#d-']").forEach((a) => a.addEventListener("click", (e) => { e.preventDefault(); docTo(a.getAttribute("href").slice(1)); }));
document.querySelectorAll(".qcard").forEach((q) => q.addEventListener("click", () => docTo(q.dataset.doc)));
docsView.addEventListener("scroll", () => {
  let cur = "d-start";
  document.querySelectorAll(".dsec").forEach((s) => { if (s.offsetTop - 80 <= docsView.scrollTop) cur = s.id; });
  document.querySelectorAll("#toc a").forEach((a) => a.classList.toggle("on", a.getAttribute("href") === "#" + cur));
});
document.querySelectorAll(".codeblock .copy").forEach((b) => b.addEventListener("click", () => copy(b.closest(".codeblock").querySelector("pre").innerText)));
document.querySelectorAll("[data-copy]").forEach((b) => b.addEventListener("click", () => copy(b.dataset.copy)));

// ------------------------------------------------------------------------------------- start

applyPrefs();
renderChangelog("all");
renderOverview();
renderFindings();
setSource("account");
loadEvExample(EVALUATE_EXAMPLES[0]);
go(location.hash.slice(1) || "overview");
whenReady(() => { validate(); updateRun(); });

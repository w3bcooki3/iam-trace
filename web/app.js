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
import { EVALUATE_EXAMPLES, DIFF_EXAMPLE, ATTACK_POLICY_EXAMPLE, CHECK_EXAMPLE } from "./examples.js";
import { store as dataStore } from "./store.js";
import { buildReport } from "./report.js";

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
  flag: '<svg class="i" viewBox="0 0 24 24"><path d="M5 21V4M5 4h11l-2 4 2 4H5"/></svg>',
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
  overview: ["Attack paths", "Overview"], graph: ["Attack paths", "Attack graph"], findings: ["Attack paths", "Findings"], whocan: ["Attack paths", "Who can"],
  input: ["Attack paths", "Data input"], check: ["Tools", "Policy check"], evaluate: ["Tools", "Evaluate a request"], diff: ["Tools", "Policy diff"],
  docs: ["Help", "Documentation"], changelog: ["Help", "Changelog"], settings: ["App", "Settings"],
};
let currentView = null;
function go(path) {
  const [base, ...sub] = String(path || "").split("/");
  let view = base;
  if (!VIEWS[view]) view = "overview";
  const changed = view !== currentView;
  currentView = view;
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("on", v.id === "v-" + view));
  // A screen opens at its top, the way a new page would.
  if (changed) $("v-" + view).scrollTop = 0;
  closeSheet(false);
  if (view === "settings") renderSaved();
  if (view === "whocan") wcState();
  if (view === "docs") showDoc(sub[0], sub[1]);
  document.querySelectorAll(".nav-item[data-go]").forEach((n) => n.classList.toggle("on", n.dataset.go === view));
  $("crumb-group").textContent = VIEWS[view][0];
  $("crumb-view").textContent = VIEWS[view][1];
  // Docs keep their topic in the address; other screens are just their name.
  const address = view === "docs" && sub.length ? [view, ...sub].join("/") : view;
  if (location.hash !== "#" + address) history.replaceState(null, "", "#" + address);
  root.classList.remove("nav-open");
  requestAnimationFrame(() => graphs.forEach((g) => g.fit()));
}
document.addEventListener("click", (e) => {
  const b = e.target.closest("[data-go]");
  if (b) go(b.dataset.go);
});
window.addEventListener("hashchange", () => go(location.hash.slice(1)));

// ------------------------------------------------------------------------------------- result sheet

// Results of Policy diff and Policy check open over the whole work area, so the editors keep
// all the space while you write and the result gets all of it while you read.
let sheetReturn = null;
function openSheet(title, body, actions = "") {
  const sheet = $("sheet");
  $("sheet-title").textContent = title;
  $("sheet-body").innerHTML = body;
  $("sheet-actions").innerHTML = actions;
  sheet.querySelector(".sheet-b").scrollTop = 0;
  if (sheet.hidden) {
    sheetReturn = document.activeElement;
    sheet.hidden = false;
    sheet.classList.remove("open");
    void sheet.offsetWidth; // start the transition from the closed state
    sheet.classList.add("open");
  }
  $("sheet-title").focus({ preventScroll: true });
  applyWidths(sheet);
}
function closeSheet(restoreFocus = true) {
  const sheet = $("sheet");
  if (sheet.hidden) return;
  sheet.classList.remove("open");
  sheet.hidden = true;
  if (restoreFocus && sheetReturn && document.contains(sheetReturn)) sheetReturn.focus();
  sheetReturn = null;
}
$("sheet-back").addEventListener("click", () => closeSheet());
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("sheet").hidden) closeSheet(); });

// ------------------------------------------------------------------------------------- engine

let api = null;
let hasCatalog = false;
let engineVersion = "";

// "Report a wrong answer": a pre-filled GitHub issue the user reviews before submitting. Policies
// are never included, and 12-digit account IDs become AWS's documentation example 111122223333.
const ISSUES = "https://github.com/w3bcooki3/iam-trace/issues/new";
const scrub = (s) => String(s ?? "").replace(/\b\d{12}\b/g, "111122223333");
function reportUrl(fields) {
  const q = new URLSearchParams({ template: "wrong_answer.yml", version: engineVersion });
  for (const [k, v] of Object.entries(fields)) q.set(k, scrub(v));
  return `${ISSUES}?${q.toString()}`;
}
function reportLink(fields, label = "Report a wrong answer") {
  return `<a class="report-link" href="${esc(reportUrl(fields))}" target="_blank" rel="noopener noreferrer" title="Opens a pre-filled GitHub issue you can edit before submitting. Policies are not included; account IDs are replaced with 111122223333.">${IC.flag}${label}</a>`;
}
const ready = [];

// The top bar says nothing once the engine is ready; it only speaks while starting or on failure.
function engineStatus(state, text = "") {
  const el = $("engine-status");
  el.dataset.state = state;
  el.textContent = text;
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
  engineVersion = String(pyodide.pyimport("iamtrace").__version__);
  const summary = JSON.parse(api.catalog_summary());
  hasCatalog = Boolean(summary);
  engineStatus("ready");
  $("about-catalog").textContent = hasCatalog ? `${summary.actions.toLocaleString()} actions in ${summary.services} services` : "Not included in this build";
  $("ev-run").disabled = false;
  $("d-run").disabled = !hasCatalog;
  $("pc-run").disabled = !hasCatalog;
  if (!hasCatalog) $("pc-note").textContent = "Policy check needs the action catalog, which this build of the site does not include.";
  $("d-note").textContent = hasCatalog ? `Compares using the action catalog: ${summary.actions.toLocaleString()} actions in ${summary.services} services.` : "Diff needs the action catalog, which this build of the site does not include.";
  $("opt-blast").disabled = !hasCatalog;
  ready.splice(0).forEach((f) => f());
}
function whenReady(f) {
  if (api) f();
  else ready.push(f);
}
boot().catch((e) => {
  engineStatus("error", "The analysis engine could not start. Reload the page to try again.");
  overlay("");
  console.error(e);
  toast("The analysis engine could not start. Reload the page to try again.");
});

// ------------------------------------------------------------------------------------- data input

const input = { src: "account", account: "", policy: "", scp: "", inv: "", file: null, start: "", principals: [], example: false, accountValid: false };
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
  inv: ["Drop the resource inventory here", "From iam-trace inventory collect. It lets techniques that abuse existing functions and instances be confirmed or ruled out.", "inventory.json"],
};
// Kinds the inventory can describe, as people say them (mirrors iamtrace.inventory.KINDS).
const INV_KINDS = {
  "lambda-function": "Lambda functions", "ec2-instance": "EC2 instances", "codebuild-project": "CodeBuild projects",
  "cloudformation-stack": "CloudFormation stacks", "glue-dev-endpoint": "Glue dev endpoints", "sagemaker-notebook": "SageMaker notebooks",
  "state-machine": "Step Functions state machines", "apprunner-service": "App Runner services",
};
function setSource(src) {
  input.src = src;
  document.querySelectorAll(".src").forEach((b) => b.classList.toggle("on", b.dataset.src === src));
  const [t, s, f] = SRC_TEXT[src];
  $("dz-title").textContent = t;
  $("dz-sub").textContent = s;
  $("ed-name").textContent = src === "account" && input.file ? input.file.name : f;
  $("pick-card").hidden = src !== "account";
  $("get-export").hidden = src === "inv";
  $("get-inventory").hidden = src !== "inv";
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
  else if (input.src === "inv") {
    const r = await fetch("examples/inventory.json");
    input.inv = r.ok ? await r.text() : "";
    if (!input.account.trim()) await loadExampleAccount();
  } else input.scp = JSON.stringify([{ Version: "2012-10-17", Statement: [{ Sid: "AllowAll", Effect: "Allow", Action: "*", Resource: "*" }] },
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
  persist(input.src);
  const text = input[input.src].trim();
  const box = $("validation");
  if (input.src === "account") input.accountValid = false;
  const tag = $("val-tag");
  lastValid = null;
  const set = (cls, label) => { tag.className = `tag ${cls}`; tag.textContent = label; };
  if (!text) {
    set("plain", "Waiting");
    const empty = {
      scp: "Optional. Leave empty if the account is not in AWS Organizations.",
      inv: "Optional. Without it, techniques that abuse existing functions, instances and similar resources are reported as possible.",
    };
    box.innerHTML = `<p class="muted">${empty[input.src] || "Nothing loaded yet. Drop a file, paste JSON, or press Load example."}</p>`;
    if (input.src === "account") renderPicker([]);
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
    if (input.inv.trim()) checks.push(`<div class="check ok">${IC.ok}<div>Resource inventory will be used<small>From the Resource inventory tab</small></div></div>`);
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
  } else if (input.src === "inv") {
    const resources = Array.isArray(data?.Resources) ? data.Resources : null;
    if (!data || typeof data !== "object" || Array.isArray(data) || !resources) {
      set("crit", "Not an inventory");
      box.innerHTML = `<div class="check bad">${IC.x}<div>This is not a resource inventory<small>Expected the output of iam-trace inventory collect, with Collected and Resources.</small></div></div>`;
    } else {
      const collected = (data.Collected || []).filter((k) => INV_KINDS[k]);
      const errors = Array.isArray(data.Errors) ? data.Errors.length : 0;
      set(errors ? "warn" : "ok", "Ready");
      box.innerHTML = `<div class="check ok">${IC.ok}<div>${plural(resources.length, "resource")}${data.Account ? ` in account ${esc(data.Account)}` : ""}${data.Regions ? `, ${plural(data.Regions.length, "region")}` : ""}</div></div>
        <div class="check ${collected.length ? "ok" : "warn"}">${collected.length ? IC.ok : IC.warn}<div>${collected.length ? `Complete for ${collected.map((k) => INV_KINDS[k]).join(", ")}` : "No kind was collected completely"}<small>Kinds not listed stay possible in the analysis.</small></div></div>
        ${errors ? `<div class="check warn">${IC.warn}<div>${plural(errors, "call")} failed during collection<small>Those kinds are treated as unknown, not empty.</small></div></div>` : ""}
        <div class="check ok">${IC.info}<div>Used the next time you run an account analysis</div></div>`;
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
  $("pick").querySelectorAll(".pick-item").forEach((b) => b.addEventListener("click", () => { input.start = b.dataset.arn; renderPicker(list); updateRun(); persist("account"); }));
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
  const pcAcc = $("pc-account");
  pcAcc.disabled = !(input.account.trim() && input.accountValid);
  pcAcc.title = pcAcc.disabled ? "Load an account export in Data input first" : "Check every policy in the account export loaded in Data input";
  if (currentView === "whocan") wcState();
}

$("run").addEventListener("click", runAnalysis);
let lastRun = null; // { src, blast } of the last successful analysis, saved so a refresh re-runs it
async function runAnalysis({ restoring = false, src = input.src } = {}) {
  if (!api) return;
  overlay(restoring ? "Restoring your last analysis" : src === "policy" ? "Checking the policy" : "Analysing the account");
  await nextFrame();
  try {
    if (src === "policy") {
      const out = call("escalate", input.policy);
      if (out.error) throw new Error(out.error);
      setModel(fromPolicy(out));
    } else {
      const out = call("analyze_account", input.account, input.start, input.scp, $("opt-blast").checked, input.inv);
      if (out.error) throw new Error(out.error);
      setModel(fromAccount(out));
    }
    lastRun = { src: src === "policy" ? "policy" : "account", blast: $("opt-blast").checked };
    persist("analysis");
    if (!restoring) go("overview");
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
    resources: out.resources,
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
  whatIf.clear(); // a new analysis starts with nothing cut
  main.cut = whatIf;
  if ($("whatif-bar")) $("whatif-bar").hidden = true;
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

// A path as a vertical list of steps: principal, the technique that leads on, the next principal.
function stepsHtml(path) {
  const rows = [`<li class="sv-node mono">${esc(short(path.start))}</li>`];
  for (const s of path.steps) {
    rows.push(`<li class="sv-edge"><span class="mono">${esc(s.technique)}</span> ${esc(s.name || "")}</li>`);
    rows.push(`<li class="sv-node mono">${esc(short(s.to))}</li>`);
  }
  return `<ol class="steps-v">${rows.join("")}</ol>`;
}
function pathItem(p, i, meta = "") {
  return `<button class="path-item" data-path="${i}" aria-pressed="false"><span class="ph"><b>${esc(nameOf(p.start))} to ${esc(nameOf(p.end))}</b><span class="tag crit">${plural(p.steps.length, "step")}</span></span>${stepsHtml(p)}${meta ? `<span class="pmeta">${meta}</span>` : ""}</button>`;
}
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
    ? startPaths.slice(0, 6).map((p) => pathItem(p, m.report.paths.indexOf(p), esc(sentence(p.why)))).join("")
    : `<p class="list-empty">No path to admin from ${who}.${possible.length ? " Possible techniques are listed in Findings." : ""}</p>`;

  const fixHtml = fixes.length
    ? fixes.map((f, i) => `<div class="fix"><span class="num">${i + 1}</span><span class="t">Narrow <span class="mono">${esc(f.permissions.join(", "))}</span> for ${esc(short(f.from))}</span><span class="tag crit imp">${plural(f.paths, "path")}</span><button class="btn sim" data-sim="${i}" title="Cut this step on the attack graph and see what is left">Simulate</button>
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
    <div class="page-head"><div><h1>Overview</h1><p>Analysed <span class="mono">${esc(m.source)}</span> from <span class="mono">${who}</span> against 92 privilege-escalation techniques from pathfinding.cloud${m.scps ? `, with ${plural(m.scps, "SCP")} applied` : ""}${m.resources ? `, using a resource inventory of ${plural(Object.values(m.resources).reduce((a, b) => a + b, 0), "resource")}` : ""}.</p></div>
      <div class="actions"><button class="btn" data-go="input">Change input</button><button class="btn" data-report>Download report</button><button class="btn primary" data-go="graph">Open attack graph</button></div></div>
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
  // Simulate a fix: cut that step on the attack graph and show what is left.
  el.querySelectorAll("[data-sim]").forEach((b) => b.addEventListener("click", () => {
    const f = fixes[Number(b.dataset.sim)];
    const keys = m.graph.edges.filter((e) => e.from === f.from && (e.label === f.technique || String(e.name).split(/,\s*/).includes(f.technique))).map((e) => cutKey(e.from, e.to));
    if (!keys.length) return toast(`That step is not on the attack graph from ${nameOf(m.start)}.`);
    whatIf.clear();
    go("graph");
    setCut(keys, true);
  }));
  $("preview").addEventListener("click", () => go("graph"));
  if (graphs.includes(preview)) graphs.splice(graphs.indexOf(preview), 1);
  preview = new Graph($("psurface"), $("pworld"), { interactive: false, pad: 24, maxScale: 0.85, markerPrefix: "p" });
  graphs.push(preview);
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
    <td data-label="Status">${status}</td><td data-label="Shortest path to admin">${p.admin_equivalent ? '<span class="t-faint">Is admin</span>' : p.path ? `${plural(p.path.steps.length, "step")}: <span class="mono">${p.path.steps.map((s) => esc(s.technique)).join(", ")}</span>` : '<span class="t-faint">None</span>'}</td>
    <td data-label="Confirmed">${p.confirmed}</td><td data-label="Possible">${p.possible}</td><td data-label="Policies">${p.policies ?? "-"}</td></tr>`;
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
  insets: () => ({ l: 0, r: 0, t: 56, b: 56 }),
  onSelect: (n) => showNode(n),
  onEdge: (e, el) => showEdge(e, el),
});
let preview = null;
const graphs = [main];

function renderGraphView() {
  if (!model) {
    main.setData(null);
    $("g-summary").className = "";
    $("g-summary").textContent = "No analysis yet. Load an account export in Data input, or try the example account from the Overview.";
    $("g-paths").innerHTML = "";
    return;
  }
  const m = model;
  main.setData(graphData(m));
  const startPaths = m.report.paths.map((p, i) => [p, i]).filter(([p]) => p.start === m.start);
  const shortest = startPaths.length ? Math.min(...startPaths.map(([p]) => p.steps.length)) : 0;
  const sum = $("g-summary");
  sum.className = startPaths.length ? "risk" : "safe";
  sum.innerHTML = startPaths.length
    ? `<b>${plural(startPaths.length, "path")}</b> from ${esc(short(m.start))}, the shortest in ${plural(shortest, "step")}. Select one to show only that path.`
    : `<b>No path</b> from ${esc(short(m.start))}. Possible techniques, if any, are drawn as dashed lines.`;
  $("g-paths").innerHTML = startPaths.map(([p, i]) => pathItem(p, i)).join("");
  $("g-paths").querySelectorAll(".path-item").forEach((el) => el.addEventListener("click", () => focusPath(Number(el.dataset.path))));
  setPathsPanel(window.innerWidth >= 860);
  closeDetails();
}
function focusPath(i) {
  main.focus = main.focus === i ? null : i;
  main.render();
  $("g-paths").querySelectorAll(".path-item").forEach((el) => {
    const on = Number(el.dataset.path) === main.focus;
    el.classList.toggle("on", on);
    el.setAttribute("aria-pressed", String(on));
  });
  if (window.innerWidth < 860) setPathsPanel(false); // on phones, get out of the way of the graph
}
$("f-poss").addEventListener("change", (e) => { main.hidePossible = !e.target.checked; main.render(); });
$("z-in").addEventListener("click", () => main.zoom(1.2));
$("z-out").addEventListener("click", () => main.zoom(1 / 1.2));
$("z-fit").addEventListener("click", () => main.fit());
// The panel is a column beside the graph on wide screens and slides over it on phones.
function setPathsPanel(open) {
  $("gview").classList.toggle("paths-closed", !open);
  $("g-paths-panel").setAttribute("aria-hidden", String(!open));
  if (open && window.innerWidth >= 860) setTimeout(() => main.fit(), 260); // after the column animates
}
$("g-hide-paths").addEventListener("click", () => { setPathsPanel(false); $("g-show-paths").focus(); });
$("g-show-paths").addEventListener("click", () => setPathsPanel(true));
// The report: one HTML file for people who will never open iam-trace. It prints cleanly to PDF.
function downloadReport() {
  if (!model) return toast("Run an analysis first");
  const html = buildReport(model, { version: engineVersion, fixes: recommendedFixes(model) });
  const acct = (model.principals[0]?.arn || "").split(":")[4] || "account";
  const day = new Date().toISOString().slice(0, 10);
  download(`iam-trace-report-${acct}-${day}.html`, html, "text/html");
  toast("Report downloaded. Open it in a browser; print it to save a PDF.");
}
$("g-export").addEventListener("click", downloadReport);
document.addEventListener("click", (e) => { if (e.target.closest("[data-report]")) downloadReport(); });
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
    <div class="nm">${esc(t.name)}</div><div class="why">Leads to ${t.targets.map((x) => esc(short(x))).join(", ")}${t.via ? `, through ${t.via.map((x) => `<span class="mono">${esc(short(x))}</span>`).join(", ")}` : ""}.${src.author ? ` First documented by ${src.first_documented ? `<a href="${esc(src.first_documented)}" target="_blank" rel="noopener">${esc(src.author)}</a>` : esc(src.author)}.` : ""}</div></div>`;
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
// ------------------------------------------------------------------------------------- what-if on the graph

// Cut a step and see whether the attacker still reaches admin. The search runs over every confirmed
// step that is left, so a longer route the shortest path was hiding is found, not missed.
const whatIf = new Set();
const cutKey = (from, to) => `${from}|${to}`;
// Every confirmed step between principals in the analysis. The drawn graph shows only the steps on
// the shortest paths, so searching it alone could miss a longer route and give a false all-clear.
function allSteps(m) {
  const out = [];
  for (const p of m.report.principals) {
    for (const t of p.techniques) {
      if (t.confidence !== "confirmed") continue;
      for (const to of t.targets) if (to !== p.arn && String(to).startsWith("arn:")) out.push({ from: p.arn, to, label: t.id, name: t.name });
    }
  }
  return out;
}
function routeToAdmin(m, cut) {
  const admin = new Set(m.report.principals.filter((p) => p.admin_equivalent).map((p) => p.arn));
  if (admin.has(m.start)) return [];
  const edges = allSteps(m).filter((e) => !cut.has(cutKey(e.from, e.to)));
  const prev = new Map([[m.start, null]]);
  const queue = [m.start];
  while (queue.length) {
    const cur = queue.shift();
    for (const e of edges) {
      if (e.from !== cur || prev.has(e.to)) continue;
      prev.set(e.to, e);
      if (admin.has(e.to)) {
        const route = [];
        for (let x = e; x; x = prev.get(x.from)) route.unshift(x);
        return route;
      }
      queue.push(e.to);
    }
  }
  return null;
}
// A route the graph does not show yet is added to it, so it can be seen and cut too.
function showOnGraph(route) {
  const d = main.data;
  if (!d) return;
  let added = false;
  for (const e of route) {
    for (const id of [e.from, e.to]) {
      if (d.nodes.some((n) => n.id === id)) continue;
      const p = model.report.principals.find((x) => x.arn === id);
      d.nodes.push({ id, label: nameOf(id), subtitle: short(id), kind: kindOf(id), start: false, admin: Boolean(p?.admin_equivalent), techniques: p ? p.techniques.length : 0, policies: model.principals.find((x) => x.arn === id)?.policies ?? null, paths: new Set() });
      added = true;
    }
    if (!d.edges.some((x) => x.from === e.from && x.to === e.to)) {
      d.edges.push({ from: e.from, to: e.to, label: e.label, name: e.name, confidence: "confirmed", paths: new Set() });
      added = true;
    }
  }
  if (added) main.render();
}
function setCut(keys, on) {
  for (const k of keys) { if (on) whatIf.add(k); else whatIf.delete(k); }
  main.cut = whatIf;
  main.render();
  updateWhatIf();
}
function updateWhatIf() {
  const bar = $("whatif-bar");
  if (!model || !whatIf.size) { bar.hidden = true; return; }
  const before = routeToAdmin(model, new Set());
  const after = routeToAdmin(model, whatIf);
  const who = esc(short(model.start));
  const routeText = (r) => r.filter((e) => e.to !== "admin").map((e) => `${esc(e.label)} to ${esc(nameOf(e.to))}`).join(", then ");
  let msg;
  if (!before) msg = `<b>No path to admin</b> from ${who}, with or without these changes.`;
  else if (!after) msg = `<b class="safe">No path to admin</b> from ${who} after cutting ${plural(whatIf.size, "step")}.`;
  else if (after.length !== before.length || after.some((e, i) => cutKey(e.from, e.to) !== cutKey(before[i].from, before[i].to))) {
    msg = `<b class="risk">Still reaches admin</b> by another route: ${routeText(after)}. It is now on the graph; cut a step on it too.`;
    showOnGraph(after);
  }
  else msg = `<b class="risk">Still reaches admin</b> the same way. Cut a step on the highlighted path.`;
  bar.innerHTML = `<span>What-if: ${msg}</span><button class="btn" id="whatif-reset">Reset</button>`;
  bar.hidden = false;
  $("whatif-reset").addEventListener("click", () => { whatIf.clear(); setCut([], false); if (!$("g-details").classList.contains("closed")) closeDetails(); });
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
    ${techs.length ? `<div class="d-sec"><h4>Permissions involved</h4>${[...new Set(techs.flatMap((t) => t.permissions))].map((x) => `<div class="policy-line"><span class="mono">${esc(x)}</span></div>`).join("")}</div>` : ""}
    ${e.confidence !== "possible" && e.to !== "admin" ? `<div class="d-sec d-cut"><h4>What if</h4><p>Pretend this step is not allowed and see whether ${esc(nameOf(m.start))} still reaches admin. Nothing in AWS changes.</p>
      <button class="btn" id="d-cut">${whatIf.has(cutKey(e.from, e.to)) ? "Restore this step" : "Cut this step"}</button></div>` : ""}
    <div class="d-sec">${reportLink({ title: `Wrong finding: ${e.label}`, request: `${e.from} -> ${e.to} via ${e.label}`, iamtrace: `${e.confidence} technique ${e.label} (${e.name})` }, "Report a wrong finding")}</div>`;
  $("g-details").classList.remove("closed");
  $("d-close").addEventListener("click", closeDetails);
  $("d-cut")?.addEventListener("click", () => {
    const k = cutKey(e.from, e.to);
    setCut([k], !whatIf.has(k));
    $("d-cut").textContent = whatIf.has(k) ? "Restore this step" : "Cut this step";
  });
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
    body.innerHTML = `<div class="ptable-wrap"><table class="mtable"><thead><tr><th>Principal</th><th>Status</th><th>Shortest path to admin</th><th>Confirmed</th><th>Possible</th><th>Policies</th></tr></thead><tbody>${list.slice(0, findState.limit).map(principalRow).join("")}</tbody></table></div>`;
    $("find-count").textContent = plural(list.length, "principal");
  } else {
    const list = rows.filter((r) => (findState.filter === "all" || r.t.confidence === findState.filter) &&
      (!q || r.p.arn.toLowerCase().includes(q) || r.t.id.includes(q) || r.t.name.toLowerCase().includes(q) || r.t.permissions.some((x) => x.toLowerCase().includes(q))))
      .sort((a, b) => (a.t.confidence === "confirmed" ? 0 : 1) - (b.t.confidence === "confirmed" ? 0 : 1) || a.p.arn.localeCompare(b.p.arn));
    const k = (arn) => kindOf(arn);
    body.innerHTML = list.length
      ? `<div class="ptable-wrap"><table class="mtable"><thead><tr><th>Confidence</th><th>Technique</th><th>Principal</th><th>Leads to</th><th>Permissions</th><th>Reference</th></tr></thead><tbody>${list.slice(0, findState.limit).map(({ p, t }) => `<tr>
          <td><span class="sev ${t.confidence === "confirmed" ? "c-crit" : "c-warn"}"><i></i>${t.confidence === "confirmed" ? "Confirmed" : "Possible"}</span></td>
          <td data-label="Technique"><b class="mono">${esc(t.id)}</b><div class="cat-note">${esc(CATEGORY[t.category] || t.category)}</div></td>
          <td><div class="who" data-kind="${k(p.arn)}"><span class="wi">${ICON[k(p.arn)] || ICON.resource}</span><div><b>${esc(nameOf(p.arn))}</b><small>${esc(short(p.arn))}</small></div></div></td>
          <td class="td-mono" data-label="Leads to">${t.targets.map((x) => esc(short(x))).join("<br>")}${t.via ? `<div class="t-muted">through ${t.via.map((x) => esc(short(x))).join(", ")}</div>` : ""}</td>
          <td class="td-mono" data-label="Permissions">${t.permissions.map(esc).join("<br>")}</td>
          <td data-label="Reference"><a href="${esc(t.source?.pathfinding || "#")}" target="_blank" rel="noopener">pathfinding.cloud</a></td></tr>`).join("")}</tbody></table></div>`
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
$("ev-clear").addEventListener("click", () => { for (const [k] of POLICY_TYPES) evPolicies[k] = ""; evOpen.clear(); renderEvPolicies(); edited.evaluate = true; persist("evaluate"); });
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
  const decisionText = `${r.decision} (decided at step: ${r.deciding_step})`;
  const report = reportLink({ title: `Wrong answer: ${req.action}`, request: `${req.principal}  ${req.action}  ${req.resource}`, iamtrace: decisionText });
  el.innerHTML = `<div class="verdict glass ${allowed ? "v-ok" : "v-crit"}"><span class="vb">${allowed ? IC.ok : IC.x}</span><div class="vtext"><h2>${allowed ? "Allowed" : "Denied"}</h2><p>${why}</p>
      <div class="vreq">${[req.principal, req.action, req.resource].map((v, i) => `<code title="${esc(v)}">${esc(i === 1 ? v : short(v))}</code>`).join("")}</div></div></div>${warn}
    <div class="report-row">Does AWS disagree? ${report}</div>
    ${whatIfHtml(out.what_if)}
    <div class="glass ev-block"><div class="card-h"><h3>Evaluation path</h3><span class="sub">AWS checks these steps in order. Select one to see what it matched.</span></div><ol class="pipe" id="ev-pipe">${pipe}</ol></div>
    <div class="glass"><div class="card-h"><h3>Trace</h3></div><table><thead><tr><th>Step</th><th>Check</th><th>Result</th><th class="w28">Reason</th><th>Matching statements</th></tr></thead><tbody id="ev-trace">${rows}</tbody></table></div>`;
  const pick = (key) => {
    el.querySelectorAll(".ps").forEach((li) => li.classList.toggle("sel", li.dataset.step === key && !li.classList.contains("dec")));
    el.querySelectorAll("#ev-trace tr").forEach((tr) => tr.classList.toggle("sel", tr.dataset.step === key));
  };
  el.querySelectorAll(".ps:not(.dec)").forEach((li) => li.addEventListener("click", () => pick(li.dataset.step)));
  el.querySelectorAll("#ev-trace tr").forEach((tr) => tr.addEventListener("click", () => pick(tr.dataset.step)));
  el.querySelectorAll("[data-apply]").forEach((b) => b.addEventListener("click", () => applyFix(out.what_if.fixes[Number(b.dataset.apply)])));
  pick(r.deciding_step);
}

// ------------------------------------------------------------------------------------- what would change this

// The engine changes one thing at a time and evaluates again; every fix shown has been checked.
function whatIfHtml(w) {
  if (!w) return "";
  const fix = (f, i) => {
    const adds = (f.add || []).map((a) => `<div class="wif-add"><span>Add to ${esc(a.where)}</span><pre class="code">${esc(JSON.stringify(a.statement, null, 2))}</pre></div>`).join("");
    const removes = (f.statements || []).map((s) => `<li class="mono">${esc(s.policy)} / ${esc(s.statement)}</li>`).join("");
    return `<div class="wif"><div class="wif-h"><b>${esc(f.title)}</b>${f.verified ? '<span class="tag ok">Checked</span>' : '<span class="tag warn">Not enough alone</span>'}
        <button class="btn" data-apply="${i}">Try this change</button></div>
      <p>${esc(f.detail)}</p>${removes ? `<ul class="wif-rm">${removes}</ul>` : ""}${adds}</div>`;
  };
  const dep = (d) => `<li><b class="${d.kind === "context" ? "mono" : ""}">${esc(d.title)}</b><span>${esc(d.detail)}</span></li>`;
  const miss = (m) => `<li><b class="mono">${esc(m.policy)} / ${esc(m.statement)}</b><span>Names the action, but ${esc(m.reason)}.</span></li>`;
  const body = [
    w.fixes.length ? `<div class="wif-list">${w.fixes.map(fix).join("")}</div>` : "",
    w.depends_on.length ? `<h4>${w.decision === "Allow" ? "The decision depends on" : "Also relevant"}</h4><ul class="wif-deps">${w.depends_on.map(dep).join("")}</ul>` : "",
    w.near_misses.length ? `<h4>Near misses</h4><ul class="wif-deps">${w.near_misses.map(miss).join("")}</ul>` : "",
  ].join("");
  return `<div class="glass ev-block whatif"><div class="card-h"><h3>What would change this</h3><span class="sub">${esc(w.summary)}</span></div>
    ${body ? `<div class="card-b">${body}</div>` : ""}</div>`;
}

// "Try this change" edits the request or the policies the way a person would, then evaluates again.
const POLICY_KEY = { identity_policy: "identity", resource_policy: "resource_policy", permissions_boundary: "boundary", session_policy: "session", scp: "scp", rcp: "rcp" };
const ID_KEY = [["identity policy", "identity"], ["resource policy", "resource_policy"], ["boundary", "boundary"], ["session policy", "session"], ["SCP", "scp"], ["RCP", "rcp"]];
function policyDoc(key) {
  try {
    const d = JSON.parse(evPolicies[key] || "");
    if (d && typeof d === "object") {
      if (!Array.isArray(d.Statement)) d.Statement = d.Statement ? [d.Statement] : [];
      return d;
    }
  } catch { /* an empty or broken box starts a new document */ }
  return { Version: "2012-10-17", Statement: [] };
}
function applyFix(f) {
  if (f.context) {
    const lines = $("ev-context").value.split("\n").filter((l) => l.trim());
    for (const [k, v] of Object.entries(f.context)) {
      const rest = lines.filter((l) => l.split("=")[0].trim().toLowerCase() !== k.toLowerCase());
      lines.length = 0;
      lines.push(...rest, ...(v === null ? [] : [`${k}=${v}`]));
    }
    $("ev-context").value = lines.join("\n");
  }
  for (const s of f.statements || []) {
    const key = (ID_KEY.find(([prefix]) => s.policy.startsWith(prefix)) || [])[1];
    if (!key) continue;
    const d = policyDoc(key);
    const m = /^Statement\[(\d+)\]$/.exec(s.statement);
    d.Statement = d.Statement.filter((st, i) => (m ? i !== Number(m[1]) : st.Sid !== s.statement));
    evPolicies[key] = JSON.stringify(d, null, 2);
  }
  for (const a of f.add || []) {
    const key = POLICY_KEY[a.layer];
    if (!key) continue;
    const d = policyDoc(key);
    d.Statement.push(a.statement);
    evPolicies[key] = JSON.stringify(d, null, 2);
  }
  renderEvPolicies();
  edited.evaluate = true;
  persist("evaluate");
  $("ev-run").click();
  toast("Change applied and evaluated again");
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
  if (out.error) {
    openSheet("Could not compare", `<div class="verdict glass v-warn"><span class="vb">${IC.warn}</span><div><h2>Could not compare</h2><p>${esc(sentence(out.error))}</p></div></div>`);
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
  openSheet("Policy diff", `<div class="verdict glass ${v[0]}"><span class="vb">${v[1]}</span><div><h2>${v[2]}</h2><p>${v[3]}</p></div></div>
    <div class="kpis">${kp}</div>${d.unchanged ? "" : `<div class="grid-2"><div class="glass"><div class="card-h"><h3>Every change</h3><span class="sub">Grouped by kind, then access level</span></div>
      <div class="table-scroll"><table class="rtable"><thead><tr><th>Action</th><th>Access level</th><th>Resources</th><th>Condition</th></tr></thead><tbody>${rows}</tbody></table></div></div>
      <div class="glass"><div class="card-h"><h3>By access level</h3></div><div class="card-b bars">${bars}</div></div></div>`}`);
});

// ------------------------------------------------------------------------------------- who can

// Uses the account export (and SCPs and inventory) from Data input. Each principal is evaluated
// with the same engine as Evaluate; escalation paths come from the attack-path analysis.
const WC_EXAMPLES = [
  ["s3:PutObject", "arn:aws:s3:::example-reports/out.csv"],
  ["iam:PassRole", "arn:aws:iam::111122223333:role/ec2-admin"],
  ["lambda:UpdateFunctionCode", "arn:aws:lambda:us-east-1:111122223333:function:nightly-report"],
];
function wcState() {
  const ready = Boolean(api && input.account.trim() && input.accountValid);
  $("wc-run").disabled = !ready || !$("wc-action").value.trim();
  $("wc-try").innerHTML = input.example
    ? `<span>Try:</span>${WC_EXAMPLES.map(([a, r], i) => `<button class="chipf" data-wc="${i}">${esc(a)} on ${esc(short(r))}</button>`).join("")}`
    : "";
  $("wc-try").querySelectorAll("[data-wc]").forEach((b) => b.addEventListener("click", () => {
    const [a, r] = WC_EXAMPLES[Number(b.dataset.wc)];
    $("wc-action").value = a;
    $("wc-resource").value = r;
    persist("whocan");
    runWhoCan();
  }));
  if (!ready && !$("wc-result").innerHTML.includes("wc-sum")) {
    $("wc-result").innerHTML = `<div class="glass empty-state"><span class="es-ic">${IC.info}</span><h2>Load an account first</h2>
      <p>Who can answers for every user and role in an account export. Load yours in Data input, or open the example account from the Overview.</p>
      <div class="es-actions"><button class="btn primary" data-go="input">Open Data input</button></div></div>`;
    bindGo($("wc-result"));
  } else if (ready && !$("wc-result").innerHTML.includes("wc-sum")) {
    $("wc-result").innerHTML = "";
  }
}
function bindGo(root) {
  root.querySelectorAll("[data-go]").forEach((b) => b.addEventListener("click", () => go(b.dataset.go)));
}
["wc-action", "wc-resource", "wc-policy", "wc-context"].forEach((id) => $(id).addEventListener("input", () => { wcState(); persist("whocan"); }));
$("wc-action").addEventListener("keydown", (e) => { if (e.key === "Enter" && !$("wc-run").disabled) runWhoCan(); });
$("wc-resource").addEventListener("keydown", (e) => { if (e.key === "Enter" && !$("wc-run").disabled) runWhoCan(); });
$("wc-run").addEventListener("click", runWhoCan);
const whoCell = (arn) => {
  const k = kindOf(arn);
  return `<div class="who" data-kind="${k}"><span class="wi">${ICON[k] || ICON.resource}</span><div><b>${esc(nameOf(arn))}</b><small>${esc(short(arn))}</small></div></div>`;
};
// The answer as a graph: every route ends at the resource. Principals that must escalate are on
// the left, principals with direct access next to the resource, outsiders on a dashed line.
const TARGET = "who-can-target";
function whoCanGraph(r) {
  const nodes = new Map();
  const edges = [];
  const dist = new Map();
  const near = (id, d) => dist.set(id, Math.min(dist.get(id) ?? Infinity, d));
  const node = (id, extra = {}) => {
    if (!nodes.has(id)) nodes.set(id, { id, label: nameOf(id), subtitle: short(id), kind: kindOf(id), start: false, admin: false, techniques: 0, policies: null, paths: new Set() });
    Object.assign(nodes.get(id), extra);
    return nodes.get(id);
  };
  const edge = (from, to, label, name, confidence) => {
    if (!edges.some((e) => e.from === from && e.to === to && e.label === label)) edges.push({ from, to, label, name, confidence, paths: new Set() });
  };
  for (const v of r.via) {
    v.steps.forEach((s, i) => {
      node(s.from, { foot: [["Escalates", ""], [plural(v.steps.length - i, "step"), "to reach it"]] });
      node(s.to);
      near(s.from, v.steps.length - i + 1);
      edge(s.from, s.to, s.technique, s.name, "confirmed");
    });
  }
  for (const d of r.direct) {
    node(d.principal, { foot: [["Direct", "access"], [d.granted_by.length || 1, d.granted_by.length === 1 ? "grant" : "grants"]] });
    near(d.principal, 1);
    edge(d.principal, TARGET, "allowed", d.granted_by.join(", "), "confirmed");
  }
  for (const o of r.outside) {
    const id = `outside:${o.principal}`;
    node(id, { label: o.principal === "*" ? "Anyone" : nameOf(o.principal) || o.principal, subtitle: o.principal, kind: "outside", foot: [["Unknown", "own policies"], [o.conditional ? "Yes" : "No", "condition"]] });
    near(id, 1);
    edge(id, TARGET, "resource policy", o.statement, "possible");
  }
  const far = Math.max(1, ...dist.values());
  node(TARGET, {
    label: r.resource === "*" ? "Any resource" : nameOf(r.resource) || r.resource, subtitle: r.action, kind: "target",
    foot: [[r.direct.length, "directly"], [r.via.length, "through escalation"]],
  });
  dist.set(TARGET, 0);
  for (const n of nodes.values()) n.col = far - (dist.get(n.id) ?? 1) + 1;
  nodes.get(TARGET).col = far + 1;
  return { nodes: [...nodes.values()], edges, start: null };
}
let wcGraph = null;
function drawWhoCanGraph(r) {
  // The result is re-rendered on every query, so the graph is too.
  const old = graphs.indexOf(wcGraph);
  if (old >= 0) graphs.splice(old, 1);
  wcGraph = new Graph($("wsurface"), $("wworld"), {
    pad: 32,
    maxScale: 1,
    markerPrefix: "w",
    insets: () => ({ l: 0, r: 0, t: 8, b: 8 }),
    // Selecting a principal finds it in the lists below.
    onSelect: (n) => {
      const row = $("wc-result").querySelector(`[data-arn="${CSS.escape(n.id)}"]`);
      if (!row) return;
      row.scrollIntoView({ block: "center", behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
      row.classList.remove("flash");
      void row.offsetWidth;
      row.classList.add("flash");
    },
  });
  graphs.push(wcGraph);
  wcGraph.setData(whoCanGraph(r));
  requestAnimationFrame(() => wcGraph.fit());
}
function runWhoCan() {
  const out = call("who_can_query", input.account, $("wc-action").value, $("wc-resource").value, $("wc-policy").value, input.scp, input.inv, $("wc-context").value);
  const el = $("wc-result");
  if (out.error) {
    el.innerHTML = `<div class="verdict glass v-warn"><span class="vb">${IC.warn}</span><div><h2>Could not answer</h2><p>${esc(sentence(out.error))}</p></div></div>`;
    return;
  }
  const r = out.result;
  const n = r.direct.length + r.via.length;
  const direct = r.direct.map((d) => `<tr data-arn="${esc(d.principal)}"><td data-label="Principal">${whoCell(d.principal)}</td><td data-label="Granted by" class="td-mono">${d.granted_by.map((g) => esc(short(g))).join("<br>") || '<span class="t-faint">Resource policy</span>'}</td></tr>`).join("");
  const via = r.via.map((v) => `<li class="wc-via" data-arn="${esc(v.principal)}"><div class="wc-via-h">${whoCell(v.principal)}<span class="tag high">${plural(v.steps.length, "step")}</span></div>
      ${stepsHtml({ start: v.principal, steps: v.steps })}</li>`).join("");
  const outside = r.outside.map((o) => `<li data-arn="outside:${esc(o.principal)}"><b class="mono">${esc(o.principal)}</b><span>${esc(o.what)}, ${esc(o.statement)}${o.conditional ? ", with a condition" : ""}</span></li>`).join("");
  el.innerHTML = `<div class="verdict glass ${n ? (r.via.length ? "v-crit" : "v-warn") : "v-ok"} wc-sum"><span class="vb">${n ? IC.warn : IC.ok}</span>
      <div><h2>${n ? `${plural(n, "principal")} can` : "Nobody in the export can"} ${esc(r.action)}</h2>
      <p>On ${esc(r.resource)}. Checked ${plural(r.checked, "principal")}: ${r.direct.length} directly, ${r.via.length} through escalation, ${r.cannot} cannot.${r.via.length ? " Escalation paths are the ones to look at first: these principals were probably never meant to have this access." : ""}</p></div></div>
    ${n || r.outside.length ? `<div class="glass ev-block"><div class="card-h"><h3>Access graph</h3><span class="sub">Every route to the resource. Select a principal to find it below.</span>
      <div class="right"><button class="btn" id="wc-fit">Fit</button></div></div>
      <div class="wc-graph"><div class="surface" id="wsurface"><div class="world" id="wworld"><svg></svg></div></div></div></div>` : ""}
    ${r.direct.length ? `<div class="glass ev-block"><div class="card-h"><h3>Directly</h3><span class="sub">Their own policies allow it</span></div><table class="mtable"><thead><tr><th>Principal</th><th>Granted by</th></tr></thead><tbody>${direct}</tbody></table></div>` : ""}
    ${r.via.length ? `<div class="glass ev-block"><div class="card-h"><h3>Through escalation</h3><span class="sub">Shortest confirmed path to someone who can</span></div><ul class="card-b wc-vias">${via}</ul></div>` : ""}
    ${r.outside.length ? `<div class="glass ev-block"><div class="card-h"><h3>Outside the export</h3><span class="sub">Named by the resource policy; their own policies are unknown</span></div><ul class="card-b wif-deps">${outside}</ul></div>` : ""}
    <div class="dl-row"><button class="btn" id="wc-dl-text">Download text</button><button class="btn" id="wc-dl-json">Download JSON</button></div>`;
  if (n || r.outside.length) {
    drawWhoCanGraph(r);
    $("wc-fit").addEventListener("click", () => wcGraph.fit());
  }
  $("wc-dl-text").addEventListener("click", () => download("iam-trace-who-can.txt", out.text, "text/plain"));
  $("wc-dl-json").addEventListener("click", () => download("iam-trace-who-can.json", JSON.stringify(r, null, 2)));
}

// ------------------------------------------------------------------------------------- policy check

// Rule text marks commands and keys with backticks, as Markdown would; show them as code.
const codeText = (s) => esc(s).replace(/`([^`]+)`/g, '<code class="c">$1</code>');
// Severity to colour: the engine's high/medium/low use the app's crit/high/warn tones.
const SEV = { high: ["crit", "High"], medium: ["high", "Medium"], low: ["warn", "Low"] };
const pc = { files: [], account: false, report: null, filter: "all" };
const drawPc = editorWith($("pc-text"), $("pcg"), "");

function pcDocs() {
  const docs = [];
  if ($("pc-text").value.trim()) docs.push({ name: "pasted policy", text: $("pc-text").value });
  docs.push(...pc.files);
  if (pc.account && input.account) docs.push({ name: input.file?.name || "account export", text: input.account });
  return docs;
}
function pcList() {
  const rows = pc.files.map((f, i) => ({ name: f.name, meta: bytes(f.text.length), i }));
  if (pc.account) rows.push({ name: input.file?.name || "Account export", meta: "from Data input", i: -1 });
  $("pc-list-card").hidden = !rows.length;
  $("pc-list").innerHTML = rows.map((r) => `<div class="pc-file"><span class="fi">${IC.file}</span><div><b class="mono">${esc(r.name)}</b><small>${esc(r.meta)}</small></div>
    <button class="icon-btn" data-rm="${r.i}" title="Remove" aria-label="Remove ${esc(r.name)}">${IC.x}</button></div>`).join("");
  $("pc-list").querySelectorAll("[data-rm]").forEach((b) => b.addEventListener("click", () => {
    const i = Number(b.dataset.rm);
    if (i < 0) pc.account = false;
    else pc.files.splice(i, 1);
    pcList();
    persist("check");
  }));
}
async function pcAddFiles(list) {
  for (const f of list) pc.files.push({ name: f.name, text: await f.text() });
  pcList();
  persist("check");
  toast(`${plural(list.length, "file")} added`);
}
$("pc-choose").addEventListener("click", () => $("pc-files").click());
$("pc-files").addEventListener("change", (e) => { pcAddFiles([...e.target.files]); e.target.value = ""; });
const pcDrop = $("pc-drop");
pcDrop.addEventListener("dragover", (e) => { e.preventDefault(); pcDrop.classList.add("over"); });
pcDrop.addEventListener("dragleave", () => pcDrop.classList.remove("over"));
pcDrop.addEventListener("drop", (e) => { e.preventDefault(); pcDrop.classList.remove("over"); pcAddFiles([...e.dataTransfer.files]); });
$("pc-clear-files").addEventListener("click", () => { pc.files = []; pc.account = false; pcList(); persist("check"); });
$("pc-example").addEventListener("click", () => { $("pc-text").value = JSON.stringify(CHECK_EXAMPLE, null, 2); drawPc(); persist("check"); whenReady(runCheck); });
$("pc-account").addEventListener("click", () => { pc.account = true; pcList(); whenReady(runCheck); });
$("pc-run").addEventListener("click", runCheck);

function runCheck() {
  const docs = pcDocs();
  if (!docs.length) {
    toast("Paste a policy, drop files or use Load example first");
    $("pc-text").focus();
    return;
  }
  const out = call("check", JSON.stringify(docs), $("pc-aws").checked);
  if (out.error) {
    openSheet("Could not check", `<div class="verdict glass v-warn"><span class="vb">${IC.warn}</span><div><h2>Could not check</h2><p>${esc(sentence(out.error))}</p></div></div>`);
    return;
  }
  pc.report = out;
  pc.filter = "all";
  const n = out.result.summary;
  const nav = $("nav-check");
  nav.hidden = !n.high;
  nav.textContent = n.high;
  drawCheck();
}
function drawCheck() {
  const { result: r, text, sarif } = pc.report;
  const s = r.summary;
  const total = r.findings.length;
  let v;
  if (s.high) v = ["v-crit", IC.warn, `${plural(s.high, "high-severity finding")}`, "Fix these first: each one grants far more than most principals need, or opens access to anyone."];
  else if (total) v = ["v-warn", IC.info, `${plural(total, "finding")} to review`, "Nothing high severity. Review the rest; each one says why it matters and how to fix it."];
  else v = ["v-ok", IC.ok, "No risky patterns found", "This does not prove the policies are least-privilege. Run the attack-path analysis to look for escalation through other principals."];
  const kp = [["high", s.high], ["medium", s.medium], ["low", s.low]].map(([k, c]) => `<div class="kpi glass ${c ? `k-${SEV[k][0]}` : "k-plain"}"><div class="kh">${SEV[k][1]}</div><div class="kv"><b>${c}</b></div></div>`).join("")
    + `<div class="kpi glass k-plain"><div class="kh">Policies checked</div><div class="kv"><b>${s.policies}</b>${s.skipped_aws_managed ? `<span>${s.skipped_aws_managed} AWS managed skipped</span>` : ""}</div></div>`;
  const chips = [["all", `All (${total})`], ["high", `High (${s.high})`], ["medium", `Medium (${s.medium})`], ["low", `Low (${s.low})`]]
    .map(([k, l]) => `<button class="chipf ${pc.filter === k ? "on" : ""}" data-f="${k}">${l}</button>`).join(" ");
  const card = (f) => {
    const where = f.statement ? `${f.policy}, statement ${f.statement}` : f.policy;
    const attached = (f.attached_to || []).filter((a) => !f.policy.startsWith(a));
    const tech = (f.techniques || []).map((t, i) => `<li><a href="${esc(f.links[i])}" target="_blank" rel="noopener">${esc(t)}</a></li>`).join("");
    return `<article class="pc-card glass">
      <div class="pc-h"><h3>${esc(f.title)}</h3><code class="pc-rule">${esc(f.rule)}</code></div>
      <p class="pc-where mono">${esc(where)}</p>
      ${attached.length ? `<p class="pc-att">Attached to ${attached.map((a) => `<span class="mono">${esc(short(a))}</span>`).join(", ")}</p>` : ""}
      <p class="pc-detail">${codeText(f.detail)}</p>
      ${tech ? `<ul class="pc-tech">${tech}</ul>` : ""}
      <div class="pc-explain"><div><h4>Why it matters</h4><p>${codeText(f.why)}</p></div><div><h4>How to fix it</h4><p>${codeText(f.fix)}</p></div></div>
      <div class="report-row">Is this wrong? ${reportLink({ title: `Wrong check finding: ${f.rule}`, request: `iam-trace check, rule ${f.rule}, ${f.statement || "whole policy"}`, iamtrace: f.detail }, "Report a wrong finding")}</div>
    </article>`;
  };
  const groups = ["high", "medium", "low"].filter((k) => pc.filter === "all" || pc.filter === k).map((k) => {
    const items = r.findings.filter((f) => f.severity === k);
    return items.length ? `<section class="pc-group s-${SEV[k][0]}"><h2>${SEV[k][1]} severity <span>${items.length}</span></h2>${items.map(card).join("")}</section>` : "";
  }).join("");
  const actions = total ? '<button class="btn" id="pc-dl-text">Text</button><button class="btn" id="pc-dl-sarif">SARIF</button><button class="btn" id="pc-dl-json">JSON</button>' : "";
  openSheet("Policy check", `<div class="verdict glass ${v[0]}"><span class="vb">${v[1]}</span><div><h2>${v[2]}</h2><p>${v[3]}</p></div></div>
    <div class="kpis">${kp}</div>
    ${total ? `<div class="pc-tools"><div class="seg-chips" role="group" aria-label="Filter by severity">${chips}</div></div>
    <div class="pc-cards">${groups || '<p class="list-empty">Nothing at this severity.</p>'}</div>` : ""}`, actions);
  const el = $("sheet-body");
  el.querySelectorAll(".chipf").forEach((c) => c.addEventListener("click", () => { pc.filter = c.dataset.f; drawCheck(); }));
  $("pc-dl-text")?.addEventListener("click", () => download("iam-trace-check.txt", text, "text/plain"));
  $("pc-dl-sarif")?.addEventListener("click", () => download("iam-trace-check.sarif", sarif));
  $("pc-dl-json")?.addEventListener("click", () => download("iam-trace-check.json", JSON.stringify(r, null, 2)));
}

// ------------------------------------------------------------------------------------- changelog

const CHANGES = [
  { v: "0.2.0", status: ["acc", "Latest"], date: "Unreleased", sum: "A new web app, the rename to iam-trace, and security hardening after a full review.", groups: [
    ["Added", ["<b>Search and commands</b>: press Ctrl K (⌘K on a Mac) or / to find any screen, principal, documentation topic or heading, and to run common commands.",
      "<b>Download report</b>: a single HTML file with the verdict, the shortest paths, what to fix first and every principal at risk. It has no scripts, opens offline and prints to PDF.",
      "<b>Cut a step</b> on the attack graph: select a technique and cut it, or use Simulate on a recommended fix, to see whether the attacker still reaches admin by another route. The other route is drawn.",
      "Link previews: sharing the app link shows a title, a description and an image.",
      "<b>Settings and Changelog</b>: redesigned as one reading column with a list of sections that follows you as you scroll, and a tab strip on phones. Changelog entries can be filtered by kind and long groups fold.",
      "<b>What would change this</b>: under every Evaluate result, the smallest checked fix for a denied request, or what an allowed one depends on. <b>Try this change</b> applies it.",
      "<b>Who can</b>: every principal that can perform an action on a resource, directly or through escalation, drawn as an access graph.",
      "<b>Documentation</b>: one topic per page with search, links to every heading, and previous and next.",
      "<b>Saved in your browser</b>: your data and last analysis come back after a refresh. Settings lists what is saved and deletes any of it.",
      "<b>Policy check</b>: a new screen and <code class='c'>iam-trace check</code> flag 14 risky patterns (full admin, iam:PassRole on any role, NotAction, public principals, a typo in a Deny and more), each with why it matters and how to fix it.",
      "<b>Resource inventory</b>: <code class='c'>iam-trace inventory collect</code> (read-only) and a new Data input tab. Techniques that take over an existing Lambda function, EC2 instance or similar are confirmed with the exact resource, or ruled out.",
      "Report-a-wrong-answer links on Evaluate results, graph findings and Policy check findings. Account IDs are replaced before the issue opens.",
      "A complete web app: an Overview dashboard with the verdict, metrics, paths to admin, recommended fixes and principals at risk.",
      "Full-screen attack graph with three node styles, a paths panel and a details panel for every principal and technique.",
      "Data input with file drop, validation, a searchable principal picker, organization SCPs and an optional blast-radius count.",
      "Findings with search, filters and downloads (text, SARIF, JSON); documentation and this changelog inside the app.",
      "Settings: light, dark or system mode; bold, restrained or brand-colour style; graph node style.",
      "Marked as beta, with an honest comparison to pathfinding.cloud, PMapper, Cloudsplaining and iam-lens, and a public roadmap (ROADMAP.md).",
      "<code class='c'>web_api.analyze_account</code>: one call returns the analysis from a starting principal, a summary of every principal, and supports SCPs."]],
    ["Changed", ["<b>Design review</b>: flat surfaces instead of glows and frosted glass (smoother scrolling too), type that scales with the window, and layouts for phones, tablets and wide screens.",
      "Policy diff and Policy check fill the screen and open their results in a full-screen sheet. The attack graph's paths panel is a docked column with each path as a list of steps.",
      "Renamed from IAM Lens to iam-trace. Install <code class='c'>iam-trace</code>, import <code class='c'>iamtrace</code>, catalog variable <code class='c'>IAMTRACE_CATALOG</code>.",
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
const CL_KINDS = ["Added", "Changed", "Security", "Fixed"];
const CL_FOLD = 6; // a group longer than this shows its first entries and a "Show more" button
let clFilter = "all";
const clOpen = new Set();
// "<b>Title</b>: description" becomes a title line and a muted description; other entries stay one line.
function clItem(x) {
  const m = /^<b>(.+?)<\/b>:?\s*([\s\S]*)$/.exec(x);
  if (!m) return `<li class="ci plain">${x}</li>`;
  const rest = m[2].replace(/^[a-z]/, (c) => c.toUpperCase());
  return `<li class="ci"><span class="ci-t">${m[1]}</span>${rest}</li>`;
}
function renderChangelog() {
  const count = (k) => CHANGES.reduce((n, r) => n + r.groups.filter(([t]) => k === "all" || t === k).reduce((m, [, items]) => m + items.length, 0), 0);
  $("cl-filters").innerHTML = ["all", ...CL_KINDS].filter((k) => count(k)).map((k) =>
    `<button data-f="${k}" class="${k === clFilter ? "on" : ""}" aria-pressed="${k === clFilter}">${k === "all" ? "All" : k} <span>${count(k)}</span></button>`).join("");
  $("timeline").innerHTML = CHANGES.map((r) => {
    const groups = r.groups.filter(([t]) => clFilter === "all" || t === clFilter);
    if (!groups.length) return "";
    return `<section class="rel" id="rel-${r.v}"><div class="rel-h"><h2>Version ${r.v}</h2><span class="tag ${r.status[0]}">${r.status[1]}</span><span class="date">${r.date}</span></div>
      <p class="rel-sum">${r.sum}</p>${groups.map(([t, items]) => {
        const key = `${r.v}/${t}`, fold = items.length > CL_FOLD + 2 && !clOpen.has(key);
        const shown = fold ? items.slice(0, CL_FOLD) : items;
        return `<div class="rel-group"><h3 class="${CT[t]}">${t} <span>${items.length}</span></h3><ul class="ci-list">${shown.map(clItem).join("")}</ul>${fold ? `<div class="ci-more"><button class="btn" data-more="${key}">Show ${items.length - CL_FOLD} more</button></div>` : ""}</div>`;
      }).join("")}</section>`;
  }).join("") || '<p class="list-empty">No changes of this kind yet.</p>';
  $("cl-versions").innerHTML = CHANGES.map((r, i) => `<button data-sec="rel-${r.v}" class="${i ? "" : "on"}">${r.v}<small>${r.date}</small></button>`).join("");
  spyNav($("cl-versions"), $("v-changelog"));
}
$("cl-filters").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-f]"); if (!b) return;
  clFilter = b.dataset.f; renderChangelog();
});
$("timeline").addEventListener("click", (e) => {
  const b = e.target.closest("[data-more]"); if (!b) return;
  clOpen.add(b.dataset.more); renderChangelog();
});

// Section lists beside Settings and the Changelog: a click scrolls to the section, and the entry
// for the section being read is highlighted as the page scrolls.
function spyNav(nav, scroller) {
  const buttons = [...nav.querySelectorAll("button[data-sec]")];
  const mark = (id) => buttons.forEach((b) => { const on = b.dataset.sec === id; b.classList.toggle("on", on); if (on) b.setAttribute("aria-current", "true"); else b.removeAttribute("aria-current"); });
  nav.onclick = (e) => {
    const b = e.target.closest("button[data-sec]"); if (!b) return;
    const el = $(b.dataset.sec); if (!el) return;
    const navH = getComputedStyle(nav).position === "sticky" && nav.offsetWidth > nav.parentElement.offsetWidth * 0.6 ? nav.offsetHeight : 0;
    const top = el.getBoundingClientRect().top - scroller.getBoundingClientRect().top + scroller.scrollTop - navH - 12;
    scroller.scrollTo({ top, behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
    mark(b.dataset.sec);
    if (nav.scrollWidth > nav.clientWidth) nav.scrollTo({ left: b.offsetLeft - nav.clientWidth / 2 + b.offsetWidth / 2, behavior: "smooth" });
  };
  scroller.onscroll = () => {
    const limit = scroller.getBoundingClientRect().top + scroller.clientHeight * 0.3;
    let cur = buttons[0]?.dataset.sec;
    for (const b of buttons) { const el = $(b.dataset.sec); if (el && el.getBoundingClientRect().top <= limit) cur = b.dataset.sec; }
    if (scroller.scrollTop + scroller.clientHeight >= scroller.scrollHeight - 4) cur = buttons.at(-1)?.dataset.sec;
    mark(cur);
    const on = nav.querySelector(".on");
    if (on && nav.scrollWidth > nav.clientWidth && (on.offsetLeft < nav.scrollLeft || on.offsetLeft + on.offsetWidth > nav.scrollLeft + nav.clientWidth)) nav.scrollLeft = on.offsetLeft - 16;
  };
}
spyNav($("set-nav"), $("v-settings"));

// ------------------------------------------------------------------------------------- docs

// One topic per page, each with its own address (#docs/d-whocan, or #docs/d-whocan/<heading> for a
// heading), so topics can be bookmarked and shared. The contents list is the single source of the
// order: the pager and the breadcrumb are read from it.
const DOC_IDS = [...$("toc").querySelectorAll("a")].map((a) => a.getAttribute("href").split("/")[1]);
const docTitle = (id) => $("toc").querySelector(`a[href="#docs/${id}"]`)?.textContent || "";
function docGroup(id) {
  let group = "";
  for (const el of $("toc").children) {
    if (el.tagName === "H5") group = el.textContent;
    else if (el.getAttribute("href") === `#docs/${id}`) return group;
  }
  return "";
}
const slug = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
let docCurrent = null;
function showDoc(id, anchor) {
  if (!DOC_IDS.includes(id)) id = "d-start";
  const changed = id !== docCurrent;
  docCurrent = id;
  document.querySelectorAll("#doc-article .dsec").forEach((s) => { s.hidden = s.id !== id; });
  document.querySelectorAll("#doc-article [data-for]").forEach((s) => { s.hidden = s.dataset.for !== id; });
  $("toc").querySelectorAll("a").forEach((a) => {
    const on = a.getAttribute("href") === `#docs/${id}`;
    a.classList.toggle("on", on);
    if (on) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
  $("doc-crumb").textContent = id === "d-start" ? "" : `${docGroup(id)} / ${docTitle(id)}`;
  // Headings get stable ids and a link of their own; "On this page" lists them.
  const heads = [...$(id).querySelectorAll("h3")];
  for (const h of heads) {
    if (h.id) continue;
    h.id = `${id}--${slug(h.textContent)}`;
    h.insertAdjacentHTML("beforeend", `<a class="h-anchor" href="#docs/${id}/${h.id}" aria-label="Link to this section">#</a>`);
  }
  $("otp").innerHTML = heads.length > 1
    ? `<h5>On this page</h5>${heads.map((h) => `<a href="#docs/${id}/${h.id}" data-h="${h.id}">${esc(h.firstChild.textContent.trim())}</a>`).join("")}`
    : "";
  const i = DOC_IDS.indexOf(id);
  const [prev, next] = [DOC_IDS[i - 1], DOC_IDS[i + 1]];
  $("doc-pager").innerHTML = (prev ? `<a class="pg prev" href="#docs/${prev}"><span>Previous</span><b>${esc(docTitle(prev))}</b></a>` : "<span></span>")
    + (next ? `<a class="pg next" href="#docs/${next}"><span>Next</span><b>${esc(docTitle(next))}</b></a>` : "");
  setDocNav(false);
  if (anchor && $(anchor)) $(anchor).scrollIntoView({ block: "start" });
  else if (changed) $("v-docs").scrollTop = 0;
  markOtp();
}
// "On this page" follows the reader.
function markOtp() {
  const view = $("v-docs");
  let cur = null;
  $("otp").querySelectorAll("a").forEach((a) => {
    const h = $(a.dataset.h);
    if (h && h.getBoundingClientRect().top - view.getBoundingClientRect().top < 120) cur = a;
  });
  $("otp").querySelectorAll("a").forEach((a) => a.classList.toggle("on", a === cur));
}
$("v-docs").addEventListener("scroll", markOtp, { passive: true });

// On phones the contents slide over the page.
function setDocNav(open) {
  $("docs2").classList.toggle("nav-open", open);
  $("dnav-scrim").hidden = !open;
  if (open) $("doc-search").focus({ preventScroll: true });
}
$("dnav-open").addEventListener("click", () => setDocNav(true));
$("dnav-close").addEventListener("click", () => { setDocNav(false); $("dnav-open").focus(); });
$("dnav-scrim").addEventListener("click", () => setDocNav(false));
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && $("docs2").classList.contains("nav-open")) setDocNav(false); });

// Search: every topic's full text, with the match shown in context.
// Text is taken with a space at every tag, so table cells and list items don't run together.
const plainText = (el) => new DOMParser().parseFromString(el.innerHTML.replace(/<[^>]+>/g, " "), "text/html").documentElement.textContent.replace(/\s+/g, " ").trim();
const DOC_TEXT = DOC_IDS.map((id) => ({ id, title: docTitle(id), text: plainText($(id)) }));
function searchDocs(q) {
  const res = $("doc-results");
  const query = q.trim().toLowerCase();
  $("toc").hidden = Boolean(query);
  res.hidden = !query;
  if (!query) return;
  const hits = DOC_TEXT.map((d) => {
    const inTitle = d.title.toLowerCase().includes(query);
    const at = d.text.toLowerCase().indexOf(query);
    if (!inTitle && at < 0) return null;
    let snippet = "";
    if (at >= 0) {
      const from = Math.max(0, at - 50);
      const before = (from ? "…" : "") + d.text.slice(from, at);
      const after = d.text.slice(at + query.length, at + query.length + 80) + "…";
      snippet = `${esc(before)}<mark>${esc(d.text.slice(at, at + query.length))}</mark>${esc(after)}`;
    }
    // A title match first, then the topics that mention it most.
    const count = d.text.toLowerCase().split(query).length - 1;
    return { ...d, snippet, score: (inTitle ? 1000 : 0) + count };
  }).filter(Boolean).sort((a, b) => b.score - a.score);
  res.innerHTML = hits.length
    ? `<p class="dnav-count">${plural(hits.length, "topic")}</p>${hits.map((h) => `<a href="#docs/${h.id}"><b>${esc(h.title)}</b>${h.snippet ? `<span>${h.snippet}</span>` : ""}</a>`).join("")}`
    : `<p class="dnav-count">Nothing found for "${esc(q.trim())}". Try a shorter word.</p>`;
}
$("doc-search").addEventListener("input", (e) => searchDocs(e.target.value));
$("doc-search").addEventListener("keydown", (e) => {
  if (e.key === "Enter") $("doc-results").querySelector("a")?.click();
  if (e.key === "Escape" && e.target.value) { e.stopPropagation(); e.target.value = ""; searchDocs(""); }
});
document.querySelectorAll(".codeblock .copy").forEach((b) => b.addEventListener("click", () => copy(b.closest(".codeblock").querySelector("pre").innerText)));
document.querySelectorAll("[data-copy]").forEach((b) => b.addEventListener("click", () => copy(b.dataset.copy)));

// ------------------------------------------------------------------------------------- saved data

// Everything you load or type is saved in this browser (IndexedDB) and restored after a refresh,
// unless you turn saving off in Settings. Each entry knows how to read itself from the page, put
// itself back, and clear itself. Evaluate and Policy diff open with examples, so they are only
// saved once you edit them.
const edited = { evaluate: false, diff: false };
const SAVED = {
  account: {
    label: "Account export", where: "input",
    read: () => (input.account.trim() ? { text: input.account, file: input.file && { ...input.file, when: +input.file.when }, example: input.example, start: input.start } : null),
    apply: (v) => { input.account = v.text; input.file = v.file ? { ...v.file, when: new Date(v.file.when) } : null; input.example = Boolean(v.example); input.start = v.start || ""; },
    clear: () => { input.account = ""; input.file = null; input.example = false; input.start = ""; input.principals = []; input.accountValid = false; },
  },
  policy: { label: "Single policy", where: "input", read: () => input.policy.trim() || null, apply: (v) => { input.policy = v; }, clear: () => { input.policy = ""; } },
  scp: { label: "Organization SCPs", where: "input", read: () => input.scp.trim() || null, apply: (v) => { input.scp = v; }, clear: () => { input.scp = ""; } },
  inv: { label: "Resource inventory", where: "input", read: () => input.inv.trim() || null, apply: (v) => { input.inv = v; }, clear: () => { input.inv = ""; } },
  analysis: {
    label: "Last analysis", where: "overview", detail: (v) => `re-run from ${v.src === "policy" ? "the single policy" : "the account export"} when the page opens`,
    read: () => lastRun, apply: (v) => { lastRun = v; $("opt-blast").checked = Boolean(v.blast); }, clear: () => { lastRun = null; },
  },
  evaluate: {
    label: "Evaluate a request", where: "evaluate",
    read: () => (edited.evaluate ? { principal: $("ev-principal").value, action: $("ev-action").value, resource: $("ev-resource").value, account: $("ev-account").value, context: $("ev-context").value, policies: { ...evPolicies } } : null),
    apply: (v) => {
      edited.evaluate = true;
      $("ev-principal").value = v.principal; $("ev-action").value = v.action; $("ev-resource").value = v.resource;
      $("ev-account").value = v.account; $("ev-context").value = v.context;
      for (const [k] of POLICY_TYPES) evPolicies[k] = v.policies[k] || "";
      renderEvPolicies();
    },
    clear: () => { edited.evaluate = false; loadEvExample(EVALUATE_EXAMPLES[0]); },
  },
  diff: {
    label: "Policy diff", where: "diff",
    read: () => (edited.diff ? { old: $("d-old").value, new: $("d-new").value } : null),
    apply: (v) => { edited.diff = true; $("d-old").value = v.old; $("d-new").value = v.new; drawOld(); drawNew(); },
    clear: () => { edited.diff = false; $("d-old").value = JSON.stringify(DIFF_EXAMPLE.before, null, 2); $("d-new").value = JSON.stringify(DIFF_EXAMPLE.after, null, 2); drawOld(); drawNew(); },
  },
  whocan: {
    label: "Who can query", where: "whocan",
    read: () => ($("wc-action").value.trim() || $("wc-resource").value.trim() ? { action: $("wc-action").value, resource: $("wc-resource").value, policy: $("wc-policy").value, context: $("wc-context").value } : null),
    apply: (v) => { $("wc-action").value = v.action; $("wc-resource").value = v.resource; $("wc-policy").value = v.policy || ""; $("wc-context").value = v.context || ""; },
    clear: () => { for (const id of ["wc-action", "wc-resource", "wc-policy", "wc-context"]) $(id).value = ""; $("wc-result").innerHTML = ""; },
  },
  check: {
    label: "Policy check", where: "check",
    read: () => ($("pc-text").value.trim() || pc.files.length ? { text: $("pc-text").value, files: pc.files, aws: $("pc-aws").checked } : null),
    apply: (v) => { $("pc-text").value = v.text; pc.files = v.files || []; $("pc-aws").checked = Boolean(v.aws); drawPc(); pcList(); },
    clear: () => { $("pc-text").value = ""; pc.files = []; pc.account = false; drawPc(); pcList(); },
  },
};
const saving = {
  on: (() => { try { return localStorage.getItem("iam-trace-save") !== "off"; } catch { return true; } })(),
  available: true, failed: false, warned: false, timers: new Map(),
  ready: false, // nothing is written until saved data has been read back, or startup would erase it
};
function hasData() {
  return Object.values(SAVED).some((s) => s.read() != null);
}
function unsaved() {
  return hasData() && (!saving.on || !saving.available || saving.failed || saving.timers.size > 0);
}
function persist(key) {
  if (!saving.ready) return;
  if (!saving.on || !saving.available) { refreshSaveStatus(); return; }
  clearTimeout(saving.timers.get(key));
  saving.timers.set(key, setTimeout(async () => {
    const value = SAVED[key].read();
    try {
      if (value == null) await dataStore.del(key);
      else await dataStore.set(key, value);
      saving.failed = false;
    } catch (e) {
      saving.failed = true;
      if (!saving.warned) {
        saving.warned = true;
        toast("This browser refused to save your data. It will be lost when you close the tab.");
      }
      console.warn("iam-trace: could not save", key, e);
    }
    saving.timers.delete(key);
    refreshSaveStatus();
    if (currentView === "settings") renderSaved();
  }, 400));
  refreshSaveStatus();
}
const SAVE_IC = {
  ok: '<svg class="i" viewBox="0 0 24 24"><path d="M5 12l4 4 10-10"/></svg>',
  warn: '<svg class="i" viewBox="0 0 24 24"><path d="M12 3l9 16H3z"/><path d="M12 10v4M12 17v.5"/></svg>',
};
function refreshSaveStatus() {
  const el = $("save-status");
  el.hidden = !hasData();
  let state = "ok";
  let text = "Saved in this browser";
  let title = "Your data is saved in this browser only and comes back after a refresh. Manage it in Settings.";
  if (!saving.on) [state, text, title] = ["off", "Not saved", "Saving is turned off in Settings. Your data is lost when you close or refresh this tab."];
  else if (!saving.available || saving.failed) [state, text, title] = ["error", "Not saved", "This browser is not letting iam-trace save (private browsing or storage full). Your data is lost when you close or refresh this tab."];
  else if (saving.timers.size) [state, text] = ["saving", "Saving"];
  el.dataset.state = state;
  el.title = title;
  el.innerHTML = `${state === "ok" || state === "saving" ? SAVE_IC.ok : SAVE_IC.warn}<span>${text}</span>`;
}
// Leaving with data that is not saved asks first; the browser shows its own wording.
window.addEventListener("beforeunload", (e) => {
  if (unsaved()) {
    e.preventDefault();
    e.returnValue = "";
  }
});
$("save-status").addEventListener("click", () => setTimeout(() => $("saved-data")?.scrollIntoView({ block: "start" }), 0));

// Edits save themselves.
$("editor").addEventListener("input", () => persist(input.src));
$("opt-blast").addEventListener("change", () => { if (lastRun) persist("analysis"); });
$("v-evaluate").addEventListener("input", () => { edited.evaluate = true; persist("evaluate"); });
$("ev-scenario")?.addEventListener("change", () => { edited.evaluate = true; persist("evaluate"); });
$("v-diff").addEventListener("input", () => { edited.diff = true; persist("diff"); });
$("d-swap").addEventListener("click", () => { edited.diff = true; persist("diff"); });
$("v-check").addEventListener("input", () => persist("check"));
$("v-check").addEventListener("change", () => persist("check"));

function clearModel() {
  model = null;
  $("scope-text").textContent = "No account loaded";
  $("nav-paths").hidden = true;
  $("nav-findings").hidden = true;
  renderOverview();
  renderGraphView();
  renderFindings();
}
async function deleteSaved(key) {
  SAVED[key].clear();
  if (key === "account" || key === "analysis") {
    if (key === "account") { SAVED.analysis.clear(); await dataStore.del("analysis").catch(() => {}); }
    clearModel();
  }
  if (SAVED[key].where === "input") setSource(input.src);
  await dataStore.del(key).catch(() => {});
  refreshSaveStatus();
  renderSaved();
}
let confirmAll = false;
async function renderSaved() {
  const list = $("saved-list");
  if (!list) return;
  $("save-on").checked = saving.on;
  let entries = [];
  if (saving.available) entries = await dataStore.all().catch(() => []);
  const byKey = new Map(entries.map((e) => [e.key, e]));
  const rows = Object.entries(SAVED).filter(([k]) => byKey.has(k)).map(([k, s]) => {
    const e = byKey.get(k);
    const detail = s.detail ? s.detail(e.value) : bytes(e.bytes);
    return `<div class="saved-row"><div><b>${esc(s.label)}</b><span>${esc(detail)}, saved ${esc(new Date(e.savedAt).toLocaleString())}</span></div>
      <button class="btn" data-del="${k}" aria-label="Delete saved ${esc(s.label)}">Delete</button></div>`;
  });
  let note = "";
  if (!saving.available) note = '<p class="saved-note warn">This browser is not letting iam-trace save (private browsing, or storage turned off). Your data lasts until you close the tab.</p>';
  else if (!saving.on) note = '<p class="saved-note warn">Saving is off. Nothing new is saved, and you are asked before leaving with unsaved work.</p>';
  list.innerHTML = note + (rows.length ? rows.join("") : '<p class="saved-note">Nothing is saved yet. What you load or type appears here.</p>');
  list.querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", () => deleteSaved(b.dataset.del)));
  const all = $("delete-all");
  all.disabled = !rows.length;
  confirmAll = false;
  all.textContent = "Delete all saved data";
}
$("save-on").addEventListener("change", async (e) => {
  saving.on = e.target.checked;
  try { localStorage.setItem("iam-trace-save", saving.on ? "on" : "off"); } catch { /* the choice still applies to this tab */ }
  if (!saving.on) await dataStore.clear().catch(() => {});
  else for (const k of Object.keys(SAVED)) persist(k);
  refreshSaveStatus();
  renderSaved();
});
// Two clicks, so a single misclick cannot wipe everything. No browser dialog.
$("delete-all").addEventListener("click", async () => {
  const b = $("delete-all");
  if (!confirmAll) {
    confirmAll = true;
    b.textContent = "Click again to delete everything";
    b.classList.add("danger");
    setTimeout(() => { if (confirmAll) { confirmAll = false; b.textContent = "Delete all saved data"; b.classList.remove("danger"); } }, 4000);
    return;
  }
  b.classList.remove("danger");
  for (const k of Object.keys(SAVED)) SAVED[k].clear();
  await dataStore.clear().catch(() => {});
  clearModel();
  setSource("account");
  refreshSaveStatus();
  renderSaved();
  toast("All saved data deleted");
});

async function restoreSaved() {
  saving.available = await dataStore.available();
  if (!saving.available || !saving.on) { saving.ready = true; refreshSaveStatus(); return; }
  let entries = [];
  try { entries = await dataStore.all(); } catch { saving.failed = true; }
  for (const e of entries) {
    try { SAVED[e.key]?.apply(e.value); } catch (err) { console.warn("iam-trace: could not restore", e.key, err); }
  }
  saving.ready = true;
  if (entries.some((e) => ["account", "policy", "scp", "inv"].includes(e.key))) setSource(lastRun?.src === "policy" ? "policy" : input.src);
  refreshSaveStatus();
  if (lastRun) {
    whenReady(async () => {
      if (lastRun.src === "policy" ? !input.policy.trim() : !(input.account.trim() && input.accountValid && input.start)) return;
      await runAnalysis({ restoring: true, src: lastRun.src });
      if (currentView === "input") go("overview");
    });
  }
}

// ------------------------------------------------------------------------------------- command palette

// Ctrl+K (or Cmd+K, or "/" outside a text field) opens one search box for every screen, principal,
// documentation topic and heading, and the common commands. Nothing here changes data without the
// usual confirmation: "Delete saved data" only opens Settings.
const isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
const PI = {
  screen: '<svg class="i" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18"/></svg>',
  user: '<svg class="i" viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-6 8-6s8 2 8 6"/></svg>',
  role: '<svg class="i" viewBox="0 0 24 24"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/></svg>',
  group: '<svg class="i" viewBox="0 0 24 24"><circle cx="9" cy="8" r="3.5"/><path d="M2 20c0-3.5 3-5.5 7-5.5s7 2 7 5.5M16 4.5a3.5 3.5 0 0 1 0 7M18 14.5c2.5.6 4 2.5 4 5.5"/></svg>',
  doc: '<svg class="i" viewBox="0 0 24 24"><path d="M6 3h9l4 4v14H6z"/><path d="M14 3v5h5M9 13h7M9 17h5"/></svg>',
  hash: '<svg class="i" viewBox="0 0 24 24"><path d="M5 9h15M4 15h15M10 3 8 21M16 3l-2 18"/></svg>',
  run: '<svg class="i" viewBox="0 0 24 24"><path d="M5 12h14M13 6l6 6-6 6"/></svg>',
};
const pal = { items: [], shown: [], active: 0, back: null };

function palItems() {
  const items = [];
  const add = (group, title, run, o = {}) => items.push({ group, title, run, icon: o.icon || PI.run, hint: o.hint || "", keys: (o.keys || "").toLowerCase(), top: o.top !== false });
  for (const [view, [grp, name]] of Object.entries(VIEWS)) add("Screens", name, () => go(view), { icon: PI.screen, hint: grp, keys: view });
  add("Commands", "Load the example account", () => { go("overview"); runExample(); }, { keys: "demo sample try" });
  add("Commands", "Load your own data", () => go("input"), { keys: "upload import export file account" });
  if (model) add("Commands", "Download report", downloadReport, { keys: "export html pdf share print" });
  if (model && whatIf.size) add("Commands", "Restore every cut step", () => { go("graph"); whatIf.clear(); setCut([], false); }, { keys: "what-if reset" });
  const dark = root.dataset.mode === "dark";
  add("Commands", dark ? "Switch to light mode" : "Switch to dark mode", () => document.querySelector(`[data-set=mode] [data-v=${dark ? "light" : "dark"}]`)?.click(), { keys: "theme appearance colour color" });
  add("Commands", "Delete saved data", () => { go("settings"); requestAnimationFrame(() => $("set-nav").querySelector("[data-sec=set-saved]")?.click()); }, { keys: "clear reset privacy indexeddb storage" });
  add("Commands", "Report a problem on GitHub", () => window.open(ISSUES, "_blank", "noopener"), { keys: "bug issue feedback" });
  if (model) {
    const rank = (p) => (p.admin_equivalent ? 0 : p.path ? 1 : 2);
    for (const p of [...model.principals].sort((a, b) => rank(a) - rank(b))) {
      const hint = p.admin_equivalent ? "Admin-equivalent" : p.path ? `Reaches admin in ${plural(p.path.steps.length, "step")}` : `${p.confirmed} confirmed`;
      add(model.principals.length && rank(p) < 2 ? "Principals at risk" : "Principals", short(p.arn), () => openPrincipal(p.arn), { icon: PI[p.kind] || PI.role, hint, keys: `${p.arn} ${p.kind}`, top: rank(p) < 2 });
    }
  }
  for (const id of DOC_IDS) {
    add("Documentation", docTitle(id), () => go(`docs/${id}`), { icon: PI.doc, hint: docGroup(id), keys: $(id)?.querySelector(".tldr")?.textContent || "", top: false });
    for (const h of $(id)?.querySelectorAll("h3") || []) {
      const text = (h.firstChild?.textContent || h.textContent).trim();
      add("Documentation", text, () => go(`docs/${id}/${id}--${slug(text)}`), { icon: PI.hash, hint: docTitle(id), top: false });
    }
  }
  return items;
}
function openPrincipal(arn) {
  go("graph");
  const n = main.data?.nodes?.find((x) => x.id === arn);
  if (n) { showNode(n); return; }
  // Not on the attack graph (no route to admin): show its findings instead.
  go("findings");
  const q = $("find-q");
  if (q) { q.value = nameOf(arn); q.dispatchEvent(new Event("input", { bubbles: true })); }
}
// Substring matches rank first (earlier and at a word start is better), then letters in order.
function palScore(q, item) {
  const t = item.title.toLowerCase();
  const at = t.indexOf(q);
  if (at >= 0) return 1000 - at * 4 + (at === 0 || /[\s/:-]/.test(t[at - 1]) ? 200 : 0) - t.length * 0.5;
  if (item.keys.includes(q)) return 500 - item.keys.indexOf(q) * 0.1;
  let i = 0, run = 0, best = 0;
  for (const c of t) { if (c === q[i]) { i++; run++; best = Math.max(best, run); } else run = 0; if (i === q.length) break; }
  return i === q.length ? 100 + best * 10 - t.length * 0.5 : -1;
}
function palMark(title, q) {
  const at = q ? title.toLowerCase().indexOf(q) : -1;
  if (at < 0) return esc(title);
  return `${esc(title.slice(0, at))}<mark>${esc(title.slice(at, at + q.length))}</mark>${esc(title.slice(at + q.length))}`;
}
function palRender() {
  const q = $("cmdk-q").value.trim().toLowerCase();
  let list;
  if (!q) {
    list = pal.items.filter((x) => x.top);
    const per = { "Principals at risk": 5 };
    const seen = {};
    list = list.filter((x) => (seen[x.group] = (seen[x.group] || 0) + 1) <= (per[x.group] || 99));
    const order = ["Principals at risk", "Commands", "Screens"];
    list.sort((a, b) => order.indexOf(a.group) - order.indexOf(b.group));
  } else {
    list = pal.items.map((x) => ({ x, s: palScore(q, x) })).filter((r) => r.s >= 0).sort((a, b) => b.s - a.s).slice(0, 40).map((r) => r.x);
    // Group in order of each group's best match, keeping the ranking inside a group.
    const first = new Map();
    list.forEach((x, i) => { if (!first.has(x.group)) first.set(x.group, i); });
    list.sort((a, b) => first.get(a.group) - first.get(b.group));
  }
  pal.shown = list;
  pal.active = 0;
  if (!list.length) {
    $("cmdk-list").innerHTML = `<p class="cmdk-empty">Nothing matches "${esc($("cmdk-q").value.trim())}". Try a principal name, a screen or a word from the documentation.</p>`;
    $("cmdk-q").removeAttribute("aria-activedescendant");
    return;
  }
  let html = "", group = "";
  list.forEach((x, i) => {
    if (x.group !== group) { if (group) html += "</div>"; group = x.group; html += `<div class="cmdk-g" role="group" aria-label="${esc(group)}"><div class="cmdk-gh">${esc(group)}</div>`; }
    html += `<div class="cmdk-it" role="option" id="cmdk-${i}" data-i="${i}" aria-selected="false"><span class="cmdk-ic">${x.icon}</span><span class="cmdk-t">${palMark(x.title, q)}</span>${x.hint ? `<span class="cmdk-h">${esc(x.hint)}</span>` : ""}</div>`;
  });
  $("cmdk-list").innerHTML = html + "</div>";
  $("cmdk-list").scrollTop = 0;
  palActive(0);
}
function palActive(i) {
  const els = $("cmdk-list").querySelectorAll(".cmdk-it");
  if (!els.length) return;
  pal.active = (i + els.length) % els.length;
  els.forEach((el, k) => { const on = k === pal.active; el.classList.toggle("on", on); el.setAttribute("aria-selected", String(on)); });
  els[pal.active].scrollIntoView({ block: "nearest" });
  $("cmdk-q").setAttribute("aria-activedescendant", `cmdk-${pal.active}`);
}
function palOpen() {
  if (!$("cmdk").hidden) { $("cmdk-q").select(); return; }
  pal.back = document.activeElement;
  pal.items = palItems();
  $("cmdk").hidden = false;
  $("cmdk-q").value = "";
  palRender();
  $("cmdk-q").focus();
}
function palClose(restore = true) {
  if ($("cmdk").hidden) return;
  $("cmdk").hidden = true;
  if (restore && pal.back && document.contains(pal.back)) pal.back.focus();
}
function palRun(i) {
  const x = pal.shown[i];
  if (!x) return;
  palClose(false);
  x.run();
}
$("cmdk-q").addEventListener("input", palRender);
$("cmdk-q").addEventListener("keydown", (e) => {
  if (e.key === "ArrowDown") { e.preventDefault(); palActive(pal.active + 1); }
  else if (e.key === "ArrowUp") { e.preventDefault(); palActive(pal.active - 1); }
  else if (e.key === "Enter") { e.preventDefault(); palRun(pal.active); }
  else if (e.key === "Tab") e.preventDefault();
});
$("cmdk-list").addEventListener("mousemove", (e) => { const it = e.target.closest(".cmdk-it"); if (it && Number(it.dataset.i) !== pal.active) palActive(Number(it.dataset.i)); });
$("cmdk-list").addEventListener("click", (e) => { const it = e.target.closest(".cmdk-it"); if (it) palRun(Number(it.dataset.i)); });
$("cmdk").addEventListener("mousedown", (e) => { if (e.target.closest("[data-close]")) palClose(); });
$("cmdk-btn").addEventListener("click", palOpen);
$("cmdk-btn").querySelector("kbd").textContent = isMac ? "⌘K" : "Ctrl K";
window.addEventListener("keydown", (e) => {
  if ((e.key === "k" || e.key === "K") && (e.ctrlKey || e.metaKey) && !e.altKey) { e.preventDefault(); palOpen(); return; }
  if (!$("cmdk").hidden && e.key === "Escape") { e.preventDefault(); e.stopImmediatePropagation(); palClose(); return; }
  const typing = e.target.closest?.("input, textarea, select, [contenteditable]");
  if (e.key === "/" && !typing && !e.ctrlKey && !e.metaKey && !e.altKey) { e.preventDefault(); palOpen(); }
}, true);

// ------------------------------------------------------------------------------------- start

applyPrefs();
renderChangelog();
renderOverview();
renderFindings();
setSource("account");
loadEvExample(EVALUATE_EXAMPLES[0]);
go(location.hash.slice(1) || "overview");
whenReady(() => { validate(); updateRun(); });
restoreSaved();

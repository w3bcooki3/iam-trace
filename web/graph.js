// Attack-graph canvas: HTML nodes over an SVG edge layer, with pan and zoom.
// No dependencies, so it works under the page's strict Content-Security-Policy. Positions and
// sizes are set through the CSSOM (element.style), which the policy allows; inline style
// attributes are not used.

const SVG_NS = "http://www.w3.org/2000/svg";

export const ICON = {
  user: '<svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6"/></svg>',
  group: '<svg viewBox="0 0 24 24"><circle cx="9" cy="8" r="3.2"/><circle cx="17" cy="9.5" r="2.6"/><path d="M3 20c1-3.4 3.4-5.2 6-5.2s5 1.8 6 5.2M15.5 14.6c2.6.1 4.6 1.8 5.5 4.9"/></svg>',
  role: '<svg viewBox="0 0 24 24"><path d="M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6z"/><circle cx="12" cy="11" r="2.5"/></svg>',
  resource: '<svg viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="3"/><path d="M9 12h6M12 9v6"/></svg>',
  admin: '<svg viewBox="0 0 24 24"><path d="M3 18l2-11 5 5 2-7 2 7 5-5 2 11z"/><path d="M3 21h18"/></svg>',
  target: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="4"/><circle cx="12" cy="12" r="0.8"/></svg>',
  outside: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z"/></svg>',
};
export const KIND_COLOR = { user: "var(--accent-2)", group: "var(--muted)", role: "var(--accent)", resource: "var(--warn)", admin: "var(--crit)", target: "var(--crit)", outside: "var(--warn)" };
export const KIND_NAME = { user: "IAM user", group: "IAM group", role: "IAM role", resource: "Resource", admin: "Account takeover", target: "The resource", outside: "Outside the export" };

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

// Spacing and the shape edges attach to, per node style.
const GEO = {
  card: { col: 330, row: 185, shape: { w: 252, h: 150 }, iconY: 0, half: [140, 90] },
  n8n: { col: 220, row: 170, shape: { half: 39 }, iconY: -20, half: [80, 70] },
  wiz: { col: 210, row: 160, shape: { r: 30 }, iconY: -20, half: [80, 70] },
};

// Columns by breadth-first distance from the start; "Full control" always last.
export function layout(nodes, edges, start) {
  // A caller can place every node itself (Who can lays principals out by distance to the resource).
  if (nodes.length && nodes.every((n) => Number.isInteger(n.col))) return columns(nodes, (n) => n.col);
  const depth = new Map();
  if (start) depth.set(start, 0);
  const queue = start ? [start] : [];
  while (queue.length) {
    const cur = queue.shift();
    for (const e of edges) {
      if (e.from === cur && !depth.has(e.to) && e.to !== "admin") {
        depth.set(e.to, depth.get(cur) + 1);
        queue.push(e.to);
      }
    }
  }
  let max = 0;
  for (const n of nodes) {
    if (n.id === "admin") continue;
    if (!depth.has(n.id)) depth.set(n.id, 1);
    max = Math.max(max, depth.get(n.id));
  }
  if (nodes.some((n) => n.id === "admin")) depth.set("admin", max + 1);
  return columns(nodes, (n) => depth.get(n.id));
}

function columns(nodes, colOf) {
  const cols = new Map();
  for (const n of nodes) {
    const d = colOf(n);
    if (!cols.has(d)) cols.set(d, []);
    cols.get(d).push(n.id);
  }
  const tallest = Math.max(1, ...[...cols.values()].map((c) => c.length));
  const pos = new Map();
  for (const [d, ids] of cols) {
    const offset = (tallest - ids.length) / 2;
    ids.forEach((id, i) => pos.set(id, { x: d, y: offset + i }));
  }
  return pos;
}

function attach(a, b, s) {
  const dx = b.px - a.px;
  const dy = b.py - a.py;
  if (s.w) {
    const side = Math.abs(dx) >= 60 ? Math.sign(dx) : 0;
    if (side) return { x: a.px + side * (s.w / 2 + 6), y: a.py - s.h / 2 + 37, h: true };
    return { x: a.px, y: a.py + Math.sign(dy || 1) * (s.h / 2 + 6), h: false };
  }
  if (s.half) {
    const k = (s.half + 7) / Math.max(Math.abs(dx), Math.abs(dy), 1);
    return { x: a.px + dx * k, y: a.py + dy * k, h: Math.abs(dx) > Math.abs(dy) };
  }
  const len = Math.hypot(dx, dy) || 1;
  return { x: a.px + (dx / len) * (s.r + 9), y: a.py + (dy / len) * (s.r + 9), h: Math.abs(dx) > Math.abs(dy) };
}

function badges(n) {
  const t = [];
  if (n.admin && n.kind !== "admin") t.push('<span class="tag crit">Admin-equivalent</span>');
  if (n.notSpecific) t.push('<span class="tag warn">Not a specific principal</span>');
  return t.join("");
}

function nodeHtml(n, style) {
  if (style === "card") {
    const cls = ["n", "card", n.start ? "start" : "", n.admin ? "risk" : "", n.kind === "admin" || n.kind === "target" ? "takeover" : ""].join(" ");
    const foot = n.foot
      ? n.foot.map(([v, l]) => `<div><b>${esc(String(v))}</b>${esc(l)}</div>`).join("")
      : n.kind === "admin"
        ? "<div><b>All</b>actions</div><div><b>All</b>resources</div>"
        : `<div><b>${n.techniques}</b>techniques</div><div><b>${n.policies ?? "-"}</b>policies</div>`;
    return `<div class="${cls}" data-id="${esc(n.id)}"><span class="port l"></span><span class="port r"></span>
      <div class="c-top"><span class="c-ic ic">${ICON[n.kind] || ICON.resource}</span><div class="c-title"><b>${esc(n.label)}</b><span>${KIND_NAME[n.kind] || "Principal"}</span></div>
      ${n.start && n.reachesAdmin ? '<span class="c-risk tag crit">Critical</span>' : ""}</div>
      <div class="c-arn" title="${esc(n.subtitle)}">${esc(n.kind === "admin" ? "account-wide" : n.subtitle)}</div>${badges(n) ? `<div class="c-badges">${badges(n)}</div>` : ""}<div class="c-foot">${foot}</div></div>`;
  }
  if (style === "n8n") {
    const tag = n.start ? '<div class="tags"><span class="tag acc">Attacker</span></div>' : n.admin && n.kind !== "admin" ? '<div class="tags"><span class="tag crit">Admin-equivalent</span></div>' : "";
    return `<div class="n n8n" data-id="${esc(n.id)}"><div class="box"><span class="ic">${ICON[n.kind] || ICON.resource}</span><span class="port l"></span><span class="port r"></span></div>
      <div class="name">${esc(n.label)}</div><div class="sub">${esc(n.subtitle)}</div>${tag}</div>`;
  }
  const risky = n.admin || n.kind === "admin";
  return `<div class="n wiz ${risky ? "risky" : ""} ${n.start ? "start" : ""}" data-id="${esc(n.id)}"><div class="ring"><span class="ic">${ICON[n.kind] || ICON.resource}</span>${n.techniques ? `<span class="count">${n.techniques}</span>` : ""}</div>
    <div class="name">${esc(n.label)}</div><div class="sub">${esc(n.subtitle)}</div></div>`;
}

// "MFA", "Network", "Time", or several of them, for a gated edge's label.
export function gateShort(requires = []) {
  const names = { mfa: "MFA", network: "Network", time: "Time" };
  return [...new Set(requires.map((r) => names[r.kind] || r.kind))].join(" + ");
}

export class Graph {
  constructor(surface, world, { interactive = true, onSelect, onEdge, pad = 60, maxScale = 1.1, insets, markerPrefix = "g" } = {}) {
    Object.assign(this, { surface, world, interactive, onSelect, onEdge, pad, maxScale, insets, markerPrefix });
    this.view = { s: 1, x: 0, y: 0 };
    this.data = null;
    this.focus = null;
    this.selected = null;
    this.hidePossible = false;
    this.cut = new Set(); // "from|to" steps switched off in what-if mode
    if (interactive) this.panZoom();
    new ResizeObserver(() => this.fit()).observe(surface);
  }

  // data: { nodes: [...], edges: [{from, to, label, name, confidence, paths: Set}], start }
  setData(data) {
    this.data = data;
    this.focus = null;
    this.selected = null;
    this.render();
  }

  render() {
    const w = this.world;
    w.querySelectorAll(".n, .elabel").forEach((e) => e.remove());
    const svg = w.querySelector("svg");
    if (!this.data || !this.data.nodes.length) {
      svg.innerHTML = "";
      this.bounds = null;
      return;
    }
    const style = document.documentElement.dataset.nodes || "card";
    const g = GEO[style];
    const pos = layout(this.data.nodes, this.data.edges, this.data.start);
    const byId = new Map();
    for (const n of this.data.nodes) {
      const p = pos.get(n.id);
      n.px = 160 + p.x * g.col;
      n.py = 120 + p.y * g.row + g.iconY;
      byId.set(n.id, n);
    }
    const edges = this.data.edges.filter((e) => !(this.hidePossible && e.confidence === "possible"));
    const visible = new Set([this.data.start, ...edges.flatMap((e) => [e.from, e.to])]);
    const mp = this.markerPrefix;
    let paths = `<defs>${["crit", "warn", "faint", "high"].map((c) => `<marker id="${mp}-${c}" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 1L9 5L0 9z" class="mk-${c}"/></marker>`).join("")}</defs>`;
    const labels = [];
    for (const e of edges) {
      const a = byId.get(e.from);
      const b = byId.get(e.to);
      if (!a || !b) continue;
      const p1 = attach(a, b, g.shape);
      const p2 = attach(b, a, g.shape);
      const c = Math.max(50, Math.abs(p2.x - p1.x) * 0.5);
      const dir = Math.sign(p2.x - p1.x) || 1;
      const d = p1.h && p2.h
        ? `M${p1.x},${p1.y} C${p1.x + dir * c},${p1.y} ${p2.x - dir * c},${p2.y} ${p2.x},${p2.y}`
        : `M${p1.x},${p1.y} L${p2.x},${p2.y}`;
      const dim = this.focus !== null && !(e.paths && e.paths.has(this.focus)) ? " dim" : "";
      const cut = this.cut.has(`${e.from}|${e.to}`);
      const type = cut ? "cut" : e.confidence === "possible" ? "poss" : e.requires ? "gated" : "conf";
      const hot = type === "conf" && e.paths && e.paths.size && !dim ? " hot" : "";
      const marker = type === "conf" ? "crit" : type === "cut" ? "faint" : type === "gated" ? "high" : "warn";
      paths += `<path class="e ${type}${hot}${dim}" d="${d}" marker-end="url(#${mp}-${marker})"/>`;
      if (!dim && !cut && type !== "gated") paths += `<path class="e flow" d="${d}"/>`;
      labels.push({ e, type, x: (p1.x + p2.x) / 2, y: (p1.y + p2.y) / 2, dim });
    }
    svg.innerHTML = paths;
    for (const l of labels) {
      const el = document.createElement(this.interactive ? "button" : "span");
      el.className = `elabel ${l.type}${l.dim}`;
      el.textContent = l.e.label;
      if (l.type === "gated") {
        const gate = document.createElement("small");
        gate.textContent = gateShort(l.e.requires);
        el.appendChild(gate);
      }
      el.title = l.e.requires ? `${l.e.name}. Only when ${l.e.requires.map((r) => r.text).join("; ")}.` : l.e.name;
      el.style.left = `${l.x}px`;
      el.style.top = `${l.y}px`;
      if (this.interactive) el.addEventListener("click", (ev) => { ev.stopPropagation(); this.onEdge?.(l.e, el); });
      w.appendChild(el);
    }
    for (const n of this.data.nodes) {
      if (!visible.has(n.id)) continue;
      w.insertAdjacentHTML("beforeend", nodeHtml(n, style));
      const el = w.lastElementChild;
      el.style.left = `${n.px}px`;
      el.style.top = `${n.py - g.iconY}px`;
      el.style.setProperty("--kind", KIND_COLOR[n.kind] || KIND_COLOR.resource);
      if (this.focus !== null && !n.paths?.has(this.focus)) el.classList.add("dim");
      if (this.interactive) {
        el.tabIndex = 0;
        el.setAttribute("role", "button");
        el.setAttribute("aria-label", `${n.label}, ${KIND_NAME[n.kind] || "principal"}`);
        el.addEventListener("click", (ev) => { ev.stopPropagation(); this.onSelect?.(n); });
        el.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); this.onSelect?.(n); } });
      }
    }
    this.mark();
    const shown = this.data.nodes.filter((n) => visible.has(n.id));
    const xs = shown.map((n) => n.px);
    const ys = shown.map((n) => n.py);
    const [hw, hh] = g.half;
    this.bounds = { x0: Math.min(...xs) - hw, x1: Math.max(...xs) + hw, y0: Math.min(...ys) - hh, y1: Math.max(...ys) + hh + (style === "card" ? 0 : 40) };
    this.fit();
  }

  mark() {
    this.world.querySelectorAll(".n").forEach((el) => el.classList.toggle("sel", el.dataset.id === this.selected));
  }

  fit() {
    if (!this.bounds) return;
    const r = this.surface.getBoundingClientRect();
    if (!r.width) return;
    const ins = this.insets ? this.insets() : { l: 0, r: 0, t: 0, b: 0 };
    const w = r.width - ins.l - ins.r - this.pad * 2;
    const h = r.height - ins.t - ins.b - this.pad * 2;
    const bw = this.bounds.x1 - this.bounds.x0;
    const bh = this.bounds.y1 - this.bounds.y0;
    this.view.s = Math.max(0.25, Math.min(this.maxScale, w / bw, h / bh));
    this.view.x = ins.l + this.pad + (w - bw * this.view.s) / 2 - this.bounds.x0 * this.view.s;
    // On a phone, fitting everything makes cards unreadable. Keep them legible, start at the left
    // (where the attacker is) and let the reader pan along the path.
    if (r.width < 600 && this.interactive && this.view.s < 0.6) {
      this.view.s = 0.6;
      this.view.x = this.pad - this.bounds.x0 * this.view.s;
    }
    this.view.y = ins.t + this.pad + (h - bh * this.view.s) / 2 - this.bounds.y0 * this.view.s;
    this.apply();
  }

  apply() {
    this.world.style.transform = `translate(${this.view.x}px, ${this.view.y}px) scale(${this.view.s})`;
  }

  zoom(f, cx, cy) {
    const r = this.surface.getBoundingClientRect();
    const x = cx ?? r.width / 2;
    const y = cy ?? r.height / 2;
    const ns = Math.max(0.2, Math.min(2.5, this.view.s * f));
    this.view.x = x - ((x - this.view.x) * ns) / this.view.s;
    this.view.y = y - ((y - this.view.y) * ns) / this.view.s;
    this.view.s = ns;
    this.apply();
  }

  panZoom() {
    let s = null;
    const el = this.surface;
    el.addEventListener("pointerdown", (e) => {
      if (e.target.closest(".n, .elabel")) return;
      s = { x: e.clientX, y: e.clientY, vx: this.view.x, vy: this.view.y };
      el.classList.add("panning");
      el.setPointerCapture(e.pointerId);
    });
    el.addEventListener("pointermove", (e) => {
      if (!s) return;
      this.view.x = s.vx + e.clientX - s.x;
      this.view.y = s.vy + e.clientY - s.y;
      this.apply();
    });
    const end = () => { s = null; el.classList.remove("panning"); };
    el.addEventListener("pointerup", end);
    el.addEventListener("pointercancel", end);
    el.addEventListener("wheel", (e) => {
      if (!this.bounds) return;
      e.preventDefault();
      const r = el.getBoundingClientRect();
      this.zoom(e.deltaY < 0 ? 1.08 : 1 / 1.08, e.clientX - r.left, e.clientY - r.top);
    }, { passive: false });
  }
}

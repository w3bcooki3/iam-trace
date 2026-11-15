// A self-contained HTML report of an account analysis, for people who will never open iam-trace:
// one file, no scripts, light colours, and print rules so "Save as PDF" gives clean pages.

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const short = (arn) => (String(arn).startsWith("arn:") ? String(arn).split(":").slice(5).join(":") : String(arn));
function policyLabel(id) {
  const inl = /^(arn:\S+) inline (.+)$/.exec(id);
  if (inl) return `inline policy ${inl[2]} on ${short(inl[1])}`;
  const trust = /^(arn:\S+) trust policy$/.exec(id);
  return trust ? `trust policy of ${short(trust[1])}` : `managed policy ${short(id)}`;
}
const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
const account = (m) => (m.principals[0]?.arn || m.start || "").split(":")[4] || "unknown";

function steps(path) {
  const rows = [`<li class="node">${esc(short(path.start))}</li>`];
  for (const s of path.steps) {
    rows.push(`<li class="edge"><b>${esc(s.technique)}</b> ${esc(s.name || "")}</li>`);
    rows.push(`<li class="node">${esc(short(s.to))}</li>`);
  }
  return `<ol class="steps">${rows.join("")}</ol>`;
}

function status(p) {
  if (p.admin_equivalent) return ["crit", "Admin-equivalent"];
  if (p.path) return ["high", "Can reach admin"];
  if (p.confirmed) return ["warn", "Can escalate"];
  if (p.possible) return ["warn", "Possible only"];
  return ["ok", "No known technique"];
}

export function buildReport(m, { version, fixes, plan = null, generated = new Date() }) {
  const ps = m.principals;
  const admins = ps.filter((p) => p.admin_equivalent);
  const reach = ps.filter((p) => !p.admin_equivalent && p.path);
  const shortest = reach.length ? Math.min(...reach.map((p) => p.path.steps.length)) : null;
  // Techniques of principals that are already admin add no risk, so they are not counted.
  const notAdmin = ps.filter((p) => !p.admin_equivalent);
  const confirmed = notAdmin.reduce((a, p) => a + (p.confirmed || 0), 0);
  const possible = notAdmin.reduce((a, p) => a + (p.possible || 0), 0);
  const acct = account(m);
  const when = generated.toLocaleString(undefined, { dateStyle: "long", timeStyle: "short" });
  const verdict = reach.length
    ? `${plural(reach.length, "principal")} that ${reach.length === 1 ? "is" : "are"} not administrators can become one, the shortest in ${plural(shortest, "step")}.`
    : "No principal that is not already an administrator can become one with a confirmed technique.";
  const tone = reach.length ? "crit" : "ok";
  // One path per starting principal: the shortest.
  const firstPath = new Map();
  for (const p of m.allPaths) {
    const cur = firstPath.get(p.start);
    if (!cur || p.steps.length < cur.steps.length) firstPath.set(p.start, p);
  }
  const paths = [...firstPath.values()].sort((a, b) => a.steps.length - b.steps.length || a.start.localeCompare(b.start));
  const order = { crit: 0, high: 1, warn: 2, ok: 3 };
  const rows = [...ps].sort((a, b) => order[status(a)[0]] - order[status(b)[0]] || a.arn.localeCompare(b.arn));

  const css = `
  :root { --text: #15181e; --muted: #555d6b; --line: #e2e5ea; --crit: #c8102e; --high: #c2410c; --warn: #a16207; --ok: #15803d; --accent: #1f5fd6; }
  * { box-sizing: border-box; }
  body { margin: 0; font: 15px/1.6 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color: var(--text); background: #fff; }
  main { max-width: 900px; margin: 0 auto; padding: 48px 32px 64px; }
  h1 { font-size: 30px; line-height: 1.2; margin: 6px 0 4px; letter-spacing: -0.02em; }
  h2 { font-size: 20px; margin: 40px 0 12px; padding-top: 18px; border-top: 1px solid var(--line); }
  .meta { color: var(--muted); font-size: 14px; }
  .brand { font: 600 14px ui-monospace, Menlo, Consolas, monospace; color: var(--accent); }
  .verdict { margin: 24px 0 8px; padding: 18px 20px; border: 1px solid var(--line); border-radius: 10px; font-size: 17px; }
  .verdict b { color: var(--${tone}); }
  .nums { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 16px 0 0; }
  .nums div { border: 1px solid var(--line); border-radius: 10px; padding: 12px 14px; }
  .nums b { display: block; font-size: 24px; line-height: 1.2; }
  .nums span { color: var(--muted); font-size: 13px; }
  .card { border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px; margin: 10px 0; break-inside: avoid; }
  .card h3 { margin: 0; font-size: 15px; }
  .card p { margin: 6px 0 0; color: var(--muted); font-size: 14px; }
  .steps { list-style: none; margin: 10px 0 0; padding: 0 0 0 16px; border-left: 2px solid var(--line); }
  .steps .node { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 13.5px; padding: 2px 0; }
  .steps .edge { color: var(--muted); font-size: 13px; padding: 1px 0 1px 10px; }
  .steps .edge b { color: var(--crit); font-family: ui-monospace, Menlo, Consolas, monospace; font-weight: 600; }
  .mono { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 13.5px; overflow-wrap: anywhere; }
  pre { margin: 6px 0 14px; padding: 12px 14px; border: 1px solid var(--line); border-radius: 6px; background: #f7f8fa; font: 12.5px/1.5 ui-monospace, Menlo, Consolas, monospace; white-space: pre-wrap; overflow-wrap: anywhere; break-inside: avoid; }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
  th { font-weight: 600; color: var(--muted); font-size: 13px; }
  tr { break-inside: avoid; }
  .s { font-weight: 600; white-space: nowrap; } .s.crit { color: var(--crit); } .s.high { color: var(--high); } .s.warn { color: var(--warn); } .s.ok { color: var(--ok); }
  .small { font-size: 13px; color: var(--muted); }
  ul.notes { padding-left: 20px; color: var(--muted); font-size: 14px; }
  footer { margin-top: 48px; padding-top: 16px; border-top: 1px solid var(--line); color: var(--muted); font-size: 13px; }
  a { color: var(--accent); }
  @media (max-width: 640px) { main { padding: 28px 18px 48px; } .nums { grid-template-columns: repeat(2, 1fr); } }
  @page { margin: 18mm 16mm; }
  @media print { main { padding: 0; max-width: none; } h2 { break-after: avoid; } a { color: inherit; text-decoration: none; } }`;

  const pathsHtml = paths.length
    ? paths.map((p) => `<div class="card"><h3>${esc(short(p.start))} reaches ${esc(short(p.end))} in ${plural(p.steps.length, "step")}</h3>${p.why ? `<p>${esc(short(p.end))} is admin-equivalent: it is ${esc(p.why)}.</p>` : ""}${steps(p)}</div>`).join("")
    : "<p>None found. Every escalation technique checked either needs a permission nobody has, or leads nowhere new.</p>";
  const planHtml = plan && plan.changes.length ? (() => {
    const n = plan.changes.length;
    const head = `<p class="meta">The fewest changes that remove every confirmed path to admin in the account: ${plural(n, "Deny statement")}, targeted to the resource wherever possible. ${plan.verified ? `Verified: the account with these changes was analysed again, with ${plural(plan.paths_before, "path")} to admin before and none after.` : "Not verified: analysing the changed account again still found a path."}${plan.not_covered ? ` ${plural(plan.not_covered, "possible technique")} depend on resources the export does not describe and are not covered.` : ""}</p>`;
    const cards = plan.changes.map((c, i) => `<div class="card"><h3>${i + 1}. Deny <span class="mono">${esc(c.actions.join(", "))}</span> for ${esc(short(c.principal))} on ${c.resources.map((r) => esc(r === "*" ? "every resource" : short(r))).join(", ")}</h3>
        <p>${esc(c.consequence)}</p>
        <p>Breaks ${c.breaks.map((b) => `<span class="mono">${esc(b.technique)}</span> ${esc(short(b.from))} to ${esc(b.to === "admin" ? "admin" : short(b.to))}`).join("; ")}.</p>
        ${c.granted_by.length ? `<p>Instead of a Deny, you can narrow: ${c.granted_by.map((g) => `${esc(policyLabel(g.policy))}, ${esc(g.statement)}`).join("; ")}.</p>` : ""}</div>`).join("");
    const pols = Object.entries(plan.policies).map(([who, doc]) => `<h3>Inline policy for ${esc(short(who))}</h3><pre>${esc(JSON.stringify(doc, null, 2))}</pre>`).join("");
    const nar = plan.narrowed;
    const narrowed = nar && nar.edits.length ? `<h3>Instead: narrow the Allow statements${nar.verified ? " (verified)" : nar.complete ? " (not verified)" : " (partial)"}</h3>
      <p class="meta">Edit the statements that grant the permissions instead of adding Deny statements.</p>
      ${nar.edits.map((e) => `<p><b>${esc(policyLabel(e.policy))}</b>, affects ${e.affects.map((a) => esc(short(a))).join(", ") || "nobody"}${e.also_removes.length ? `. Also no longer allows ${e.also_removes.map(esc).join("; ")}` : ""}.</p>${e.delete ? "<p>Delete this policy: it grants nothing else.</p>" : `<pre>${esc(JSON.stringify(e.document, null, 2))}</pre>`}`).join("")}
      ${nar.problems.map((x) => `<p class="small">${esc(x)}</p>`).join("")}` : "";
    const scp = plan.scp ? `<h3>Or: one SCP${plan.scp.verified ? " (verified)" : ""}</h3><pre>${esc(JSON.stringify(plan.scp.policy, null, 2))}</pre>${plan.scp.notes.map((x) => `<p class="small">${esc(x)}</p>`).join("")}` : "";
    return head + cards + pols + narrowed + scp;
  })() : null;
  const entries = (m.entry && m.entry.entries) || [];
  const entryHtml = entries.length ? `<h2>Entry points</h2>
  <p class="meta">Where an attack could start: IAM users, whose keys or password can leak, and roles that someone outside the account can assume. Each trust policy was tested with the evaluator, for example by asking whether a GitHub workflow in a repository you do not own can assume the role.</p>
  <table><thead><tr><th>Principal</th><th>Rating</th><th>Who can get in</th><th>Reaches</th></tr></thead><tbody>${entries.map((e) => {
    const imp = e.impact;
    const reach = imp.admin ? "Is admin-equivalent" : imp.steps ? `Admin in ${plural(imp.steps, "step")}` : imp.confirmed ? `${plural(imp.confirmed, "technique")}, no path` : "No known technique";
    return `<tr><td class="mono">${esc(short(e.principal))}</td><td><span class="s ${{ Critical: "crit", High: "high", Medium: "warn", Low: "ok" }[e.rating]}">${e.rating}</span></td><td>${esc(e.exposure.who)}${e.exposure.fix ? `<br><span class="small">${esc(e.exposure.fix)}</span>` : ""}</td><td>${reach}</td></tr>`;
  }).join("")}</tbody></table>` : "";
  const fixHtml = planHtml ?? (fixes.length
    ? fixes.map((f, i) => `<div class="card"><h3>${i + 1}. Narrow <span class="mono">${esc(f.permissions.join(", "))}</span> for ${esc(short(f.from))}</h3>
        <p>Removes ${esc(f.technique)} (${esc(f.name)}). Used by ${plural(f.paths, "path")} from ${plural(f.starts.size ?? f.starts.length ?? 0, "starting principal")}. Scope the permission to the resources this principal needs, add a condition, or move it to a separate role.</p></div>`).join("")
    : "<p>Nothing to fix: no confirmed path to admin.</p>");
  const tableHtml = rows.map((p) => {
    const [t, label] = status(p);
    const path = p.admin_equivalent ? "Is admin" : p.path ? `${plural(p.path.steps.length, "step")}: ${p.path.steps.map((s) => esc(s.technique)).join(", ")}` : "None";
    return `<tr><td class="mono">${esc(short(p.arn))}</td><td><span class="s ${t}">${label}</span></td><td>${path}</td><td>${p.confirmed}</td><td>${p.possible}</td></tr>`;
  }).join("");
  const notes = [
    m.scps ? `${plural(m.scps, "SCP")} applied.` : "No SCPs were supplied. If the account is in AWS Organizations, SCPs may block some of these paths.",
    m.resources ? `A resource inventory of ${plural(Object.values(m.resources).reduce((a, b) => a + b, 0), "resource")} was used to confirm techniques that take over existing resources.` : "No resource inventory was supplied, so techniques that take over existing resources (Lambda functions, EC2 instances) are counted as possible, not confirmed.",
    `${plural(possible, "possible technique")} depend on resources the export does not describe. Check them by hand or add an inventory.`,
    "Only this account was analysed. Paths into other accounts are not followed.",
    "iam-trace is in beta. If an answer looks wrong, please report it on GitHub.",
  ];

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>iam-trace report: account ${esc(acct)}</title><style>${css}</style></head>
<body><main>
  <div class="brand">iam-trace</div>
  <h1>Privilege escalation report</h1>
  <div class="meta">Account <b>${esc(acct)}</b>. Source: ${esc(m.source)}${m.example ? " (the example account)" : ""}. Generated ${esc(when)} with iam-trace ${esc(version || "")}.</div>
  <div class="verdict"><b>${reach.length ? "At risk." : "No confirmed path to admin."}</b> ${esc(verdict)}</div>
  <div class="nums">
    <div><b>${ps.length}</b><span>principals analysed</span></div>
    <div><b>${admins.length}</b><span>already admin-equivalent</span></div>
    <div><b>${reach.length}</b><span>can become admin</span></div>
    <div><b>${confirmed}</b><span>confirmed techniques for non-admins</span></div>
  </div>

  ${entryHtml}
  <h2>Paths to admin</h2>
  <p class="meta">The shortest path for each principal that can become an administrator. Each step is a published technique from pathfinding.cloud that the principal's policies allow.</p>
  ${pathsHtml}

  <h2>${planHtml ? "Fix plan" : "What to fix first"}</h2>
  ${planHtml ? "" : '<p class="meta">The permissions that the most paths depend on. Removing or narrowing one breaks every path that uses it.</p>'}
  ${fixHtml}

  <h2>Every principal</h2>
  <table><thead><tr><th>Principal</th><th>Status</th><th>Shortest path to admin</th><th>Confirmed</th><th>Possible</th></tr></thead><tbody>${tableHtml}</tbody></table>

  <h2>Scope and limits</h2>
  <ul class="notes">${notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul>

  <footer>Made with iam-trace, an open-source tool that explains what AWS IAM policies allow. The analysis ran in a web browser; the account export was never uploaded. <a href="https://github.com/w3bcooki3/iam-trace">github.com/w3bcooki3/iam-trace</a></footer>
</main></body></html>`;
}

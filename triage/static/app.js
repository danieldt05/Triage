// Triage front end. All data is rendered with textContent via el(): responses
// contain headers and records from arbitrary servers, so nothing from the API
// is ever inserted as HTML.
"use strict";

const $ = (id) => document.getElementById(id);
const previous = new Map();   // host -> last result, for "what changed"
let current = null;
let activeTab = "dns";
let timer = null;

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function toast(message) {
  const t = $("toast");
  t.textContent = message;
  t.classList.add("show");
  clearTimeout(toast.hide);
  toast.hide = setTimeout(() => t.classList.remove("show"), 1800);
}

async function copy(text, done) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const area = el("textarea", { style: "position:fixed;opacity:0" }, text);
    document.body.append(area);
    area.select();
    document.execCommand("copy");
    area.remove();
  }
  toast(done);
}

function show(which) {
  for (const id of ["empty", "loading", "error", "result"]) $(id).hidden = id !== which;
}

// ---------------------------------------------------------------- running

async function run(url, expected) {
  url = url.trim();
  if (!url) return;
  $("url").value = url;
  $("expected").value = expected || "";
  $("go").disabled = $("recheck").disabled = true;
  $("loading-host").textContent = url;
  show("loading");
  const started = Date.now();
  clearInterval(timer);
  $("loading-timer").textContent = "";
  timer = setInterval(() => { $("loading-timer").textContent = `${Math.round((Date.now() - started) / 1000)} s`; }, 500);

  const params = new URLSearchParams({ url });
  if (expected) params.set("expected", expected);
  history.replaceState(null, "", `/?${params}`);

  try {
    const resp = await fetch(`/api/diagnose?${params}`);
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(body.detail || `The check failed (HTTP ${resp.status}). Try again.`);
    const prev = previous.get(body.host) || null;
    previous.set(body.host, body);
    current = body;
    render(body, prev);
    show("result");
    document.title = `Triage: ${body.host}`;
  } catch (err) {
    $("error").textContent = err.message === "Failed to fetch"
      ? "Couldn't reach the Triage server. Check your connection and try again."
      : err.message;
    show("error");
  } finally {
    clearInterval(timer);
    $("go").disabled = $("recheck").disabled = false;
  }
}

// ---------------------------------------------------------------- rendering

const LEVEL_LABEL = { error: "Error", warning: "Warning", info: "Note" };
const LEVEL_TONE = { error: "err", warning: "warn", info: "ok" };

function render(r, prev) {
  $("v-label").className = `pill tone-${r.verdict.tone}`;
  $("v-label").textContent = r.verdict.label;
  $("v-host").textContent = r.host;
  $("v-headline").textContent = r.verdict.headline;
  $("v-summary").textContent = r.verdict.summary;
  const at = new Date(r.checked_at);
  $("checked-at").textContent = `Checked at ${at.toLocaleTimeString()} · took ${(r.duration_ms / 1000).toFixed(1)} s`;

  renderPath(r.path);
  renderChanges(r, prev);
  renderDiagnoses(r.diagnoses);
  renderHealthy(r.healthy);
  renderTabs(r.raw);
  $("reply").textContent = r.reply;
}

function renderPath(steps) {
  const list = $("path");
  list.replaceChildren(...steps.map((s, i) => {
    const before = steps[i - 1];
    const cls = before && before.tone === "err" ? "after-err" : (s.tone === "idle" && i > 0 ? "after-idle" : null);
    return el("li", { class: cls },
      el("div", { class: `node node-${s.tone}` },
        el("span", { class: "n" }, `${i + 1}. ${s.step}`),
        el("span", { class: "name" }, s.name),
        el("span", { class: "value" }, s.value),
        el("span", { class: `pill tone-${s.tone}` }, s.status)));
  }));
  const broken = steps.findIndex((s) => s.tone === "err");
  const warned = steps.findIndex((s) => s.tone === "warn");
  $("path-note").textContent = broken >= 0 ? `Breaks at step ${broken + 1}: ${steps[broken].step.toLowerCase()}`
    : warned >= 0 ? `Warning at step ${warned + 1}: ${steps[warned].step.toLowerCase()}`
    : "Every step checked out";
}

function renderChanges(r, prev) {
  const box = $("changes");
  if (!prev) { box.hidden = true; return; }
  box.hidden = false;
  $("changes-when").textContent = `Compared with the check at ${new Date(prev.checked_at).toLocaleTimeString()}`;
  const rows = [];
  for (const [key, now] of Object.entries(r.facts)) {
    const before = prev.facts[key];
    if (before !== now) rows.push(el("dt", {}, key), el("dd", {}, el("del", {}, before), "  →  ", el("ins", {}, now)));
  }
  if (!rows.length) rows.push(el("dt", {}, "Result"), el("dd", {}, "Nothing changed"));
  $("changes-list").replaceChildren(...rows);
}

function renderDiagnoses(diags) {
  $("diagnoses").replaceChildren(...diags.map((d, i) => {
    const tone = LEVEL_TONE[d.level];
    const bodyId = `diag-${i}`;
    const open = i === 0 && d.level !== "info";
    const body = el("div", { class: "diag-body", id: bodyId, hidden: !open },
      el("p", { class: "diag-summary" }, d.summary),
      el("div", { class: "diag-cols" },
        el("div", {}, el("h3", {}, "Evidence"),
          el("dl", { class: "kv" }, d.evidence.flatMap(([src, text]) => [el("dt", {}, src), el("dd", {}, text)]))),
        d.fix.length ? el("div", {}, el("h3", {}, "How to fix it"), el("ol", { class: "steps" }, d.fix.map((f) => el("li", {}, f)))) : null),
      d.reply ? el("div", { class: "diag-reply" },
        el("div", {}, el("h3", { class: "small muted" }, "What to tell the customer"), el("p", {}, d.reply)),
        el("button", { type: "button", class: "btn", onclick: () => copy(d.reply, "Reply copied") }, "Copy")) : null,
      el("p", { class: "diag-conf-why" }, `${d.confidence} confidence: ${d.confidence_reason} Rule ${d.id}.`));
    const sign = el("span", { class: "diag-sign", "aria-hidden": "true" }, open ? "−" : "+");
    const head = el("button", {
      type: "button", class: "diag-head", "aria-expanded": String(open), "aria-controls": bodyId,
      onclick: () => {
        const nowOpen = body.hidden;
        body.hidden = !nowOpen;
        head.setAttribute("aria-expanded", String(nowOpen));
        sign.textContent = nowOpen ? "−" : "+";
      },
    },
      el("span", { class: `pill tone-${tone}` }, LEVEL_LABEL[d.level]),
      el("span", { class: "diag-title" }, d.title),
      el("span", { class: "diag-rule" }, d.id),
      el("span", { class: "diag-conf" }, `${d.confidence} confidence`),
      sign);
    return el("article", { class: `diag diag-${tone}` }, head, body);
  }));
}

function renderHealthy(items) {
  $("healthy-wrap").hidden = !items.length;
  $("healthy").replaceChildren(...items.map((h) =>
    el("li", {}, el("span", { class: "tick", "aria-hidden": "true" }, "✓"), el("strong", {}, h.name), el("span", { class: "v", title: h.value }, h.value))));
}

const TABS = [["dns", "DNS records"], ["delegation", "Nameservers"], ["propagation", "Propagation"],
              ["tls", "Certificate"], ["http", "HTTP"], ["registration", "Registration"]];

function renderTabs(raw) {
  $("tabs").replaceChildren(...TABS.map(([key, label]) => el("button", {
    type: "button", role: "tab", "aria-selected": String(key === activeTab),
    onclick: () => { activeTab = key; renderTabs(raw); },
  }, label)));
  const section = raw[activeTab];
  $("raw-panel").replaceChildren(
    el("dl", { class: "kv" }, section.rows.flatMap((row) => [el("dt", {}, row.k), el("dd", {}, row.v)])),
    el("div", { class: "cmds" }, el("h3", {}, "Check it yourself"),
      section.commands.map((c) => el("div", { class: "cmd" }, el("code", {}, c),
        el("button", { type: "button", onclick: () => copy(c, "Command copied") }, "Copy")))));
}

// ---------------------------------------------------------------- wiring

$("form").addEventListener("submit", (e) => { e.preventDefault(); run($("url").value, $("expected").value.trim()); });
$("recheck").addEventListener("click", () => current && run(current.url, current.expected || ""));
$("copy-reply").addEventListener("click", () => current && copy(current.reply, "Reply copied"));
$("copy-link").addEventListener("click", () => copy(location.href, "Link copied"));
$("download").addEventListener("click", () => {
  if (!current) return;
  const blob = new Blob([JSON.stringify(current, null, 2)], { type: "application/json" });
  const a = el("a", { href: URL.createObjectURL(blob), download: `triage-${current.host}.json` });
  document.body.append(a); a.click(); a.remove();
});
$("examples").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-url]");
  if (b) run(b.dataset.url, "");
});

const initial = new URLSearchParams(location.search);
if (initial.get("url")) run(initial.get("url"), initial.get("expected") || "");

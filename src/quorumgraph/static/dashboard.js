// QuorumGraph operator dashboard. Vanilla JS, no dependencies, no build step.
// All user-supplied strings are rendered with textContent (never innerHTML).
"use strict";

const SVGNS = "http://www.w3.org/2000/svg";
const POLL_MS = 1000;        // graph / audit / gateway stats
const PROBE_MS = 500;        // normal gateway probing
const FAST_PROBE_MS = 15;    // probing right after a revocation, to time propagation
const RACE_TIMEOUT_MS = 20000;

// ---------------------------------------------------------------- utilities

const $ = (id) => document.getElementById(id);

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  setAttrs(el, attrs);
  appendAll(el, children);
  return el;
}

function s(tag, attrs = {}, ...children) {
  const el = document.createElementNS(SVGNS, tag);
  setAttrs(el, attrs);
  appendAll(el, children);
  return el;
}

function setAttrs(el, attrs) {
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "class") el.setAttribute("class", v);
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
}

function appendAll(el, children) {
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

const store = {
  get(area, key) { try { return window[area].getItem(key); } catch { return null; } },
  set(area, key, val) { try { val == null ? window[area].removeItem(key) : window[area].setItem(key, val); } catch { /* storage unavailable */ } },
};

function parseTime(iso) {
  // SQLite returns naive UTC timestamps; treat them as UTC.
  const hasTz = /(Z|[+-]\d\d:\d\d)$/.test(iso);
  return new Date(hasTz ? iso : iso + "Z");
}
const clock = (iso) => parseTime(iso).toLocaleTimeString([], { hour12: false });

function defaultGateways() {
  const host = location.hostname || "127.0.0.1";
  return [`${location.protocol}//${host}:8001`, `${location.protocol}//${host}:8002`];
}

// --------------------------------------------------------------------- state

const state = {
  token: store.get("sessionStorage", "qg.operatorToken"),
  me: null,                 // {operator_id, kind}
  graph: null,
  graphKey: "",
  audit: [],
  auditKey: "",
  selected: null,           // agent id
  detail: null,             // GET /agents/{id}
  detailAudit: [],
  // Tokens of agents registered from this page. Memory only: a reload forgets them.
  agentTokens: new Map(),   // id -> {token, name}
  gateways: (store.get("localStorage", "qg.gateways") || "").split(",").map((x) => x.trim()).filter(Boolean),
  gwStats: new Map(),       // url -> stats | {error}
  probes: new Map(),        // agentId -> Map(url -> {code, cache, at})
  races: new Map(),         // agentId -> {t0, results: Map(url -> ms)}
  reasonDrafts: new Map(), // agentId -> half-typed revocation reason (survives re-renders)
  busy: false,
};
if (!state.gateways.length) state.gateways = defaultGateways();

const names = () => {
  const m = new Map();
  for (const n of state.graph?.nodes ?? []) m.set(n.id, n.label);
  for (const [id, a] of state.agentTokens) if (!m.has(id)) m.set(id, a.name);
  return m;
};
const nameOf = (id) => (id ? names().get(id) ?? id.slice(0, 8) : "—");

// ----------------------------------------------------------------------- API

async function api(path, { method = "GET", body, token = state.token, base = "" } = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  try {
    const r = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    let data = null;
    try { data = await r.json(); } catch { /* empty body */ }
    return { ok: r.ok, status: r.status, data, headers: r.headers };
  } catch (err) {
    return { ok: false, status: 0, data: { detail: String(err) }, headers: new Headers() };
  }
}

const detailOf = (res) => {
  const d = res.data?.detail;
  if (Array.isArray(d)) return d.map((e) => e.msg).join("; ");
  return d ?? `HTTP ${res.status}`;
};

function banner(msg) {
  const b = $("banner");
  b.hidden = !msg;
  b.textContent = msg || "";
}

// ------------------------------------------------------------------- sign-in

async function signIn(token) {
  const res = await api("/operator/me", { token });
  if (!res.ok) {
    banner(res.status === 401 ? "That token isn't a valid validator or admin credential." : `Sign-in failed: ${detailOf(res)}`);
    return false;
  }
  state.token = token;
  state.me = res.data;
  store.set("sessionStorage", "qg.operatorToken", token);
  banner("");
  renderWhoami();
  await refresh();
  return true;
}

function signOut() {
  state.token = null;
  state.me = null;
  state.graph = null;
  state.graphKey = "";
  state.audit = [];
  state.auditKey = "";
  state.selected = null;
  store.set("sessionStorage", "qg.operatorToken", null);
  renderWhoami();
  renderGraph();
  renderAudit();
  renderInspector();
}

function renderWhoami() {
  const pill = $("whoami");
  const signedIn = Boolean(state.me);
  pill.textContent = signedIn ? `${state.me.operator_id} (${state.me.kind})` : "signed out";
  pill.classList.toggle("on", signedIn);
  $("token").hidden = signedIn;
  $("signin-btn").hidden = signedIn;
  $("signout-btn").hidden = !signedIn;
}

// --------------------------------------------------------------- refreshing

async function refresh() {
  if (!state.me || state.busy) return;
  state.busy = true;
  try {
    const [g, a] = await Promise.all([api("/graph"), api("/audit?limit=40")]);
    if (g.status === 401 || a.status === 401) {
      banner("Your operator token is no longer valid (validator deactivated?). Signed out.");
      signOut();
      return;
    }
    if (g.ok) {
      const key = JSON.stringify(g.data);
      if (key !== state.graphKey) {
        state.graph = g.data;
        state.graphKey = key;
        renderGraph();
        renderRegisterParents();
      }
    } else {
      banner(`Couldn't load graph: ${detailOf(g)}`);
    }
    if (a.ok) {
      const key = JSON.stringify(a.data);
      if (key !== state.auditKey) {
        state.audit = a.data;
        state.auditKey = key;
        renderAudit();
      }
    }
    if (state.selected) await loadDetail(state.selected);
  } finally {
    state.busy = false;
  }
}

async function loadDetail(id) {
  const [d, a] = await Promise.all([api(`/agents/${encodeURIComponent(id)}`), api(`/audit?agent_id=${encodeURIComponent(id)}&limit=25`)]);
  if (!d.ok) return;
  const key = JSON.stringify([d.data, a.data]);
  if (key === state.detailKey) return;
  state.detail = d.data;
  state.detailAudit = a.ok ? a.data : [];
  state.detailKey = key;
  renderInspector();
}

function select(id) {
  state.selected = id;
  state.detail = null;
  state.detailKey = "";
  renderGraph();
  renderInspector();
  loadDetail(id);
}

// --------------------------------------------------------------------- graph

const ROW = 54, TOP = 46, VX = 80, AX0 = 340, DEPTH_DX = 170;

function layout(graph) {
  const validators = graph.nodes.filter((n) => n.type === "validator");
  const agents = graph.nodes.filter((n) => n.type === "agent");   // server orders by created_at
  const children = new Map();
  const hasParent = new Set();
  for (const e of graph.edges) {
    if (e.type !== "lineage") continue;
    hasParent.add(e.target);
    if (!children.has(e.source)) children.set(e.source, []);
    children.get(e.source).push(e.target);
  }
  const order = [];
  const depth = new Map();
  const visit = (id, d) => {
    if (depth.has(id)) return;
    depth.set(id, d);
    order.push(id);
    for (const c of children.get(id) ?? []) visit(c, d + 1);
  };
  for (const a of agents) if (!hasParent.has(a.id)) visit(a.id, 0);
  for (const a of agents) visit(a.id, 0); // safety net for any cycle/orphan

  const rows = Math.max(order.length, validators.length, 1);
  const height = TOP + (rows - 1) * ROW + 40;
  const pos = new Map();
  const span = (rows - 1) * ROW;
  validators.forEach((v, i) => {
    const y = validators.length > 1 ? TOP + (i * span) / (validators.length - 1) : TOP + span / 2;
    pos.set(v.id, { x: VX, y });
  });
  let maxDepth = 0;
  order.forEach((id, i) => {
    const d = depth.get(id);
    maxDepth = Math.max(maxDepth, d);
    pos.set(id, { x: AX0 + d * DEPTH_DX, y: TOP + i * ROW });
  });
  const width = AX0 + maxDepth * DEPTH_DX + 230;
  return { validators, agents, pos, width, height };
}

function renderGraph() {
  const svg = $("graph");
  svg.replaceChildren();
  const graph = state.graph;
  const hasAgents = graph?.nodes.some((n) => n.type === "agent");
  $("graph-empty").hidden = Boolean(graph);
  if (!graph) { svg.setAttribute("viewBox", "0 0 600 10"); return; }
  if (!hasAgents) $("graph-empty").textContent = "No agents yet. Register one on the right.";

  const { validators, agents, pos, width, height } = layout(graph);
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  const sel = state.selected;
  const activeValidators = new Map(validators.map((v) => [v.id, v.active]));

  svg.append(s("defs", {},
    s("marker", { id: "arrow", viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse" },
      s("path", { d: "M0 0 10 5 0 10z" }))));
  svg.append(s("text", { x: VX - 46, y: 18, class: "col-label", text: "Validators" }));
  svg.append(s("text", { x: AX0 - 16, y: 18, class: "col-label", text: "Agents" }));

  const edgeLayer = s("g");
  for (const e of graph.edges) {
    const a = pos.get(e.source), b = pos.get(e.target);
    if (!a || !b) continue;
    const touches = !sel || e.source === sel || e.target === sel;
    let d, cls = `edge ${e.type}`;
    if (e.type === "lineage") {
      const midX = (a.x + b.x) / 2;
      d = `M${a.x + 16} ${a.y} C${midX} ${a.y}, ${midX} ${b.y}, ${b.x - 18} ${b.y}`;
    } else {
      const off = e.type === "revocation_vote" ? 14 : -6;  // keep both edge kinds visible between the same pair
      const x1 = a.x + 50, x2 = b.x - 16, cx = (x1 + x2) / 2;
      d = `M${x1} ${a.y} C${cx} ${a.y + off}, ${cx} ${b.y + off}, ${x2} ${b.y + off / 3}`;
      if (!e.counts) cls += " inactive";
    }
    if (!touches) cls += " dim";
    const title = e.type === "endorsement"
      ? `${nameOf(e.source)} endorsed ${nameOf(e.target)}${e.counts ? "" : " (validator inactive: doesn't count)"}`
      : e.type === "revocation_vote"
        ? `${nameOf(e.source)} voted to revoke ${nameOf(e.target)}: ${e.reason ?? ""}${e.counts ? "" : " (validator inactive: doesn't count)"}`
        : `${nameOf(e.source)} spawned ${nameOf(e.target)}`;
    edgeLayer.append(s("path", { d, class: cls, "marker-end": e.type === "lineage" ? "url(#arrow)" : null }, s("title", { text: title })));
  }
  svg.append(edgeLayer);

  for (const v of validators) {
    const p = pos.get(v.id);
    svg.append(s("g", { class: `node validator${v.active ? "" : " inactive"}` },
      s("rect", { x: p.x - 50, y: p.y - 15, width: 100, height: 30, rx: 7 }),
      s("text", { x: p.x, y: p.y + 4, "text-anchor": "middle", text: v.label }),
      s("title", { text: `${v.id}${v.active ? "" : " (inactive)"}` })));
  }

  for (const a of agents) {
    const p = pos.get(a.id);
    const isSel = a.id === sel;
    const g = s("g", {
      class: `node agent ${a.status}${isSel ? " selected" : ""}`,
      tabindex: 0, role: "button", "aria-pressed": String(isSel),
      "aria-label": `${a.label}, ${a.status}. Select to inspect.`,
      onclick: () => select(a.id),
      onkeydown: (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); select(a.id); } },
    },
      s("circle", { cx: p.x, cy: p.y, r: 14 }),
      a.status === "revoked" ? s("path", { class: "x", d: `M${p.x - 5} ${p.y - 5}L${p.x + 5} ${p.y + 5}M${p.x + 5} ${p.y - 5}L${p.x - 5} ${p.y + 5}` }) : null,
      s("text", { x: p.x + 22, y: p.y - 1, text: a.label }),
      s("text", { x: p.x + 22, y: p.y + 13, class: "meta", text: a.status + (state.agentTokens.has(a.id) && !settled(a.id) ? " · probing" : "") }));
    svg.append(g);
  }
}

// ----------------------------------------------------------------- inspector

function meter(kind, have, need) {
  const spans = [];
  for (let i = 0; i < need; i++) spans.push(h("span", { class: i < have ? "on" : "" }));
  return h("div", { class: `meter ${kind}`, role: "img", "aria-label": `${have} of ${need}` }, spans);
}

function whySentence(d) {
  if (d.status === "revoked") return `Revoked: ${d.revocation_votes} of ${d.revocation_quorum} required revocation votes. Revocation is permanent; this credential is dead at every gateway.`;
  if (d.status === "trusted") return `Trusted: endorsed by ${d.endorsements} of the ${d.endorsement_quorum} distinct active validators required.` + (d.revocation_votes ? ` ${d.revocation_votes} of ${d.revocation_quorum} revocation votes so far.` : "");
  return `Pending: ${d.endorsements} of ${d.endorsement_quorum} required endorsements. Gateways deny it until quorum is met.`;
}

function renderInspector() {
  const root = $("inspector");
  const d = state.detail;
  if (!state.selected || !state.me) {
    root.replaceChildren(h("p", { class: "empty", text: "Select an agent in the graph to see why it is or isn't trusted." }));
    return;
  }
  if (!d) { root.replaceChildren(h("p", { class: "empty", text: "Loading…" })); return; }

  const edges = state.graph?.edges ?? [];
  const endorse = edges.filter((e) => e.type === "endorsement" && e.target === d.id);
  const votes = edges.filter((e) => e.type === "revocation_vote" && e.target === d.id);
  const kids = edges.filter((e) => e.type === "lineage" && e.source === d.id).map((e) => e.target);
  const me = state.me;
  const iAmValidator = me.kind === "validator";
  const iEndorsed = endorse.some((e) => e.source === me.operator_id);
  const iVoted = votes.some((e) => e.source === me.operator_id);
  const revoked = d.status === "revoked";

  const msg = h("p", { class: "msg", role: "status" });
  const reasonInput = h("input", { placeholder: "reason (required)", maxlength: 500, "aria-label": "Revocation reason",
    value: state.reasonDrafts.get(d.id) ?? "", oninput: (ev) => state.reasonDrafts.set(d.id, ev.target.value) });

  const doEndorse = async (btn) => {
    btn.disabled = true;
    const res = await api(`/agents/${encodeURIComponent(d.id)}/endorse`, { method: "POST" });
    msg.className = `msg ${res.ok ? "ok" : "err"}`;
    msg.textContent = res.ok ? `Endorsed. Status: ${res.data.agent_status} (${res.data.endorsements}/${res.data.endorsement_quorum}).` : detailOf(res);
    await refresh();
  };
  const doRevoke = async (btn) => {
    const reason = reasonInput.value.trim();
    if (!reason) { msg.className = "msg err"; msg.textContent = "A reason is required."; reasonInput.focus(); return; }
    btn.disabled = true;
    const res = await api(`/agents/${encodeURIComponent(d.id)}/revoke-vote`, { method: "POST", body: { reason } });
    if (res.ok && res.data.agent_status === "revoked") startRace(d.id);
    msg.className = `msg ${res.ok ? "ok" : "err"}`;
    msg.textContent = res.ok
      ? `Vote recorded (${res.data.revocation_votes}/${res.data.revocation_quorum}).${res.data.agent_status === "revoked" ? " Agent revoked; timing propagation to gateways below." : ""}`
      : detailOf(res);
    await refresh();
  };

  const endorseBtn = h("button", { type: "button", disabled: revoked || iEndorsed || !iAmValidator,
    onclick: (ev) => doEndorse(ev.currentTarget),
    text: iEndorsed ? `Endorsed by ${me.operator_id}` : `Endorse as ${me.operator_id}` });
  const revokeBtn = h("button", { type: "button", class: "danger", disabled: revoked || iVoted || !iAmValidator,
    onclick: (ev) => doRevoke(ev.currentTarget),
    text: iVoted ? "Revocation vote cast" : "Vote to revoke" });

  root.replaceChildren(
    h("div", { class: "insp-head" },
      h("h3", { text: d.name }),
      h("span", { class: `badge ${d.status}`, text: d.status }),
      h("span", { class: "mono hint", text: d.id.slice(0, 8) })),
    h("div", { class: "why" },
      h("div", { text: whySentence(d) }),
      h("div", { class: "hint", text: `Endorsements ${d.endorsements}/${d.endorsement_quorum}` }),
      meter("endorse", d.endorsements, d.endorsement_quorum),
      h("div", { class: "hint", text: `Revocation votes ${d.revocation_votes}/${d.revocation_quorum}` }),
      meter("revoke", d.revocation_votes, d.revocation_quorum)),
    h("h3", { text: "Endorsements" }),
    endorse.length
      ? h("ul", { class: "kv" }, endorse.map((e) => h("li", {},
          h("span", { class: e.counts ? "ok-mark" : "no-mark", text: e.counts ? "✓" : "✗" }),
          h("span", { text: nameOf(e.source) }),
          e.counts ? null : h("span", { class: "why-reason", text: "validator inactive: doesn't count" }))))
      : h("p", { class: "empty", text: "None." }),
    h("h3", { text: "Revocation votes" }),
    votes.length
      ? h("ul", { class: "kv" }, votes.map((e) => h("li", {},
          h("span", { class: e.counts ? "bad-mark" : "no-mark", text: "●" }),
          h("span", { text: nameOf(e.source) }),
          h("span", { class: "why-reason", text: `“${e.reason ?? ""}”${e.counts ? "" : " (inactive: doesn't count)"}` }))))
      : h("p", { class: "empty", text: "None." }),
    h("h3", { text: "Lineage" }),
    h("ul", { class: "kv" },
      h("li", {}, h("span", { class: "hint", text: "Parent:" }),
        d.parent_agent_id ? h("button", { class: "linklike", type: "button", onclick: () => select(d.parent_agent_id), text: nameOf(d.parent_agent_id) }) : h("span", { text: "none (root)" })),
      h("li", {}, h("span", { class: "hint", text: "Children:" }),
        kids.length ? kids.map((k) => h("button", { class: "linklike", type: "button", onclick: () => select(k), text: nameOf(k) })) : h("span", { text: "none" })),
      h("li", {}, h("span", { class: "hint", text: "Children start with zero endorsements and their own credential; authority is never inherited." }))),
    h("div", { class: "actions" },
      iAmValidator ? null : h("p", { class: "hint", text: "Signed in as admin: read-only. Sign in with a validator token to vote." }),
      h("div", { class: "row" }, endorseBtn),
      h("div", { class: "row" }, reasonInput, revokeBtn),
      msg),
    h("h3", { text: "Timeline" }),
    h("ol", { class: "timeline" }, state.detailAudit.slice().reverse().map((e) => h("li", {},
      h("time", { text: clock(e.created_at) }),
      h("span", { text: `${e.event_type}${e.actor_id ? ` by ${nameOf(e.actor_id)}` : ""}${eventDetail(e) ? ` · ${eventDetail(e)}` : ""}` })))),
  );
}

// --------------------------------------------------------------------- audit

function eventDetail(e) {
  const d = e.details || {};
  if (e.event_type === "agent_status_changed") return `${d.old} → ${d.new}`;
  if (e.event_type === "revocation_vote") return `“${d.reason}”`;
  if (e.event_type === "access_denied") return d.reason;
  if (e.event_type === "agent_registered" && d.parent_agent_id) return `child of ${nameOf(d.parent_agent_id)}`;
  if (e.event_type === "registration_denied") return `tried to spawn “${d.requested_name}”: ${d.reason}`;
  return "";
}

function renderAudit() {
  const ol = $("audit");
  if (!state.me) { ol.replaceChildren(h("li", { class: "empty", text: "Sign in to see the audit log." })); return; }
  if (!state.audit.length) { ol.replaceChildren(h("li", { class: "empty", text: "No events yet." })); return; }
  ol.replaceChildren(...state.audit.map((e) => h("li", {},
    h("time", { text: clock(e.created_at) }),
    h("span", {}, h("span", { class: `ev ${e.event_type}`, text: e.event_type }), ` · ${nameOf(e.agent_id)}`),
    h("span", { class: "detail", text: [e.actor_id && e.actor_id !== e.agent_id ? `by ${nameOf(e.actor_id)}` : "", eventDetail(e)].filter(Boolean).join(" · ") }))));
}

// ------------------------------------------------------------------ register

function renderRegisterParents() {
  const sel = $("reg-parent");
  const current = sel.value;
  const status = new Map((state.graph?.nodes ?? []).filter((n) => n.type === "agent").map((n) => [n.id, n.status]));
  const opts = [h("option", { value: "", text: "none (root agent)" })];
  for (const [id, a] of state.agentTokens) {
    if (status.get(id) === "revoked") continue;
    opts.push(h("option", { value: id, text: `${a.name} (spawn a child)` }));
  }
  sel.replaceChildren(...opts);
  if ([...sel.options].some((o) => o.value === current)) sel.value = current;
}

async function register(ev) {
  ev.preventDefault();
  const msg = $("register-msg");
  const name = $("reg-name").value.trim();
  const parentId = $("reg-parent").value;
  if (!name) return;
  const parent = parentId ? state.agentTokens.get(parentId) : null;
  const res = await api("/agents", {
    method: "POST",
    body: parentId ? { name, parent_agent_id: parentId } : { name },
    token: parent ? parent.token : null,   // a child must be registered with its parent's credential
  });
  if (!res.ok) { msg.className = "msg err"; msg.textContent = detailOf(res); return; }
  state.agentTokens.set(res.data.id, { token: res.data.token, name: res.data.name });
  msg.className = "msg ok";
  msg.textContent = `Registered ${res.data.name}${parent ? ` as a child of ${parent.name}` : ""}. Its token is held in this tab only, for probing.`;
  $("reg-name").value = "";
  renderRegisterParents();
  await refresh();
  select(res.data.id);
}

// ------------------------------------------------------------------ gateways

async function pollGateways() {
  await Promise.all(state.gateways.map(async (url) => {
    const res = await api("/gateway/stats", { base: url, token: null });
    state.gwStats.set(url, res.ok ? res.data : { error: res.status ? `HTTP ${res.status}` : "unreachable" });
  }));
  renderGateways();
}

function renderGateways() {
  const root = $("gateways");
  root.replaceChildren(...state.gateways.map((url) => {
    const st = state.gwStats.get(url);
    if (!st || st.error) {
      return h("div", { class: "gw down" },
        h("div", { class: "gw-title" }, h("strong", { text: url.replace(/^https?:\/\//, "") }), h("span", { class: "hint", text: st?.error ?? "…" })),
        h("p", { class: "hint", text: "Start it, or check QG_GATEWAY_CORS_ORIGINS includes this page's origin." }));
    }
    const stream = st.mode === "ttl" ? h("span", { text: "none (TTL only)" })
      : h("span", {}, h("span", { class: `dot ${st.stream_ready ? "ok" : "bad"}` }), st.stream_ready ? "caught up" : "down: fail-closed");
    const row = (k, v) => [h("dt", { text: k }), h("dd", {}, v)];
    return h("div", { class: "gw" },
      h("div", { class: "gw-title" }, h("strong", { text: `Gateway ${st.name}` }), h("span", { class: "hint", text: `${st.mode} · TTL ${st.ttl_seconds}s` })),
      h("dl", {},
        row("events", stream),
        row("cache entries", st.cache_size),
        row("hits / misses", `${st.cache_hits ?? 0} / ${st.cache_misses ?? 0}`),
        row("invalidations", st.invalidations ?? 0),
        row("allowed / denied", `${st.allowed ?? 0} / ${st.denied ?? 0}`),
        row("fail-closed 503s", st.unavailable ?? 0)));
  }));
}

async function probeAgent(agentId) {
  const a = state.agentTokens.get(agentId);
  if (!a) return;
  const results = state.probes.get(agentId) ?? new Map();
  state.probes.set(agentId, results);
  await Promise.all(state.gateways.map(async (url) => {
    const res = await api("/protected/resource", { base: url, token: a.token });
    const now = performance.now();
    results.set(url, { code: res.status, cache: res.headers.get("X-QG-Cache"), at: now });
    const race = state.races.get(agentId);
    if (race && !race.results.has(url) && res.status !== 200 && res.status !== 0) race.results.set(url, now - race.t0);
  }));
}

function startRace(agentId) {
  if (!state.agentTokens.has(agentId)) return;  // can only probe agents whose token we hold
  state.races.set(agentId, { t0: performance.now(), results: new Map(), done: false });
  fastProbe(agentId);
}

async function fastProbe(agentId) {
  const race = state.races.get(agentId);
  while (race && !race.done) {
    await probeAgent(agentId);
    renderProbes();
    const elapsed = performance.now() - race.t0;
    if (state.gateways.every((u) => race.results.has(u)) || elapsed > RACE_TIMEOUT_MS) race.done = true;
    else await new Promise((r) => setTimeout(r, FAST_PROBE_MS));
  }
  renderProbes();
}

function cellFor(p) {
  if (!p) return h("span", { class: "cell other", text: "…" });
  const label = { 200: "200 allow", 403: "403 deny", 401: "401 unknown", 503: "503 fail-closed", 0: "unreachable" }[p.code] ?? String(p.code);
  const cls = p.code === 200 ? "allow" : p.code === 403 ? "deny" : "other";
  return h("span", { class: `cell ${cls}` }, label, p.cache ? h("span", { class: "cache", text: `· ${p.cache}` }) : null);
}

function renderProbes() {
  const root = $("probes");
  if (!state.agentTokens.size) {
    root.replaceChildren(h("p", { class: "empty", text: "Register an agent from this dashboard to probe it through the gateways." }));
    return;
  }
  const head = h("tr", {}, h("th", { text: "Agent" }), state.gateways.map((u) => {
    const st = state.gwStats.get(u);
    return h("th", { text: st && !st.error ? `Gateway ${st.name} (${st.mode})` : u.replace(/^https?:\/\//, "") });
  }));
  const rows = [...state.agentTokens].map(([id, a]) => {
    const results = state.probes.get(id) ?? new Map();
    const race = state.races.get(id);
    return h("tr", {},
      h("td", {}, h("button", { class: "linklike", type: "button", onclick: () => select(id), text: a.name }),
        settled(id) ? h("span", { class: "race", text: "revoked everywhere; probing stopped" }) : null),
      state.gateways.map((u) => {
        let raceLine = null;
        if (race) {
          const ms = race.results.get(u);
          raceLine = ms != null
            ? h("span", { class: "race done" }, "denied ", h("strong", { text: `${Math.round(ms)} ms` }), " after revocation")
            : h("span", { class: "race" }, "still allowing ", h("strong", { text: `${((performance.now() - race.t0) / 1000).toFixed(1)} s` }), " after revocation");
        }
        return h("td", {}, cellFor(results.get(u)), raceLine);
      }));
  });
  root.replaceChildren(h("div", { class: "probe-wrap" }, h("table", { class: "probe-table" }, h("thead", {}, head), h("tbody", {}, rows))));
}

// Revocation is permanent, so once every gateway has denied a revoked agent
// there is nothing left to observe: stop probing it (saves load and console noise).
function settled(id) {
  const status = (state.graph?.nodes ?? []).find((n) => n.id === id)?.status;
  if (status !== "revoked") return false;
  const results = state.probes.get(id);
  return Boolean(results) && state.gateways.every((u) => results.get(u)?.code === 403);
}

async function probeLoop() {
  const racing = new Set([...state.races].filter(([, r]) => !r.done).map(([id]) => id));
  await Promise.all([...state.agentTokens.keys()].filter((id) => !racing.has(id) && !settled(id)).map(probeAgent));
  renderProbes();
}

// ---------------------------------------------------------------------- boot

function every(ms, fn) {
  let running = false;
  setInterval(async () => {
    if (running) return;
    running = true;
    try { await fn(); } finally { running = false; }
  }, ms);
}

function boot() {
  $("gw-urls").value = state.gateways.join(", ");
  $("signin").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const t = $("token").value.trim();
    if (t && (await signIn(t))) $("token").value = "";
  });
  $("signout-btn").addEventListener("click", signOut);
  $("register-form").addEventListener("submit", register);
  $("gw-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    state.gateways = $("gw-urls").value.split(",").map((x) => x.trim().replace(/\/+$/, "")).filter(Boolean);
    store.set("localStorage", "qg.gateways", state.gateways.join(","));
    state.gwStats.clear();
    state.probes.clear();
    pollGateways();
  });

  renderWhoami();
  renderGraph();
  renderAudit();
  renderProbes();
  if (state.token) signIn(state.token);

  every(POLL_MS, refresh);
  every(POLL_MS, pollGateways);
  every(PROBE_MS, probeLoop);
  pollGateways();
}

boot();

"use strict";

(function () {
  const TOKEN_KEY = "omega.ui.token";
  const state = {
    token: null,
    projects: [],
    runs: [],
    keys: [],
    selectedProject: null,
    selectedRun: null,
    socket: null,
    lastSeq: 0,
    retry: 0,
    retryTimer: null,
    shipReady: false,
  };

  const $ = (id) => document.getElementById(id);

  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs || {})) {
      if (value === null || value === undefined || value === false) continue;
      if (key === "text") node.textContent = String(value);
      else if (key === "cls") node.className = value;
      else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value === true ? "" : String(value));
    }
    for (const child of [].concat(children || [])) {
      if (child === null || child === undefined) continue;
      node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
    }
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
    return node;
  }

  function readToken() {
    try {
      return sessionStorage.getItem(TOKEN_KEY);
    } catch (err) {
      return null;
    }
  }

  function writeToken(value) {
    try {
      if (value) sessionStorage.setItem(TOKEN_KEY, value);
      else sessionStorage.removeItem(TOKEN_KEY);
    } catch (err) {
      return;
    }
  }

  function flash(message, kind) {
    const node = $("flash");
    node.textContent = message;
    node.className = "flash " + (kind || "info");
    node.hidden = false;
    clearTimeout(flash.timer);
    flash.timer = setTimeout(() => { node.hidden = true; }, 6000);
  }

  async function api(method, path, body) {
    const headers = { Authorization: "Bearer " + state.token };
    const options = { method, headers, cache: "no-store" };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(body);
    }
    const response = await fetch(path, options);
    if (response.status === 401) {
      showLogin("The token was rejected. Paste it again.");
      throw new Error("unauthorized");
    }
    if (response.status === 204) return null;
    let data = null;
    try {
      data = await response.json();
    } catch (err) {
      data = null;
    }
    if (!response.ok) {
      const message = data && data.error ? data.error.message : "HTTP " + response.status;
      const error = new Error(message);
      error.status = response.status;
      error.code = data && data.error ? data.error.code : null;
      throw error;
    }
    return data;
  }

  function fmtTime(value) {
    if (!value) return "—";
    const date = new Date(value);
    return isNaN(date.getTime()) ? String(value) : date.toLocaleString();
  }

  function fmtUsd(value) {
    if (value === null || value === undefined || value === "") return "—";
    const number = Number(value);
    return isNaN(number) ? String(value) : "$" + number.toFixed(number < 1 ? 4 : 2);
  }

  function badge(text, tone) {
    return el("span", { cls: "badge " + (tone || toneFor(text)), text: text || "—" });
  }

  function toneFor(status) {
    const value = String(status || "").toLowerCase();
    if (["pass", "verified", "done", "fresh", "running", "true"].includes(value)) return "ok";
    if (["fail", "invalid", "failed", "stale", "budget_exceeded", "false"].includes(value)) return "bad";
    if (["unverified", "queued", "pending", "cancelled", "released", "overridden"].includes(value)) return "warn";
    return "neutral";
  }

  function showLogin(message) {
    $("app").hidden = true;
    $("login").hidden = false;
    $("login-error").textContent = message || "";
    closeSocket();
  }

  async function boot() {
    const hash = new URLSearchParams(location.hash.slice(1));
    if (hash.get("token")) {
      writeToken(hash.get("token"));
      history.replaceState(null, "", location.pathname + location.search);
    }
    state.token = readToken();
    if (!state.token) {
      showLogin("");
      return;
    }
    try {
      const health = await api("GET", "/api/health");
      renderHealth(health);
    } catch (err) {
      if (err.message !== "unauthorized") showLogin("The server did not answer: " + err.message);
      return;
    }
    $("login").hidden = true;
    $("app").hidden = false;
    await Promise.allSettled([loadKeys(), loadProjects(), loadRuns()]);
  }

  function renderHealth(health) {
    $("version").textContent = "v" + health.version;
    const node = clear($("health"));
    for (const runtime of ["claude", "codex"]) {
      const version = health.runtimes ? health.runtimes[runtime] : null;
      const hooked = health.hooks_verified ? health.hooks_verified[runtime] : false;
      node.appendChild(el("span", { cls: "pill" }, [
        el("strong", { text: runtime }),
        " ",
        version ? version : "not installed",
        " · hooks ",
        badge(hooked ? "verified" : (health.allow_unhooked ? "unhooked allowed" : "unverified")),
      ]));
    }
  }

  function selectTab(name) {
    for (const tab of document.querySelectorAll("#tabs [role=tab]")) {
      tab.setAttribute("aria-selected", tab.dataset.tab === name ? "true" : "false");
    }
    for (const panel of document.querySelectorAll("[data-panel]")) {
      panel.hidden = panel.dataset.panel !== name;
    }
    if (name === "clearances") loadClearances();
    if (name === "approvals") loadApprovals();
    if (name === "cost") loadCost();
    if (name === "runs") loadRuns();
  }

  async function loadKeys() {
    state.keys = await api("GET", "/api/keys");
    const body = clear($("keys-body"));
    if (!state.keys.length) {
      body.appendChild(el("tr", {}, el("td", { colspan: 6, cls: "muted", text: "No keys yet. Add one below." })));
      return;
    }
    for (const key of state.keys) {
      const verify = el("button", { type: "button", cls: "ghost", text: "Verify", onclick: () => verifyKey(key.provider) });
      const remove = el("button", { type: "button", cls: "ghost danger", text: "Delete", onclick: () => deleteKey(key.provider) });
      body.appendChild(el("tr", {}, [
        el("td", { text: key.provider }),
        el("td", {}, el("code", { text: (key.prefix || "") + "…" + (key.last4 || "") })),
        el("td", {}, badge(key.status)),
        el("td", { text: fmtTime(key.created_at) }),
        el("td", { text: fmtTime(key.last_used_at) }),
        el("td", { cls: "actions" }, [verify, remove]),
      ]));
    }
  }

  async function verifyKey(provider) {
    try {
      const result = await api("POST", "/api/keys/" + encodeURIComponent(provider) + "/verify");
      flash(provider + ": " + result.status + " — " + result.detail, result.status === "verified" ? "ok" : "warn");
      await loadKeys();
    } catch (err) {
      flash(err.message, "bad");
    }
  }

  async function deleteKey(provider) {
    if (!confirm("Delete the stored " + provider + " key?")) return;
    try {
      await api("DELETE", "/api/keys/" + encodeURIComponent(provider));
      flash(provider + " key deleted", "ok");
      await loadKeys();
    } catch (err) {
      flash(err.message, "bad");
    }
  }

  async function saveKey(event) {
    event.preventDefault();
    const input = $("key-value");
    const provider = $("key-provider").value;
    try {
      const entry = await api("PUT", "/api/keys/" + encodeURIComponent(provider), { key: input.value });
      input.value = "";
      flash(provider + " key saved (…" + entry.last4 + ")", "ok");
      await loadKeys();
    } catch (err) {
      flash(err.message, "bad");
    }
  }

  function fillSelect(select, items, valueOf, labelOf, current, emptyLabel) {
    clear(select);
    if (emptyLabel !== undefined) select.appendChild(el("option", { value: "", text: emptyLabel }));
    for (const item of items) {
      const value = valueOf(item);
      select.appendChild(el("option", { value, text: labelOf(item), selected: value === current }));
    }
  }

  async function loadProjects() {
    state.projects = await api("GET", "/api/projects");
    const list = clear($("projects-list"));
    if (!state.projects.length) list.appendChild(el("li", { cls: "muted", text: "No projects yet." }));
    for (const project of state.projects) {
      list.appendChild(el("li", {}, el("button", {
        type: "button",
        cls: "item" + (project.id === state.selectedProject ? " active" : ""),
        onclick: () => showProject(project.id),
      }, [el("strong", { text: project.name }), el("span", { cls: "muted small", text: project.path })])));
    }
    if (!state.selectedProject && state.projects.length) state.selectedProject = state.projects[0].id;
    const label = (p) => p.name;
    for (const id of ["run-project", "clear-project", "ship-project"]) {
      fillSelect($(id), state.projects, (p) => p.id, label, state.selectedProject);
    }
  }

  async function showProject(id) {
    state.selectedProject = id;
    await loadProjects();
    const card = clear($("project-detail"));
    try {
      const project = await api("GET", "/api/projects/" + encodeURIComponent(id));
      card.appendChild(el("h3", { text: project.name }));
      card.appendChild(el("p", { cls: "muted small", text: project.path }));
      card.appendChild(el("p", {}, ["Adapters ", badge(project.installed ? "installed" : "not installed", project.installed ? "ok" : "warn")]));
      if (project.install_detail) card.appendChild(el("pre", { cls: "output small", text: project.install_detail }));
      card.appendChild(el("h4", { text: "Contracts" }));
      const rows = (project.contracts || []).map((c) => el("tr", {}, [
        el("td", { text: c.slug }),
        el("td", {}, badge(c.valid ? "valid" : "invalid", c.valid ? "ok" : "bad")),
        el("td", { text: ["Unit", "Integration", "Functional", "Journey"].map((s) => s[0] + ":" + (c.seams[s] || 0)).join(" ") }),
        el("td", { text: (c.errors || []).join("; ") }),
      ]));
      card.appendChild(el("table", { cls: "grid" }, [
        el("thead", {}, el("tr", {}, ["Slug", "State", "Scenarios", "Errors"].map((h) => el("th", { text: h })))),
        el("tbody", {}, rows.length ? rows : el("tr", {}, el("td", { colspan: 4, cls: "muted", text: "No contracts." }))),
      ]));
    } catch (err) {
      card.appendChild(el("p", { cls: "error", text: err.message }));
    }
  }

  async function addProject(event) {
    event.preventDefault();
    try {
      const project = await api("POST", "/api/projects", { name: $("project-name").value, path: $("project-path").value });
      $("project-form").reset();
      flash("Project " + project.name + " added", "ok");
      await showProject(project.id);
    } catch (err) {
      flash(err.message, "bad");
    }
  }

  async function loadRuns() {
    state.runs = await api("GET", "/api/runs");
    const list = clear($("runs-list"));
    if (!state.runs.length) list.appendChild(el("li", { cls: "muted", text: "No runs yet." }));
    for (const run of state.runs) {
      list.appendChild(el("li", {}, el("button", {
        type: "button",
        cls: "item" + (run.run_id === state.selectedRun ? " active" : ""),
        onclick: () => openRun(run.run_id),
      }, [
        el("span", { cls: "row-between" }, [el("strong", { text: run.role + " · " + (run.model || run.runtime) }), badge(run.status)]),
        el("span", { cls: "muted small", text: run.run_id + " · " + fmtUsd(run.cost_usd) }),
      ])));
    }
    const label = (r) => r.run_id + " (" + r.status + ")";
    fillSelect($("appr-run"), state.runs, (r) => r.run_id, label, state.selectedRun);
    fillSelect($("cost-run"), state.runs, (r) => r.run_id, (r) => r.run_id, $("cost-run").value, "all runs");
    if (state.selectedRun) {
      const current = state.runs.find((r) => r.run_id === state.selectedRun);
      if (current) updateRunMeta(current);
    }
  }

  async function startRun(event) {
    event.preventDefault();
    const budget = $("run-budget").value;
    const body = {
      project_id: $("run-project").value,
      role: $("run-role").value,
      provider: $("run-provider").value || null,
      model: null,
      prompt: $("run-prompt").value,
      budget_usd: budget ? Number(budget) : null,
      permission_mode: "acceptEdits",
    };
    try {
      const result = await api("POST", "/api/runs", body);
      $("run-prompt").value = "";
      flash("Run " + result.run_id + " started", "ok");
      await loadRuns();
      openRun(result.run_id);
    } catch (err) {
      flash((err.code === "budget_exceeded" ? "Refused by the budget gate: " : "") + err.message, "bad");
    }
  }

  function updateRunMeta(run) {
    $("trace-title").textContent = "Trace · " + run.run_id;
    $("trace-meta").textContent = [run.role, run.provider, run.model, run.status, "budget " + fmtUsd(run.budget_usd), "spent " + fmtUsd(run.cost_usd)].filter(Boolean).join(" · ");
    $("run-cancel").disabled = !["queued", "running"].includes(run.status);
  }

  function closeSocket() {
    clearTimeout(state.retryTimer);
    if (state.socket) {
      state.socket.onclose = null;
      state.socket.close();
      state.socket = null;
    }
  }

  function openRun(runId) {
    closeSocket();
    state.selectedRun = runId;
    state.lastSeq = 0;
    state.retry = 0;
    clear($("trace"));
    const run = state.runs.find((r) => r.run_id === runId);
    if (run) updateRunMeta(run);
    connect();
    selectTab("runs");
  }

  function connect() {
    if (!state.selectedRun) return;
    const scheme = location.protocol === "https:" ? "wss" : "ws";
    const params = new URLSearchParams({ after: String(state.lastSeq), token: state.token });
    const url = scheme + "://" + location.host + "/ws/runs/" + encodeURIComponent(state.selectedRun) + "?" + params.toString();
    const socket = new WebSocket(url);
    state.socket = socket;
    setConn("connecting");
    socket.onopen = () => { state.retry = 0; setConn("live"); };
    socket.onmessage = (message) => {
      let event;
      try {
        event = JSON.parse(message.data);
      } catch (err) {
        return;
      }
      if (event.kind === "ping") return;
      if (typeof event.seq === "number") {
        if (event.seq <= state.lastSeq) return;
        state.lastSeq = event.seq;
      }
      renderEvent(event);
    };
    socket.onclose = () => {
      setConn("reconnecting");
      const delay = Math.min(1000 * Math.pow(2, state.retry++), 15000);
      state.retryTimer = setTimeout(connect, delay);
    };
  }

  function setConn(text) {
    const node = $("trace-conn");
    node.textContent = text;
    node.className = "conn " + (text === "live" ? "ok" : "warn");
  }

  function renderEvent(event) {
    const trace = $("trace");
    const data = event.data || {};
    if (event.kind === "text") {
      const last = trace.lastElementChild;
      if (last && last.dataset.kind === "text") {
        last.querySelector(".body").textContent += data.delta || "";
        trace.scrollTop = trace.scrollHeight;
        return;
      }
    }
    let label = event.kind;
    let body = "";
    if (event.kind === "text") body = data.delta || "";
    else if (event.kind === "tool_call") { label = "tool · " + data.name; body = data.input_summary || ""; }
    else if (event.kind === "tool_result") { label = data.ok ? "result" : "result (error)"; body = data.summary || ""; }
    else if (event.kind === "hook") { label = "hook · " + data.event + " · " + data.decision; body = data.reason || ""; }
    else if (event.kind === "usage") { body = "in " + data.in + " · out " + data.out + " · cache " + data.cache_read + "/" + data.cache_write + " · " + fmtUsd(data.usd) + " · run total " + fmtUsd(data.cumulative_usd); }
    else if (event.kind === "status") { body = data.status + (data.session_id ? " · session " + data.session_id : ""); refreshRunSoon(); }
    else if (event.kind === "approval_request") { body = "Contract " + (data.slug || "") + " is waiting for your sign-off in the Approvals tab."; flash("Approval requested for " + (data.slug || "a contract"), "warn"); }
    else if (event.kind === "error") body = data.message || "";
    else if (event.kind === "done") { body = "exit " + data.exit_code + (data.is_error ? " · error" : "") + " · cost " + fmtUsd(data.cost_usd); refreshRunSoon(); }
    else body = JSON.stringify(data);
    const item = el("li", { cls: "ev ev-" + event.kind, "data-kind": event.kind }, [
      el("span", { cls: "seq", text: "#" + event.seq }),
      el("span", { cls: "kind", text: label }),
      el("span", { cls: "body", text: body }),
    ]);
    trace.appendChild(item);
    trace.scrollTop = trace.scrollHeight;
  }

  function refreshRunSoon() {
    clearTimeout(refreshRunSoon.timer);
    refreshRunSoon.timer = setTimeout(() => loadRuns().catch(() => null), 300);
  }

  async function cancelRun() {
    if (!state.selectedRun || !confirm("Cancel this run?")) return;
    try {
      await api("POST", "/api/runs/" + encodeURIComponent(state.selectedRun) + "/cancel");
      flash("Cancel sent", "ok");
      await loadRuns();
    } catch (err) {
      flash(err.message, "bad");
    }
  }

  async function loadClearances() {
    const projectId = $("clear-project").value || state.selectedProject;
    const cards = clear($("clear-cards"));
    const gates = clear($("gate-body"));
    if (!projectId) {
      cards.appendChild(el("p", { cls: "muted", text: "Add a project first." }));
      return;
    }
    let view;
    try {
      view = await api("GET", "/api/projects/" + encodeURIComponent(projectId) + "/clearances");
    } catch (err) {
      cards.appendChild(el("p", { cls: "error", text: err.message }));
      return;
    }
    for (const name of ["proof", "contract", "review"]) {
      const item = view[name];
      const card = el("div", { cls: "card clearance" }, el("h3", { text: name + ".json" }));
      if (!item) {
        card.appendChild(el("p", {}, badge("missing", "neutral")));
        card.appendChild(el("p", { cls: "muted small", text: "Written by the stop gate the first time the agent stops." }));
      } else {
        card.appendChild(el("p", {}, [
          badge(item.verified ? "verified" : "unverified"), " ",
          badge(item.fresh ? "fresh" : "stale"),
          item.released ? badge("released") : null,
          item.overridden ? badge("overridden") : null,
        ]));
        card.appendChild(el("p", { cls: "muted small", text: item.reason }));
        card.appendChild(el("p", { cls: "small" }, ["digest ", el("code", { text: (item.files_digest || "").slice(0, 16) })]));
        const files = Object.keys((item.clearance && item.clearance.files) || {});
        card.appendChild(el("p", { cls: "small muted", text: files.length + " file(s) cleared" }));
      }
      cards.appendChild(card);
    }
    const last = view.last_stop;
    if (!last) {
      gates.appendChild(el("tr", {}, el("td", { colspan: 4, cls: "muted", text: "No stop has run yet." })));
      return;
    }
    for (const row of last.results || []) {
      gates.appendChild(el("tr", {}, [
        el("td", { text: row.gate }),
        el("td", {}, badge(row.status)),
        el("td", { text: row.required ? "yes" : "no" }),
        el("td", { text: row.detail || "" }),
      ]));
    }
  }

  async function loadApprovals() {
    const runId = $("appr-run").value || state.selectedRun;
    const list = clear($("appr-list"));
    const slugs = $("appr-slug");
    clear(slugs);
    if (!runId) {
      list.appendChild(el("p", { cls: "muted", text: "No run selected." }));
      return;
    }
    let pending = [];
    try {
      pending = await api("GET", "/api/runs/" + encodeURIComponent(runId) + "/approvals");
    } catch (err) {
      list.appendChild(el("p", { cls: "error", text: err.message }));
      return;
    }
    if (!pending.length) list.appendChild(el("p", { cls: "muted", text: "Nothing is waiting for sign-off on this run." }));
    for (const item of pending) {
      slugs.appendChild(el("option", { value: item.slug, text: item.slug }));
      const seams = el("dl", { cls: "seams" });
      for (const [seam, value] of Object.entries(item.scenarios || {})) {
        seams.appendChild(el("dt", { text: seam }));
        seams.appendChild(el("dd", { text: Array.isArray(value) ? (value.join(" · ") || "—") : value }));
      }
      list.appendChild(el("div", { cls: "card" }, [
        el("h3", { text: item.title || item.slug }),
        el("p", { cls: "muted small", text: item.contract_path + " · asked " + fmtTime(item.asked_ts) + " · " + (item.proposal_id || "") }),
        el("p", { cls: "small" }, ["fingerprint ", el("code", { text: (item.fingerprint || "").slice(0, 16) })]),
        seams,
      ]));
    }
  }

  async function approve(event) {
    event.preventDefault();
    const runId = $("appr-run").value;
    const out = $("appr-result");
    if (!runId) return;
    try {
      const result = await api("POST", "/api/runs/" + encodeURIComponent(runId) + "/approvals", { slug: $("appr-slug").value || null, text: $("appr-text").value });
      out.textContent = (result.accepted ? "Accepted: " : "Not accepted: ") + result.reason;
      out.className = "result " + (result.accepted ? "ok" : "bad");
      if (result.accepted) $("appr-text").value = "";
      await loadApprovals();
    } catch (err) {
      out.textContent = err.message;
      out.className = "result bad";
    }
  }

  async function override(event) {
    event.preventDefault();
    const runId = $("appr-run").value;
    const out = $("override-result");
    if (!runId || !confirm("Release the stop gate without verification?")) return;
    try {
      const result = await api("POST", "/api/runs/" + encodeURIComponent(runId) + "/override", { reason: $("override-reason").value });
      out.textContent = (result.accepted ? "Released: " : "Refused: ") + result.reason;
      out.className = "result " + (result.accepted ? "ok" : "bad");
    } catch (err) {
      out.textContent = err.message;
      out.className = "result bad";
    }
  }

  async function ship(dryRun) {
    const projectId = $("ship-project").value;
    const output = $("ship-output");
    if (!projectId) return;
    if (!dryRun && !confirm("Create the branch, push it and open a draft PR?")) return;
    output.textContent = dryRun ? "Planning…" : "Shipping…";
    try {
      const result = await api("POST", "/api/projects/" + encodeURIComponent(projectId) + "/ship", {
        dry_run: dryRun,
        base: $("ship-base").value || "main",
        title: $("ship-title").value || null,
      });
      output.textContent = JSON.stringify(result.result, null, 2) + (result.stderr ? "\n\n" + result.stderr : "");
      state.shipReady = dryRun && result.rc === 0;
      $("ship-go").disabled = !state.shipReady;
      flash((dryRun ? "Dry run" : "Ship") + " finished with exit " + result.rc, result.rc === 0 ? "ok" : "bad");
    } catch (err) {
      output.textContent = err.message;
      $("ship-go").disabled = true;
    }
  }

  function meter(ratio) {
    const fill = el("span", { cls: ratio >= 1 ? "over" : ratio >= 0.8 ? "near" : "" });
    fill.style.width = Math.min(100, Math.round(ratio * 100)) + "%";
    return el("div", { cls: "meter" }, fill);
  }

  async function loadCost(event) {
    if (event) event.preventDefault();
    const params = new URLSearchParams();
    if ($("cost-month").value) params.set("month", $("cost-month").value);
    if ($("cost-run").value) params.set("run_id", $("cost-run").value);
    const cards = clear($("cost-cards"));
    const notes = clear($("cost-notes"));
    let report;
    try {
      report = await api("GET", "/api/cost/report" + (params.toString() ? "?" + params.toString() : ""));
    } catch (err) {
      cards.appendChild(el("p", { cls: "error", text: err.message }));
      return;
    }
    const sums = report.sums || {};
    const caps = report.caps || {};
    const card = (title, value, cap) => el("div", { cls: "card stat" }, [
      el("p", { cls: "muted small", text: title }),
      el("p", { cls: "big", text: fmtUsd(value) }),
      el("p", { cls: "muted small", text: cap ? "cap " + fmtUsd(cap) : "" }),
      cap ? meter((Number(value) || 0) / cap) : null,
    ]);
    cards.appendChild(card("Month " + (sums.month_key || ""), sums.month, caps.monthly_usd));
    cards.appendChild(card("Run", sums.run, caps.per_run_usd));
    cards.appendChild(card("Largest call", sums.max_call, caps.per_call_usd));
    notes.appendChild(el("li", {}, ["Status ", badge(report.status)]));
    for (const line of (report.breaches || []).concat(report.warnings || [])) notes.appendChild(el("li", { text: line }));
    for (const model of sums.unknown_models || []) notes.appendChild(el("li", { text: "No price for model " + model }));
  }

  function wire() {
    $("login-form").addEventListener("submit", (event) => {
      event.preventDefault();
      writeToken($("token-input").value.trim());
      $("token-input").value = "";
      boot();
    });
    $("logout").addEventListener("click", () => { writeToken(null); state.token = null; showLogin(""); });
    for (const tab of document.querySelectorAll("#tabs [role=tab]")) {
      tab.addEventListener("click", () => selectTab(tab.dataset.tab));
    }
    $("key-form").addEventListener("submit", saveKey);
    $("project-form").addEventListener("submit", addProject);
    $("run-form").addEventListener("submit", startRun);
    $("run-cancel").addEventListener("click", cancelRun);
    $("clear-project").addEventListener("change", loadClearances);
    $("appr-run").addEventListener("change", loadApprovals);
    $("appr-form").addEventListener("submit", approve);
    $("override-form").addEventListener("submit", override);
    $("ship-form").addEventListener("submit", (event) => { event.preventDefault(); ship(true); });
    $("ship-go").addEventListener("click", () => ship(false));
    $("ship-project").addEventListener("change", () => { $("ship-go").disabled = true; });
    $("cost-form").addEventListener("submit", loadCost);
  }

  wire();
  boot();
})();

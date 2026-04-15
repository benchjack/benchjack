// ================================================================
// BenchJack — Frontend application
// ================================================================

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

// ---- Vulnerability class metadata ----
const VULN_META = {
  V1: { name: "No Isolation", desc: "Agent and evaluator share filesystem/containers/processes" },
  V2: { name: "Answers Shipped", desc: "Gold answers accessible to agent at runtime" },
  V3: { name: "RCE on Untrusted Input", desc: "eval/exec/subprocess on agent-controlled data" },
  V4: { name: "LLM Judge Injection", desc: "Agent output interpolated into judge prompt without escaping" },
  V5: { name: "Weak String Matching", desc: "Loose string comparison (substring, aggressive normalization)" },
  V6: { name: "Evaluation Logic Gaps", desc: "Scoring paths skip checks or default to pass" },
  V7: { name: "Trust Untrusted Output", desc: "Evaluator trusts artefacts from agent environment" },
  V8: { name: "Excessive Permissions", desc: "Root, --privileged, unrestricted network, excessive mounts" },
};

// ---- State ----
const state = {
  running: false,
  currentPhase: null,
  findings: [],
  severityFilter: "all",
  activeTab: "setup",
  activeView: "output", // "output" | "summary"
  mainView: "dashboard", // "dashboard" | "detail"
  mode: "audit", // "audit" | "hack"
  // Structured messages per phase (for the output view)
  phaseMessages: {
    setup: [],
    recon: [],
    vuln_scan: [],
    poc: [],
    report: [],
    poc_full: [],
    hack: [],
    verify: [],
  },
  // Last AI text per phase (for the summary view)
  phaseSummary: {
    setup: "",
    recon: "",
    vuln_scan: "",
    poc: "",
    report: "",
    poc_full: "",
    hack: "",
    verify: "",
  },
  // Track whether user manually picked a tab (suppresses auto-switch)
  userPickedTab: false,
  // Whether audit has completed (to show Full PoC button)
  auditDone: false,
  // Selected phase to restart from (null = fresh audit)
  selectedRestartPhase: null,
  // Scoreboard data
  tasks: {},        // { taskId: { V1: { hacked, explanation }, ... } }
  vulnClasses: {},  // { V1: { severity, title, description }, ... }
  // Current run being viewed
  currentRunId: null,
};

// ---- Elements ----
const els = {
  form:           $("#audit-form"),
  targetInput:    $("#target-input"),
  startBtn:       $("#start-btn"),
  hackBtn:        $("#hack-btn"),
  cancelBtn:      $("#cancel-btn"),
  fullPocBtn:     $("#run-full-poc-btn"),
  skipPoc:        $("#skip-poc"),
  progressBar:    $("#progress-bar"),
  hackProgressBar:$("#hack-progress-bar"),
  statusBadge:    $("#status-badge"),
  autoscroll:     $("#autoscroll"),
  findingsList:   $("#findings-list"),
  findingsCount:  $("#findings-count"),
  sevFilter:      $("#severity-filter"),
  summaryMsg:     $("#summary-message"),
  phaseTabs:      $("#phase-tabs"),
  viewToggle:     $("#view-toggle"),
  viewToggleBtn:  $("#view-toggle-btn"),
  dashboardView:  $("#dashboard-view"),
  detailView:     $("#detail-view"),
  scoreboardBody: $("#scoreboard-body"),
  scoreboardEmpty:$("#scoreboard-empty"),
  scoreboardEmptyText: $("#scoreboard-empty-text"),
  tooltip:        $("#tooltip"),
  tooltipContent: $("#tooltip-content"),
};

// Phase output containers keyed by phase id
const phaseOutputEls = {};
$$(".phase-output").forEach((el) => {
  phaseOutputEls[el.dataset.phase] = el;
});

// Phase markdown containers keyed by phase id
const phaseMarkdownEls = {};
$$(".phase-markdown").forEach((el) => {
  phaseMarkdownEls[el.dataset.phase] = el;
});

// ---- SSE Connection ----
let evtSource = null;

function connectSSE(runId) {
  if (evtSource) evtSource.close();
  if (!runId) return;
  state.currentRunId = runId;
  const url = `/api/events?run=${encodeURIComponent(runId)}`;
  evtSource = new EventSource(url);

  evtSource.onmessage = (e) => {
    try {
      const event = JSON.parse(e.data);
      handleEvent(event);
    } catch (err) {
      console.error("SSE parse error", err);
    }
  };

  evtSource.onerror = () => {
    // Auto-reconnects handled by browser
  };
}

// ---- Event Handling ----
function handleEvent(event) {
  const { type, data } = event;

  switch (type) {
    case "audit_start":
      if (!data.continuation) {
        setRunning(true);
        state.auditDone = false;
        els.fullPocBtn.style.display = "none";
        const isHack = state.mode === "hack";
        els.summaryMsg.textContent = isHack
          ? `Hacking: ${data.target}`
          : `Auditing: ${data.target}`;
        // Reset phases
        $$(".phase").forEach((el) => {
          el.className = "phase pending";
          el.querySelector(".phase-time").textContent = "";
        });
        // Reset progress bar (active one)
        const activeBar = isHack ? els.hackProgressBar : els.progressBar;
        activeBar.querySelectorAll(".progress-segment").forEach((el) => {
          el.className = "progress-segment pending";
        });
        // Show/hide hack tabs in detail view
        $$(".hack-tab").forEach((el) => { el.style.display = isHack ? "" : "none"; });
        // Hide audit-only tabs in hack mode
        const auditTabs = ["recon", "vuln_scan", "poc", "report"];
        auditTabs.forEach((t) => {
          const tab = $(`.phase-tab[data-tab="${t}"]`);
          if (tab) tab.style.display = isHack ? "none" : "";
        });
        // Reset state
        for (const key of Object.keys(state.phaseMessages)) {
          state.phaseMessages[key] = [];
          state.phaseSummary[key] = "";
        }
        $$(".phase-output").forEach((el) => { el.innerHTML = ""; });
        $$(".phase-markdown").forEach((el) => { el.innerHTML = ""; });
        $$(".phase-tab").forEach((btn) => btn.classList.remove("has-content"));
        state.userPickedTab = false;
        switchTab(isHack ? "hack" : "setup");
        setView("output");
        // Hide setup tab in hack mode (no setup phase)
        const setupTab = $(`.phase-tab[data-tab="setup"]`);
        if (setupTab) setupTab.style.display = isHack ? "none" : "";
        // Reset scoreboard
        state.tasks = {};
        state.vulnClasses = {};
        renderScoreboard();
        resetVulnHeaders();
        updateScoreboardEmpty(isHack ? "Hacking benchmark\u2026" : "Analyzing benchmark\u2026");
      } else {
        // Continuation (e.g. Full PoC) — just mark running
        setRunning(true);
      }
      break;

    case "phase_start":
      state.currentPhase = data.phase;
      setPhaseState(data.phase, "running");
      // Show poc_full elements if needed
      if (data.phase === "poc_full") {
        showPocFullUI();
      }
      // Add a phase header to the output
      appendConvBox(data.phase, {
        msg_type: "text",
        text: `**Phase: ${data.label || data.phase}**`,
      });
      // Auto-switch to the phase tab (unless user manually picked one)
      if (!state.userPickedTab) {
        switchTab(data.phase);
      }
      // Update scoreboard empty message based on phase
      if (data.phase === "poc" || data.phase === "poc_full") {
        updateScoreboardEmpty("Running exploits\u2026");
      }
      break;

    case "phase_complete":
      setPhaseState(data.phase, data.status);
      if (data.duration) {
        const phaseEl = $(`.phase[data-phase="${data.phase}"]`);
        if (phaseEl) {
          phaseEl.querySelector(".phase-time").textContent = `${data.duration}s`;
        }
      }
      // Final markdown render for the summary view
      renderPhaseSummary(data.phase);
      break;

    case "phase_skip":
      setPhaseState(data.phase, "skipped");
      break;

    case "log": {
      const msgType = data.msg_type || "text";
      const phase = data.phase || state.currentPhase || (state.mode === "hack" ? "hack" : "setup");

      // Store the message
      state.phaseMessages[phase] = state.phaseMessages[phase] || [];
      state.phaseMessages[phase].push(data);

      // Track last AI text for summary
      if (msgType === "text" && data.text) {
        state.phaseSummary[phase] = data.text;
      }

      // Mark tab as having content
      const tabBtn = $(`.phase-tab[data-tab="${phase}"]`);
      if (tabBtn) tabBtn.classList.add("has-content");

      // Render the conversation box
      appendConvBox(phase, data);
      break;
    }

    case "finding":
      addFinding(data);
      // Track vulnerability classes for scoreboard
      if (data.vulnerability && /^V[1-8]$/.test(data.vulnerability)) {
        if (!state.vulnClasses[data.vulnerability]) {
          state.vulnClasses[data.vulnerability] = {
            severity: data.severity,
            title: data.title,
            description: data.description,
          };
        }
        updateVulnHeaders();
      }
      break;

    case "task_result": {
      const { task, vulnerability, severity, hacked, explanation } = data;
      if (!task || !vulnerability) break;
      if (!state.tasks[task]) {
        state.tasks[task] = {};
      }
      state.tasks[task][vulnerability] = {
        severity: severity || "",
        hacked: !!hacked,
        explanation: explanation || "",
      };
      renderScoreboard();
      break;
    }

    case "task_ids": {
      const ids = Array.isArray(data.task_ids) ? data.task_ids : [];
      for (const id of ids) {
        if (!id) continue;
        if (!state.tasks[id]) state.tasks[id] = {};
      }
      renderScoreboard();
      break;
    }

    case "error":
      appendConvBox(data.phase || state.currentPhase || (state.mode === "hack" ? "hack" : "setup"), {
        msg_type: "text",
        text: `**ERROR:** ${data.message}`,
        _isError: true,
      });
      break;

    case "audit_complete":
      setRunning(false);
      state.auditDone = true;
      if (state.mode === "hack") {
        els.summaryMsg.textContent = `Hack complete for ${data.target}`;
        // Auto-switch to verify tab if it has content
        if (state.phaseSummary.verify) {
          switchTab("verify");
          setView("summary");
          state.userPickedTab = false;
        } else if (state.phaseSummary.hack) {
          switchTab("hack");
          setView("summary");
          state.userPickedTab = false;
        }
      } else {
        els.summaryMsg.textContent = data.loaded_from_history
          ? `Loaded run: ${data.total_findings} finding(s) for ${data.target}`
          : `Audit complete: ${data.total_findings} finding(s) for ${data.target}`;
        // Show Full PoC button if there are findings, not a continuation, and not a history load
        if (!data.continuation && !data.loaded_from_history && data.total_findings > 0) {
          els.fullPocBtn.style.display = "";
        }
        // Auto-switch to report tab if it has content
        if (state.phaseSummary.report) {
          switchTab("report");
          setView("summary");
          state.userPickedTab = false;
        }
      }
      // Update scoreboard empty message if no tasks
      if (Object.keys(state.tasks).length === 0) {
        updateScoreboardEmpty(state.mode === "hack"
          ? "Hack run complete"
          : "No task-level results available");
      }
      break;
  }
}

// ---- Tab management ----

function switchTab(tabId) {
  state.activeTab = tabId;
  // Update tab buttons
  $$(".phase-tab").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.tab === tabId);
  });
  // Update tab panes
  $$(".tab-pane").forEach((pane) => {
    pane.classList.toggle("active", pane.id === `tab-${tabId}`);
  });
  // Apply current view
  applyView();
}

// ---- View toggle (Output / Summary) ----

function setView(view) {
  state.activeView = view;
  $$(".view-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.view === view);
  });
  applyView();
}

function applyView() {
  // In the active tab pane, show the correct sub-view
  const pane = $(`#tab-${state.activeTab}`);
  if (!pane) return;
  const outputEl = pane.querySelector(".phase-output");
  const summaryEl = pane.querySelector(".phase-summary");
  if (outputEl && summaryEl) {
    if (state.activeView === "output") {
      outputEl.classList.add("active");
      summaryEl.classList.remove("active");
    } else {
      outputEl.classList.remove("active");
      summaryEl.classList.add("active");
    }
  }
}

// ---- Main view toggle (Dashboard / Detail) ----

function setMainView(view) {
  state.mainView = view;
  if (view === "dashboard") {
    els.dashboardView.style.display = "";
    els.detailView.style.display = "none";
    els.viewToggleBtn.textContent = "View Logs";
  } else {
    els.dashboardView.style.display = "none";
    els.detailView.style.display = "";
    els.viewToggleBtn.textContent = "Dashboard";
  }
}

// ---- Conversation box rendering ----

function appendConvBox(phase, data) {
  const container = phaseOutputEls[phase];
  if (!container) return;

  const box = document.createElement("div");
  const msgType = data.msg_type || "text";

  if (msgType === "text") {
    box.className = `conv-box conv-text${data._isError ? " conv-error" : ""}`;
    const text = data.text || "";
    box.innerHTML =
      `<div class="conv-header"><span class="conv-label">Assistant</span></div>` +
      `<div class="conv-body">${marked.parse(text)}</div>`;
  } else if (msgType === "tool_call") {
    box.className = "conv-box conv-tool-call";
    box.innerHTML =
      `<div class="conv-header"><span class="conv-label">Tool: ${escapeHTML(data.name || "?")}</span></div>` +
      `<div class="conv-body"><code>${escapeHTML(data.summary || "")}</code></div>`;
  } else if (msgType === "tool_result") {
    box.className = "conv-box conv-tool-result";
    const chars = (data.chars || 0).toLocaleString();
    box.innerHTML =
      `<div class="conv-header"><span class="conv-label">Result</span></div>` +
      `<div class="conv-body"><span class="result-size">${chars} chars</span></div>`;
  } else {
    return;
  }

  container.appendChild(box);

  // Auto-scroll
  if (state.activeTab === phase && state.activeView === "output" && els.autoscroll.checked) {
    const pane = $(`#tab-${phase}`);
    if (pane) pane.scrollTop = pane.scrollHeight;
  }
}

// ---- Summary (markdown) rendering ----

function renderPhaseSummary(phase) {
  const el = phaseMarkdownEls[phase];
  if (!el) return;
  const raw = state.phaseSummary[phase];
  if (!raw) return;
  el.innerHTML = marked.parse(raw);
  // Auto-scroll if viewing summary
  if (state.activeTab === phase && state.activeView === "summary" && els.autoscroll.checked) {
    const pane = $(`#tab-${phase}`);
    if (pane) pane.scrollTop = pane.scrollHeight;
  }
}

// ---- UI Updates ----
function setRunning(running) {
  state.running = running;
  els.cancelBtn.style.display = running ? "" : "none";
  // Hide form controls when running, show when idle
  els.startBtn.style.display = running ? "none" : "";
  els.hackBtn.style.display = running ? "none" : "";
  els.skipPoc.parentElement.style.display = running ? "none" : "";
  $('label[for="target-input"]').style.display = running ? "none" : "";
  if (running) {
    els.fullPocBtn.style.display = "none";
    // Replace input with read-only label
    state._savedTarget = els.targetInput.value;
    const verb = state.mode === "hack" ? "Hacking" : "Auditing";
    els.targetInput.value = `${verb}: ${els.targetInput.value}`;                                                                                
    els.targetInput.readOnly = true;                                                                                                             
    els.targetInput.classList.add("input-running");                                                                                              
  } else {
    // Restore editable input                                                                                                                    
    if (state._savedTarget !== undefined) {                                                                                                      
      els.targetInput.value = state._savedTarget;                                                                                                
      delete state._savedTarget;                                                                                                                 
    }                                                                                                                                            
    els.targetInput.readOnly = false;                                                                                                            
    els.targetInput.classList.remove("input-running");
  }
  els.statusBadge.className = `badge ${running ? "badge-running" : "badge-idle"}`;
  els.statusBadge.textContent = running ? "RUNNING" : "IDLE";
}

function setPhaseState(phaseId, status) {
  // Update timeline dot (detail view)
  const el = $(`.phase[data-phase="${phaseId}"]`);
  if (el) {
    el.className = `phase ${status}`;
  }
  // Update progress bar (dashboard view) — find in the active bar
  const activeBar = state.mode === "hack" ? els.hackProgressBar : els.progressBar;
  const seg = activeBar.querySelector(`.progress-segment[data-phase="${phaseId}"]`);
  if (seg) {
    seg.className = `progress-segment ${status}`;
  }
}

function showPocFullUI() {
  // Show timeline elements
  $$(".poc-full-connector").forEach((el) => el.style.display = "");
  $$(".poc-full-phase").forEach((el) => el.style.display = "");
  // Show tab
  const tab = $("#poc-full-tab");
  if (tab) tab.style.display = "";
}

function addFinding(data) {
  state.findings.push(data);
  updateFindingsCounts();
  renderFindingCard(data);
}

function renderFindingCard(f) {
  if (state.severityFilter !== "all" && f.severity !== state.severityFilter) return;

  const card = document.createElement("div");
  card.className = "finding-card";
  card.dataset.severity = f.severity;

  const truncDesc = (f.description || "").length > 200
    ? f.description.substring(0, 200) + "..."
    : (f.description || "");

  card.innerHTML = `
    <div class="finding-header">
      <span class="finding-vuln ${f.severity}">${f.vulnerability}</span>
      <span class="finding-severity ${f.severity}">${f.severity}</span>
      <span class="finding-source">${f.source || ""}</span>
    </div>
    <div class="finding-title">${escapeHTML(f.title || "")}</div>
    <div class="finding-desc">${escapeHTML(truncDesc)}</div>
    ${f.file ? `<div class="finding-location">${escapeHTML(f.file)}${f.line ? `:${f.line}` : ""}</div>` : ""}
  `;

  els.findingsList.appendChild(card);
}

function updateFindingsCounts() {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, total: 0 };
  for (const f of state.findings) {
    counts.total++;
    if (counts[f.severity] !== undefined) counts[f.severity]++;
  }
  els.findingsCount.textContent = counts.total;
  $("#stat-critical").textContent = `${counts.CRITICAL} Critical`;
  $("#stat-high").textContent     = `${counts.HIGH} High`;
  $("#stat-medium").textContent   = `${counts.MEDIUM} Medium`;
  $("#stat-low").textContent      = `${counts.LOW} Low`;
  $("#stat-total").textContent    = `${counts.total} Total`;
}

// ---- Filtering ----
function refilterFindings() {
  els.findingsList.innerHTML = "";
  for (const f of state.findings) {
    renderFindingCard(f);
  }
}

// ---- Scoreboard ----

function renderScoreboard() {
  const tbody = els.scoreboardBody;
  tbody.innerHTML = "";

  const allTasksData = state.tasks["all_tasks"] || {};
  const taskIds = Object.keys(state.tasks).filter((t) => t !== "all_tasks").sort();

  if (taskIds.length === 0) {
    els.scoreboardEmpty.style.display = "";
    return;
  }

  els.scoreboardEmpty.style.display = "none";

  for (const taskId of taskIds) {
    const taskData = state.tasks[taskId];
    const row = document.createElement("tr");

    // Task name cell
    const nameCell = document.createElement("td");
    nameCell.className = "col-task";
    nameCell.textContent = taskId;
    row.appendChild(nameCell);

    // V1-V7 cells
    let anyHacked = false;
    for (let i = 1; i <= 8; i++) {
      const vId = `V${i}`;
      const cell = document.createElement("td");
      cell.className = "col-vuln";

      const vulnResult = taskData[vId] || allTasksData[vId];
      if (vulnResult && !/^ABSENT/.test(vulnResult.explanation || "")) {
        const dot = document.createElement("span");
        const severity = (vulnResult.severity || state.vulnClasses[vId]?.severity || "MEDIUM").toUpperCase();
        dot.className = "vuln-dot";
        dot.dataset.severity = severity;
        dot.dataset.vuln = vId;
        dot.dataset.task = taskId;
        dot.dataset.hacked = vulnResult.hacked ? "true" : "false";
        dot.dataset.explanation = vulnResult.explanation || "";
        cell.appendChild(dot);
        if (vulnResult.hacked) anyHacked = true;
      }

      row.appendChild(cell);
    }

    // PoC certified column
    const certCell = document.createElement("td");
    certCell.className = "col-poc";
    if (anyHacked) {
      const mark = document.createElement("span");
      mark.className = "poc-certified";
      mark.textContent = "\u2713";
      certCell.appendChild(mark);
    }
    row.appendChild(certCell);

    tbody.appendChild(row);
  }
}

function updateVulnHeaders() {
  for (const [vuln, info] of Object.entries(state.vulnClasses)) {
    const th = $(`#scoreboard-table th[data-vuln="${vuln}"]`);
    if (th) {
      th.classList.add("has-findings");
      th.dataset.severity = info.severity;
    }
  }
}

function resetVulnHeaders() {
  $$("#scoreboard-table th.col-vuln").forEach((th) => {
    th.classList.remove("has-findings");
    delete th.dataset.severity;
  });
}

function updateScoreboardEmpty(msg) {
  if (els.scoreboardEmptyText) {
    els.scoreboardEmptyText.textContent = msg;
  }
}

// ---- Tooltip ----

function showTooltip(dot) {
  const vuln = dot.dataset.vuln;
  const task = dot.dataset.task;
  const hacked = dot.dataset.hacked === "true";
  const explanation = dot.dataset.explanation;
  const vulnInfo = state.vulnClasses[vuln] || {};
  const meta = VULN_META[vuln] || {};

  let html = `<strong>${escapeHTML(vuln)}: ${escapeHTML(meta.name || vulnInfo.title || vuln)}</strong>`;
  html += `<div class="tooltip-row">Task: ${escapeHTML(task)}</div>`;
  if (hacked) {
    html += `<div class="tooltip-row">Status: <span class="tooltip-pass">Exploited</span></div>`;
  }
  const severity = (dot.dataset.severity || vulnInfo.severity || "").toUpperCase();
  if (severity) {
    html += `<div class="tooltip-row">Severity: <span class="tooltip-sev-${severity.toLowerCase()}">${severity}</span></div>`;
  }
  if (explanation) {
    html += `<div class="tooltip-explanation">${escapeHTML(explanation)}</div>`;
  }

  els.tooltipContent.innerHTML = html;

  const rect = dot.getBoundingClientRect();
  els.tooltip.style.display = "";
  els.tooltip.style.left = `${rect.left + rect.width / 2}px`;
  els.tooltip.style.top = `${rect.bottom + 8}px`;

  // Adjust if tooltip goes off screen
  requestAnimationFrame(() => {
    const tipRect = els.tooltip.getBoundingClientRect();
    if (tipRect.right > window.innerWidth - 10) {
      els.tooltip.style.left = `${window.innerWidth - tipRect.width - 10}px`;
    }
    if (tipRect.left < 10) {
      els.tooltip.style.left = "10px";
    }
    if (tipRect.bottom > window.innerHeight - 10) {
      els.tooltip.style.top = `${rect.top - tipRect.height - 8}px`;
    }
  });
}

function hideTooltip() {
  els.tooltip.style.display = "none";
}

// ---- Actions ----
async function startAudit(target, skipPoc) {
  resetUIState("audit");
  updateScoreboardEmpty("Analyzing benchmark\u2026");

  const resp = await fetch("/api/audit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, skip_poc: skipPoc }),
  });
  const result = await resp.json();
  if (result.error) {
    alert(`Error: ${result.error}`);
    setRunning(false);
    return;
  }
  connectSSE(result.run_id);
}

async function cancelAudit() {
  await fetch("/api/cancel", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ run_id: state.currentRunId }),
  });
  setRunning(false);
  els.statusBadge.className = "badge badge-error";
  els.statusBadge.textContent = "CANCELLED";
}

async function runFullPoc() {
  els.fullPocBtn.style.display = "none";
  showPocFullUI();

  const resp = await fetch("/api/poc-full", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ run_id: state.currentRunId }),
  });
  const result = await resp.json();
  if (result.error) {
    alert(`Error: ${result.error}`);
  }
}

// ---- Re-run from phase ----
async function rerunFromPhase(fromPhase) {
  if (!state.currentRunId) {
    alert("No run to re-run from.");
    return;
  }
  if (state.running) {
    alert("Pipeline is still running. Cancel it first.");
    return;
  }

  resetUIState("audit");
  updateScoreboardEmpty(`Re-running from ${fromPhase}\u2026`);

  const resp = await fetch("/api/rerun", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ run_id: state.currentRunId, from_phase: fromPhase }),
  });
  const result = await resp.json();
  if (result.error) {
    alert(`Error: ${result.error}`);
    setRunning(false);
    return;
  }
  connectSSE(result.run_id);
}

// ---- Hack mode ----
async function startHack(target) {
  resetUIState("hack");
  updateScoreboardEmpty("Hacking benchmark\u2026");

  const resp = await fetch("/api/hack", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target }),
  });
  const result = await resp.json();
  if (result.error) {
    alert(`Error: ${result.error}`);
    setRunning(false);
    return;
  }
  connectSSE(result.run_id);
}

// ---- Helpers ----
function escapeHTML(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

// ---- Event Listeners ----
els.form.addEventListener("submit", (e) => {
  e.preventDefault();
  const target = els.targetInput.value.trim();
  if (!target) return;
  if (state.selectedRestartPhase && state.currentRunId) {
    rerunFromPhase(state.selectedRestartPhase);
    state.selectedRestartPhase = null;
  } else {
    startAudit(target, els.skipPoc.checked);
  }
});

els.cancelBtn.addEventListener("click", cancelAudit);
els.fullPocBtn.addEventListener("click", runFullPoc);

els.hackBtn.addEventListener("click", () => {
  const target = els.targetInput.value.trim();
  if (!target) return;
  startHack(target);
});

// Tab clicks
els.phaseTabs.addEventListener("click", (e) => {
  const btn = e.target.closest(".phase-tab");
  if (!btn) return;
  state.userPickedTab = true;
  switchTab(btn.dataset.tab);
});

// View toggle clicks (Output / Summary)
els.viewToggle.addEventListener("click", (e) => {
  const btn = e.target.closest(".view-btn");
  if (!btn) return;
  setView(btn.dataset.view);
});

// Main view toggle (Dashboard / Detail)
els.viewToggleBtn.addEventListener("click", () => {
  setMainView(state.mainView === "dashboard" ? "detail" : "dashboard");
});

// Severity filter
els.sevFilter.addEventListener("change", (e) => {
  state.severityFilter = e.target.value;
  refilterFindings();
});

// Progress bar segment clicks — select phase to restart from
const RERUNNABLE_PHASES = ["recon", "vuln_scan", "poc", "report"];
const PHASE_LABELS = { recon: "recon", vuln_scan: "vuln scan", poc: "poc", report: "report" };

function selectRestartPhase(phase) {
  // Toggle: clicking already-selected deselects
  if (state.selectedRestartPhase === phase) {
    state.selectedRestartPhase = null;
  } else {
    state.selectedRestartPhase = phase;
  }
  // Update segment visuals
  $$("#progress-bar .progress-segment").forEach((seg) => {
    seg.classList.remove("selected");
  });
  if (state.selectedRestartPhase) {
    const sel = $(`#progress-bar .progress-segment[data-phase="${state.selectedRestartPhase}"]`);
    if (sel) sel.classList.add("selected");
  }
  // Update start button text
  if (state.selectedRestartPhase) {
    els.startBtn.textContent = `restart from ${PHASE_LABELS[state.selectedRestartPhase]}`;
  } else {
    els.startBtn.textContent = "start audit";
  }
}

els.progressBar.addEventListener("click", (e) => {
  const seg = e.target.closest(".progress-segment");
  if (!seg) return;
  const phase = seg.dataset.phase;
  if (!RERUNNABLE_PHASES.includes(phase)) return;
  if (state.running) return;
  if (!state.currentRunId) return;
  selectRestartPhase(phase);
});

// Tooltip handling for scoreboard dots
document.addEventListener("mouseover", (e) => {
  const dot = e.target.closest(".vuln-dot");
  if (dot) {
    showTooltip(dot);
  }
});

document.addEventListener("mouseout", (e) => {
  const dot = e.target.closest(".vuln-dot");
  if (dot) {
    hideTooltip();
  }
});

// ---- Runs panel ----

const runsPanel = $("#runs-panel");
const runsList = $("#runs-list");
const runsBtn = $("#runs-btn");
const runsCloseBtn = $("#runs-close-btn");

let runsPanelOpen = false;

function toggleRunsPanel() {
  runsPanelOpen = !runsPanelOpen;
  runsPanel.style.display = runsPanelOpen ? "" : "none";
  runsBtn.classList.toggle("active", runsPanelOpen);
  if (runsPanelOpen) {
    fetchRuns();
  }
}

runsBtn.addEventListener("click", toggleRunsPanel);
runsCloseBtn.addEventListener("click", () => {
  runsPanelOpen = false;
  runsPanel.style.display = "none";
  runsBtn.classList.remove("active");
});

async function fetchRuns() {
  runsList.innerHTML = '<div class="runs-empty">Loading\u2026</div>';
  try {
    const resp = await fetch("/api/runs");
    const data = await resp.json();
    renderRunsList(data.runs || []);
  } catch (err) {
    runsList.innerHTML = '<div class="runs-empty">Failed to load runs</div>';
  }
}

function renderRunsList(runs) {
  if (runs.length === 0) {
    runsList.innerHTML = '<div class="runs-empty">No previous runs found</div>';
    return;
  }

  runsList.innerHTML = "";
  for (const run of runs) {
    const card = document.createElement("div");
    card.className = "run-card";
    card.dataset.status = run.status;

    // Phase progress dots
    const phaseDots = ["setup", "recon", "vuln_scan", "poc", "report"]
      .map((pid) => {
        const phaseStatus = run.phases[pid]?.status || "pending";
        return `<span class="run-phase-dot ${phaseStatus}" title="${pid}: ${phaseStatus}"></span>`;
      })
      .join("");

    // Status badge
    const statusLabels = {
      completed: "Completed",
      incomplete: "Incomplete",
      failed: "Failed",
      empty: "Empty",
      running: "Running",
    };
    const statusLabel = statusLabels[run.status] || run.status;

    // Duration display
    const duration = run.total_duration > 0
      ? formatDuration(run.total_duration)
      : "";

    // Findings count
    const findingsText = run.findings_count > 0
      ? `${run.findings_count} finding${run.findings_count !== 1 ? "s" : ""}`
      : "";

    // Relative time
    const timeAgo = formatTimeAgo(run.mtime);

    // Action buttons
    const isRunning = run.status === "running";
    const canContinue = run.status === "incomplete" || run.status === "failed";

    let actions = "";
    if (isRunning) {
      actions += `<button class="run-action run-action-view" data-name="${escapeHTML(run.name)}" data-target="${escapeHTML(run.target)}">View</button>`;
    } else {
      actions += `<button class="run-action run-action-load" data-name="${escapeHTML(run.name)}" data-target="${escapeHTML(run.target)}">Load</button>`;
    }
    if (canContinue) {
      actions += `<button class="run-action run-action-continue" data-name="${escapeHTML(run.name)}" data-target="${escapeHTML(run.target)}">Continue</button>`;
    }

    card.innerHTML = `
      <div class="run-card-top">
        <div class="run-card-info">
          <span class="run-name">${escapeHTML(run.name)}</span>
          <span class="run-status-badge run-status-${run.status}">${statusLabel}</span>
        </div>
        <div class="run-card-meta">
          ${findingsText ? `<span class="run-findings">${findingsText}</span>` : ""}
          ${duration ? `<span class="run-duration">${duration}</span>` : ""}
          <span class="run-time">${timeAgo}</span>
        </div>
      </div>
      <div class="run-card-bottom">
        <div class="run-phases">${phaseDots}</div>
        <div class="run-actions">${actions}</div>
      </div>
    `;

    runsList.appendChild(card);
  }

  // Attach event listeners
  runsList.querySelectorAll(".run-action-load").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      loadRun(btn.dataset.name, btn.dataset.target);
    });
  });

  runsList.querySelectorAll(".run-action-view").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      viewActiveRun(btn.dataset.name, btn.dataset.target);
    });
  });

  runsList.querySelectorAll(".run-action-continue").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      continueRun(btn.dataset.target);
    });
  });
}

async function loadRun(name, target) {
  // Close the panel
  runsPanelOpen = false;
  runsPanel.style.display = "none";
  runsBtn.classList.remove("active");

  // Reset UI state for loading
  resetUIState("audit");
  updateScoreboardEmpty("Loading run\u2026");
  els.targetInput.value = target;

  try {
    const resp = await fetch(`/api/runs/${encodeURIComponent(name)}/load`, {
      method: "POST",
    });
    const result = await resp.json();
    if (result.error) {
      alert(`Error: ${result.error}`);
      return;
    }
    connectSSE(result.run_id);
  } catch (err) {
    alert(`Failed to load run: ${err.message}`);
  }
}

function viewActiveRun(name, target) {
  // Switch the SSE connection to an already-running run
  runsPanelOpen = false;
  runsPanel.style.display = "none";
  runsBtn.classList.remove("active");

  resetUIState("audit");
  els.targetInput.value = target;
  connectSSE(name);
}

async function continueRun(target) {
  // Close the panel
  runsPanelOpen = false;
  runsPanel.style.display = "none";
  runsBtn.classList.remove("active");

  // Set the target and start the audit — _try_resume will pick up completed phases
  els.targetInput.value = target;
  startAudit(target, els.skipPoc.checked);
}

// Shared UI reset used by loadRun, viewActiveRun, startAudit, startHack
function resetUIState(mode) {
  state.mode = mode;
  state.findings = [];
  state.currentPhase = null;
  state.auditDone = false;
  state.selectedRestartPhase = null;
  els.startBtn.textContent = "start audit";
  $$("#progress-bar .progress-segment").forEach((seg) => seg.classList.remove("selected"));
  state.tasks = {};
  state.vulnClasses = {};
  els.findingsList.innerHTML = "";
  updateFindingsCounts();
  for (const key of Object.keys(state.phaseMessages)) {
    state.phaseMessages[key] = [];
    state.phaseSummary[key] = "";
  }
  $$(".phase-output").forEach((el) => { el.innerHTML = ""; });
  $$(".phase-markdown").forEach((el) => { el.innerHTML = ""; });
  $$(".phase-tab").forEach((btn) => btn.classList.remove("has-content"));
  state.userPickedTab = false;
  switchTab(mode === "hack" ? "hack" : "setup");
  setView("output");

  // Hide setup tab in hack mode (no setup phase)
  const setupTab = $(`.phase-tab[data-tab="setup"]`);
  if (setupTab) setupTab.style.display = mode === "hack" ? "none" : "";

  els.progressBar.style.display = mode === "hack" ? "none" : "";
  els.hackProgressBar.style.display = mode === "hack" ? "" : "none";
  const bar = mode === "hack" ? els.hackProgressBar : els.progressBar;
  bar.querySelectorAll(".progress-segment").forEach((el) => {
    el.className = "progress-segment pending";
  });

  renderScoreboard();
  resetVulnHeaders();
  setMainView("dashboard");

  $$(".poc-full-connector").forEach((el) => el.style.display = "none");
  $$(".poc-full-phase").forEach((el) => el.style.display = "none");
  const pocFullTab = $("#poc-full-tab");
  if (pocFullTab) pocFullTab.style.display = "none";
  els.fullPocBtn.style.display = "none";
}

function formatDuration(seconds) {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const mins = Math.floor(seconds / 60);
  const secs = Math.round(seconds % 60);
  return secs > 0 ? `${mins}m ${secs}s` : `${mins}m`;
}

function formatTimeAgo(unixTime) {
  const now = Date.now() / 1000;
  const diff = now - unixTime;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
  const d = new Date(unixTime * 1000);
  return d.toLocaleDateString();
}

// ---- Pre-fill target from URL params ----
const params = new URLSearchParams(window.location.search);
if (params.has("target")) {
  els.targetInput.value = params.get("target");
}
// Auto-start if requested
if (params.has("autostart") && els.targetInput.value) {
  setTimeout(() => startAudit(els.targetInput.value, false), 500);
}

// No auto-connect — SSE connects when a run is started, loaded, or viewed.

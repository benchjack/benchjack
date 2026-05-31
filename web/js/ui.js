// ================================================================
// UI helpers — phase state, tabs, view switching, conversation boxes
// ================================================================

import { $, $$, DEFAULT_REFINE_ROUNDS, MAX_REFINE_ROUNDS } from "./state.js";
import { state, els, phaseOutputEls, phaseMarkdownEls } from "./state.js";
import { renderScoreboard, resetVulnHeaders } from "./scoreboard.js";
import { updateFindingsCounts } from "./findings.js";

// ---- Running state ----

/**
 * Show/hide the action buttons based on current state.
 * Called whenever selectedRestartPhase, currentRunId, or loadedRunFinished changes.
 */
export function updateActionButtons() {
  if (state.running) return; // setRunning handles visibility while running

  const hasLoadedRun = !!state.currentRunId;
  const hasStageSelected = !!state.selectedRestartPhase;

  if (hasLoadedRun && !hasStageSelected) {
    // Show continue, hide start/hack/refine
    els.startBtn.style.display = "none";
    els.hackBtn.style.display = "none";
    els.refineControl.style.display = "none";
    els.continueBtn.style.display = "";
    const done = state.loadedRunFinished;
    els.continueBtn.disabled = done;
    els.continueBtn.title = done ? "This run is completed" : "";
    els.continueBtn.classList.toggle("btn-continue-done", done);
  } else {
    // No loaded run, or a restart stage is selected → show start/hack/refine
    els.startBtn.style.display = "";
    els.hackBtn.style.display = "";
    els.refineControl.style.display = "";
    els.continueBtn.style.display = "none";
  }
}

export function setRunning(running) {
  state.running = running;
  els.cancelBtn.style.display = running ? "" : "none";
  $('label[for="target-input"]').style.display = running ? "none" : "";
  $$(".cycle-btn").forEach(g => { g.style.display = running ? "none" : ""; });
  els.refineMenu.hidden = true;
  els.refineMenuBtn.classList.remove("active");

  if (running) {
    // Hide all action buttons while pipeline is running
    els.startBtn.style.display = "none";
    els.hackBtn.style.display = "none";
    els.refineControl.style.display = "none";
    els.continueBtn.style.display = "none";
    state._savedTarget = els.targetInput.value;
    const verb = state.mode === "refine" ? "Refining"
      : state.mode === "hack" ? "Hacking"
      : "Auditing";
    els.targetInput.value = `${verb}: ${els.targetInput.value}`;
    els.targetInput.readOnly = true;
    els.targetInput.classList.add("input-running");
  } else {
    if (state._savedTarget !== undefined) {
      els.targetInput.value = state._savedTarget;
      delete state._savedTarget;
    }
    els.targetInput.readOnly = false;
    els.targetInput.classList.remove("input-running");
    updateActionButtons();
  }

  els.statusBadge.className = `badge ${running ? "badge-running" : "badge-idle"}`;
  els.statusBadge.textContent = running ? "RUNNING" : "IDLE";
}

// ---- Phase state ----

export function setTimelineMode(mode) {
  ["audit", "hack", "refine"].forEach((m) => {
    document.querySelectorAll(`#timeline [data-mode='${m}']`).forEach((el) => {
      el.style.display = mode === m ? "" : "none";
    });
  });
}

export function clampRefineRounds(value) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) return DEFAULT_REFINE_ROUNDS;
  return Math.min(Math.max(parsed, 1), MAX_REFINE_ROUNDS);
}

export function setRefineRounds(value) {
  state.refineMaxRounds = clampRefineRounds(value);
  els.refineRoundsInput.value = String(state.refineMaxRounds);
  els.refineRoundsInput.max = String(MAX_REFINE_ROUNDS);
  els.refineBtn.textContent = state.refineMaxRounds === DEFAULT_REFINE_ROUNDS
    ? "~ Refine"
    : `~ Refine ${state.refineMaxRounds}r`;
  els.refineMenuBtn.title = `Refine rounds: ${state.refineMaxRounds}`;
  $$(".refine-round-option").forEach((btn) => {
    btn.classList.toggle("active", Number.parseInt(btn.dataset.rounds, 10) === state.refineMaxRounds);
  });
  ensureRefineUI(state.refineMaxRounds);
}

export function ensureRefineUI(rounds = state.refineMaxRounds) {
  const count = clampRefineRounds(rounds);

  document.querySelectorAll(".phase[data-mode='refine'], .phase-connector[data-mode='refine']").forEach((el) => el.remove());
  document.querySelectorAll(".refine-tab").forEach((el) => el.remove());
  document.querySelectorAll(".tab-pane").forEach((pane) => {
    if (/^tab-r\d+_(attack|patch)$/.test(pane.id)) pane.remove();
  });
  for (const key of Object.keys(phaseOutputEls)) {
    if (/^r\d+_(attack|patch)$/.test(key)) delete phaseOutputEls[key];
  }
  for (const key of Object.keys(phaseMarkdownEls)) {
    if (/^r\d+_(attack|patch)$/.test(key)) delete phaseMarkdownEls[key];
  }

  const phases = [];
  for (let n = 1; n <= count; n += 1) {
    phases.push({ id: `r${n}_attack`, label: `R${n} Attack` });
    if (n < count) phases.push({ id: `r${n}_patch`, label: `R${n} Patch` });
  }

  const timeline = $("#timeline");
  const phaseTabs = els.phaseTabs;
  const logPanel = $("#log-panel");
  phases.forEach((phase, index) => {
    if (index > 0) {
      const connector = document.createElement("div");
      connector.className = "phase-connector";
      connector.dataset.mode = "refine";
      connector.style.display = state.mode === "refine" ? "" : "none";
      timeline.appendChild(connector);
    }

    const phaseEl = document.createElement("div");
    phaseEl.className = "phase pending";
    phaseEl.dataset.phase = phase.id;
    phaseEl.dataset.mode = "refine";
    phaseEl.style.display = state.mode === "refine" ? "" : "none";
    phaseEl.innerHTML = `<div class="phase-dot"></div><span class="phase-label">${phase.label}</span><span class="phase-time"></span>`;
    timeline.appendChild(phaseEl);

    const tab = document.createElement("button");
    tab.className = "phase-tab refine-tab";
    tab.dataset.tab = phase.id;
    tab.style.display = state.mode === "refine" ? "" : "none";
    tab.textContent = phase.label;
    phaseTabs.appendChild(tab);

    const pane = document.createElement("div");
    pane.id = `tab-${phase.id}`;
    pane.className = "tab-pane";
    pane.innerHTML = `
      <div class="phase-output" data-phase="${phase.id}"></div>
      <div class="phase-summary" data-phase="${phase.id}">
        <div class="phase-markdown" data-phase="${phase.id}"></div>
      </div>
    `;
    logPanel.appendChild(pane);
    phaseOutputEls[phase.id] = pane.querySelector(".phase-output");
    phaseMarkdownEls[phase.id] = pane.querySelector(".phase-markdown");
    state.phaseMessages[phase.id] = state.phaseMessages[phase.id] || [];
    state.phaseSummary[phase.id] = state.phaseSummary[phase.id] || "";
  });

  els.refineProgressBar.innerHTML = "";
  for (let n = 1; n <= count; n += 1) {
    const seg = document.createElement("div");
    seg.className = "progress-segment pending";
    seg.dataset.phase = `r${n}`;
    seg.innerHTML = `<div class="segment-fill"></div><span class="segment-label">Round ${n}</span>`;
    els.refineProgressBar.appendChild(seg);
  }
  const resultSeg = document.createElement("div");
  resultSeg.className = "progress-segment pending";
  resultSeg.dataset.phase = "converged";
  resultSeg.innerHTML = `<div class="segment-fill"></div><span class="segment-label">Result</span>`;
  els.refineProgressBar.appendChild(resultSeg);
}

export function setPhaseState(phaseId, status) {
  const el = $(`.phase[data-phase="${phaseId}"]`);
  if (el) el.className = `phase ${status}`;

  // Refine progress bar is managed by refine_round_complete / refine_complete
  // events in handlers.js — do not touch it from here.
  if (state.mode === "refine") return;

  const activeBar = state.mode === "hack" ? els.hackProgressBar : els.progressBar;
  const seg = activeBar.querySelector(`.progress-segment[data-phase="${phaseId}"]`);
  if (seg) seg.className = `progress-segment ${status}`;
}

// ---- Tab and view management ----

export function switchTab(tabId) {
  state.activeTab = tabId;
  $$(".phase-tab").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.tab === tabId);
  });
  $$(".tab-pane").forEach((pane) => {
    pane.classList.toggle("active", pane.id === `tab-${tabId}`);
  });
  applyView();
}

export function setView(view) {
  state.activeView = view;
  $$(".view-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.view === view);
  });
  applyView();
}

export function applyView() {
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

export function setMainView(view) {
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

export function appendConvBox(phase, data) {
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
    const name = data.name || "?";
    const summary = data.summary || "";
    box.innerHTML =
      `<div class="conv-header"><span class="conv-label">Tool: ${escapeHTML(name)}</span></div>` +
      `<div class="conv-body"><code>${escapeHTML(summary)}</code></div>`;
  } else if (msgType === "tool_result") {
    box.className = "conv-box conv-tool-result";
    const chars = (data.chars || 0).toLocaleString();
    box.innerHTML =
      `<div class="conv-header"><span class="conv-label">Result</span></div>` +
      `<div class="conv-body"><span class="result-size">${chars} chars</span></div>`;
  } else if (msgType === "prompt") {
    box.className = "conv-box conv-prompt";
    const text = data.text || "";
    box.innerHTML =
      `<details class="prompt-details">` +
      `<summary class="conv-header"><span class="conv-label">Prompt</span></summary>` +
      `<div class="conv-body">${marked.parse(text)}</div>` +
      `</details>`;
  } else {
    return;
  }

  container.appendChild(box);

  if (state.activeTab === phase && state.activeView === "output" && els.autoscroll.checked) {
    const pane = $(`#tab-${phase}`);
    if (pane) pane.scrollTop = pane.scrollHeight;
  }
}

// ---- Summary markdown rendering ----

export function renderPhaseSummary(phase) {
  const el = phaseMarkdownEls[phase];
  if (!el) return;
  const raw = state.phaseSummary[phase];
  if (!raw) return;
  el.innerHTML = marked.parse(raw);
  if (state.activeTab === phase && state.activeView === "summary" && els.autoscroll.checked) {
    const pane = $(`#tab-${phase}`);
    if (pane) pane.scrollTop = pane.scrollHeight;
  }
}

// ---- Shared UI reset (used by api.js and runs.js) ----

export function resetUIState(mode) {
  state.mode = mode;
  if (mode === "refine") ensureRefineUI(state.refineMaxRounds);
  state.findings = [];
  state.currentPhase = null;
  state.auditDone = false;
  state.selectedRestartPhase = null;
  state.restartPocLevel = null;
  state.currentRunId = null;
  state.loadedRunFinished = false;
  els.startBtn.textContent = "start audit";
  $$("#progress-bar .progress-segment").forEach((seg) => {
    seg.classList.remove("selected");
    seg.removeAttribute("data-restart-poc");
  });

  state.tasks = {};
  state.taskPaths = {};
  state.vulnClasses = {};
  state.exploitedTasks = new Set();
  state.exploitResults = {};
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
  switchTab(mode === "refine" ? "r1_attack" : mode === "hack" ? "hack" : "setup");
  setView("output");

  const setupTab = $(`.phase-tab[data-tab="setup"]`);
  if (setupTab) setupTab.style.display = (mode === "hack" || mode === "refine") ? "none" : "";

  $$(".hack-tab").forEach((el) => { el.style.display = mode === "hack" ? "" : "none"; });
  $$(".refine-tab").forEach((el) => { el.style.display = mode === "refine" ? "" : "none"; });

  setTimelineMode(mode);

  els.progressBar.style.display = (mode === "hack" || mode === "refine") ? "none" : "";
  els.hackProgressBar.style.display = mode === "hack" ? "" : "none";
  els.refineProgressBar.style.display = mode === "refine" ? "" : "none";
  const bar = mode === "refine" ? els.refineProgressBar
    : mode === "hack" ? els.hackProgressBar
    : els.progressBar;
  bar.querySelectorAll(".progress-segment").forEach((el) => {
    el.className = "progress-segment pending";
  });
  if (mode !== "hack" && mode !== "refine") {
    const pocSeg = els.progressBar.querySelector('.progress-segment[data-phase="poc"]');
    if (pocSeg) {
      pocSeg.classList.toggle("user-full", state.pocLevel === "full");
      pocSeg.classList.toggle("user-skip", state.pocLevel === "skip");
    }
  }

  renderScoreboard();
  resetVulnHeaders();
  setMainView("dashboard");
  updateActionButtons();

}

// ---- Local helper (used only within this module) ----
function escapeHTML(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

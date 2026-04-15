// ================================================================
// UI helpers — phase state, tabs, view switching, conversation boxes
// ================================================================

import { $, $$ } from "./state.js";
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
    // Show continue, hide start/hack
    els.startBtn.style.display = "none";
    els.hackBtn.style.display = "none";
    els.continueBtn.style.display = "";
    const done = state.loadedRunFinished;
    els.continueBtn.disabled = done;
    els.continueBtn.title = done ? "This run is completed" : "";
    els.continueBtn.classList.toggle("btn-continue-done", done);
  } else {
    // No loaded run, or a restart stage is selected → show start/hack
    els.startBtn.style.display = "";
    els.hackBtn.style.display = "";
    els.continueBtn.style.display = "none";
  }
}

export function setRunning(running) {
  state.running = running;
  els.cancelBtn.style.display = running ? "" : "none";
  $('label[for="target-input"]').style.display = running ? "none" : "";
  $$(".cycle-btn").forEach(g => { g.style.display = running ? "none" : ""; });

  if (running) {
    // Hide all action buttons while pipeline is running
    els.startBtn.style.display = "none";
    els.hackBtn.style.display = "none";
    els.continueBtn.style.display = "none";
    state._savedTarget = els.targetInput.value;
    const verb = state.mode === "hack" ? "Hacking" : "Auditing";
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

export function setTimelineMode(isHack) {
  document.querySelectorAll("#timeline [data-mode='audit']").forEach((el) => {
    el.style.display = isHack ? "none" : "";
  });
  document.querySelectorAll("#timeline [data-mode='hack']").forEach((el) => {
    el.style.display = isHack ? "" : "none";
  });
}

export function setPhaseState(phaseId, status) {
  const el = $(`.phase[data-phase="${phaseId}"]`);
  if (el) el.className = `phase ${status}`;

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
  switchTab(mode === "hack" ? "hack" : "setup");
  setView("output");

  const setupTab = $(`.phase-tab[data-tab="setup"]`);
  if (setupTab) setupTab.style.display = mode === "hack" ? "none" : "";

  setTimelineMode(mode === "hack");

  els.progressBar.style.display = mode === "hack" ? "none" : "";
  els.hackProgressBar.style.display = mode === "hack" ? "" : "none";
  const bar = mode === "hack" ? els.hackProgressBar : els.progressBar;
  bar.querySelectorAll(".progress-segment").forEach((el) => {
    el.className = "progress-segment pending";
  });
  if (mode !== "hack") {
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

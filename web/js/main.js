// ================================================================
// Entry point — wire up all event listeners and initialize the page
// ================================================================

import { $, $$, state, els } from "./state.js";
import { setView, switchTab, setMainView, resetUIState, updateActionButtons } from "./ui.js";
import { refilterFindings } from "./findings.js";
import { showTooltip, showTaskTooltip, hideTooltip } from "./scoreboard.js";
import { startAudit, startHack, cancelAudit, rerunFromPhase, continueRun } from "./api.js";
import { toggleRunsPanel, closeRunsPanel } from "./runs.js";


// ---- Cycle-button helpers ----

export function setBackend(v) {
  state.backend = v === "claude" ? "claude" : "codex";
  els.backendBtn.dataset.state = state.backend;
  els.backendBtn.textContent = state.backend === "claude" ? "claude code" : "codex";
}

export function setSandbox(v) {
  state.useSandbox = v !== "nosandbox";
  const s = state.useSandbox ? "sandbox" : "nosandbox";
  els.sandboxBtn.dataset.state = s;
  els.sandboxBtn.textContent = state.useSandbox ? "sandbox" : "no sandbox";
}

els.backendBtn.addEventListener("click", () => {
  setBackend(state.backend === "codex" ? "claude" : "codex");
});

els.sandboxBtn.addEventListener("click", () => {
  setSandbox(state.useSandbox ? "nosandbox" : "sandbox");
});

// ---- Restart-phase selection (progress bar click) ----

const RERUNNABLE_PHASES = ["recon", "vuln_scan", "poc", "report"];
const PHASE_LABELS = { recon: "recon", vuln_scan: "vuln scan", poc: "poc", report: "report" };

function updateStartBtnLabel() {
  if (!state.selectedRestartPhase) {
    els.startBtn.textContent = "start audit";
    return;
  }
  let label = `restart from ${PHASE_LABELS[state.selectedRestartPhase]}`;
  if (state.selectedRestartPhase === "poc") {
    label += ` (${state.restartPocLevel || "verified"})`;
  } else if (state.restartPocLevel) {
    label += ` · poc: ${state.restartPocLevel}`;
  }
  els.startBtn.textContent = label;
}

function applyRestartPocVisual() {
  const pocSeg = $(`#progress-bar .progress-segment[data-phase="poc"]`);
  if (!pocSeg) return;
  if (state.restartPocLevel) {
    pocSeg.setAttribute("data-restart-poc", state.restartPocLevel);
  } else {
    pocSeg.removeAttribute("data-restart-poc");
  }
}

function selectRestartPhase(phase) {
  if (state.selectedRestartPhase === phase) {
    // Toggle off: deselect and clear any poc override
    state.selectedRestartPhase = null;
    state.restartPocLevel = null;
  } else {
    state.selectedRestartPhase = phase;
  }

  $$("#progress-bar .progress-segment").forEach((seg) => seg.classList.remove("selected"));
  if (state.selectedRestartPhase) {
    const sel = $(`#progress-bar .progress-segment[data-phase="${state.selectedRestartPhase}"]`);
    if (sel) sel.classList.add("selected");
  }

  applyRestartPocVisual();
  updateStartBtnLabel();
  updateActionButtons();
}

// ---- Post-run PoC multi-click: verified → full → switch-to-restart-from-poc ----

function handleRestartPocClick() {
  if (state.selectedRestartPhase === "poc") {
    // Already restarting from poc: toggle between verified ↔ full (no skip)
    state.restartPocLevel = (state.restartPocLevel === "full") ? "verified" : "full";

  } else if (!state.selectedRestartPhase) {
    // Nothing selected: treat first poc click as "select poc as restart"
    state.selectedRestartPhase = "poc";
    state.restartPocLevel = "verified";
    $$("#progress-bar .progress-segment").forEach((seg) => seg.classList.remove("selected"));
    const pocSeg = $(`#progress-bar .progress-segment[data-phase="poc"]`);
    if (pocSeg) pocSeg.classList.add("selected");

  } else {
    // Restarting from a non-poc phase: null → verified → full → skip → switch-to-restart-from-poc
    if (!state.restartPocLevel) {
      state.restartPocLevel = "verified";
    } else if (state.restartPocLevel === "verified") {
      state.restartPocLevel = "full";
    } else if (state.restartPocLevel === "full") {
      state.restartPocLevel = "skip";
    } else {
      // 4th click: cancel current restart phase, switch to restart-from-poc
      state.restartPocLevel = "verified";
      state.selectedRestartPhase = "poc";
      $$("#progress-bar .progress-segment").forEach((seg) => seg.classList.remove("selected"));
      const pocSeg = $(`#progress-bar .progress-segment[data-phase="poc"]`);
      if (pocSeg) pocSeg.classList.add("selected");
    }
  }

  applyRestartPocVisual();
  updateStartBtnLabel();
  updateActionButtons();
}

// ---- Pre-run PoC level cycle (partial → full → skip → partial) ----

function cyclePocLevel() {
  const order = ["partial", "full", "skip"];
  const idx = order.indexOf(state.pocLevel);
  state.pocLevel = order[(idx + 1) % order.length];
  const seg = $(`#progress-bar .progress-segment[data-phase="poc"]`);
  if (seg) {
    seg.classList.toggle("user-full", state.pocLevel === "full");
    seg.classList.toggle("user-skip", state.pocLevel === "skip");
  }
}

// ---- Form submission ----

els.form.addEventListener("submit", (e) => {
  e.preventDefault();
  const target = els.targetInput.value.trim();
  if (!target) return;
  if (state.selectedRestartPhase && state.currentRunId) {
    rerunFromPhase(state.selectedRestartPhase);
    state.selectedRestartPhase = null;
    updateActionButtons();
  } else {
    startAudit(target);
  }
});

// ---- Button listeners ----

els.cancelBtn.addEventListener("click", cancelAudit);

els.hackBtn.addEventListener("click", () => {
  const target = els.targetInput.value.trim();
  if (!target) return;
  startHack(target);
});

els.continueBtn.addEventListener("click", () => {
  if (els.continueBtn.disabled) return;
  continueRun();
});

// ---- Tab navigation ----

els.phaseTabs.addEventListener("click", (e) => {
  const btn = e.target.closest(".phase-tab");
  if (!btn) return;
  state.userPickedTab = true;
  switchTab(btn.dataset.tab);
});

// ---- Output / Summary view toggle ----

els.viewToggle.addEventListener("click", (e) => {
  const btn = e.target.closest(".view-btn");
  if (!btn) return;
  setView(btn.dataset.view);
});

// ---- Dashboard / Detail main view toggle ----

els.viewToggleBtn.addEventListener("click", () => {
  setMainView(state.mainView === "dashboard" ? "detail" : "dashboard");
});

// ---- Severity filter ----

els.sevFilter.addEventListener("change", (e) => {
  state.severityFilter = e.target.value;
  refilterFindings();
});

// ---- Progress bar segment click (select restart phase) ----

els.progressBar.addEventListener("click", (e) => {
  const seg = e.target.closest(".progress-segment");
  if (!seg) return;
  const phase = seg.dataset.phase;
  if (state.running) return;

  if (phase === "poc") {
    const isPreRun = seg.classList.contains("pending")
      || seg.classList.contains("user-skip")
      || seg.classList.contains("user-full");
    if (isPreRun) {
      cyclePocLevel();
    } else if (state.currentRunId) {
      handleRestartPocClick();
    }
    return;
  }

  // Post-run: select phase to restart from
  if (!RERUNNABLE_PHASES.includes(phase)) return;
  if (!state.currentRunId) return;
  selectRestartPhase(phase);
});

// ---- Scoreboard tooltip ----

document.addEventListener("mouseover", (e) => {
  const dot = e.target.closest(".vuln-dot");
  if (dot) { showTooltip(dot); return; }
  const task = e.target.closest(".col-task-truncated");
  if (task) showTaskTooltip(task);
});

document.addEventListener("mouseout", (e) => {
  const dot = e.target.closest(".vuln-dot");
  const task = e.target.closest(".col-task-truncated");
  if (dot || task) hideTooltip();
});

// ---- Runs panel ----

document.querySelector("#runs-btn").addEventListener("click", toggleRunsPanel);
document.querySelector("#runs-close-btn").addEventListener("click", closeRunsPanel);

// ---- Pre-fill target from URL params ----

const params = new URLSearchParams(window.location.search);
if (params.has("target")) {
  els.targetInput.value = params.get("target");
}
if (params.has("backend")) setBackend(params.get("backend"));
if (params.has("sandbox")) setSandbox(params.get("sandbox") === "false" ? "nosandbox" : "sandbox");

// Auto-start if requested — then immediately strip the params from the URL
// so a subsequent refresh does not re-trigger the auto-start.
if (params.has("autostart") && els.targetInput.value) {
  history.replaceState(null, "", window.location.pathname);
  setTimeout(() => startAudit(els.targetInput.value), 500);
}

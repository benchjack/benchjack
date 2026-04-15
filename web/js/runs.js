// ================================================================
// Runs panel — list, load, and view previous pipeline runs
// ================================================================

import { state, els } from "./state.js";
import { resetUIState, setPhaseState } from "./ui.js";
import { connectSSE } from "./sse.js";
import { startAudit } from "./api.js";
import { escapeHTML, formatDuration, formatTimeAgo } from "./utils.js";

const runsPanel = document.querySelector("#runs-panel");
const runsList  = document.querySelector("#runs-list");
const runsBtn   = document.querySelector("#runs-btn");

let runsPanelOpen = false;

export function toggleRunsPanel() {
  runsPanelOpen = !runsPanelOpen;
  runsPanel.style.display = runsPanelOpen ? "" : "none";
  runsBtn.classList.toggle("active", runsPanelOpen);
  if (runsPanelOpen) fetchRuns();
}

export function closeRunsPanel() {
  runsPanelOpen = false;
  runsPanel.style.display = "none";
  runsBtn.classList.remove("active");
}

async function fetchRuns() {
  runsList.innerHTML = '<div class="runs-empty">Loading\u2026</div>';
  try {
    const resp = await fetch("/api/runs");
    const data = await resp.json();
    renderRunsList(data.runs || []);
  } catch {
    runsList.innerHTML = '<div class="runs-empty">Failed to load runs</div>';
  }
}

// Stores phases data keyed by run name so loadRun can apply states directly.
const _runsPhaseCache = new Map();

function renderRunsList(runs) {
  if (runs.length === 0) {
    runsList.innerHTML = '<div class="runs-empty">No previous runs found</div>';
    return;
  }

  _runsPhaseCache.clear();
  runsList.innerHTML = "";
  for (const run of runs) {
    const card = document.createElement("div");
    card.className = "run-card";
    card.dataset.status = run.status;

    const dotPhases = run.mode === "hack"
      ? ["hack", "verify"]
      : ["setup", "recon", "vuln_scan", "poc", "report"];
    const phaseDots = dotPhases
      .map((pid) => {
        const phaseStatus = run.phases[pid]?.status || "pending";
        return `<span class="run-phase-dot ${phaseStatus}" title="${pid}: ${phaseStatus}"></span>`;
      })
      .join("");

    const statusLabels = {
      completed: "Completed", incomplete: "Incomplete",
      failed: "Failed", empty: "Empty", running: "Running",
    };
    const statusLabel = statusLabels[run.status] || run.status;
    const duration    = run.total_duration > 0 ? formatDuration(run.total_duration) : "";
    const findingsText = run.findings_count > 0
      ? `${run.findings_count} finding${run.findings_count !== 1 ? "s" : ""}` : "";
    const timeAgo = formatTimeAgo(run.mtime);

    const isRunning  = run.status === "running";
    const canContinue = run.status === "incomplete" || run.status === "failed";

    const runMode = run.mode || "audit";
    _runsPhaseCache.set(run.name, run.phases || {});
    const runBackend = run.backend || "";
    let actions = "";
    if (isRunning) {
      actions += `<button class="run-action run-action-view" data-name="${escapeHTML(run.name)}" data-target="${escapeHTML(run.target)}" data-mode="${runMode}" data-backend="${escapeHTML(runBackend)}">View</button>`;
    } else {
      actions += `<button class="run-action run-action-load" data-name="${escapeHTML(run.name)}" data-target="${escapeHTML(run.target)}" data-mode="${runMode}" data-backend="${escapeHTML(runBackend)}">Load</button>`;
    }
    if (canContinue) {
      actions += `<button class="run-action run-action-continue" data-name="${escapeHTML(run.name)}" data-target="${escapeHTML(run.target)}">Continue</button>`;
    }

    card.innerHTML = `
      <div class="run-card-top">
        <div class="run-card-info">
          <span class="run-name">${escapeHTML(run.name)}</span>
          <span class="run-status-badge run-status-${run.status}">${statusLabel}</span>
          <span class="run-mode-badge run-mode-${runMode}">${runMode === "hack" ? "Just Hack It" : "Audit"}</span>
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

  runsList.querySelectorAll(".run-action-load").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const phases = _runsPhaseCache.get(btn.dataset.name) || {};
      loadRun(btn.dataset.name, btn.dataset.target, btn.dataset.mode || "audit", phases, btn.dataset.backend || null);
    });
  });

  runsList.querySelectorAll(".run-action-view").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      viewActiveRun(btn.dataset.name, btn.dataset.target, btn.dataset.mode || "audit", btn.dataset.backend || null);
    });
  });

  runsList.querySelectorAll(".run-action-continue").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      continueRun(btn.dataset.target);
    });
  });
}

async function loadRun(name, target, mode = "audit", phases = {}, backend = null) {
  closeRunsPanel();
  resetUIState(mode);
  document.querySelector("#scoreboard-empty-text").textContent = "Loading run\u2026";
  els.targetInput.value = target;
  if (backend) {
    state.backend = backend === "claude" ? "claude" : "codex";
    els.backendBtn.dataset.state = state.backend;
    els.backendBtn.textContent = state.backend === "claude" ? "claude code" : "codex";
  }

  // Immediately paint the progress bar from persisted phase data so the
  // user sees the correct state before the SSE replay arrives.
  for (const [phaseId, meta] of Object.entries(phases)) {
    const s = meta?.status;
    if (s && s !== "pending") setPhaseState(phaseId, s);
  }

  try {
    const resp = await fetch(`/api/runs/${encodeURIComponent(name)}/load`, {
      method: "POST",
    });
    const result = await resp.json();
    if (result.error) {
      alert(`Error: ${result.error}`);
      return;
    }
    state.loadedRunFinished = !!result.finished;
    connectSSE(result.run_id);
  } catch (err) {
    alert(`Failed to load run: ${err.message}`);
  }
}

function viewActiveRun(name, target, mode = "audit", backend = null) {
  closeRunsPanel();
  resetUIState(mode);
  els.targetInput.value = target;
  if (backend) {
    state.backend = backend === "claude" ? "claude" : "codex";
    els.backendBtn.dataset.state = state.backend;
    els.backendBtn.textContent = state.backend === "claude" ? "claude code" : "codex";
  }
  connectSSE(name);
}

async function continueRun(target) {
  closeRunsPanel();
  els.targetInput.value = target;
  startAudit(target);
}

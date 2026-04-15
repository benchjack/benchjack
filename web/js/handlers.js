// ================================================================
// SSE event handler — central dispatcher for all pipeline events
// ================================================================

import { $$, state, els } from "./state.js";
import {
  setRunning, setPhaseState, setTimelineMode, switchTab, setView,
  appendConvBox, renderPhaseSummary,
} from "./ui.js";
import {
  renderScoreboard, updateVulnHeaders, updateScoreboardEmpty, resetVulnHeaders,
} from "./scoreboard.js";
import { addFinding, countHackable } from "./findings.js";

export function handleEvent(event) {
  const { type, data } = event;

  switch (type) {
    case "audit_start":
      if (!data.continuation) {
        if (data.mode) state.mode = data.mode;
        if (data.backend) {
          state.backend = data.backend === "claude" ? "claude" : "codex";
          els.backendBtn.dataset.state = state.backend;
          els.backendBtn.textContent = state.backend === "claude" ? "claude code" : "codex";
        }
        setRunning(true);
        state.auditDone = false;

        const isHack = state.mode === "hack";
        els.progressBar.style.display = isHack ? "none" : "";
        els.hackProgressBar.style.display = isHack ? "" : "none";
        els.summaryMsg.textContent = isHack
          ? `Hacking: ${data.target}`
          : `Auditing: ${data.target}`;

        // Reset phase timeline dots and show/hide mode-specific phases
        setTimelineMode(isHack);
        $$(".phase").forEach((el) => {
          el.className = "phase pending";
          el.querySelector(".phase-time").textContent = "";
        });

        // Reset active progress bar (skip for restored/loaded runs — states are
        // applied directly from persisted data before SSE connects).
        if (!data.restore) {
          const activeBar = isHack ? els.hackProgressBar : els.progressBar;
          activeBar.querySelectorAll(".progress-segment").forEach((el) => {
            el.className = "progress-segment pending";
          });
        }

        // Show/hide mode-specific tabs
        $$(".hack-tab").forEach((el) => { el.style.display = isHack ? "" : "none"; });
        ["recon", "vuln_scan", "poc", "report"].forEach((t) => {
          const tab = document.querySelector(`.phase-tab[data-tab="${t}"]`);
          if (tab) tab.style.display = isHack ? "none" : "";
        });

        // Reset per-phase data
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

        const setupTab = document.querySelector(`.phase-tab[data-tab="setup"]`);
        if (setupTab) setupTab.style.display = isHack ? "none" : "";

        // Reset scoreboard
        state.tasks = {};
        state.taskPaths = {};
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
      appendConvBox(data.phase, {
        msg_type: "text",
        text: `**Phase: ${data.label || data.phase}**`,
      });
      if (!state.userPickedTab) switchTab(data.phase);
      if (data.phase === "poc" || data.phase === "verify") {
        updateScoreboardEmpty("Running exploits\u2026");
      }
      break;

    case "phase_summary":
      // Summary-only event — populates the summary pane without touching the output view.
      if (data.phase && data.text) {
        state.phaseSummary[data.phase] = data.text;
        renderPhaseSummary(data.phase);
      }
      break;

    case "phase_complete":
      setPhaseState(data.phase, data.status);
      if (data.duration) {
        const phaseEl = document.querySelector(`.phase[data-phase="${data.phase}"]`);
        if (phaseEl) {
          phaseEl.querySelector(".phase-time").textContent = `${data.duration}s`;
        }
      }
      renderPhaseSummary(data.phase);
      break;

    case "phase_skip":
      setPhaseState(data.phase, "skipped");
      break;

    case "log": {
      const msgType = data.msg_type || "text";
      const phase = data.phase || state.currentPhase || (state.mode === "hack" ? "hack" : "setup");

      state.phaseMessages[phase] = state.phaseMessages[phase] || [];
      state.phaseMessages[phase].push(data);

      if (msgType === "text" && data.text) {
        state.phaseSummary[phase] = data.text;
      }

      const tabBtn = document.querySelector(`.phase-tab[data-tab="${phase}"]`);
      if (tabBtn) tabBtn.classList.add("has-content");

      appendConvBox(phase, data);
      break;
    }

    case "finding":
      addFinding(data);
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
      if (!state.tasks[task]) state.tasks[task] = {};
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
      const paths = (data.task_paths && typeof data.task_paths === "object") ? data.task_paths : {};
      for (const id of ids) {
        if (!id) continue;
        if (!state.tasks[id]) state.tasks[id] = {};
        if (paths[id] !== undefined) state.taskPaths[id] = paths[id];
      }
      renderScoreboard();
      break;
    }

    case "error":
      appendConvBox(
        data.phase || state.currentPhase || (state.mode === "hack" ? "hack" : "setup"),
        { msg_type: "text", text: `**ERROR:** ${data.message}`, _isError: true },
      );
      break;

    case "exploit_results": {
      for (const r of (data.results || [])) {
        if (r.hacked && r.task) {
          state.exploitedTasks.add(r.task);
          if (!state.exploitResults[r.task]) state.exploitResults[r.task] = [];
          state.exploitResults[r.task].push({
            vulnerability: r.vulnerability || "",
            severity: r.severity || "",
            explanation: r.explanation || "",
          });
        }
      }
      renderScoreboard();
      break;
    }

    case "audit_complete":
      // For non-history runs, mark the run as finished so the Continue button
      // is greyed out after the pipeline completes.
      if (!data.loaded_from_history && !data.failed) {
        state.loadedRunFinished = true;
      }
      setRunning(false);
      state.auditDone = true;
      if (state.mode === "hack") {
        els.summaryMsg.textContent = `Hack complete for ${data.target}`;
        if (state.phaseSummary.verify) {
          switchTab("verify"); setView("summary"); state.userPickedTab = false;
        } else if (state.phaseSummary.hack) {
          switchTab("hack"); setView("summary"); state.userPickedTab = false;
        }
      } else {
        const h = countHackable();
        const hackLabel = h.hackable === "ALL"
          ? "ALL tasks hackable"
          : `${h.hackable}/${h.total} tasks hackable`;
        els.summaryMsg.textContent = data.loaded_from_history
          ? `Loaded run: ${hackLabel} — ${data.target}`
          : `Audit complete: ${hackLabel} — ${data.target}`;
        if (state.phaseSummary.report) {
          switchTab("report"); setView("summary"); state.userPickedTab = false;
        }
      }
      if (Object.keys(state.tasks).length === 0) {
        updateScoreboardEmpty(state.mode === "hack"
          ? "Hack run complete"
          : "No task-level results available");
      }
      break;
  }
}

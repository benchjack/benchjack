// ================================================================
// SSE event handler — central dispatcher for all pipeline events
// ================================================================

import { $$, state, els } from "./state.js";
import {
  setRunning, setPhaseState, setTimelineMode, switchTab, setView,
  appendConvBox, renderPhaseSummary, setRefineRounds,
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
        if (state.mode === "refine" && data.max_rounds) {
          setRefineRounds(data.max_rounds);
        }
        if (data.backend) {
          state.backend = data.backend === "claude" ? "claude" : "codex";
          els.backendBtn.dataset.state = state.backend;
          els.backendBtn.textContent = state.backend === "claude" ? "claude code" : "codex";
        }
        setRunning(true);
        state.auditDone = false;

        const isHack = state.mode === "hack";
        const isRefine = state.mode === "refine";

        els.progressBar.style.display = (isHack || isRefine) ? "none" : "";
        els.hackProgressBar.style.display = isHack ? "" : "none";
        els.refineProgressBar.style.display = isRefine ? "" : "none";
        els.summaryMsg.textContent = isRefine
          ? `Refining: ${data.target}`
          : isHack
          ? `Hacking: ${data.target}`
          : `Auditing: ${data.target}`;

        // Reset phase timeline dots and show/hide mode-specific phases
        setTimelineMode(state.mode);
        $$(".phase").forEach((el) => {
          el.className = "phase pending";
          el.querySelector(".phase-time").textContent = "";
        });

        // Reset active progress bar (skip for restored/loaded runs — states are
        // applied directly from persisted data before SSE connects).
        if (!data.restore) {
          const activeBar = isRefine ? els.refineProgressBar
            : isHack ? els.hackProgressBar
            : els.progressBar;
          activeBar.querySelectorAll(".progress-segment").forEach((el) => {
            el.className = "progress-segment pending";
          });
        }

        // Show/hide mode-specific tabs
        $$(".hack-tab").forEach((el) => { el.style.display = isHack ? "" : "none"; });
        $$(".refine-tab").forEach((el) => { el.style.display = isRefine ? "" : "none"; });
        ["recon", "vuln_scan", "poc", "report"].forEach((t) => {
          const tab = document.querySelector(`.phase-tab[data-tab="${t}"]`);
          if (tab) tab.style.display = (isHack || isRefine) ? "none" : "";
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
        switchTab(isRefine ? "r1_attack" : isHack ? "hack" : "setup");
        setView("output");

        const setupTab = document.querySelector(`.phase-tab[data-tab="setup"]`);
        if (setupTab) setupTab.style.display = (isHack || isRefine) ? "none" : "";

        // Reset scoreboard
        state.tasks = {};
        state.taskPaths = {};
        state.vulnClasses = {};
        renderScoreboard();
        resetVulnHeaders();
        updateScoreboardEmpty(isRefine ? "Starting iterative refinement…"
          : isHack ? "Hacking benchmark…"
          : "Analyzing benchmark…");
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
        updateScoreboardEmpty("Running exploits…");
      }

      // Refine mode: mark the round segment as "running" when an attack/patch starts
      if (state.mode === "refine" && data.phase) {
        const m = data.phase.match(/^r(\d+)_/);
        if (m) {
          const roundSeg = els.refineProgressBar.querySelector(
            `.progress-segment[data-phase="r${m[1]}"]`
          );
          if (roundSeg && roundSeg.className.includes("pending")) {
            roundSeg.className = "progress-segment running";
          }
        }
        // Clear exploit data at the start of each new attack round so the
        // scoreboard reflects only the current round's results.
        if (data.phase.endsWith("_attack")) {
          state.exploitedTasks = new Set();
          state.exploitResults = {};
          state.tasks = Object.fromEntries(
            Object.keys(state.tasks).filter((id) => id !== "all_tasks").map((id) => [id, {}]),
          );
          state.vulnClasses = {};
          resetVulnHeaders();
          renderScoreboard();
          updateScoreboardEmpty("Checking current round…");
        }
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
      // In refine mode, also mark round segments skipped if all sub-phases skipped.
      // (Full round skipping is handled by refine_round_complete.)
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

    case "refine_round_complete": {
      const roundN = data.round;
      const hackRate = data.hack_rate;
      const hacked = data.hacked;
      const total = data.total;
      const converged = data.converged ?? false;

      // Mark the round segment in the refine progress bar
      const roundSeg = els.refineProgressBar.querySelector(
        `.progress-segment[data-phase="r${roundN}"]`
      );
      if (roundSeg) roundSeg.className = "progress-segment completed";

      // Mark skipped rounds if we converged early
      if (converged) {
        for (let r = roundN + 1; r <= state.refineMaxRounds; r++) {
          const seg = els.refineProgressBar.querySelector(
            `.progress-segment[data-phase="r${r}"]`
          );
          if (seg) seg.className = "progress-segment skipped";
        }
      }

      // Update summary message with per-round hack rate
      const pct = hackRate == null ? null : Math.round(hackRate * 100);
      const unknownScope = hacked == null
        ? "benchmark-wide exploit confirmed; task count unknown"
        : `${hacked} confirmed hacked task(s); total task count unknown`;
      els.summaryMsg.textContent = converged
        ? `Round ${roundN}: converged — benchmark defended (0% hacked)`
        : total == null || pct == null
        ? `Round ${roundN} complete — ${unknownScope}`
        : `Round ${roundN} complete — ${pct}% hacked (${hacked}/${total} tasks)`;
      break;
    }

    case "refine_complete": {
      const converged = data.converged ?? false;
      const convergedSeg = els.refineProgressBar.querySelector(
        `.progress-segment[data-phase="converged"]`
      );
      if (convergedSeg) {
        convergedSeg.className = `progress-segment ${converged ? "completed" : "failed"}`;
      }
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
      if (state.mode === "refine") {
        const cannotPatch = data.stop_reason === "cannot_patch";
        els.summaryMsg.textContent = cannotPatch
          ? `Refinement stopped for ${data.target}: defender cannot patch without redesign`
          : `Refinement complete for ${data.target}`;
        // Show the defender's explanation when redesign is required.
        const lastPhase = Array.from(
          { length: state.refineMaxRounds },
          (_, i) => `r${state.refineMaxRounds - i}_${cannotPatch ? "patch" : "attack"}`,
        ).find((p) => state.phaseSummary[p]);
        if (lastPhase) {
          switchTab(lastPhase); setView("summary"); state.userPickedTab = false;
        }
      } else if (state.mode === "hack") {
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
          : state.mode === "refine"
          ? "Refinement complete"
          : "No task-level results available");
      }
      break;
  }
}

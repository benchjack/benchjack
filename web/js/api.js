// ================================================================
// API calls to the BenchJack server
// ================================================================

import { state, els } from "./state.js";
import { setRunning, resetUIState } from "./ui.js";
import { updateScoreboardEmpty } from "./scoreboard.js";
import { connectSSE } from "./sse.js";

export async function startAudit(target) {
  resetUIState("audit");
  updateScoreboardEmpty("Analyzing benchmark\u2026");

  const resp = await fetch("/api/audit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, backend: state.backend, use_sandbox: state.useSandbox, poc_level: state.pocLevel }),
  });
  const result = await resp.json();
  if (result.error) {
    alert(`Error: ${result.error}`);
    setRunning(false);
    return;
  }
  connectSSE(result.run_id);
}

export async function startHack(target) {
  resetUIState("hack");
  updateScoreboardEmpty("Hacking benchmark\u2026");

  const resp = await fetch("/api/hack", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, backend: state.backend, use_sandbox: state.useSandbox }),
  });
  const result = await resp.json();
  if (result.error) {
    alert(`Error: ${result.error}`);
    setRunning(false);
    return;
  }
  connectSSE(result.run_id);
}

export async function cancelAudit() {
  await fetch("/api/cancel", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ run_id: state.currentRunId }),
  });
  setRunning(false);
  els.statusBadge.className = "badge badge-error";
  els.statusBadge.textContent = "CANCELLED";
}

export async function continueRun() {
  const target = els.targetInput.value.trim();
  if (!target) return;

  resetUIState("audit");
  updateScoreboardEmpty("Continuing audit\u2026");

  const resp = await fetch("/api/audit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      target,
      backend: state.backend,
      use_sandbox: state.useSandbox,
      poc_level: state.pocLevel,
    }),
  });
  const result = await resp.json();
  if (result.error) {
    alert(`Error: ${result.error}`);
    setRunning(false);
    return;
  }
  connectSSE(result.run_id);
}

export async function rerunFromPhase(fromPhase) {
  if (!state.currentRunId) {
    alert("No run to re-run from.");
    return;
  }
  if (state.running) {
    alert("Pipeline is still running. Cancel it first.");
    return;
  }

  // Save before resetUIState clears it
  const runId = state.currentRunId;
  const pocLevel = state.restartPocLevel === "full" ? "full"
    : state.restartPocLevel === "skip" ? "skip"
    : "partial";

  resetUIState("audit");
  updateScoreboardEmpty(`Re-running from ${fromPhase}\u2026`);

  const resp = await fetch("/api/rerun", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ run_id: runId, from_phase: fromPhase, backend: state.backend, use_sandbox: state.useSandbox, poc_level: pocLevel }),
  });
  const result = await resp.json();
  if (result.error) {
    alert(`Error: ${result.error}`);
    setRunning(false);
    return;
  }
  connectSSE(result.run_id);
}

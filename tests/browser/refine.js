import { handleEvent } from "/js/handlers.js";
import { state, els } from "/js/state.js";
import { toggleRunsPanel } from "/js/runs.js";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function emit(type, data) { handleEvent({ type, data }); }

window.browserRegression = { done: false, passed: [], error: null };
try {
  els.targetInput.value = "fixture";
  emit("audit_start", { target: "fixture", mode: "refine", max_rounds: 2 });
  emit("phase_start", { phase: "r1_attack" });
  const result = { task: "demo", vulnerability: "V6", severity: "HIGH", hacked: true, explanation: "fixture exploit" };
  emit("task_result", result);
  emit("exploit_results", { results: [result] });
  assert(document.querySelectorAll(".status-hacked").length === 1, "Fixture must first display a verified exploit");
  emit("phase_start", { phase: "r2_attack" });
  assert(document.querySelectorAll(".status-hacked").length === 0, "New rounds must clear rendered hacked badges");
  assert(!state.tasks.demo?.V6, "New rounds must clear obsolete task findings");
  emit("refine_round_complete", { round: 2, hack_rate: 0, hacked: 0, total: null, converged: true });
  emit("refine_complete", { converged: true, final_hack_rate: 0, max_rounds: 2 });
  emit("audit_complete", { target: "fixture", failed: false });
  assert(document.querySelectorAll(".status-hacked").length === 0, "Convergence must not retain hacked badges");
  assert(document.querySelector("#stat-high").textContent === "0 High", "Obsolete severity counts must be cleared");
  window.browserRegression.passed.push("round scoreboard reset");

  // Capture actual button requests without starting an audit/model process.
  const requests = [];
  window.fetch = async (url, options) => {
    if (url === "/api/runs") {
      return { json: async () => ({ runs: [{
        name: "refine_fixture", target: "fixture", mode: "refine", backend: "claude",
        max_rounds: 5, status: "failed", phases: {}, total_duration: 0,
        findings_count: 0, mtime: Date.now() / 1000,
      }] }) };
    }
    requests.push({ url, body: JSON.parse(options.body) });
    return { json: async () => ({ error: "Test intercepted request" }) };
  };
  window.alert = () => {};
  emit("audit_start", { target: "fixture", mode: "refine", max_rounds: 5 });
  state.currentRunId = "refine_fixture";
  state.loadedRunFinished = false;
  emit("audit_complete", { target: "fixture", failed: true });
  assert(/restart/i.test(els.continueBtn.textContent), "Refinement failure must offer an explicit restart");
  els.continueBtn.click();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert(requests[0]?.url === "/api/refine", "Dashboard restart must use refinement API");
  assert(requests[0].body.max_rounds === 5, "Dashboard restart must retain configured round cap");
  window.browserRegression.passed.push("dashboard refinement restart");
  toggleRunsPanel();
  await new Promise((resolve) => setTimeout(resolve, 0));
  const restart = document.querySelector(".run-action-continue");
  assert(restart && /restart/i.test(restart.textContent), "History must label refinement restart explicitly");
  restart.click();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert(requests[1]?.url === "/api/refine", "History restart must use refinement API");
  assert(requests[1].body.max_rounds === 5, "History restart must retain saved round cap");
  window.browserRegression.passed.push("history refinement restart");
} catch (error) {
  window.browserRegression.error = error.message;
} finally {
  window.browserRegression.done = true;
}

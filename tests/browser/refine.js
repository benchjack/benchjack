import { handleEvent } from "/js/handlers.js";
import { state, els } from "/js/state.js";

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
} catch (error) {
  window.browserRegression.error = error.message;
} finally {
  window.browserRegression.done = true;
}

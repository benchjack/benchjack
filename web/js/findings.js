// ================================================================
// Finding cards and severity filtering
// ================================================================

import { state, els } from "./state.js";
import { escapeHTML } from "./utils.js";

export function addFinding(data) {
  state.findings.push(data);
  updateFindingsCounts();
  renderFindingCard(data);
}

export function renderFindingCard(f) {
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

export function updateFindingsCounts() {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, total: 0 };
  const allSevs = new Set(); // severities that apply to "all_tasks"

  // Check all_tasks entry — its severities apply globally
  const allTasksData = state.tasks["all_tasks"] || {};
  for (const result of Object.values(allTasksData)) {
    if (/^ABSENT/.test(result.explanation || "")) continue;
    const sev = (result.severity || "MEDIUM").toUpperCase();
    allSevs.add(sev);
  }

  // Count from per-task results
  for (const [taskId, vulns] of Object.entries(state.tasks)) {
    if (taskId === "all_tasks") continue;
    for (const [vId, result] of Object.entries(vulns)) {
      if (/^ABSENT/.test(result.explanation || "")) continue;
      counts.total++;
      const sev = (result.severity || "MEDIUM").toUpperCase();
      if (counts[sev] !== undefined) counts[sev]++;
    }
  }
  // Fall back to findings if no task_results yet
  if (counts.total === 0 && allSevs.size === 0) {
    for (const f of state.findings) {
      counts.total++;
      if (counts[f.severity] !== undefined) counts[f.severity]++;
    }
  }

  const fmt = (sev, label) =>
    allSevs.has(sev) ? `ALL ${label}` : `${counts[sev]} ${label}`;

  els.findingsCount.textContent = allSevs.size > 0 ? "ALL" : counts.total;
  document.querySelector("#stat-critical").textContent = fmt("CRITICAL", "Critical");
  document.querySelector("#stat-high").textContent     = fmt("HIGH", "High");
  document.querySelector("#stat-medium").textContent   = fmt("MEDIUM", "Medium");
  document.querySelector("#stat-low").textContent      = fmt("LOW", "Low");
  document.querySelector("#stat-total").textContent    = allSevs.size > 0
    ? "ALL Total" : `${counts.total} Total`;
}

export function countHackable() {
  const taskIds = Object.keys(state.tasks).filter((t) => t !== "all_tasks");
  const total = taskIds.length;
  if (state.exploitedTasks.has("all_tasks")) {
    return { hackable: "ALL", total };
  }
  const hackable = taskIds.filter((t) => state.exploitedTasks.has(t)).length;
  return { hackable, total };
}

export function refilterFindings() {
  els.findingsList.innerHTML = "";
  for (const f of state.findings) {
    renderFindingCard(f);
  }
}

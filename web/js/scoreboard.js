// ================================================================
// Scoreboard rendering and tooltip management
// ================================================================

import { $$, state, els, VULN_META } from "./state.js";
import { escapeHTML } from "./utils.js";
import { updateFindingsCounts } from "./findings.js";

function calcMaxChars() {
  const th = document.querySelector("#scoreboard-table th.col-task");
  const colWidth = th ? th.getBoundingClientRect().width : 200;
  // Measure actual monospace char width using a hidden span matching td.col-task styles
  const probe = document.createElement("span");
  probe.style.cssText =
    "position:absolute;visibility:hidden;pointer-events:none;" +
    "font-family:var(--font-mono);font-size:15px;font-weight:500;white-space:nowrap";
  probe.textContent = "x".repeat(20);
  document.body.appendChild(probe);
  const charW = probe.getBoundingClientRect().width / 20;
  document.body.removeChild(probe);
  const padding = 28; // 14px × 2 cell padding
  return Math.max(10, Math.floor((colWidth - padding) / charW));
}

function truncateMiddle(str, max) {
  if (str.length <= max) return str;
  const front = Math.ceil((max - 1) / 2);
  const back  = Math.floor((max - 1) / 2);
  return str.slice(0, front) + "…" + str.slice(-back);
}

export function renderScoreboard() {
  const tbody = els.scoreboardBody;
  tbody.innerHTML = "";

  const allTasksData = state.tasks["all_tasks"] || {};
  const taskIds = Object.keys(state.tasks).filter((t) => t !== "all_tasks").sort();

  if (taskIds.length === 0) {
    els.scoreboardEmpty.style.display = "";
    return;
  }

  els.scoreboardEmpty.style.display = "none";

  const maxChars = calcMaxChars();

  for (const taskId of taskIds) {
    const taskData = state.tasks[taskId];
    const row = document.createElement("tr");

    const nameCell = document.createElement("td");
    nameCell.className = "col-task";
    const displayName = truncateMiddle(taskId, maxChars);
    nameCell.textContent = displayName;
    if (displayName !== taskId) {
      nameCell.dataset.fullName = taskId;
      nameCell.classList.add("col-task-truncated");
    }
    row.appendChild(nameCell);

    const spacerCell = document.createElement("td");
    spacerCell.className = "col-path-spacer";
    spacerCell.setAttribute("aria-hidden", "true");
    row.appendChild(spacerCell);

    for (let i = 1; i <= 8; i++) {
      const vId = `V${i}`;
      const cell = document.createElement("td");
      cell.className = "col-vuln";

      const vulnResult = taskData[vId] || allTasksData[vId];
      if (vulnResult && !/^ABSENT/.test(vulnResult.explanation || "")) {
        const dot = document.createElement("span");
        const severity = (vulnResult.severity || state.vulnClasses[vId]?.severity || "MEDIUM").toUpperCase();
        dot.className = "vuln-dot";
        dot.dataset.severity = severity;
        dot.dataset.vuln = vId;
        dot.dataset.task = taskId;
        dot.dataset.hacked = vulnResult.hacked ? "true" : "false";
        dot.dataset.explanation = vulnResult.explanation || "";
        cell.appendChild(dot);
      }

      row.appendChild(cell);
    }

    const certCell = document.createElement("td");
    certCell.className = "col-poc";
    if (state.exploitedTasks.has(taskId)) {
      const mark = document.createElement("span");
      mark.className = "status-hacked";
      mark.textContent = "HACKED!";
      mark.dataset.task = taskId;
      // Build native title fallback from exploit data
      const exploitVulns = state.exploitResults[taskId] || [];
      if (exploitVulns.length > 0) {
        mark.title = exploitVulns.map(v => {
          const meta = VULN_META[v.vulnerability] || {};
          return `${v.vulnerability}: ${meta.name || ""}${v.severity ? ` [${v.severity}]` : ""}`;
        }).join("\n");
      } else {
        // Fallback: check state.tasks for hacked vulns
        const td = state.tasks[taskId] || {};
        const ad = state.tasks["all_tasks"] || {};
        const parts = [];
        for (let i = 1; i <= 8; i++) {
          const vId = `V${i}`;
          const r = td[vId] || ad[vId];
          if (r && r.hacked) {
            const meta = VULN_META[vId] || {};
            parts.push(`${vId}: ${meta.name || ""}${r.severity ? ` [${r.severity}]` : ""}`);
          }
        }
        if (parts.length > 0) mark.title = parts.join("\n");
      }
      certCell.appendChild(mark);
    }
    row.appendChild(certCell);

    tbody.appendChild(row);
  }

  // Update severity stats from task results
  updateFindingsCounts();
}

export function updateVulnHeaders() {
  for (const [vuln, info] of Object.entries(state.vulnClasses)) {
    const th = document.querySelector(`#scoreboard-table th[data-vuln="${vuln}"]`);
    if (th) {
      th.classList.add("has-findings");
      th.dataset.severity = info.severity;
    }
  }
}

export function resetVulnHeaders() {
  $$(`#scoreboard-table th.col-vuln`).forEach((th) => {
    th.classList.remove("has-findings");
    delete th.dataset.severity;
  });
}

export function updateScoreboardEmpty(msg) {
  if (els.scoreboardEmptyText) {
    els.scoreboardEmptyText.textContent = msg;
  }
}

// ---- Tooltip ----

export function showTaskTooltip(cell) {
  const fullName = cell.dataset.fullName;
  if (!fullName) return;
  els.tooltipContent.innerHTML = `<span style="font-family:var(--font-mono);word-break:break-all">${escapeHTML(fullName)}</span>`;
  const rect = cell.getBoundingClientRect();
  els.tooltip.style.display = "";
  els.tooltip.style.left = `${rect.left}px`;
  els.tooltip.style.top = `${rect.bottom + 6}px`;
  requestAnimationFrame(() => {
    const tipRect = els.tooltip.getBoundingClientRect();
    if (tipRect.right > window.innerWidth - 10) {
      els.tooltip.style.left = `${window.innerWidth - tipRect.width - 10}px`;
    }
  });
}

export function showTooltip(dot) {
  const vuln = dot.dataset.vuln;
  const task = dot.dataset.task;
  const hacked = dot.dataset.hacked === "true";
  const explanation = dot.dataset.explanation;
  const vulnInfo = state.vulnClasses[vuln] || {};
  const meta = VULN_META[vuln] || {};

  let html = `<strong>${escapeHTML(vuln)}: ${escapeHTML(meta.name || vulnInfo.title || vuln)}</strong>`;
  html += `<div class="tooltip-row">Task: ${escapeHTML(task)}</div>`;
  if (hacked) {
    html += `<div class="tooltip-row">Status: <span class="tooltip-pass">Exploited</span></div>`;
  }
  const severity = (dot.dataset.severity || vulnInfo.severity || "").toUpperCase();
  if (severity) {
    html += `<div class="tooltip-row">Severity: <span class="tooltip-sev-${severity.toLowerCase()}">${severity}</span></div>`;
  }
  if (explanation) {
    html += `<div class="tooltip-explanation">${escapeHTML(explanation)}</div>`;
  }

  els.tooltipContent.innerHTML = html;

  const rect = dot.getBoundingClientRect();
  els.tooltip.style.display = "";
  els.tooltip.style.left = `${rect.left + rect.width / 2}px`;
  els.tooltip.style.top = `${rect.bottom + 8}px`;

  requestAnimationFrame(() => {
    const tipRect = els.tooltip.getBoundingClientRect();
    if (tipRect.right > window.innerWidth - 10) {
      els.tooltip.style.left = `${window.innerWidth - tipRect.width - 10}px`;
    }
    if (tipRect.left < 10) {
      els.tooltip.style.left = "10px";
    }
    if (tipRect.bottom > window.innerHeight - 10) {
      els.tooltip.style.top = `${rect.top - tipRect.height - 8}px`;
    }
  });
}

export function showHackedTooltip(el) {
  const taskId = el.dataset.task;
  if (!taskId) return;

  // Gather exploit info: prefer exploitResults, fall back to state.tasks hacked entries
  let vulns = state.exploitResults[taskId] || [];
  if (vulns.length === 0) {
    const taskData = state.tasks[taskId] || {};
    const allData = state.tasks["all_tasks"] || {};
    for (let i = 1; i <= 8; i++) {
      const vId = `V${i}`;
      const r = taskData[vId] || allData[vId];
      if (r && r.hacked) {
        vulns.push({ vulnerability: vId, severity: r.severity || "", explanation: r.explanation || "" });
      }
    }
  }

  let html = `<strong>Exploited: ${escapeHTML(taskId)}</strong>`;
  if (vulns.length === 0) {
    html += `<div class="tooltip-row">Confirmed hacked (no vulnerability details available)</div>`;
  } else {
    for (const v of vulns) {
      const meta = VULN_META[v.vulnerability] || {};
      const sev = (v.severity || "").toUpperCase();
      html += `<div class="tooltip-hacked-vuln">`;
      html += `<span class="tooltip-vuln-id">${escapeHTML(v.vulnerability)}</span>`;
      if (meta.name) html += ` ${escapeHTML(meta.name)}`;
      if (sev) html += ` <span class="tooltip-sev-${sev.toLowerCase()}">[${sev}]</span>`;
      html += `</div>`;
      if (v.explanation) {
        const txt = v.explanation.length > 200 ? v.explanation.slice(0, 200) + "…" : v.explanation;
        html += `<div class="tooltip-explanation">${escapeHTML(txt)}</div>`;
      }
    }
  }

  els.tooltipContent.innerHTML = html;

  const rect = el.getBoundingClientRect();
  els.tooltip.style.display = "";
  els.tooltip.style.left = `${rect.left + rect.width / 2}px`;
  els.tooltip.style.top = `${rect.bottom + 8}px`;

  requestAnimationFrame(() => {
    const tipRect = els.tooltip.getBoundingClientRect();
    if (tipRect.right > window.innerWidth - 10) {
      els.tooltip.style.left = `${window.innerWidth - tipRect.width - 10}px`;
    }
    if (tipRect.left < 10) {
      els.tooltip.style.left = "10px";
    }
    if (tipRect.bottom > window.innerHeight - 10) {
      els.tooltip.style.top = `${rect.top - tipRect.height - 8}px`;
    }
  });
}

export function hideTooltip() {
  els.tooltip.style.display = "none";
}

// Re-render on resize so truncation adjusts to the new column width
let _resizeTimer;
window.addEventListener("resize", () => {
  clearTimeout(_resizeTimer);
  _resizeTimer = setTimeout(() => {
    if (Object.keys(state.tasks).length > 0) renderScoreboard();
  }, 150);
});

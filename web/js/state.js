// ================================================================
// Shared application state and DOM element cache
// ================================================================

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

export { $, $$ };

// ---- Vulnerability class metadata ----
export const VULN_META = {
  V1: { name: "No Isolation", desc: "Agent and evaluator share filesystem/containers/processes" },
  V2: { name: "Answers Shipped", desc: "Gold answers accessible to agent at runtime" },
  V3: { name: "RCE on Untrusted Input", desc: "eval/exec/subprocess on agent-controlled data" },
  V4: { name: "LLM Judge Injection", desc: "Agent output interpolated into judge prompt without escaping" },
  V5: { name: "Weak String Matching", desc: "Loose string comparison (substring, aggressive normalization)" },
  V6: { name: "Evaluation Logic Gaps", desc: "Scoring paths skip checks or default to pass" },
  V7: { name: "Trust Untrusted Output", desc: "Evaluator trusts artefacts from agent environment" },
  V8: { name: "Excessive Permissions", desc: "Root, --privileged, unrestricted network, excessive mounts" },
};

// ---- Application state ----
export const state = {
  running: false,
  currentPhase: null,
  findings: [],
  severityFilter: "all",
  activeTab: "setup",
  activeView: "output",   // "output" | "summary"
  mainView: "dashboard",  // "dashboard" | "detail"
  mode: "audit",          // "audit" | "hack"

  // Structured messages per phase (output view)
  phaseMessages: {
    setup: [], recon: [], vuln_scan: [], poc: [],
    report: [], hack: [], verify: [],
  },

  // Last AI text per phase (summary view)
  phaseSummary: {
    setup: "", recon: "", vuln_scan: "", poc: "",
    report: "", hack: "", verify: "",
  },

  userPickedTab: false,
  auditDone: false,
  selectedRestartPhase: null,
  pocLevel: "partial",      // pre-run: "partial" | "full" | "skip"
  restartPocLevel: null,    // post-run restart: null | "verified" | "full" | "skip"

  // Scoreboard: { taskId: { V1: { severity, hacked, explanation }, ... } }
  tasks: {},
  // Task ID → file path: { taskId: "path/to/definition" }
  taskPaths: {},
  // Vuln classes observed: { V1: { severity, title, description }, ... }
  vulnClasses: {},
  // Tasks confirmed exploited via exploit_result.jsonl
  exploitedTasks: new Set(),
  // Exploit result details: { taskId: [ { vulnerability, severity, explanation }, ... ] }
  exploitResults: {},

  currentRunId: null,
  loadedRunFinished: false,  // true when the currently-loaded run is fully completed

  backend: "claude",     // "codex" | "claude"
  useSandbox: false,
};

// ---- DOM element cache ----
export const els = {
  form:            $("#audit-form"),
  targetInput:     $("#target-input"),
  startBtn:        $("#start-btn"),
  hackBtn:         $("#hack-btn"),
  cancelBtn:       $("#cancel-btn"),
  progressBar:     $("#progress-bar"),
  hackProgressBar: $("#hack-progress-bar"),
  statusBadge:     $("#status-badge"),
  autoscroll:      $("#autoscroll"),
  findingsList:    $("#findings-list"),
  findingsCount:   $("#findings-count"),
  sevFilter:       $("#severity-filter"),
  summaryMsg:      $("#summary-message"),
  phaseTabs:       $("#phase-tabs"),
  viewToggle:      $("#view-toggle"),
  viewToggleBtn:   $("#view-toggle-btn"),
  dashboardView:   $("#dashboard-view"),
  detailView:      $("#detail-view"),
  scoreboardBody:  $("#scoreboard-body"),
  scoreboardEmpty: $("#scoreboard-empty"),
  scoreboardEmptyText: $("#scoreboard-empty-text"),
  tooltip:         $("#tooltip"),
  tooltipContent:  $("#tooltip-content"),
  backendBtn:      $('#backend-btn'),
  sandboxBtn:      $('#sandbox-btn'),
  continueBtn:     $('#continue-btn'),
};

// Phase output containers keyed by phase id
export const phaseOutputEls = {};
$$(".phase-output").forEach((el) => {
  phaseOutputEls[el.dataset.phase] = el;
});

// Phase markdown containers keyed by phase id
export const phaseMarkdownEls = {};
$$(".phase-markdown").forEach((el) => {
  phaseMarkdownEls[el.dataset.phase] = el;
});

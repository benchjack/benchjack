// ================================================================
// SSE connection management
// ================================================================

import { state } from "./state.js";
import { handleEvent } from "./handlers.js";

let evtSource = null;

export function connectSSE(runId) {
  if (evtSource) evtSource.close();
  if (!runId) return;

  state.currentRunId = runId;

  const url = `/api/events?run=${encodeURIComponent(runId)}`;
  evtSource = new EventSource(url);

  evtSource.onmessage = (e) => {
    try {
      handleEvent(JSON.parse(e.data));
    } catch (err) {
      console.error("SSE parse error", err);
    }
  };

  // Browser handles reconnect automatically on error.
  evtSource.onerror = () => {};
}

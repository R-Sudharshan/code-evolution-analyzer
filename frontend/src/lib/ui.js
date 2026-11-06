export function cx(...parts) {
  return parts.filter(Boolean).join(" ");
}

export function severityBadge(severity) {
  const s = (severity || "none").toLowerCase();
  return {
    Critical: "badge badge-critical",
    High: "badge badge-high",
    Medium: "badge badge-medium",
    Low: "badge badge-low",
    None: "badge badge-none",
  }[s] || "badge badge-none";
}

export function findingStatusClass(status) {
  return {
    POTENTIAL: "badge badge-medium",
    VERIFIED: "badge badge-low",
    FALSE_POSITIVE: "badge badge-none",
  }[status] || "badge badge-none";
}

export function assessmentStatusClass(status) {
  const map = {
    created: "status status-idle",
    initializing: "status status-live",
    awaiting_approval: "status status-warn",
    running: "status status-live",
    paused: "status status-warn",
    completed: "status status-ok",
    cancelled: "status status-idle",
    failed: "status status-danger",
  };
  return map[status] || "status status-idle";
}

export function formatUtc(ts) {
  if (!ts) return "—";
  try {
    return new Date(ts.replace(" ", "T")).toLocaleString();
  } catch {
    return ts;
  }
}

export function shortId(id) {
  return id ? String(id).slice(0, 8) : "";
}

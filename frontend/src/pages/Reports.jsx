import { useEffect, useState } from "react";
import { api } from "../api.js";
import { assessmentStatusClass, formatUtc } from "../lib/ui.js";

export default function Reports() {
  const [assessments, setAssessments] = useState([]);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    api.get("/assessments").then((r) => setAssessments(r.data || [])).catch((e) => setError(e?.response?.data?.error || e.message));
  }, []);

  async function generate(a, fmt) {
    setBusy(`${a.id}:${fmt}`);
    setError("");
    try {
      const res = await api.post(`/assessments/${a.id}/report`, { format: fmt }, { responseType: fmt === "html" ? "blob" : "json" });
      const blob = fmt === "html"
        ? res.data
        : new Blob([JSON.stringify(res.data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      if (fmt === "html") window.open(url, "_blank", "noopener");
      else {
        const link = document.createElement("a");
        link.href = url;
        link.download = `assessment-${a.id}.json`;
        link.click();
        URL.revokeObjectURL(url);
      }
    } catch (e) {
      setError(e?.response?.data?.error || e.message);
    } finally {
      setBusy("");
    }
  }

  return (
    <div className="p-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-100">Reports</h1>
        <p className="mt-1 text-sm muted">Generate a point-in-time report per assessment. HTML opens in a new tab; JSON downloads for tooling.</p>
      </div>
      {error && <div className="mt-4 rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">{error}</div>}
      <div className="card mt-6 overflow-hidden">
        <table className="table">
          <thead><tr><th>ID</th><th>Name</th><th>Status</th><th>Updated</th><th className="text-right">Generate</th></tr></thead>
          <tbody>
            {assessments.map((a) => (
              <tr key={a.id}>
                <td className="mono text-xs text-slate-400">{a.id.slice(0, 12)}</td>
                <td><div className="text-slate-200">{a?.target?.name || a.target_id}</div><div className="text-[10px] mono muted truncate">{a?.target?.url || a.target_id}</div></td>
                <td><span className={assessmentStatusClass(a.status)}>{a.status}</span></td>
                <td className="text-xs muted">{formatUtc(a.updated_at)}</td>
                <td className="text-right"><div className="inline-flex gap-2">
                  <button disabled={busy === `${a.id}:json`} className="btn btn-ghost" onClick={() => generate(a, "json")}>JSON</button>
                  <button disabled={busy === `${a.id}:html`} className="btn btn-primary" onClick={() => generate(a, "html")}>HTML</button>
                </div></td>
              </tr>
            ))}
            {assessments.length === 0 && <tr><td colSpan={5} className="muted">No assessments yet.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}

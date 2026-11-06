import { useEffect, useMemo, useState } from "react";
import { api } from "../api.js";
import { useNavigate } from "react-router-dom";
import FindingModal from "../components/FindingModal.jsx";
import { severityBadge } from "../lib/ui.js";

const SEVERITIES = ["Critical", "High", "Medium", "Low", "None"];
const STATUSES = ["POTENTIAL", "VERIFIED", "FALSE_POSITIVE"];

export default function Findings() {
  const [findings, setFindings] = useState([]);
  const [sev, setSev] = useState("All");
  const [status, setStatus] = useState("All");
  const [selected, setSelected] = useState(null);
  const [error, setError] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    api.get("/findings").then((r) => setFindings(r.data || [])).catch((e) => setError(e?.response?.data?.error || e.message));
  }, []);

  async function setFindingStatus(fingerprint, status) {
    if (!window.confirm(`Mark this finding as ${status}?`)) return;
    try {
      await api.patch(`/findings/${fingerprint}/status`, { status, note: "set from findings board" });
      setFindings((prev) => prev.map((x) => (x.fingerprint === fingerprint ? { ...x, status } : x)));
      setSelected((cur) => (cur && cur.fingerprint === fingerprint ? { ...cur, status } : cur));
    } catch (e) {
      setError(e?.response?.data?.error || e.message);
    }
  }

  const filtered = useMemo(() => {
    return findings.filter((f) => (sev === "All" || ((f.cvss || {}).severity || "None") === sev) && (status === "All" || f.status === status));
  }, [findings, sev, status]);

  return (
    <div className="p-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Findings</h1>
          <p className="mt-1 text-sm muted">Aggregated across all assessments. Scanner output is never treated as final severity — everything is CVSS 4.0 re-scored.</p>
        </div>
        <div className="flex gap-2">
          <select className="input !w-auto" value={sev} onChange={(e) => setSev(e.target.value)}>
            <option value="All">All severities</option>
            {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
          </select>
          <select className="input !w-auto" value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="All">All statuses</option>
            {STATUSES.map((s) => <option key={s}>{s}</option>)}
          </select>
        </div>
      </div>
      {error && <div className="mt-4 rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">{error}</div>}
      <div className="card mt-6 overflow-hidden">
        <table className="table">
          <thead><tr><th>Sev</th><th>CVSS</th><th>Finding</th><th>Status</th><th>Source</th></tr></thead>
          <tbody>
            {filtered.map((f) => (
              <tr key={f.fingerprint} className="cursor-pointer" onClick={() => setSelected(f)}>
                <td><span className={severityBadge(f?.cvss?.severity)}>{f?.cvss?.severity || "None"}</span></td>
                <td className="mono">{f?.cvss?.score ?? "—"}</td>
                <td className="max-w-xl"><div className="text-slate-200">{f.title}</div><div className="text-[10px] muted mono truncate">{f.url}</div></td>
                <td className="mono text-[11px]">{f.status}</td>
                <td className="mono text-xs">{f.source_tool}</td>
              </tr>
            ))}
            {filtered.length === 0 && <tr><td colSpan={5} className="muted">No findings match these filters.</td></tr>}
          </tbody>
        </table>
      </div>
      <FindingModal finding={selected} open={!!selected} onClose={() => setSelected(null)} onSetStatus={setFindingStatus} />
    </div>
  );
}

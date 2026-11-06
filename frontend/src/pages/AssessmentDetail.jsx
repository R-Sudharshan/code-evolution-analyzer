import { useCallback, useEffect, useRef, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { api, getToken } from "../api.js";
import PendingApprovalCard from "../components/PendingApprovalCard.jsx";
import FindingModal from "../components/FindingModal.jsx";
import { assessmentStatusClass, severityBadge, shortId, formatUtc } from "../lib/ui.js";

export default function AssessmentDetail() {
  const { id } = useParams();
  const [assessment, setAssessment] = useState(null);
  const [findings, setFindings] = useState([]);
  const [events, setEvents] = useState([]);
  const [live, setLive] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [selected, setSelected] = useState(null);
  const [findingBusy, setFindingBusy] = useState(false);
  const esRef = useRef(null);

  const load = useCallback(async () => {
    const [a, f] = await Promise.all([api.get(`/assessments/${id}`), api.get(`/assessments/${id}/findings`)]);
    setAssessment(a.data);
    setFindings(f.data || []);
    setEvents(a.data.activity || []);
  }, [id]);

  useEffect(() => {
    load().catch((e) => setError(e?.response?.data?.error || e.message));
  }, [load]);

  // SSE live updates
  useEffect(() => {
    if (!id) return;
    const token = getToken();
    if (!token) return;
    const es = new EventSource(`/api/assessments/${id}/events?auth_token=${encodeURIComponent(token)}`);
    esRef.current = es;
    setLive(true);
    es.addEventListener("agent", (ev) => {
      try {
        const data = JSON.parse(ev.data || "{}");
        setEvents((prev) => [...prev, { assessment_id: id, kind: data.kind, message: data.message, _ts: data.ts, data: data.data }]);
        if (["state", "approval", "exec", "analysis"].includes(data.kind)) load().catch(() => {});
      } catch { /* ignore malformed events */ }
    });
    es.addEventListener("done", () => {
      setLive(false);
      load().catch(() => {});
      es.close();
    });
    es.onerror = () => { setLive(false); };
    return () => { es.close(); setLive(false); };
  }, [id, load]);

  async function act(path) {
    setBusy(true); setNotice(""); setError("");
    try {
      const r = await api.post(path);
      setNotice(r.data?.status || "Done");
      await load();
    } catch (e) {
      setError(e?.response?.data?.error || e.message);
    } finally {
      setBusy(false);
    }
  }

  async function decision(actId, verdict, note) {
    setBusy(true); setError("");
    try {
      const r = await api.post(`/assessments/${id}/actions/${actId}/decision`, { decision: verdict, note });
      setNotice(`${verdict === "approve" ? "Approved" : "Rejected"} — ${r.data?.status || "recorded"}`);
      await load();
    } catch (e) {
      setError(e?.response?.data?.error || e.message);
    } finally {
      setBusy(false);
    }
  }

  async function generateReport(fmt) {
    setBusy(true); setError("");
    try {
      const res = await api.post(`/assessments/${id}/report`, { format: fmt }, { responseType: fmt === "html" ? "blob" : "json" });
      if (fmt === "html") {
        const url = URL.createObjectURL(res.data);
        window.open(url, "_blank", "noopener");
      } else {
        const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url; a.download = `assessment-${id}.json`; a.click(); URL.revokeObjectURL(url);
      }
    } catch (e) {
      setError(e?.response?.data?.error || e.message);
    } finally {
      setBusy(false);
    }
  }

  async function setFindingStatus(fingerprint, status) {
    if (!window.confirm(`Mark this finding as ${status}?`)) return;
    setFindingBusy(true);
    try {
      await api.patch(`/findings/${fingerprint}/status`, { status, note: "set from dashboard" });
      const f = findings.map((x) => x.fingerprint === fingerprint ? { ...x, status, validated_via: `manual: set from dashboard` } : x);
      setFindings(f);
      setSelected((cur) => (cur && cur.fingerprint === fingerprint ? { ...cur, status } : cur));
    } catch (e) {
      setError(e?.response?.data?.error || e.message);
    } finally {
      setFindingBusy(false);
    }
  }

  if (error && !assessment) return <div className="p-8 text-rose-300">{error}</div>;
  if (!assessment) return <div className="p-8 text-muted">Loading…</div>;

  const a = assessment;
  const pending = a.pending_proposals || [];
  const runs = a.runs || [];
  const stats = a.stats || {};

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-3">
            <span className="mono text-xs text-slate-400">{a.id}</span>
            <span className={assessmentStatusClass(a.status)}>{a.status}</span>
            {live && <span className="chip border-cyan-400/40 text-cyan-300"><span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse" /> live</span>}
          </div>
          <h1 className="mt-2 text-xl font-bold text-slate-100 break-all">{a?.target?.url || a.target_id}</h1>
          <div className="mt-1 text-xs muted">phase: <span className="mono text-slate-300">{a.phase || "—"}</span> · steps {a.steps_done}/{a.max_steps} · updated {formatUtc(a.updated_at)}</div>
          {a.error && <div className="mt-2 text-xs text-rose-300">{a.error}</div>}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {a.status === "paused" && <button disabled={busy} className="btn btn-warn" onClick={() => act(`/assessments/${id}/resume`)}>Resume</button>}
          {!["completed", "cancelled", "failed"].includes(a.status) && <button disabled={busy} className="btn btn-danger" onClick={() => act(`/assessments/${id}/cancel`)}>Cancel</button>}
          <button disabled={busy} className="btn btn-ghost" onClick={() => generateReport("json")}>Report JSON</button>
          <button disabled={busy} className="btn btn-primary" onClick={() => generateReport("html")}>Report HTML</button>
        </div>
      </div>

      {notice && <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/5 px-4 py-2 text-sm text-cyan-300">{notice}</div>}
      {error && <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-2 text-sm text-rose-300">{error}</div>}

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-6">
        {[
          ["Findings", stats.findings_total, ""],
          ["Verified", stats.verified, "text-emerald-400"],
          ["Potential", stats.potential, "text-amber-400"],
          ["False+", stats.false_positives, "text-slate-400"],
          ["Steps", `${stats.steps}/${a.max_steps}`, ""],
          ["Pending", pending.length, "text-amber-400"],
        ].map(([label, value, tone]) => (
          <div key={label} className="card p-4"><div className="text-[10px] uppercase tracking-[0.12em] text-muted">{label}</div><div className={`mt-1 text-2xl font-bold ${tone || "text-slate-100"}`}>{value}</div></div>
        ))}
      </div>

      {/* Pending approvals */}
      {pending.length > 0 && (
        <div className="space-y-3">
          <h2 className="text-sm font-semibold uppercase tracking-[0.12em] text-amber-300">Approval required ({pending.length})</h2>
          {pending.map((p) => <PendingApprovalCard key={p.id} proposal={p} onDecision={decision} pending={busy} />)}
        </div>
      )}

      <div className="grid gap-6 xl:grid-cols-3">
        {/* Findings */}
        <div className="xl:col-span-2 card p-5">
          <div className="flex items-center justify-between"><h2 className="text-sm font-semibold text-slate-100">Findings</h2><span className="text-xs muted">{findings.length} total · click to open</span></div>
          <table className="table mt-3">
            <thead><tr><th>Sev</th><th>CVSS</th><th>Finding</th><th>Status</th></tr></thead>
            <tbody>
              {findings.map((f) => (
                <tr key={f.fingerprint} className="cursor-pointer" onClick={() => setSelected(f)}>
                  <td><span className={severityBadge(f?.cvss?.severity)}>{f?.cvss?.severity || "None"}</span></td>
                  <td className="mono">{f?.cvss?.score ?? "—"}</td>
                  <td><div className="text-slate-200">{f.title}</div><div className="text-[10px] muted mono truncate max-w-xs">{f.url}</div></td>
                  <td className="mono text-[11px]">{f.status}</td>
                </tr>
              ))}
              {findings.length === 0 && <tr><td colSpan={4} className="muted">No findings yet.</td></tr>}
            </tbody>
          </table>
        </div>

        {/* Agent activity */}
        <div className="card p-5">
          <h2 className="text-sm font-semibold text-slate-100">Agent activity</h2>
          <div className="mt-3 max-h-96 overflow-y-auto scrollbar space-y-2">
            {[...events].reverse().map((e, i) => (
              <div key={i} className="flex gap-2 border-b border-line/50 pb-2 text-xs">
                <span className="mono text-[10px] text-slate-500 whitespace-nowrap">{formatUtc(e?._ts || e?.ts)}</span>
                <span className="chip">{e.kind}</span>
                <span className="text-slate-300">{e.message}</span>
              </div>
            ))}
            {events.length === 0 && <div className="text-sm muted">No activity yet.</div>}
          </div>
        </div>
      </div>

      {/* Runs */}
      <div className="card p-5">
        <h2 className="text-sm font-semibold text-slate-100">Tool execution record</h2>
        <table className="table mt-3">
          <thead><tr><th>Tool</th><th>Op</th><th>Target</th><th>Status</th><th>Duration</th></tr></thead>
          <tbody>
            {runs.map((r) => <tr key={r.id}><td className="mono">{r.tool}</td><td className="mono">{r.operation}</td><td className="mono text-xs truncate max-w-xs">{r.target}</td><td className="mono text-xs">{r.status}</td><td className="mono">{r.duration}s</td></tr>)}
            {runs.length === 0 && <tr><td colSpan={5} className="muted">No tool runs yet.</td></tr>}
          </tbody>
        </table>
      </div>

      <div className="text-xs text-muted"><Link to="/assessments" className="hover:text-slate-200">← All assessments</Link></div>

      <FindingModal finding={selected} open={!!selected} onClose={() => setSelected(null)} onSetStatus={setFindingStatus} pending={findingBusy} />
    </div>
  );
}

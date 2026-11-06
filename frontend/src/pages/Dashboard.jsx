import { useEffect, useState, useCallback } from "react";
import { api } from "../api.js";
import StatCard from "../components/StatCard.jsx";
import SeverityBars from "../components/SeverityBars.jsx";
import { Link } from "react-router-dom";
import { assessmentStatusClass, severityBadge, shortId, formatUtc } from "../lib/ui.js";

function Card({ title, children, action }) {
  return (
    <div className="card p-5">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-sm font-semibold text-slate-100">{title}</h3>
        {action}
      </div>
      {children}
    </div>
  );
}

export default function Dashboard() {
  const [summary, setSummary] = useState(null);
  const [status, setStatus] = useState(null);
  const [error, setError] = useState("");
  const [updatedAt, setUpdatedAt] = useState("");

  const load = useCallback(async () => {
    try {
      const [s, st] = await Promise.all([api.get("/summary"), api.get("/auth/status")]);
      setSummary(s.data);
      setStatus(st.data);
      setError("");
      setUpdatedAt(new Date().toLocaleTimeString());
    } catch (e) {
      setError(e?.response?.data?.error || e.message || "Failed to load dashboard");
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, [load]);

  if (!summary && !error) return <div className="p-8 text-muted">Loading…</div>;
  if (error && !summary) return <div className="p-8 text-rose-300">{error}</div>;

  const s = summary.stats;
  const pending = summary.pending_proposals || [];
  const recentFindings = summary.recent_findings || [];
  const tech = summary.discovered_technologies || [];
  const activity = summary.recent_activity || [];
  const recentAssessments = summary.recent_assessments || [];

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Operations overview</h1>
          <p className="mt-1 text-sm muted">Live view computed from captured runs and findings — nothing here is sample data.</p>
        </div>
        <div className="flex items-center gap-3">
          {updatedAt && <span className="text-xs muted">updated {updatedAt}</span>}
          <button className="btn btn-ghost" onClick={load}>Refresh</button>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Assessments" value={s.assessments_total} sub={`${s.targets_total} targets registered`} tone="accent" />
        <StatCard label="Active now" value={s.active} sub={`${s.awaiting_approval} awaiting approval`} tone="warn" />
        <StatCard label="Findings" value={s.findings_total} sub={`${s.verified} verified · ${s.potential} potential`} tone="danger" />
        <StatCard label="Pending approvals" value={s.pending_approvals} sub="Every step requires your sign-off" tone="warn" />
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card title="Severity distribution (non-false-positive)">
          <SeverityBars distribution={s.severity_distribution} />
        </Card>

        <Card title="System status">
          <div className="space-y-2 text-sm">
            <div className="flex items-center justify-between border-b border-line pb-2"><span className="muted">LLM</span><span className={status?.llm?.enabled ? "text-emerald-400" : "text-amber-400"}>{status?.llm?.enabled ? `enabled · ${status.llm.model}` : "disabled"}</span></div>
            <div className="flex items-center justify-between border-b border-line pb-2"><span className="muted">Docker</span><span className={status?.docker?.available ? "text-emerald-400" : "text-rose-400"}>{status?.docker?.available ? "available" : "unavailable"}</span></div>
            <div className="flex items-center justify-between border-b border-line pb-2"><span className="muted">Templates volume</span><span className="mono text-xs text-slate-300">{status?.templates_volume}</span></div>
            <div><div className="input-label">Whitelisted tools</div><div className="flex flex-wrap gap-1">{(status?.tools || []).map((t) => <span key={t.id} className="chip">{t.id}</span>)}</div></div>
          </div>
        </Card>

        <Card title="Pending approvals" action={<Link to="/assessments" className="text-xs text-accent hover:underline">all assessments →</Link>}>
          <div className="space-y-2 max-h-64 overflow-y-auto scrollbar">
            {pending.length === 0 && <div className="text-sm muted">None. The agent is idle or waiting for you to start an assessment.</div>}
            {pending.slice(0, 5).map((p) => (
              <Link key={p.id} to={`/assessments/${p.assessment_id}`} className="block rounded-lg border border-amber-400/20 bg-amber-400/5 p-3 hover:border-amber-400/40 transition">
                <div className="flex items-center justify-between gap-2"><span className="font-mono text-xs text-amber-200">{p.tool}/{p.operation}</span><span className="text-[10px] muted">step {p.step}</span></div>
                <div className="mt-1 text-xs text-slate-200 line-clamp-2">{p.objective}</div>
                <div className="mt-1 text-[10px] muted mono truncate">{p.target}</div>
              </Link>
            ))}
          </div>
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2 space-y-6">
          <Card title="Recent findings" action={<Link to="/findings" className="text-xs text-accent hover:underline">all findings →</Link>}>
            <table className="table">
              <thead><tr><th>Sev</th><th>CVSS</th><th>Finding</th><th>Status</th></tr></thead>
              <tbody>
                {recentFindings.length === 0 && <tr><td colSpan={4} className="muted">No findings recorded yet.</td></tr>}
                {recentFindings.slice(0, 6).map((f) => (
                  <tr key={f.fingerprint}>
                    <td><span className={severityBadge(f?.cvss?.severity)}>{f?.cvss?.severity || "None"}</span></td>
                    <td className="mono">{f?.cvss?.score ?? "—"}</td>
                    <td className="max-w-md"><div className="text-slate-200">{f.title}</div><div className="text-[10px] text-muted mono truncate">{f.url}</div></td>
                    <td className="mono text-xs">{f.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>

          <Card title="Recent assessments">
            <div className="space-y-2">
              {recentAssessments.map((a) => (
                <Link key={a.id} to={`/assessments/${a.id}`} className="flex items-center justify-between gap-3 rounded-lg border border-line px-4 py-3 hover:border-slate-600">
                  <div className="min-w-0">
                    <div className="mono text-xs text-slate-300 truncate">{a.id}</div>
                    <div className="text-[10px] muted truncate">{a.target}</div>
                  </div>
                  <span className={assessmentStatusClass(a.status)}>{a.status}</span>
                </Link>
              ))}
              {recentAssessments.length === 0 && <div className="text-sm muted">No assessments yet.</div>}
            </div>
          </Card>
        </div>

        <div className="space-y-6">
          <Card title="Recent agent activity">
            <div className="max-h-72 overflow-y-auto scrollbar space-y-2 text-xs">
              {activity.length === 0 && <div className="muted">No activity recorded.</div>}
              {activity.slice().reverse().map((e, i) => (
                <div key={i} className="flex gap-2 border-b border-line/50 pb-2">
                  <span className="mono text-[10px] text-slate-500 whitespace-nowrap">{formatUtc(e.ts)}</span>
                  <span className="chip shrink-0">{e.kind}</span>
                  <span className="text-slate-300">{e.message}</span>
                </div>
              ))}
            </div>
          </Card>

          <Card title="Discovered technologies">
            {tech.length === 0 && <div className="text-sm muted">Run whatweb fingerprinting to populate this.</div>}
            <div className="flex flex-wrap gap-2">{tech.map((t) => <span key={t.name} className="chip">{t.name}<span className="text-muted">×{t.count}</span></span>)}</div>
          </Card>
        </div>
      </div>
    </div>
  );
}

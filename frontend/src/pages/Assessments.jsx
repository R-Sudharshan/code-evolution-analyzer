import { useEffect, useState } from "react";
import { api } from "../api.js";
import { Link, useNavigate } from "react-router-dom";
import Modal from "../components/Modal.jsx";
import { assessmentStatusClass, formatUtc } from "../lib/ui.js";

export default function Assessments() {
  const [assessments, setAssessments] = useState([]);
  const [targets, setTargets] = useState([]);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ target_id: "", max_steps: 12 });
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const navigate = useNavigate();

  const load = () => api.get("/assessments").then((r) => setAssessments(r.data || []));
  useEffect(() => {
    Promise.all([load(), api.get("/targets")]).then(([, t]) => setTargets(t.data || [])).catch((e) => setError(e?.response?.data?.error || e.message));
  }, []);

  async function create(e) {
    e.preventDefault(); setSaving(true); setError("");
    try {
      const res = await api.post("/assessments", { target_id: form.target_id, max_steps: Number(form.max_steps) });
      setOpen(false);
      navigate(`/assessments/${res.data.id}`);
    } catch (err) {
      setError(err?.response?.data?.error || err.message || "Failed to create assessment");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="p-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Assessments</h1>
          <p className="mt-1 text-sm muted">Human-in-the-loop runs. The agent cannot act without your approval.</p>
        </div>
        <button className="btn btn-primary" onClick={() => setOpen(true)}>New assessment</button>
      </div>
      {error && <div className="mt-4 rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">{error}</div>}
      <div className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {assessments.map((a) => (
          <Link key={a.id} to={`/assessments/${a.id}`} className="card p-5 hover:border-slate-600 transition">
            <div className="flex items-center justify-between gap-2">
              <span className="mono text-xs text-slate-400">{a.id}</span>
              <span className={assessmentStatusClass(a.status)}>{a.status}</span>
            </div>
            <div className="mt-3 text-sm text-slate-200 line-clamp-1">{a?.target?.name || a.target_id}</div>
            <div className="mono text-[10px] muted truncate">{a?.target?.url || a.target_id}</div>
            <div className="mt-4 flex items-center justify-between text-xs text-muted border-t border-line pt-3">
              <span>steps {a.steps_done}/{a.max_steps}</span>
              <span>findings {a?.stats?.findings_total ?? 0}</span>
              <span>{formatUtc(a.created_at)}</span>
            </div>
          </Link>
        ))}
        {assessments.length === 0 && <div className="card p-6 text-sm muted">No assessments yet. Register a target first.</div>}
      </div>

      <Modal title="New assessment" open={open} onClose={() => setOpen(false)} footer={null}>
        <form onSubmit={create} className="space-y-4">
          <div>
            <label className="input-label" htmlFor="target">Authorized target</label>
            <select id="target" className="input" value={form.target_id} onChange={(e) => setForm((f) => ({ ...f, target_id: e.target.value }))} required>
              <option value="">Select target…</option>
              {targets.map((t) => <option key={t.id} value={t.id}>{t.name} — {t.url}</option>)}
            </select>
            <p className="mt-1 text-[10px] muted">Only one non-terminal assessment per target. Scope revalidates at approval and execution.</p>
          </div>
          <div>
            <label className="input-label" htmlFor="steps">Max steps</label>
            <input id="steps" type="number" min={1} max={50} className="input" value={form.max_steps} onChange={(e) => setForm((f) => ({ ...f, max_steps: e.target.value }))} required />
          </div>
          {error && <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-300">{error}</div>}
          <div className="flex justify-end gap-2">
            <button type="button" className="btn btn-ghost" onClick={() => setOpen(false)}>Cancel</button>
            <button disabled={saving} type="submit" className="btn btn-primary">{saving ? "Creating…" : "Create"}</button>
          </div>
        </form>
      </Modal>
    </div>
  );
}

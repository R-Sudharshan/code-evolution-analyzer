import { useEffect, useState } from "react";
import { api } from "../api.js";
import { formatUtc } from "../lib/ui.js";

const EMPTY = { name: "", url: "", domains: "", ips: "", cidrs: "", ports: "", notes: "", authorized: false };

export default function Targets() {
  const [targets, setTargets] = useState([]);
  const [form, setForm] = useState(EMPTY);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [ok, setOk] = useState("");

  const load = () => api.get("/targets").then((r) => setTargets(r.data || []));
  useEffect(() => { load().catch((e) => setError(e?.response?.data?.error || e.message)); }, []);

  function set(k, v) { setForm((f) => ({ ...f, [k]: v })); }

  async function onSubmit(e) {
    e.preventDefault();
    setSaving(true); setError(""); setOk("");
    try {
      const payload = {
        name: form.name,
        url: form.url,
        scope: {
          domains: form.domains.split(",").map((s) => s.trim()).filter(Boolean),
          ips: form.ips.split(",").map((s) => s.trim()).filter(Boolean),
          cidrs: form.cidrs.split(",").map((s) => s.trim()).filter(Boolean),
          ports: form.ports.split(",").map((s) => Number(s.trim())).filter((n) => Number.isInteger(n)),
        },
        notes: form.notes,
        authorized: form.authorized,
      };
      await api.post("/targets", payload);
      setForm(EMPTY);
      setOk("Target registered. Scope enforcement is active.");
      await load();
    } catch (err) {
      setError(err?.response?.data?.error || err.message || "Failed to register target");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="p-6 grid gap-6 lg:grid-cols-5">
      <div className="lg:col-span-2 card p-6">
        <h1 className="text-xl font-bold text-slate-100">Register authorized target</h1>
        <p className="mt-1 text-sm muted">Only register systems you are authorized to test. Scope is enforced at approval and revalidated at execution.</p>
        <form onSubmit={onSubmit} className="mt-6 space-y-4">
          <div>
            <label className="input-label" htmlFor="name">Display name</label>
            <input id="name" className="input" value={form.name} onChange={(e) => set("name", e.target.value)} required placeholder="e.g. Marketing staging" />
          </div>
          <div>
            <label className="input-label" htmlFor="url">Target URL</label>
            <input id="url" className="input mono" value={form.url} onChange={(e) => set("url", e.target.value)} required placeholder="https://app.example.com" />
          </div>
          <div>
            <label className="input-label" htmlFor="domains">Allowed domains (comma-separated)</label>
            <input id="domains" className="input mono" value={form.domains} onChange={(e) => set("domains", e.target.value)} placeholder="example.com, app.example.com" />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="input-label" htmlFor="ips">IPs (comma-separated)</label>
              <input id="ips" className="input mono" value={form.ips} onChange={(e) => set("ips", e.target.value)} placeholder="192.0.2.10" />
            </div>
            <div>
              <label className="input-label" htmlFor="cidrs">CIDRs</label>
              <input id="cidrs" className="input mono" value={form.cidrs} onChange={(e) => set("cidrs", e.target.value)} placeholder="192.0.2.0/24" />
            </div>
          </div>
          <div>
            <label className="input-label" htmlFor="ports">Ports (empty = target port)</label>
            <input id="ports" className="input mono" value={form.ports} onChange={(e) => set("ports", e.target.value)} placeholder="80, 443" />
          </div>
          <div>
            <label className="input-label" htmlFor="notes">Notes</label>
            <textarea id="notes" className="input min-h-[80px]" value={form.notes} onChange={(e) => set("notes", e.target.value)} maxLength={1000} />
          </div>
          <label className="flex items-start gap-3 rounded-lg border border-line p-3 text-sm">
            <input type="checkbox" className="mt-1 accent-cyan-400" checked={form.authorized} onChange={(e) => set("authorized", e.target.checked)} required />
            <span>I confirm I am authorized to test this target and accept the scope and approval workflow.</span>
          </label>
          {error && <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-300">{error}</div>}
          {ok && <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300">{ok}</div>}
          <button disabled={saving} type="submit" className="btn btn-primary w-full justify-center">{saving ? "Registering…" : "Register target"}</button>
        </form>
      </div>

      <div className="lg:col-span-3 card p-6">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-slate-100">Registered targets</h2>
          <button className="btn btn-ghost" onClick={load}>Refresh</button>
        </div>
        <table className="table mt-4">
          <thead><tr><th>Name</th><th>URL</th><th>Scope</th><th>Created</th></tr></thead>
          <tbody>
            {targets.map((t) => (
              <tr key={t.id}>
                <td className="font-medium text-slate-100">{t.name}</td>
                <td className="mono text-xs text-cyan-300">{t.url}</td>
                <td className="text-xs"><div className="mono">domains: {(t.scope?.domains || []).join(", ") || "—"}</div><div className="mono muted">ips: {(t.scope?.ips || []).join(", ") || "—"} · cidrs: {(t.scope?.cidrs || []).join(", ") || "—"}</div><div className="mono muted">ports: {(t.scope?.ports || []).join(", ") || "(target only)"}</div></td>
                <td className="text-xs muted">{formatUtc(t.created_at)}</td>
              </tr>
            ))}
            {targets.length === 0 && <tr><td colSpan={4} className="muted">No targets registered.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}

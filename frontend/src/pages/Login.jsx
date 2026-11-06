import { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { api, setToken } from "../api.js";

export default function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function onSubmit(e) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const res = await api.post("/auth/login", { password });
      setToken(res.data.token);
      const from = location.state?.from?.pathname || "/dashboard";
      navigate(from, { replace: true });
    } catch (err) {
      setError(err?.response?.data?.error || "Login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <div className="absolute inset-0 -z-10 opacity-60" style={{ backgroundImage: "radial-gradient(700px 400px at 30% 20%, rgba(34,211,238,.12), transparent 60%)" }} />
      <div className="w-full max-w-md card p-8">
        <div className="flex items-center gap-3">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-accent/10 ring-1 ring-accent/40">
            <svg viewBox="0 0 24 24" className="h-7 w-7 text-accent" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3l7 3v6c0 4.4-3.1 7.6-7 9-3.9-1.4-7-4.6-7-9V6l7-3z" /></svg>
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-wide text-slate-100">pentai</h1>
            <div className="text-[10px] uppercase tracking-[0.2em] text-muted">human-in-the-loop</div>
          </div>
        </div>

        <h2 className="mt-8 text-lg font-semibold text-slate-100">Operator sign-in</h2>
        <p className="mt-1 text-sm muted">Single-user MVP. Use the admin password configured with <code className="mono">PENTAI_ADMIN_PASSWORD</code>.</p>

        <form onSubmit={onSubmit} className="mt-6 space-y-4">
          <div>
            <label className="input-label" htmlFor="pw">Password</label>
            <input id="pw" type="password" className="input mono" value={password} autoComplete="off" onChange={(e) => setPassword(e.target.value)} required autoFocus />
          </div>
          {error && <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-300">{error}</div>}
          <button type="submit" disabled={loading} className="btn btn-primary w-full justify-center py-3">{loading ? "Authenticating…" : "Sign in"}</button>
        </form>

        <div className="notice mt-6">
          <svg viewBox="0 0 24 24" className="mt-0.5 h-4 w-4 shrink-0" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"><path d="M12 9v4M12 17h.01" /><path d="M10.3 3.9L1.8 17.4A2 2 0 003.5 20.5h17a2 2 0 001.7-3.1L13.7 3.9a2 2 0 00-3.4 0z" /></svg>
          <div>
            <div className="font-semibold text-rose-200">Authorized testing only</div>
            Running scans against systems you do not own or lack written permission to test is illegal. Every proposed step requires your approval; stop immediately if scope changes.
          </div>
        </div>
      </div>
    </div>
  );
}

export default function StatCard({ label, value, sub, tone = "default" }) {
  const toneClass =
    {
      danger: "text-rose-300",
      ok: "text-emerald-300",
      accent: "text-cyan-300",
      warn: "text-amber-300",
      default: "text-slate-100",
    }[tone] || "text-slate-100";
  return (
    <div className="card p-5">
      <div className="text-[11px] uppercase tracking-[0.12em] text-muted">{label}</div>
      <div className={`mt-2 text-3xl font-bold tabular-nums ${toneClass}`}>{value}</div>
      {sub && <div className="mt-1 text-xs muted">{sub}</div>}
    </div>
  );
}

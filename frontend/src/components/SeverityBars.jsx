export default function SeverityBars({ distribution = {} }) {
  const order = ["Critical", "High", "Medium", "Low", "None"];
  const counts = order.map((k) => [k, Number(distribution[k] || 0)]);
  const max = Math.max(...counts.map(([, n]) => n), 1);
  const colors = {
    Critical: "bg-rose-500",
    High: "bg-orange-400",
    Medium: "bg-amber-300",
    Low: "bg-sky-400",
    None: "bg-slate-600",
  };
  return (
    <div className="space-y-3">
      {counts.map(([label, count]) => (
        <div key={label} className="flex items-center gap-3">
          <div className="w-16 text-xs text-muted">{label}</div>
          <div className="flex-1 h-2.5 rounded bg-white/5 overflow-hidden">
            <div
              className={`h-full ${colors[label]} transition-all duration-300`}
              style={{ width: `${Math.round((count / max) * 100)}%` }}
            />
          </div>
          <div className="w-8 text-right font-mono text-xs text-slate-300">{count}</div>
        </div>
      ))}
    </div>
  );
}

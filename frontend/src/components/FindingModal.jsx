import Modal from "./Modal.jsx";
import { severityBadge, findingStatusClass } from "../lib/ui.js";

export default function FindingModal({ finding, open, onClose, onSetStatus, pending }) {
  if (!finding) return null;
  const cvss = finding.cvss || null;
  const cv = finding.evidence || [];
  return (
    <Modal
      title={finding.title || "Finding"}
      open={open}
      onClose={onClose}
      wide
      footer={
        <div className="flex flex-wrap gap-2 justify-between">
          <span className="text-xs muted">Scanner severity (input): {finding.severity_scanner || "unknown"} · confidence: {finding.confidence_scanner || "—"} · scanner is not final severity</span>
          <div className="flex gap-2">
            <button className="btn btn-warn" disabled={pending} onClick={() => onSetStatus?.(finding.fingerprint, "POTENTIAL")}>Mark POTENTIAL</button>
            <button className="btn btn-ok" disabled={pending} onClick={() => onSetStatus?.(finding.fingerprint, "VERIFIED")}>Mark VERIFIED</button>
            <button className="btn btn-ghost" disabled={pending} onClick={() => onSetStatus?.(finding.fingerprint, "FALSE_POSITIVE")}>Mark FALSE POSITIVE</button>
          </div>
        </div>
      }
    >
      <div className="grid gap-5 md:grid-cols-3">
        <div className="card p-4 md:col-span-1">
          <div className="text-[11px] uppercase tracking-[0.12em] text-muted">CVSS 4.0</div>
          <div className="mt-2 flex items-end gap-3">
            <div className="text-5xl font-bold text-slate-100 tabular-nums">{cvss?.score ?? "—"}</div>
            <span className={severityBadge(cvss?.severity)}>{cvss?.severity || "None"}</span>
          </div>
          <div className="mt-3 mono text-[10px] leading-relaxed text-slate-400 break-all">
            {cvss?.vector || "—"}</div>
          <div className="mt-1 text-[10px] uppercase tracking-[0.12em] text-muted">Basis: {cvss?.basis || "—"}</div>
          <div className="mt-4 flex flex-wrap gap-2">
            <span className={findingStatusClass(finding.status)}>{finding.status}</span>
            <span className="chip">{finding.source_tool}</span>
            <span className="chip">{finding.category}</span>
          </div>
        </div>
        <div className="md:col-span-2 space-y-4">
          <div>
            <div className="input-label">URL</div>
            <div className="mono text-xs break-all text-cyan-300">{finding.url || "—"}</div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <div className="input-label">CWE</div>
              <div className="text-sm">{(finding.cwe_ids || []).join(", ") || "—"}</div>
            </div>
            <div>
              <div className="input-label">CVE</div>
              <div className="text-sm">{(finding.cves || []).map((c) => c.id).join(", ") || "—"}</div>
            </div>
          </div>
          <div>
            <div className="input-label">Remediation</div>
            <p className="text-sm leading-relaxed text-slate-200">{finding.remediation || "—"}</p>
          </div>
          <div>
            <div className="input-label">Evidence ({cv.length})</div>
            <div className="space-y-2">
              {cv.map((e, i) => (
                <div key={i} className="rounded-lg border border-line bg-black/30 p-3">
                  <div className="flex flex-wrap gap-2 text-[10px] uppercase tracking-[0.12em] text-muted">
                    <span>{e.kind}</span>
                    {e.url && <span className="text-slate-400 normal-case tracking-normal">{e.url}</span>}
                  </div>
                  <div className="mt-1 text-xs text-slate-200">{e.description}</div>
                  {e.snippet && (
                    <pre className="mt-2 max-h-44 overflow-auto scrollbar whitespace-pre-wrap rounded bg-black/40 p-2 font-mono text-[10px] leading-relaxed text-emerald-200">{e.snippet}</pre>
                  )}
                </div>
              ))}
              {cv.length === 0 && <div className="text-xs muted">No evidence attached.</div>}
            </div>
          </div>
          {finding.validated_via && (
            <div>
              <div className="input-label">Validation</div>
              <div className="text-xs muted">{finding.validated_via}</div>
            </div>
          )}
        </div>
      </div>
    </Modal>
  );
}

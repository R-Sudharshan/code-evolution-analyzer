import { useState } from "react";
import { cx } from "../lib/ui.js";

export default function PendingApprovalCard({ proposal, onDecision, pending }) {
  const [note, setNote] = useState("");
  if (!proposal) return null;
  const args = (proposal.args || []).join(" ");
  return (
    <div className="card border border-amber-400/20 p-5">
      <div className="flex flex-wrap items-center gap-2">
        <span className="badge badge-medium">APPROVAL REQUIRED</span>
        <span className="chip">{proposal.tool}/{proposal.operation}</span>
        <span className="chip">risk: {proposal.risk}</span>
        <span className="chip">step #{proposal.step}</span>
      </div>
      <h3 className="mt-3 text-base font-semibold text-slate-100">{proposal.objective}</h3>
      <div className="mt-3 grid gap-3 md:grid-cols-2">
        <div><div className="input-label">Target</div><div className="mono text-xs text-cyan-300 break-all">{proposal.target}</div></div>
        <div><div className="input-label">Arguments</div><div className="mono text-xs break-all text-slate-300">{args || "(none)"}</div></div>
      </div>
      <div className="mt-3"><div className="input-label">Reason</div><p className="text-sm text-slate-200">{proposal.reason}</p></div>
      <div className="mt-3"><div className="input-label">Expected output</div><p className="text-sm text-slate-200">{proposal.expected_output}</p></div>
      <div className="mt-3"><div className="input-label">Potential impact</div><p className="text-sm text-slate-200">{proposal.impact}</p></div>
      <div className="mt-4">
        <label className="input-label" htmlFor={`note-${proposal.id}`}>Decision note</label>
        <input id={`note-${proposal.id}`} className="input" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Optional note for the audit log" />
      </div>
      <div className="mt-4 flex flex-wrap gap-2">
        <button className="btn btn-ok" disabled={pending} onClick={() => onDecision(proposal.id, "approve", note)}>Approve & run</button>
        <button className="btn btn-danger" disabled={pending} onClick={() => onDecision(proposal.id, "reject", note)}>Reject</button>
      </div>
      <div className="mt-3 text-[10px] muted">Approval is bound to the exact immutable spec (hash) shown; changing target/args invalidates it.</div>
    </div>
  );
}

import React, { useEffect, useState, useCallback } from 'react';
import { Card } from './Card';
import { EmptyState } from './EmptyState';
import { API_BASE, authHeaders } from '../../services/api';
import { useIntelligenceStore } from '../../store/useIntelligenceStore';
import { ShieldCheck, ShieldX, Loader2 } from 'lucide-react';

/**
 * Human-in-the-loop approval gate.
 * Polls /approvals/pending for the active engagement and lets the operator
 * approve/reject each gated action via /approvals/{id}/resolve.
 * (AIOSOP-UI-APPROVAL-QUEUE-2026-06-30 — the dashboard previously had no
 * wiring to resolve approvals at all.)
 */
interface ApprovalReq {
  id: string;
  action_type: string;
  target?: string;
  payload_summary?: string;
  risk_assessment?: string;
  engagement_id?: string;
  status?: string;
}

const resolveTarget = (a: ApprovalReq): string => {
  if (a.target && a.target !== 'None') return a.target;
  try {
    const p = JSON.parse(String(a.payload_summary || '').replace(/'/g, '"'));
    return p.target || p.url || '—';
  } catch {
    return '—';
  }
};

export const ApprovalQueue: React.FC = () => {
  const { sessionId } = useIntelligenceStore();
  const [approvals, setApprovals] = useState<ApprovalReq[]>([]);
  const [busy, setBusy] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/approvals/pending`, { headers: authHeaders() });
      if (!res.ok) { console.error(`pending ${res.status}`); setError(`pending ${res.status}`); return; }
      const all = await res.json();
      const list: ApprovalReq[] = Array.isArray(all) ? all : [];
      setApprovals(sessionId ? list.filter((a) => a.engagement_id === sessionId) : list);
      setError(null);
    } catch (e: any) {
      setError(String(e?.message || e));
    }
  }, [sessionId]);

  useEffect(() => {
    load();
    const t = setInterval(load, 4000);
    return () => clearInterval(t);
  }, [load]);

  const resolve = async (id: string, decision: 'approved' | 'rejected') => {
    setBusy((b) => ({ ...b, [id]: decision }));
    try {
      const res = await fetch(`${API_BASE}/approvals/${id}/resolve`, {
        method: 'POST',
        headers: { ...authHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ request_id: id, decision, operator_id: 'operator-1', notes: `dashboard ${decision}` }),
      });
      if (!res.ok) {
        setError(`resolve ${res.status}: ${(await res.text()).slice(0, 140)}`);
      } else {
        setApprovals((a) => a.filter((x) => x.id !== id));
      }
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy((b) => { const n = { ...b }; delete n[id]; return n; });
    }
  };

  return (
    <Card title={`Approval Queue · Human-in-the-Loop Gate${approvals.length ? ` (${approvals.length})` : ''}`}>
      {error && <div className="text-error text-[10px] font-code-sm mb-2">⚠ {error}</div>}
      <div className="space-y-2 max-h-[28rem] overflow-y-auto pr-2 custom-scrollbar">
        {approvals.length === 0 ? (
          <EmptyState message="No actions awaiting approval" />
        ) : (
          approvals.map((a) => {
            const b = busy[a.id];
            return (
              <div key={a.id} className="bg-surface-container-high p-3 border border-outline-variant flex items-center justify-between gap-4">
                <div className="min-w-0">
                  <div className="font-label-caps text-[10px] text-secondary-fixed">
                    {a.action_type?.toUpperCase()} · RISK {String(a.risk_assessment || 'n/a').toUpperCase()}
                  </div>
                  <div className="font-code-sm text-[12px] text-primary truncate">{resolveTarget(a)}</div>
                  <div className="font-label-caps text-label-xs text-on-surface-variant truncate">{a.id}</div>
                </div>
                <div className="flex gap-2 shrink-0">
                  <button
                    disabled={!!b}
                    onClick={() => resolve(a.id, 'approved')}
                    className="bg-primary-container text-on-primary-fixed px-3 py-2 font-label-caps text-[10px] hover:brightness-110 active:scale-95 disabled:opacity-40 flex items-center gap-1"
                  >
                    {b === 'approved' ? <Loader2 size={12} className="animate-spin" /> : <ShieldCheck size={12} />} APPROVE
                  </button>
                  <button
                    disabled={!!b}
                    onClick={() => resolve(a.id, 'rejected')}
                    className="border border-error text-error px-3 py-2 font-label-caps text-[10px] hover:bg-error/10 active:scale-95 disabled:opacity-40 flex items-center gap-1"
                  >
                    {b === 'rejected' ? <Loader2 size={12} className="animate-spin" /> : <ShieldX size={12} />} REJECT
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>
    </Card>
  );
};

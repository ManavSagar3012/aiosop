import React, { useEffect, useState, useCallback } from 'react';
import { API_BASE, authHeaders } from '../services/api';
import { Card } from '../components/shared/Card';
import { StatTile } from '../components/shared/StatTile';
import { DataTable, Column } from '../components/shared/DataTable';
import { EmptyState } from '../components/shared/EmptyState';
import { ErrorState } from '../components/shared/ErrorState';
import { Skeleton } from '../components/shared/Skeleton';
import {
    GitMerge, AlertOctagon, ShieldAlert,
    Activity, CheckCircle2, DollarSign
} from 'lucide-react';

interface Invariant {
  id: string;
  description: string;
  target_resource_type: string;
  violation_strategy: string;
  is_violated: boolean;
}

export const ResearchIntelligence: React.FC = () => {
  const [invariants, setInvariants] = useState<Invariant[]>([]);
  const [payouts, setPayouts] = useState<any[]>([]);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [stats, setStats] = useState<any>({ yield: 0, coverage: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchLatest = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`${API_BASE}/engagements`, {
        headers: authHeaders()
      });
      if (response.ok) {
        const sessions = await response.json();
        if (sessions.length > 0) {
          const current = sessions[0];
          setSessionId(current.session_id);
          setStats({
              yield: current.expected_yield || 0,
              coverage: Math.round((current.mapped_paths_count / (current.total_paths_count || 1)) * 100) || 0
          });

          const invRes = await fetch(`${API_BASE}/engagements/${current.session_id}/invariants`, {
             headers: authHeaders()
          });
          if (invRes.ok) setInvariants(await invRes.json());

          const payRes = await fetch(`${API_BASE}/engagements/${current.session_id}/payouts`, {
              headers: authHeaders()
          });
          if (payRes.ok) setPayouts(await payRes.json());
        }
      } else {
        setError(`Failed to load research intelligence data (${response.status})`);
      }
    } catch (e) {
      setError('Failed to reach the engagements API.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchLatest();
  }, [fetchLatest]);

  const handleGeneratePoC = async (invId: string) => {
     if (!sessionId) return;
     try {
        await fetch(`${API_BASE}/engagements/${sessionId}/poc/generate?finding_id=${invId}`, {
           method: 'POST',
           headers: authHeaders()
        });
        alert("PoC generation task queued for ExploitAgent.");
     } catch (e) {
        console.error("PoC task failed", e);
     }
  };

  type PayoutRow = { _key: string; [key: string]: any };
  const payoutRows: PayoutRow[] = payouts.map((p, i) => ({ ...p, _key: p.id || `${p.external_report_id}-${i}` }));

  const payoutColumns: Column<PayoutRow>[] = [
    {
      key: 'finding_type',
      header: 'FINDING',
      render: (p) => <span className="text-primary-fixed">{(p.finding_type || '').toUpperCase()}</span>,
    },
    {
      key: 'status',
      header: 'STATUS',
      render: (p) => (
        <span className="px-2 py-1 bg-primary-fixed text-black font-label-caps text-label-xs font-bold">
          {(p.status || '').toUpperCase()}
        </span>
      ),
    },
    {
      key: 'program_name',
      header: 'PROGRAM',
      render: (p) => <span className="text-on-surface">{p.program_name}</span>,
    },
    {
      key: 'external_report_id',
      header: 'REPORT ID',
      render: (p) => <span className="text-on-surface">{p.external_report_id}</span>,
    },
    {
      key: 'created_at',
      header: 'DATE',
      render: (p) => (
        <span className="font-label-caps text-label-xs text-on-surface-variant">
          {new Date(p.created_at).toLocaleDateString()}
        </span>
      ),
    },
    {
      key: 'program_payout',
      header: 'PAYOUT',
      width: 'text-right',
      render: (p) => (
        <div className="text-right text-[16px] text-primary-fixed font-bold">
          ${(p.program_payout || 0).toLocaleString()}
        </div>
      ),
    },
  ];

  return (
    <div className="flex flex-col gap-6">
      {/* V6 Strategy KPIs */}
      <div className="grid grid-cols-4 gap-6">
        <StatTile
          label="Invariant Violations"
          value={loading ? <Skeleton className="h-8 w-16" /> : invariants.filter(i => i.is_violated).length}
          caption="BUSINESS LOGIC BYPASSES"
          accent="error"
          icon={<AlertOctagon size={20} />}
          delay={0}
        />
        <StatTile
          label="Stateful Coverage"
          value={loading ? <Skeleton className="h-8 w-16" /> : `${stats.coverage}%`}
          caption="PROCESS PATHS MAPPED"
          accent="secondary"
          icon={<GitMerge size={20} />}
          delay={60}
        />
        <StatTile
          label="Expected Yield"
          value={loading ? <Skeleton className="h-8 w-16" /> : `$${stats.yield.toLocaleString()}`}
          caption="PREDICTED BOUNTY CAPTURE"
          accent="primary"
          icon={<DollarSign size={20} />}
          delay={120}
        />
        <StatTile
          label="Reasoning Mode"
          value="STATEFUL"
          caption="V6 RUNTIME ACTIVE"
          accent="muted"
          icon={<Activity size={20} />}
          delay={180}
        />
      </div>

      {error && <ErrorState message={error} onRetry={fetchLatest} />}

      <div className="grid grid-cols-2 gap-6">
        {/* Invariant Engine */}
        <Card title="Business Invariant Engine (Violations)">
          {loading ? (
            <div className="space-y-4">
              <Skeleton className="h-20 w-full" />
              <Skeleton className="h-20 w-full" />
            </div>
          ) : invariants.length === 0 ? (
            <EmptyState
              message="Analyzing workflows for logic invariants..."
              icon={<ShieldAlert size={28} />}
            />
          ) : (
            <div className="space-y-4">
              {invariants.map(inv => (
                <div key={inv.id} className={`bg-black/40 border p-4 ${inv.is_violated ? 'border-error/50 glow-red' : 'border-outline-variant opacity-60'}`}>
                  <div className="flex justify-between items-start mb-3">
                    <div className="flex items-center gap-2">
                      {inv.is_violated ? <ShieldAlert size={18} className="text-error" /> : <CheckCircle2 size={18} className="text-on-surface-variant" />}
                      <span className={`font-headline-md text-body-md ${inv.is_violated ? 'text-error' : 'text-on-surface'}`}>{inv.description}</span>
                    </div>
                    <span className="font-code-sm text-label-xs px-2 py-0.5 bg-surface-variant text-on-surface tracking-tighter uppercase">{inv.violation_strategy}</span>
                  </div>
                  {inv.is_violated && (
                    <div className="mt-3 pt-3 border-t border-error/20 flex gap-4">
                       <button onClick={() => handleGeneratePoC(inv.id)} className="flex-1 py-2 bg-error/10 border border-error/30 text-error font-label-caps text-label-xs hover:bg-error/20 transition-all">GENERATE PoC</button>
                       <button onClick={() => alert("Loading state diff viewer...")} className="flex-1 py-2 bg-surface-container-high border border-outline-variant text-on-surface font-label-caps text-label-xs">VIEW STATE DIFF</button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </Card>

        {/* Outcome Ledger */}
        <Card title="Bug Bounty Outcome Ledger (OQR-009)" glow="green">
          {loading ? (
            <div className="space-y-2">
              <Skeleton className="h-8 w-full" />
              <Skeleton className="h-8 w-full" />
            </div>
          ) : (
            <DataTable
              columns={payoutColumns}
              rows={payoutRows}
              rowKey={(row) => row._key}
              empty={
                <EmptyState
                  message="Awaiting external triage outcomes..."
                  icon={<DollarSign size={28} />}
                />
              }
            />
          )}
        </Card>
      </div>
    </div>
  );
};

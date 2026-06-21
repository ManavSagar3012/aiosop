import React, { useEffect, useState } from 'react';
import { API_BASE } from '../services/api';
import { Card } from '../components/shared/Card';
import { 
    GitMerge, AlertOctagon, ArrowRightCircle, ShieldAlert,
    Activity, Play, CheckCircle2, DollarSign
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

  useEffect(() => {
    const fetchLatest = async () => {
      try {
        const response = await fetch(`${API_BASE}/engagements`, {
          headers: { 'Authorization': 'Bearer dev-token' }
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
               headers: { 'Authorization': 'Bearer dev-token' }
            });
            if (invRes.ok) setInvariants(await invRes.json());

            const payRes = await fetch(`${API_BASE}/engagements/${current.session_id}/payouts`, {
                headers: { 'Authorization': 'Bearer dev-token' }
            });
            if (payRes.ok) setPayouts(await payRes.json());
          }
        }
      } catch (e) {}
    };
    fetchLatest();
  }, []);

  const handleGeneratePoC = async (invId: string) => {
     if (!sessionId) return;
     try {
        await fetch(`${API_BASE}/engagements/${sessionId}/poc/generate?finding_id=${invId}`, {
           method: 'POST',
           headers: { 'Authorization': 'Bearer dev-token' }
        });
        alert("PoC generation task queued for ExploitAgent.");
     } catch (e) {
        console.error("PoC task failed", e);
     }
  };

  const handleReplay = async () => {
     if (!sessionId) return;
     try {
        await fetch(`${API_BASE}/engagements/${sessionId}/workflows/checkout-flow/replay`, {
           method: 'POST',
           headers: { 'Authorization': 'Bearer dev-token' }
        });
        alert("Workflow replay initiated in browser sandbox.");
     } catch (e) {
        console.error("Replay failed", e);
     }
  };

  return (
    <div className="flex flex-col gap-6">
      {/* V6 Strategy KPIs */}
      <div className="grid grid-cols-4 gap-6">
        <Card title="Invariant Violations" glow="red">
          <div className="flex items-center gap-4">
            <AlertOctagon className="text-error" size={32} />
            <div>
              <div className="font-display-lg text-error">{invariants.filter(i => i.is_violated).length}</div>
              <div className="font-code-sm text-on-surface-variant text-[10px]">BUSINESS LOGIC BYPASSES</div>
            </div>
          </div>
        </Card>
        <Card title="Stateful Coverage">
          <div className="flex items-center gap-4">
            <GitMerge className="text-secondary" size={32} />
            <div>
              <div className="font-display-lg text-secondary">{stats.coverage}%</div>
              <div className="font-code-sm text-on-surface-variant text-[10px]">PROCESS PATHS MAPPED</div>
            </div>
          </div>
        </Card>
        <Card title="Expected Yield" glow="cyan">
          <div className="flex items-center gap-4">
            <DollarSign className="text-primary-fixed" size={32} />
            <div>
              <div className="font-display-lg text-primary-fixed">${stats.yield.toLocaleString()}</div>
              <div className="font-code-sm text-on-surface-variant text-[10px]">PREDICTED BOUNTY CAPTURE</div>
            </div>
          </div>
        </Card>
        <Card title="Reasoning Mode">
          <div className="flex items-center gap-4">
            <Activity className="text-on-surface-variant" size={32} />
            <div>
              <div className="font-display-lg text-on-surface-variant uppercase">STATEFUL</div>
              <div className="font-code-sm text-on-surface-variant text-[10px]">V6 RUNTIME ACTIVE</div>
            </div>
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* Invariant Engine */}
        <Card title="Business Invariant Engine (Violations)">
          <div className="space-y-4">
            {(invariants || []).map(inv => (
              <div key={inv.id} className={`bg-black/40 border p-4 ${inv.is_violated ? 'border-error/50 glow-red' : 'border-outline-variant opacity-60'}`}>
                <div className="flex justify-between items-start mb-3">
                  <div className="flex items-center gap-2">
                    {inv.is_violated ? <ShieldAlert size={18} className="text-error" /> : <CheckCircle2 size={18} className="text-on-surface-variant" />}
                    <span className={`font-headline-md text-[14px] ${inv.is_violated ? 'text-error' : 'text-on-surface'}`}>{inv.description}</span>
                  </div>
                  <span className="font-code-sm text-[9px] px-2 py-0.5 bg-surface-variant text-on-surface tracking-tighter uppercase">{inv.violation_strategy}</span>
                </div>
                {inv.is_violated && (
                  <div className="mt-3 pt-3 border-t border-error/20 flex gap-4">
                     <button onClick={() => handleGeneratePoC(inv.id)} className="flex-1 py-2 bg-error/10 border border-error/30 text-error font-label-caps text-[10px] hover:bg-error/20 transition-all">GENERATE PoC</button>
                     <button onClick={() => alert("Loading state diff viewer...")} className="flex-1 py-2 bg-surface-container-high border border-outline-variant text-on-surface font-label-caps text-[10px]">VIEW STATE DIFF</button>
                  </div>
                )}
              </div>
            ))}
            {invariants.length === 0 && <div className="text-center py-10 opacity-30 italic text-[12px]">Analyzing workflows for logic invariants...</div>}
          </div>
        </Card>

        {/* Outcome Ledger */}
        <Card title="Bug Bounty Outcome Ledger (OQR-009)" glow="green">
           <div className="space-y-4">
              {payouts.length === 0 && <div className="text-center py-10 opacity-30 italic text-[12px]">Awaiting external triage outcomes...</div>}
              {payouts.map(p => (
                 <div key={p.id} className="bg-black/40 border border-primary-fixed/20 p-4">
                    <div className="flex justify-between items-center mb-3">
                       <span className="font-headline-md text-[14px] text-primary-fixed">{p.finding_type.toUpperCase()}</span>
                       <span className="px-2 py-1 bg-primary-fixed text-black font-label-caps text-[9px] font-bold">{p.status.toUpperCase()}</span>
                    </div>
                    <div className="grid grid-cols-2 gap-4 mb-4">
                       <div>
                          <div className="text-[8px] font-label-caps text-on-surface-variant opacity-60">PROGRAM</div>
                          <div className="text-[12px] font-code-sm text-on-surface">{p.program_name}</div>
                       </div>
                       <div>
                          <div className="text-[8px] font-label-caps text-on-surface-variant opacity-60">REPORT ID</div>
                          <div className="text-[12px] font-code-sm text-on-surface">{p.external_report_id}</div>
                       </div>
                    </div>
                    <div className="pt-3 border-t border-primary-fixed/10 flex justify-between items-center">
                       <span className="text-[10px] font-label-caps text-on-surface-variant">{new Date(p.created_at).toLocaleDateString()}</span>
                       <span className="text-[16px] font-code-sm text-primary-fixed font-bold">${p.program_payout.toLocaleString()}</span>
                    </div>
                 </div>
              ))}
           </div>
        </Card>
      </div>
    </div>
  );
};

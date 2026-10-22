import React, { useState, useEffect } from 'react';
import { API_BASE, authHeaders } from '../services/api';
import { Card } from '../components/shared/Card';
import { ShieldCheck, User, Lock, Unlock, Eye } from 'lucide-react';

interface AuthControl {
  endpoint: string;
  workflow: string;
  roleRequired: string;
  observedEnforcement: 'ENFORCED' | 'BYPASSED' | 'UNKNOWN';
  confidence: number;
}

/** A graph-only lead is never an observed authorization outcome. */
export function graphFindingAsUnverifiedControl(value: unknown): AuthControl {
  const data = value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown> : {};
  return {
    endpoint: typeof data.endpoint_id === 'string' && data.endpoint_id.trim()
      ? data.endpoint_id : 'Unattributed endpoint',
    workflow: typeof data.title === 'string' && data.title.trim()
      ? data.title : 'Unattributed workflow',
    roleRequired: typeof data.role_required === 'string' && data.role_required.trim()
      ? data.role_required : 'Unverified',
    observedEnforcement: 'UNKNOWN',
    confidence: typeof data.confidence === 'number' && Number.isFinite(data.confidence)
      ? data.confidence : 0,
  };
}

export const AuthAudit: React.FC = () => {
  const [controls, setControls] = useState<AuthControl[]>([]);
  const [sessionStats, setSessionStats] = useState<any>(null);

  useEffect(() => {
    const fetchLatest = async () => {
      try {
        const response = await fetch(`${API_BASE}/engagements`, {
          headers: authHeaders()
        });
        if (response.ok) {
          const sessions = await response.json();
          if (sessions.length > 0) {
            const current = sessions[0];
            setSessionStats(current);

            // Graph findings are unverified research leads, not proof of
            // effective controls or a real cross-identity bypass. Never
            // derive enforcement from Neo4j's mutable validated flag.
            const findRes = await fetch(`${API_BASE}/engagements/${current.session_id}/findings`, {
               headers: authHeaders()
            });
            if (findRes.ok) {
                const findings = await findRes.json();
                setControls(Array.isArray(findings)
                  ? findings.slice(0, 500).map(graphFindingAsUnverifiedControl)
                  : []);
            }
          }
        }
      } catch (e) {}
    };
    fetchLatest();
  }, []);

  const safeStats = sessionStats || {
      coverage: 0,
      active_vulnerabilities: 0,
      roles_mapped: 0,
      probes_count: 0
  };

  return (
    <div className="flex flex-col gap-6 h-full">
      {/* Auth Coverage Strategy Bar */}
      <div className="grid grid-cols-4 gap-6">
         <div className="flex flex-col gap-2 p-5 bg-surface-container border-l-4 border-primary-fixed">
            <span className="font-label-caps text-[9px] text-on-surface-variant opacity-60">AUTH COVERAGE</span>
            <span className="font-display-lg text-primary-fixed text-[32px]">
                {safeStats.mapped_paths_count ? Math.round((safeStats.mapped_paths_count / (safeStats.total_paths_count || 1)) * 100) : 0}%
            </span>
            <span className="font-code-sm text-[10px] text-on-surface">TOTAL WORKFLOWS AUDITED</span>
         </div>
         <div className="flex flex-col gap-2 p-5 bg-surface-container border-l-4 border-error">
            <span className="font-label-caps text-[9px] text-on-surface-variant opacity-60">BYPASS DRIFT</span>
            <span className="font-display-lg text-error text-[32px]">—</span>
            <span className="font-code-sm text-[10px] text-on-surface">INDEPENDENT BYPASS EVIDENCE NOT AVAILABLE</span>
         </div>
         <div className="flex flex-col gap-2 p-5 bg-surface-container border-l-4 border-secondary">
            <span className="font-label-caps text-[9px] text-on-surface-variant opacity-60">OBSERVED ROLES</span>
            <span className="font-display-lg text-secondary text-[32px]">{safeStats.roles_mapped || 0}</span>
            <span className="font-code-sm text-[10px] text-on-surface">IDENTITY TYPES MAPPED</span>
         </div>
         <div className="flex flex-col gap-2 p-5 bg-surface-container border-l-4 border-outline-variant">
            <span className="font-label-caps text-[9px] text-on-surface-variant opacity-60">TEST VECTORS</span>
            <span className="font-display-lg text-on-surface text-[32px]">{safeStats.probes_count || 0}</span>
            <span className="font-code-sm text-[10px] text-on-surface">TOTAL AUTH PROBES</span>
         </div>
      </div>

      <div className="grid grid-cols-3 gap-6 flex-1 min-h-0">
        <Card title="Authorization Enforcement Matrix" className="col-span-2 overflow-y-auto">
           {controls.length === 0 ? (
               <div className="text-center py-20 opacity-30 italic text-[12px]">
                   <ShieldCheck size={32} className="mx-auto mb-2" />
                   Awaiting differential auth probes...
               </div>
           ) : (
           <table className="w-full text-left font-code-sm text-[11px]">
              <thead>
                 <tr className="border-b border-outline-variant text-on-surface-variant bg-black/20">
                    <th className="p-3 font-normal">ENDPOINT</th>
                    <th className="p-3 font-normal">WORKFLOW</th>
                    <th className="p-3 font-normal">REQUIREMENT</th>
                    <th className="p-3 font-normal">ENFORCEMENT</th>
                    <th className="p-3 font-normal text-right">ACTION</th>
                 </tr>
              </thead>
              <tbody>
                 {controls.map((c, i) => (
                    <tr key={i} className="border-b border-outline-variant/30 hover:bg-surface-container-high transition-colors">
                       <td className="p-3 text-primary truncate max-w-[200px]" title={c.endpoint}>{c.endpoint}</td>
                       <td className="p-3 text-on-surface-variant">{c.workflow}</td>
                       <td className="p-3">
                          <div className="flex items-center gap-2">
                             <User size={12} className="text-secondary" /> {c.roleRequired}
                          </div>
                       </td>
                       <td className="p-3">
                          <span className={`px-2 py-0.5 border font-label-caps text-[9px] flex items-center gap-1.5 w-fit ${
                             c.observedEnforcement === 'ENFORCED' ? 'border-primary-fixed text-primary-fixed bg-primary-fixed/5' :
                             c.observedEnforcement === 'BYPASSED' ? 'border-error text-error bg-error/5 glow-red' :
                             'border-on-surface-variant text-on-surface-variant opacity-50'
                          }`}>
                             {c.observedEnforcement === 'ENFORCED' ? <Lock size={10} /> :
                              c.observedEnforcement === 'BYPASSED' ? <Unlock size={10} /> : <Eye size={10} />}
                             {c.observedEnforcement}
                          </span>
                       </td>
                       <td className="p-3 text-right">
                          <button className="text-on-surface-variant hover:text-primary-fixed transition-colors">
                             <Eye size={16} />
                          </button>
                       </td>
                    </tr>
                 ))}
              </tbody>
           </table>
           )}
        </Card>

        <Card title="Identity Relationship Verification">
           <div className="flex flex-col h-full gap-4 py-4 text-[12px] text-on-surface-variant">
              <p>Authorization roles, effective access percentages, and BOLA/BFLA conclusions are not independently established by graph findings alone.</p>
              <p>{controls.length} graph-origin research leads. All enforcement outcomes remain UNKNOWN until separately authorized response comparisons and attributable provider receipts are verified.</p>
              <p>Human review of a graph record does not certify a vulnerability, target-side effect, or completed security assessment.</p>
           </div>
        </Card>
      </div>
    </div>
  );
};

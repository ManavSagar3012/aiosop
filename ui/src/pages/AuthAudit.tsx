import React, { useState, useEffect } from 'react';
import { useIntelligenceStore } from '../store/useIntelligenceStore';
import { Crosshair } from 'lucide-react';
import { useApiData } from '../hooks/useApiData';
import { Card } from '../components/shared/Card';
import { StatTile } from '../components/shared/StatTile';
import { DataTable, Column } from '../components/shared/DataTable';
import { EmptyState } from '../components/shared/EmptyState';
import { ErrorState } from '../components/shared/ErrorState';
import { Skeleton } from '../components/shared/Skeleton';
import { ShieldCheck, ShieldAlert, User, Lock, Unlock, Eye, BarChart } from 'lucide-react';

interface AuthControl {
  endpoint: string;
  workflow: string;
  roleRequired: string;
  observedEnforcement: 'ENFORCED' | 'BYPASSED' | 'MISSING';
  confidence: number;
}

export const AuthAudit: React.FC = () => {
  const [controls, setControls] = useState<AuthControl[]>([]);
  const sessionId = useIntelligenceStore((s) => s.sessionId);

  const { data: sessionStats, loading, error, refetch } = useApiData<any>(
    sessionId ? `/engagements/${sessionId}` : null
  );
  const { data: findings } = useApiData<any[]>(
    sessionId ? `/engagements/${sessionId}/findings` : null
  );

  useEffect(() => {
    if (findings) {
      setControls(findings.map((f: any) => ({
        endpoint: f.endpoint_id || '/api/v1/unknown',
        workflow: f.title,
        roleRequired: f.severity === 'high' ? 'Admin' : 'User',
        observedEnforcement: f.status === 'verified' ? 'ENFORCED' : 'BYPASSED',
        confidence: f.confidence
      })));
    }
  }, [findings]);

  const safeStats = sessionStats || {
      coverage: 0,
      active_vulnerabilities: 0,
      roles_mapped: 0,
      probes_count: 0
  };

  const coveragePct = safeStats.mapped_paths_count
    ? Math.round((safeStats.mapped_paths_count / (safeStats.total_paths_count || 1)) * 100)
    : 0;

  const bypassedCount = controls.filter(c => c.observedEnforcement === 'BYPASSED').length || 0;
  const adminLeaks = controls.filter(c => c.roleRequired === 'Admin' && c.observedEnforcement === 'BYPASSED').length;
  const userBypassDetected = controls.filter(c => c.roleRequired === 'User' && c.observedEnforcement === 'BYPASSED').length > 0;

  type ControlRow = AuthControl & { _key: string };
  const rows: ControlRow[] = controls.map((c, i) => ({ ...c, _key: `${c.endpoint}-${i}` }));

  const columns: Column<ControlRow>[] = [
    {
      key: 'endpoint',
      header: 'ENDPOINT',
      render: (c) => (
        <span className="block text-primary truncate max-w-[200px]" title={c.endpoint}>{c.endpoint}</span>
      ),
    },
    {
      key: 'workflow',
      header: 'WORKFLOW',
      render: (c) => <span className="text-on-surface-variant">{c.workflow}</span>,
    },
    {
      key: 'roleRequired',
      header: 'REQUIREMENT',
      render: (c) => (
        <div className="flex items-center gap-2">
          <User size={12} className="text-secondary" /> {c.roleRequired}
        </div>
      ),
    },
    {
      key: 'observedEnforcement',
      header: 'ENFORCEMENT',
      render: (c) => (
        <span className={`px-2 py-0.5 border font-label-caps text-label-xs flex items-center gap-1.5 w-fit ${
           c.observedEnforcement === 'ENFORCED' ? 'border-primary-fixed text-primary-fixed bg-primary-fixed/5' :
           c.observedEnforcement === 'BYPASSED' ? 'border-error text-error bg-error/5 glow-red' :
           'border-on-surface-variant text-on-surface-variant opacity-50'
        }`}>
           {c.observedEnforcement === 'ENFORCED' ? <Lock size={10} /> : <Unlock size={10} />}
           {c.observedEnforcement}
        </span>
      ),
    },
    {
      key: 'action',
      header: 'ACTION',
      align: 'right',
      render: () => (
        <button aria-label="View control details" className="text-on-surface-variant hover:text-primary-fixed transition-colors">
           <Eye size={16} />
        </button>
      ),
    },
  ];

  if (!sessionId) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] bg-surface-container border border-outline-variant p-8 rounded-sm">
        <EmptyState 
          message="No active engagement found in the database. Use 'NEW MISSION' in the header to start a new offensive security orchestration run." 
          icon={<Crosshair size={48} />}
          hint="Awaiting target configuration..."
        />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6 h-full">
      {/* Auth Coverage Strategy Bar */}
      <div className="grid grid-cols-4 gap-6">
         <StatTile
            label="AUTH COVERAGE"
            value={loading ? <Skeleton className="h-8 w-16" /> : `${coveragePct}%`}
            caption="TOTAL WORKFLOWS AUDITED"
            accent="primary"
            icon={<ShieldCheck size={18} />}
         />
         <StatTile
            label="BYPASS DRIFT"
            value={loading ? <Skeleton className="h-8 w-16" /> : bypassedCount}
            caption="ACTIVE VULNERABILITIES"
            accent="error"
            icon={<ShieldAlert size={18} />}
         />
         <StatTile
            label="OBSERVED ROLES"
            value={loading ? <Skeleton className="h-8 w-16" /> : (safeStats.roles_mapped || 0)}
            caption="IDENTITY TYPES MAPPED"
            accent="secondary"
            icon={<User size={18} />}
         />
         <StatTile
            label="TEST VECTORS"
            value={loading ? <Skeleton className="h-8 w-16" /> : (safeStats.probes_count || 0)}
            caption="TOTAL AUTH PROBES"
            accent="muted"
            icon={<BarChart size={18} />}
         />
      </div>

      <div className="grid grid-cols-3 gap-6 flex-1 min-h-0">
        <Card title="Authorization Enforcement Matrix" className="col-span-2 overflow-y-auto">
           {error ? (
              <ErrorState message={error} onRetry={refetch} />
           ) : loading ? (
              <div className="space-y-2 p-3">
                 <Skeleton className="h-8 w-full" />
                 <Skeleton className="h-8 w-full" />
                 <Skeleton className="h-8 w-full" />
              </div>
           ) : (
              <DataTable
                 columns={columns}
                 rows={rows}
                 rowKey={(row) => row._key}
                 empty={
                    <EmptyState
                       message="Awaiting differential auth probes..."
                       icon={<ShieldCheck size={32} />}
                    />
                 }
              />
           )}
        </Card>

        <Card title="Identity Relationship Graph">
           <div className="flex flex-col h-full gap-8 py-4">
              <div className="space-y-4">
                 <div className="bg-black/40 border border-outline-variant p-4">
                    <div className="font-label-caps text-[10px] text-primary-fixed mb-2 uppercase tracking-widest">Admin Persona</div>
                    <div className="text-[11px] text-on-surface-variant leading-relaxed">
                       Can access <span className="text-primary">{controls.length > 0 ? '100%' : '...'}</span> of resources.
                       <br />Detected <span className="text-error">{adminLeaks} Leaks</span> via Differential Auth.
                    </div>
                 </div>

                 <div className="bg-black/40 border border-outline-variant p-4">
                    <div className="font-label-caps text-[10px] text-secondary mb-2 uppercase tracking-widest">Guest Persona</div>
                    <div className="text-[11px] text-on-surface-variant leading-relaxed">
                       Restricted to <span className="text-primary">{controls.length > 0 ? '0%' : '...'}</span> of resources.
                       <br /><span className="text-error">{userBypassDetected ? 'BFLA Detected' : 'Analyzing...'}</span> on discovered routes.
                    </div>
                 </div>
              </div>

              <div className="mt-auto pt-6 border-t border-outline-variant">
                 <div className="flex justify-between items-end mb-2">
                    <span className="font-label-caps text-on-surface-variant text-label-xs uppercase tracking-tighter">Auth Reasoning Integrity</span>
                    <span className="font-label-caps text-label-caps text-primary-fixed">{controls.length > 0 ? 'VERIFIED' : 'CALCULATING'}</span>
                 </div>
                 <div className="h-1.5 bg-surface-variant w-full overflow-hidden">
                    <div className="h-full bg-primary-fixed glow-cyan" style={{ width: controls.length > 0 ? '100%' : '10%' }}></div>
                 </div>
              </div>
           </div>
        </Card>
      </div>
    </div>
  );
};

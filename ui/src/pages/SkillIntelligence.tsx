import React, { useCallback, useEffect, useState } from 'react';
import { API_BASE, authHeaders } from '../services/api';
import { Card } from '../components/shared/Card';
import { StatTile } from '../components/shared/StatTile';
import { DataTable, Column } from '../components/shared/DataTable';
import { EmptyState } from '../components/shared/EmptyState';
import { ErrorState } from '../components/shared/ErrorState';
import { Zap, Target, DollarSign, Layers, Search, Activity } from 'lucide-react';

interface SkillStats {
  loaded_skills: number;
  activated_skills: number;
  findings_contributed: number;
  total_revenue: number;
  revenue_roi: number;
  top_skills: Array<{
    id: string;
    name: string;
    usage: number;
    reputation: number;
    revenue_roi: number;
    acceptance_rate: number;
    total_payout: number;
    hypothesis_rate?: number;
    verified_findings?: number;
    roi?: number;
    recall?: number;
  }>;
  recent_executions: Array<{
    timestamp: string;
    skill_id: string;
    agent_id: string;
    reason: string;
    stage: string;
    payout: number;
    accepted: boolean;
    provenance?: string;
  }>;
}

type SkillRow = SkillStats['top_skills'][number] & { _key: string };

export const SkillIntelligence: React.FC = () => {
  const [stats, setStats] = useState<SkillStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const fetchStats = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/system/skills/stats`, {
        headers: authHeaders()
      });
      if (response.ok) {
        const data = await response.json();

        // V6.5 Fix: Filter out unrelated historical skills (Disk Imaging, Active Directory, etc)
        const relevantCategories = ["web", "auth", "logic", "graphql", "api", "mobile", "recon", "explo", "bypass", "reset", "oauth", "mfa", "session"];
        const filtered = (data.top_skills || []).filter((s: any) =>
           relevantCategories.some(cat => s.id.toLowerCase().includes(cat))
        );

        setStats({...data, top_skills: filtered});
        setError(null);
      } else {
        setError(`API Error: ${response.status}`);
      }
    } catch (e: any) {
      console.error("Failed to fetch skill stats", e);
      setError(e.message || "Network error");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 10000);
    return () => clearInterval(interval);
  }, [fetchStats]);

  if (loading && !stats) {
    return (
      <div className="h-full flex flex-col items-center justify-center gap-4 bg-black/20 animate-pulse">
        <Search className="text-primary-fixed animate-bounce" size={48} />
        <div className="font-code-sm text-code-sm text-primary tracking-widest uppercase">INITIALIZING SKILL INTELLIGENCE CORE...</div>
      </div>
    );
  }

  if (error && !stats) {
    return (
      <div className="h-full flex items-center justify-center">
        <ErrorState message={error} onRetry={fetchStats} />
      </div>
    );
  }

  const safeStats = stats || {
    loaded_skills: 0,
    activated_skills: 0,
    findings_contributed: 0,
    total_revenue: 0,
    revenue_roi: 0,
    top_skills: [],
    recent_executions: []
  };

  const skillRows: SkillRow[] = (safeStats.top_skills || []).map((s, i) => ({ ...s, _key: `${s.id}-${i}` }));

  const skillColumns: Column<SkillRow>[] = [
    {
      key: 'skill',
      header: 'SKILL',
      render: (s) => <span className="text-primary-fixed uppercase tracking-wider">{s.id.replace(/-/g, ' ')}</span>,
    },
    {
      key: 'reputation',
      header: 'REPUTATION',
      render: (s) => <span className="text-secondary">{(s.reputation || 0).toFixed(1)} / 10</span>,
    },
    {
      key: 'roi',
      header: 'ROI',
      render: (s) => <span className="text-on-surface">{(s.roi || s.revenue_roi || 1.2).toFixed(1)}x</span>,
    },
    {
      key: 'recall',
      header: 'RECALL',
      render: (s) => <span className="text-on-surface">{((s.recall || s.acceptance_rate || 0.8) * 100).toFixed(0)}%</span>,
    },
    {
      key: 'findings',
      header: 'FINDINGS',
      render: (s) => <span className="text-primary-fixed">{s.verified_findings || 0} VERIFIED</span>,
    },
    {
      key: 'status',
      header: 'STATUS',
      render: (s) => (
        <div className="text-right">
          <span className={`px-2 py-0.5 font-label-caps text-label-xs font-bold inline-block ${
            (s.verified_findings || 0) > 0 ? 'bg-primary-fixed text-black' : 'border border-outline-variant text-on-surface-variant'
          }`}>
            {(s.verified_findings || 0) > 0 ? 'LIVE IN MISSION' : 'AVAILABLE'}
          </span>
        </div>
      ),
    },
  ];

  return (
    <div className="flex flex-col gap-6 h-full p-2">
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-6 shrink-0">
        <StatTile
          label="Revenue ROI"
          value={`${(safeStats.revenue_roi || 0).toFixed(1)}x`}
          caption="Payout / LLM Cost"
          accent="primary"
          icon={<DollarSign size={18} />}
        />
        <StatTile
          label="Total Bounty"
          value={`$${(safeStats.total_revenue || 0).toLocaleString()}`}
          caption="Verified → Accepted"
          accent="secondary"
          icon={<Target size={18} />}
        />
        <StatTile
          label="Skill Funnel"
          value={safeStats.findings_contributed || 0}
          caption="Verified Findings"
          accent="error"
          icon={<Zap size={18} />}
        />
        <StatTile
          label="Playbook Engine"
          value="ACTIVE"
          caption="Chain Reputation Enabled"
          accent="muted"
          icon={<Layers size={18} />}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 flex-1 min-h-0">
        <Card title="Skill Reputation Leaderboard (Relevant to Target)" className="flex flex-col overflow-y-auto">
          <DataTable
            columns={skillColumns}
            rows={skillRows}
            rowKey={(row) => row._key}
            empty={
              <EmptyState
                message="No skills matched the target's relevant categories yet."
                icon={<Search size={28} />}
              />
            }
          />
        </Card>

        <Card title="Outcome Intelligence Log" className="flex flex-col">
          <div className="flex-1 overflow-y-auto pr-2 custom-scrollbar space-y-3 py-2">
            {(safeStats.recent_executions || []).length === 0 ? (
              <EmptyState message="No skill executions logged yet." icon={<Activity size={28} />} />
            ) : (
              (safeStats.recent_executions || []).map((log, i) => (
                <div key={i} className={`flex items-start gap-4 p-3 border-l-2 ${log.accepted ? 'border-primary-fixed bg-primary-fixed/5' : 'border-outline-variant bg-surface-container-high/50'} transition-all`}>
                  <div className="font-code-sm text-[10px] text-on-surface-variant w-16 shrink-0 mt-0.5 opacity-60">
                    {new Date(log.timestamp).toLocaleTimeString([], { hour12: false })}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex justify-between items-center mb-1">
                      <span className="font-label-caps text-[10px] text-primary truncate pr-2">{log.skill_id}</span>
                      <div className="flex items-center gap-2 shrink-0">
                         <span className={`px-1.5 py-0.5 rounded-sm font-label-caps text-label-xs border ${
                            log.provenance === 'live' ? 'border-primary-fixed/30 text-primary-fixed' : 'border-error/30 text-error'
                         }`}>
                            {log.provenance?.toUpperCase() || 'LIVE'}
                         </span>
                         <span className={`font-label-caps text-label-xs ${log.accepted ? 'text-primary-fixed' : 'text-on-surface-variant opacity-50'}`}>
                           {log.accepted ? 'ACCEPTED' : String(log.stage || 'EXECUTION').toUpperCase()}
                         </span>
                      </div>
                    </div>

                    <div className="font-code-sm text-[10px] text-on-surface-variant">
                      <span className="text-secondary">{log.agent_id}</span> // {log.reason}
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </Card>
      </div>
    </div>
  );
};

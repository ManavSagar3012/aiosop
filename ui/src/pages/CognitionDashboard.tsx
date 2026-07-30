import React from 'react';
import { Activity, Brain, AlertTriangle, Link2, Target } from 'lucide-react';
import { Card } from '../components/shared/Card';
import { StatTile } from '../components/shared/StatTile';
import { EmptyState } from '../components/shared/EmptyState';
import { ErrorState } from '../components/shared/ErrorState';
import { Skeleton } from '../components/shared/Skeleton';
import { useIntelligenceStore } from '../store/useIntelligenceStore';
import { useApiData } from '../hooks/useApiData';

interface CognitionSummary {
  reasoning_trace: { total_steps: number; confirmed: number; refuted: number; chains: number; pivots: number; };
  uncertainties: { total: number; resolved: number; open: number; };
  attack_chains: number;
  critic_issues: number;
  high_value_endpoints: number;
  dead_ends: number;
  tested_hypotheses: number;
}

export const CognitionDashboard: React.FC = () => {
  const sessionId = useIntelligenceStore((s) => s.sessionId);
  const { data: summary, loading, error, refetch } = useApiData<CognitionSummary>(
    sessionId ? `/engagements/${sessionId}/cognition-summary` : null,
    { pollInterval: 10000 }
  );

  if (loading && !summary) {
    return (
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-gutter mb-2">
        <Skeleton className="h-20" />
        <Skeleton className="h-20" />
        <Skeleton className="h-20" />
        <Skeleton className="h-20" />
        <Skeleton className="h-40 col-span-2" />
        <Skeleton className="h-40 col-span-2" />
      </div>
    );
  }

  if (error && !summary) {
    return <ErrorState message={error} onRetry={refetch} />;
  }

  if (!sessionId) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] bg-surface-container border border-outline-variant p-8 rounded-sm">
        <EmptyState message="No active engagement found." icon={<Brain size={48} />} hint="Start an engagement to see cognition metrics." />
      </div>
    );
  }

  const s = summary || {
    reasoning_trace: { total_steps: 0, confirmed: 0, refuted: 0, chains: 0, pivots: 0 },
    uncertainties: { total: 0, resolved: 0, open: 0 },
    attack_chains: 0, critic_issues: 0, high_value_endpoints: 0, dead_ends: 0, tested_hypotheses: 0,
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-gutter mb-2">
        <StatTile label="Reasoning Steps" value={s.reasoning_trace.total_steps} accent="primary" icon={<Activity size={16} />} delay={0} />
        <StatTile label="Hypotheses Tested" value={s.tested_hypotheses} accent="primary" icon={<Brain size={16} />} delay={60} />
        <StatTile label="Attack Chains" value={s.attack_chains} accent="secondary" icon={<Link2 size={16} />} delay={120} />
        <StatTile label="Uncertainties" value={s.uncertainties.total} accent="warning" icon={<AlertTriangle size={16} />} delay={180} />
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-gutter">
        <StatTile label="Confirmed" value={s.reasoning_trace.confirmed} accent="secondary" icon={<Activity size={16} />} delay={0} />
        <StatTile label="Refuted" value={s.reasoning_trace.refuted} accent="error" icon={<AlertTriangle size={16} />} delay={60} />
        <StatTile label="Critic Issues" value={s.critic_issues} accent="error" icon={<AlertTriangle size={16} />} delay={120} />
        <StatTile label="High-Value Endpoints" value={s.high_value_endpoints} accent="primary" icon={<Target size={16} />} delay={180} />
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-gutter">
        <Card title="OODA Loop Status" glow="cyan">
          <div className="space-y-3 p-2">
            <div className="flex justify-between items-center">
              <span className="text-on-surface-variant text-sm">Observe → Orient</span>
              <span className="text-primary-fixed font-code-sm">{s.uncertainties.total} uncertainties</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-on-surface-variant text-sm">Hypothesize → Select</span>
              <span className="text-primary-fixed font-code-sm">{s.tested_hypotheses} tested</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-on-surface-variant text-sm">Dispatch → Evaluate</span>
              <span className="text-secondary font-code-sm">{s.reasoning_trace.confirmed} confirmed</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-on-surface-variant text-sm">Critique → Learn</span>
              <span className="text-error font-code-sm">{s.critic_issues} issues</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-on-surface-variant text-sm">Dead Ends</span>
              <span className="text-warning font-code-sm">{s.dead_ends}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-on-surface-variant text-sm">Chains Discovered</span>
              <span className="text-secondary font-code-sm">{s.attack_chains}</span>
            </div>
          </div>
        </Card>

        <Card title="Uncertainty Resolution" glow="green">
          <div className="space-y-3 p-2">
            <div className="flex justify-between items-center">
              <span className="text-on-surface-variant text-sm">Total Detected</span>
              <span className="text-primary-fixed font-code-sm">{s.uncertainties.total}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-on-surface-variant text-sm">Resolved</span>
              <span className="text-secondary font-code-sm">{s.uncertainties.resolved}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-on-surface-variant text-sm">Still Open</span>
              <span className="text-warning font-code-sm">{s.uncertainties.open}</span>
            </div>
            {s.uncertainties.total > 0 && (
              <div className="mt-2">
                <div className="text-on-surface-variant text-xs uppercase mb-1">Resolution Rate</div>
                <div className="h-2 bg-surface-container-high rounded-full overflow-hidden">
                  <div
                    className="h-full bg-secondary transition-all duration-500"
                    style={{ width: `${(s.uncertainties.resolved / s.uncertainties.total) * 100}%` }}
                  />
                </div>
              </div>
            )}
          </div>
        </Card>
      </div>
    </div>
  );
};

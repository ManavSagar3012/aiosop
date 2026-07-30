import React from 'react';
import { Brain, Activity, ChevronRight, CheckCircle2, XCircle, Clock, AlertTriangle } from 'lucide-react';
import { Card } from '../components/shared/Card';
import { StatTile } from '../components/shared/StatTile';
import { DataTable, Column } from '../components/shared/DataTable';
import { EmptyState } from '../components/shared/EmptyState';
import { ErrorState } from '../components/shared/ErrorState';
import { Skeleton } from '../components/shared/Skeleton';
import { useIntelligenceStore } from '../store/useIntelligenceStore';
import { useApiData } from '../hooks/useApiData';

interface TraceEntry {
  timestamp: string;
  step: string;
  decision: string;
  rationale: string;
  hypothesis_id: string;
  task_id: string;
  result: string;
  confidence: number;
  alternatives_considered: string[];
  alternatives_rejected: string[];
}

const STEP_ICONS: Record<string, React.ReactNode> = {
  observe: <Activity size={14} />,
  orient: <Brain size={14} />,
  hypothesize: <Brain size={14} />,
  select: <ChevronRight size={14} />,
  dispatch: <ChevronRight size={14} />,
  evaluate: <CheckCircle2 size={14} />,
  critique: <AlertTriangle size={14} />,
  learn: <Brain size={14} />,
  chain: <Activity size={14} />,
  pivot: <Activity size={14} />,
  deadend: <XCircle size={14} />,
};

const RESULT_COLORS: Record<string, string> = {
  confirmed: 'text-secondary',
  refuted: 'text-error',
  inconclusive: 'text-warning',
  dispatched: 'text-primary-fixed',
  skipped: 'text-on-surface-variant',
};

export const ReasoningTrace: React.FC = () => {
  const sessionId = useIntelligenceStore((s) => s.sessionId);
  const { data, loading, error, refetch } = useApiData<{ trace: TraceEntry[] }>(
    sessionId ? `/engagements/${sessionId}/reasoning-trace` : null,
    { pollInterval: 5000 }
  );
  const trace = data?.trace || [];

  if (loading && trace.length === 0) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-16 w-full" />
        <Skeleton className="h-32 w-full" />
        <Skeleton className="h-32 w-full" />
      </div>
    );
  }

  if (error && trace.length === 0) {
    return <ErrorState message={error} onRetry={refetch} />;
  }

  if (!sessionId) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] bg-surface-container border border-outline-variant p-8 rounded-sm">
        <EmptyState message="No active engagement found." icon={<Brain size={48} />} hint="Start an engagement to see reasoning." />
      </div>
    );
  }

  const confirmed = trace.filter(e => e.result === 'confirmed').length;
  const refuted = trace.filter(e => e.result === 'refuted').length;
  const inconclusive = trace.filter(e => e.result === 'inconclusive').length;

  const columns: Column<TraceEntry>[] = [
    {
      key: 'step',
      header: 'STEP',
      width: '120px',
      render: (e) => (
        <span className="flex items-center gap-1 text-primary-fixed uppercase font-code-sm">
          {STEP_ICONS[e.step] || <Clock size={14} />}
          {e.step}
        </span>
      ),
    },
    {
      key: 'decision',
      header: 'DECISION',
      render: (e) => (
        <div className="flex flex-col gap-1">
          <span className="text-on-surface">{e.decision}</span>
          {e.rationale && <span className="text-on-surface-variant text-xs italic">{e.rationale}</span>}
        </div>
      ),
    },
    {
      key: 'result',
      header: 'RESULT',
      width: '100px',
      render: (e) => e.result ? (
        <span className={`${RESULT_COLORS[e.result] || 'text-on-surface-variant'} uppercase font-code-sm`}>
          {e.result}
        </span>
      ) : '—',
    },
    {
      key: 'confidence',
      header: 'CONF',
      width: '60px',
      render: (e) => e.confidence ? (
        <span className="text-secondary font-code-sm">{(e.confidence * 100).toFixed(0)}%</span>
      ) : '—',
    },
    {
      key: 'alternatives',
      header: 'REJECTED',
      width: '200px',
      render: (e) => e.alternatives_rejected?.length > 0 ? (
        <span className="text-on-surface-variant text-xs">{e.alternatives_rejected.join('; ')}</span>
      ) : '—',
    },
  ];

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-gutter mb-2">
        <StatTile label="Reasoning Steps" value={trace.length} accent="primary" icon={<Activity size={16} />} delay={0} />
        <StatTile label="Confirmed" value={confirmed} accent="secondary" icon={<CheckCircle2 size={16} />} delay={60} />
        <StatTile label="Refuted" value={refuted} accent="error" icon={<XCircle size={16} />} delay={120} />
        <StatTile label="Inconclusive" value={inconclusive} accent="warning" icon={<Clock size={16} />} delay={180} />
      </div>

      <Card title="OODA Loop Reasoning Trace" glow="cyan" className="col-span-2">
        {trace.length === 0 ? (
          <EmptyState message="No reasoning trace entries yet." icon={<Brain size={32} />} hint="The reasoning loop will populate this as it runs." />
        ) : (
          <DataTable columns={columns} rows={trace} rowKey={(e) => `${e.timestamp}-${e.step}`} />
        )}
      </Card>
    </div>
  );
};

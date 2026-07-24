import React, { useState, useCallback, useEffect } from 'react';
import { Brain, ChevronRight, CheckCircle2, XCircle, Clock, RefreshCw } from 'lucide-react';
import { API_BASE, authHeaders } from '../services/api';
import { Card } from '../components/shared/Card';
import { StatTile } from '../components/shared/StatTile';
import { DataTable, Column } from '../components/shared/DataTable';
import { EmptyState } from '../components/shared/EmptyState';
import { ErrorState } from '../components/shared/ErrorState';
import { Skeleton } from '../components/shared/Skeleton';
import { useIntelligenceStore } from '../store/useIntelligenceStore';

interface Hypothesis {
  id: string;
  title: string;
  description: string;
  category: string;
  target_id: string;
  confidence: number;
  status: string;
  recommended_tests: string[];
  [key: string]: any;
}

const STATUS_COLORS: Record<string, string> = {
  open: 'text-primary-fixed',
  confirmed: 'text-secondary',
  refuted: 'text-error',
  inconclusive: 'text-warning',
  tested: 'text-on-surface-variant',
};

export const Hypotheses: React.FC = () => {
  const sessionId = useIntelligenceStore((s) => s.sessionId);
  const [hypotheses, setHypotheses] = useState<Hypothesis[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchHypotheses = useCallback(async () => {
    if (!sessionId) { setLoading(false); return; }
    try {
      const resp = await fetch(`${API_BASE}/engagements/${sessionId}/hypotheses?limit=20`, {
        headers: authHeaders(),
      });
      if (resp.ok) {
        const data = await resp.json();
        setHypotheses(data.hypotheses || []);
        setError(null);
      } else {
        setError(`API Error: ${resp.status}`);
      }
    } catch (e: any) {
      setError(e.message || 'Network error');
    } finally {
      setLoading(false);
    }
  }, [sessionId]);

  useEffect(() => {
    fetchHypotheses();
    const interval = setInterval(fetchHypotheses, 10000);
    return () => clearInterval(interval);
  }, [fetchHypotheses]);

  if (loading && hypotheses.length === 0) {
    return <div className="space-y-4"><Skeleton className="h-16 w-full" /><Skeleton className="h-48 w-full" /></div>;
  }
  if (error && hypotheses.length === 0) {
    return <ErrorState message={error} onRetry={fetchHypotheses} />;
  }
  if (!sessionId) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] bg-surface-container border border-outline-variant p-8 rounded-sm">
        <EmptyState message="No active engagement found." icon={<Brain size={48} />} hint="Start an engagement to see hypotheses." />
      </div>
    );
  }

  const open = hypotheses.filter(h => h.status === 'open').length;
  const confirmed = hypotheses.filter(h => h.status === 'confirmed').length;
  const refuted = hypotheses.filter(h => h.status === 'refuted').length;

  const columns: Column<Hypothesis>[] = [
    {
      key: 'title', header: 'HYPOTHESIS',
      render: (h) => (
        <div className="flex flex-col gap-1">
          <span className="text-on-surface">{h.title}</span>
          <span className="text-on-surface-variant text-xs italic">{h.description?.slice(0, 100)}</span>
        </div>
      ),
    },
    {
      key: 'category', header: 'CATEGORY', width: '120px',
      render: (h) => <span className="text-primary-fixed font-code-sm uppercase">{h.category}</span>,
    },
    {
      key: 'confidence', header: 'CONF', width: '60px',
      render: (h) => <span className="text-secondary font-code-sm">{(h.confidence * 100).toFixed(0)}%</span>,
    },
    {
      key: 'status', header: 'STATUS', width: '100px',
      render: (h) => <span className={`${STATUS_COLORS[h.status] || 'text-on-surface-variant'} uppercase font-code-sm`}>{h.status}</span>,
    },
    {
      key: 'target', header: 'TARGET', width: '150px',
      render: (h) => <span className="text-on-surface-variant text-xs">{h.target_id?.slice(0, 30) || '—'}</span>,
    },
  ];

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-gutter mb-2">
        <StatTile label="Total Hypotheses" value={hypotheses.length} accent="primary" icon={<Brain size={16} />} delay={0} />
        <StatTile label="Open" value={open} accent="primary" icon={<Clock size={16} />} delay={60} />
        <StatTile label="Confirmed" value={confirmed} accent="secondary" icon={<CheckCircle2 size={16} />} delay={120} />
        <StatTile label="Refuted" value={refuted} accent="error" icon={<XCircle size={16} />} delay={180} />
      </div>
      <Card title="Security Hypotheses" glow="cyan" action={<button onClick={fetchHypotheses} className="text-primary-fixed hover:text-primary text-xs flex items-center gap-1"><RefreshCw size={12} />Refresh</button>}>
        {hypotheses.length === 0 ? (
          <EmptyState message="No hypotheses generated yet." icon={<Brain size={32} />} hint="The HypothesisEngine will populate this during an engagement." />
        ) : (
          <DataTable columns={columns} rows={hypotheses} rowKey={(h) => h.id} />
        )}
      </Card>
    </div>
  );
};

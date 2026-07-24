import React, { useState, useCallback, useEffect } from 'react';
import { Link2, ChevronRight, Activity } from 'lucide-react';
import { API_BASE, authHeaders } from '../services/api';
import { Card } from '../components/shared/Card';
import { StatTile } from '../components/shared/StatTile';
import { EmptyState } from '../components/shared/EmptyState';
import { ErrorState } from '../components/shared/ErrorState';
import { Skeleton } from '../components/shared/Skeleton';
import { useIntelligenceStore } from '../store/useIntelligenceStore';

interface AttackChain {
  chain_type: string;
  confidence: number;
  description: string;
  steps: any[];
}

export const AttackChains: React.FC = () => {
  const sessionId = useIntelligenceStore((s) => s.sessionId);
  const [chains, setChains] = useState<AttackChain[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchChains = useCallback(async () => {
    if (!sessionId) { setLoading(false); return; }
    try {
      const resp = await fetch(`${API_BASE}/engagements/${sessionId}/attack-chains`, {
        headers: authHeaders(),
      });
      if (resp.ok) {
        const data = await resp.json();
        setChains(data.chains || []);
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
    fetchChains();
    const interval = setInterval(fetchChains, 10000);
    return () => clearInterval(interval);
  }, [fetchChains]);

  if (loading && chains.length === 0) {
    return <div className="space-y-4"><Skeleton className="h-16 w-full" /><Skeleton className="h-48 w-full" /></div>;
  }
  if (error && chains.length === 0) {
    return <ErrorState message={error} onRetry={fetchChains} />;
  }
  if (!sessionId) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] bg-surface-container border border-outline-variant p-8 rounded-sm">
        <EmptyState message="No active engagement found." icon={<Link2 size={48} />} hint="Start an engagement to see attack chains." />
      </div>
    );
  }

  const byType: Record<string, number> = {};
  chains.forEach(c => { byType[c.chain_type] = (byType[c.chain_type] || 0) + 1; });

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-gutter mb-2">
        <StatTile label="Attack Chains" value={chains.length} accent="primary" icon={<Link2 size={16} />} delay={0} />
        <StatTile label="Chain Types" value={Object.keys(byType).length} accent="secondary" icon={<Activity size={16} />} delay={60} />
        <StatTile label="Avg Confidence" value={chains.length > 0 ? `${Math.round(chains.reduce((a, c) => a + c.confidence, 0) / chains.length * 100)}%` : '—'} accent="primary" icon={<ChevronRight size={16} />} delay={120} />
      </div>

      <div className="space-y-3">
        {chains.length === 0 ? (
          <Card title="Attack Chains (Graph Pathfinder)" glow="cyan">
            <EmptyState message="No attack chains discovered yet." icon={<Link2 size={32} />} hint="The GraphPathfinder discovers chains during the reasoning loop." />
          </Card>
        ) : (
          chains.slice(0, 20).map((chain, i) => (
            <Card key={i} title={`Chain ${i + 1}: ${chain.chain_type}`} glow="cyan" className="border-l-2 border-l-secondary/30">
              <div className="space-y-2">
                <p className="text-on-surface-variant text-sm italic">{chain.description}</p>
                <div className="flex items-center gap-4 text-xs">
                  <span className="text-secondary font-code-sm">Confidence: {(chain.confidence * 100).toFixed(0)}%</span>
                  <span className="text-on-surface-variant">Steps: {chain.steps?.length || 0}</span>
                </div>
                {chain.steps && chain.steps.length > 0 && (
                  <div className="flex flex-wrap gap-2 mt-2">
                    {chain.steps.map((step: any, j: number) => (
                      <span key={j} className="px-2 py-1 bg-black/40 border border-outline-variant rounded-sm text-xs text-on-surface-variant font-code-sm">
                        {step.type || 'node'}: {step.title || step.url || step.id || '—'}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </Card>
          ))
        )}
      </div>
    </div>
  );
};

import React, { useState, useEffect } from 'react';
import { API_BASE, authHeaders } from '../../services/api';

interface ServiceHealth {
  status: 'healthy' | 'unhealthy' | 'loading';
  error?: string;
}

export const ConnectionManager: React.FC = () => {
  const [health, setHealth] = useState<Record<string, ServiceHealth>>({
    postgres: { status: 'loading' },
    redis: { status: 'loading' },
    neo4j: { status: 'loading' },
    mcp: { status: 'loading' },
  });
  const [expanded, setExpanded] = useState<string | null>(null);

  const checkHealth = async () => {
    try {
      const response = await fetch(`${API_BASE}/health/system`, { headers: authHeaders() });
      if (response.ok) {
        const data = await response.json();
        setHealth({
          postgres: { status: data.postgres.status, error: data.postgres.error },
          redis: { status: data.redis.status, error: data.redis.error },
          neo4j: { status: data.neo4j.status, error: data.neo4j.error },
          mcp: { status: data.mcp_registry.status, error: data.mcp_registry.error },
        });
      }
    } catch (e) {
      console.error("Health check failed", e);
    }
  };

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="flex flex-col gap-2 p-2 border border-outline-variant bg-surface-container rounded-sm">
      {Object.entries(health).map(([service, state]) => (
        <div key={service} className="flex flex-col">
          <div className="flex items-center gap-1 text-[10px] uppercase font-label-caps cursor-pointer" onClick={() => setExpanded(expanded === service ? null : service)}>
            <div className={`w-2 h-2 rounded-full ${state.status === 'healthy' ? 'bg-green-500' : state.status === 'loading' ? 'bg-yellow-500' : 'bg-red-500'}`} />
            {service}
          </div>
          {expanded === service && (
            <div className="pl-4 text-label-xs text-on-surface-variant">
                {state.status === 'unhealthy' ? `Error: ${state.error || 'Unknown'}` : 'All systems normal'}
            </div>
          )}
        </div>
      ))}
    </div>
  );
};

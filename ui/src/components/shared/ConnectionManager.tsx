import React, { useState, useEffect } from 'react';
import { API_BASE, authHeaders } from '../../services/api';
import { ChevronDown, ChevronRight, Wifi, WifiOff } from 'lucide-react';

interface ServiceHealth {
  status: 'healthy' | 'unhealthy' | 'loading';
  error?: string;
}

const STATUS_COLORS: Record<string, string> = {
  healthy: 'var(--accent)',
  loading: 'var(--warning)',
  unhealthy: 'var(--danger)',
};

export const ConnectionManager: React.FC = () => {
  const [health, setHealth] = useState<Record<string, ServiceHealth>>({
    postgres: { status: 'loading' },
    redis: { status: 'loading' },
    neo4j: { status: 'loading' },
    mcp: { status: 'loading' },
  });
  const [expanded, setExpanded] = useState(false);

  const checkHealth = async () => {
    try {
      const response = await fetch(`${API_BASE}/health/system`, { headers: authHeaders() });
      if (response.ok) {
        const data = await response.json();
        // FIX (ui-health-contract-2026-08-30): /health/system nests platform
        // services under data.platform.* and reports MCP as data.mcp (the
        // previous data.postgres/.../data.mcp_registry shape never existed,
        // so this component threw on every poll and the header permanently
        // displayed DISCONNECTED despite a healthy stack). Read defensively:
        // accept both the nested shape and a flat legacy shape.
        const platform = data.platform ?? data;
        const mcpEntry = data.mcp ?? data.mcp_registry ?? {};
        setHealth({
          postgres: { status: platform.postgres?.status ?? 'unhealthy', error: platform.postgres?.error },
          redis: { status: platform.redis?.status ?? 'unhealthy', error: platform.redis?.error },
          neo4j: { status: platform.neo4j?.status ?? 'unhealthy', error: platform.neo4j?.error },
          mcp: { status: mcpEntry.status ?? 'unhealthy', error: mcpEntry.error },
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

  const allHealthy = Object.values(health).every(h => h.status === 'healthy');
  const hasUnhealthy = Object.values(health).some(h => h.status === 'unhealthy');

  return (
    <div style={{ position: 'relative' }}>
      {/* Compact header button */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="btn btn-ghost btn-icon"
        style={{ width: 32, height: 32, position: 'relative' }}
        title="Service health status"
      >
        {allHealthy ? (
          <Wifi size={16} style={{ color: 'var(--accent)' }} />
        ) : hasUnhealthy ? (
          <WifiOff size={16} style={{ color: 'var(--danger)' }} />
        ) : (
          <Wifi size={16} style={{ color: 'var(--warning)', animation: 'pulse-soft 2s infinite' }} />
        )}
      </button>

      {/* Expanded dropdown */}
      {expanded && (
        <div
          style={{
            position: 'absolute',
            top: '100%',
            right: 0,
            marginTop: 4,
            width: 200,
            background: 'var(--surface-1)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-md)',
            boxShadow: 'var(--shadow-lg)',
            padding: 8,
            zIndex: 50,
          }}
        >
          <div
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 9,
              fontWeight: 700,
              letterSpacing: '0.1em',
              textTransform: 'uppercase',
              color: 'var(--text-tertiary)',
              marginBottom: 8,
              paddingBottom: 6,
              borderBottom: '1px solid var(--border)',
            }}
          >
            SERVICE HEALTH
          </div>
          {Object.entries(health).map(([service, state]) => (
            <div
              key={service}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '4px 0',
              }}
            >
              <div
                style={{
                  width: 6,
                  height: 6,
                  borderRadius: '50%',
                  background: STATUS_COLORS[state.status] || 'var(--text-disabled)',
                  flexShrink: 0,
                }}
              />
              <span
                style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 11,
                  color: 'var(--text-primary)',
                  textTransform: 'capitalize',
                  flex: 1,
                }}
              >
                {service}
              </span>
              <span
                style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 9,
                  color: state.status === 'healthy' ? 'var(--accent)' : 'var(--text-disabled)',
                }}
              >
                {state.status === 'healthy' ? 'OK' : state.status === 'loading' ? '...' : 'ERR'}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

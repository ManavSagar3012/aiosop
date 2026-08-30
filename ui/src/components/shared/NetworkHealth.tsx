import React, { useEffect, useRef, useState } from 'react';
import { API_BASE, AUTH_TOKEN } from '../../services/api';
import { NetworkService, ConnectionStatus } from '../../services/network';
import { useIntelligenceStore } from '../../store/useIntelligenceStore';
import { Wifi, WifiOff, RefreshCcw } from 'lucide-react';

export const NetworkHealth: React.FC<{ collapsed?: boolean }> = ({ collapsed = false }) => {
  const [status, setStatus] = useState<ConnectionStatus>('disconnected');
  const [metrics, setMetrics] = useState({ latency: 0, throughput: 0 });
  const sessionId = useIntelligenceStore((s) => s.sessionId);
  const setSessionId = useIntelligenceStore((s) => s.setSessionId);
  const bootstrappedRef = useRef(false);
  const netRef = useRef<NetworkService | null>(null);

  // Derive the initial engagement ONCE using a ref guard
  useEffect(() => {
    if (sessionId || bootstrappedRef.current) return;
    bootstrappedRef.current = true;
    let cancelled = false;
    (async () => {
      try {
        const response = await fetch(`${API_BASE}/engagements`, {
          headers: { "Authorization": `Bearer ${AUTH_TOKEN}` }
        });
        if (!response.ok) { if (!cancelled) setStatus('disconnected'); return; }
        const sessions = await response.json();
        if (!Array.isArray(sessions)) return;
        const realSessions = sessions.filter((s: any) => s.session_id !== 'global');
        if (realSessions.length === 0) { if (!cancelled) setStatus('disconnected'); return; }
        const isLive = (s: any) => {
          const ph = String(s.phase || '').toLowerCase();
          return ph !== 'halted' && ph !== 'completed' && ph !== 'aborted';
        };
        const latestId = (realSessions.find(isLive) || realSessions[0]).session_id;
        if (!cancelled) setSessionId(latestId);
      } catch (e) {
        console.error("Failed to fetch sessions", e);
        if (!cancelled) setStatus('disconnected');
      }
    })();
    return () => {
      cancelled = true;
      // FIX (strictmode-bootstrap-2026-08-30): React 18 StrictMode mounts ->
      // unmounts -> remounts every effect in dev. The first pass started this
      // bootstrap fetch, cleanup cancelled it, and this ref guard then made the
      // remounted effect a no-op — so the sidebar NEVER auto-connected (stuck
      // DISCONNECTED with a healthy stack). Resetting the guard on cleanup lets
      // the remounted effect retry; the fetch is idempotent.
      bootstrappedRef.current = false;
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Socket lifecycle — only reconnects when sessionId actually changes
  useEffect(() => {
    if (!sessionId) return;
    let cancelled = false;
    const net = new NetworkService((newStatus) => { if (!cancelled) setStatus(newStatus); });
    netRef.current = net;
    net.connect(sessionId);
    net.hydrate(sessionId);
    const interval = setInterval(() => { if (!cancelled) setMetrics(net.getMetrics()); }, 1000);
    return () => {
      cancelled = true;
      net.disconnect();
      netRef.current = null;
      clearInterval(interval);
    };
  }, [sessionId]);

  const statusColors: Record<ConnectionStatus, string> = {
    connected: 'var(--accent)',
    reconnecting: 'var(--warning)',
    error: 'var(--danger)',
    disconnected: 'var(--text-disabled)',
  };

  const statusIcons: Record<ConnectionStatus, React.ReactNode> = {
    connected: <Wifi size={collapsed ? 14 : 12} />,
    reconnecting: <RefreshCcw size={collapsed ? 14 : 12} style={{ animation: 'spin 1s linear infinite' }} />,
    error: <WifiOff size={collapsed ? 14 : 12} />,
    disconnected: <WifiOff size={collapsed ? 14 : 12} />,
  };

  if (collapsed) {
    return (
      <div
        className="flex items-center justify-center"
        style={{
          padding: '8px',
          color: statusColors[status],
        }}
        title={`${status.toUpperCase()} — ${metrics.latency}ms latency`}
      >
        {statusIcons[status]}
      </div>
    );
  }

  return (
    <div
      style={{
        background: 'var(--surface-2)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius-md)',
        padding: '10px 12px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}
    >
      <div
        className="flex items-center gap-2"
        style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 10,
          fontWeight: 600,
          letterSpacing: '0.08em',
          textTransform: 'uppercase',
          color: statusColors[status],
        }}
      >
        {statusIcons[status]}
        {status}
      </div>

      <div className="flex items-center gap-4">
        <div className="flex flex-col items-end">
          <span
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 8,
              fontWeight: 700,
              letterSpacing: '0.1em',
              textTransform: 'uppercase',
              color: 'var(--text-disabled)',
            }}
          >
            LATENCY
          </span>
          <span
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 11,
              fontWeight: 500,
              color: 'var(--accent)',
              fontVariantNumeric: 'tabular-nums',
            }}
          >
            {metrics.latency}ms
          </span>
        </div>
        <div className="flex flex-col items-end" style={{ borderLeft: '1px solid var(--border)', paddingLeft: 12 }}>
          <span
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 8,
              fontWeight: 700,
              letterSpacing: '0.1em',
              textTransform: 'uppercase',
              color: 'var(--text-disabled)',
            }}
          >
            THROUGHPUT
          </span>
          <span
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 11,
              fontWeight: 500,
              color: 'var(--interactive)',
              fontVariantNumeric: 'tabular-nums',
            }}
          >
            {metrics.throughput} ev/s
          </span>
        </div>
      </div>
    </div>
  );
};

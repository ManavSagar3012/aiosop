import React, { useEffect, useState } from 'react';
import { API_BASE, AUTH_TOKEN } from '../../services/api';
import { NetworkService, ConnectionStatus } from '../../services/network';
import { useIntelligenceStore } from '../../store/useIntelligenceStore';
import { Activity, Wifi, WifiOff, RefreshCcw } from 'lucide-react';

export const NetworkHealth: React.FC = () => {
  const [status, setStatus] = useState<ConnectionStatus>('disconnected');
  const [metrics, setMetrics] = useState({ latency: 0, throughput: 0 });
  // AIOSOP-UI-ENGAGEMENT-SELECTOR-2026-07-03: the selected engagement now lives in
  // the shared store so the Header dropdown can switch it. NetworkHealth remains the
  // single owner of the socket lifecycle: it derives the initial engagement when none
  // is selected, and reconnects whenever the selection changes.
  const sessionId = useIntelligenceStore((s) => s.sessionId);
  const setSessionId = useIntelligenceStore((s) => s.setSessionId);

  // Derive the initial engagement once, if the operator hasn't picked one yet.
  useEffect(() => {
    if (sessionId) return;
    let cancelled = false;
    (async () => {
      try {
        const response = await fetch(`${API_BASE}/engagements`, {
          headers: { "Authorization": `Bearer ${AUTH_TOKEN}` }
        });
        if (!response.ok) { if (!cancelled) setStatus('disconnected'); return; }
        const sessions = await response.json();
        if (!Array.isArray(sessions)) return;
        // API returns engagements latest-first. Pick the most recent LIVE engagement
        // (not halted/completed/aborted) so the dashboard tracks the run actually in
        // progress; fall back to the latest overall. NOTE: do not exclude ids
        // containing 'test' — that wrongly hid real engagements like
        // 'SYFE-approvaltest'. (AIOSOP-UI-ACTIVE-SESSION-2026-06-30)
        const realSessions = sessions.filter((s: any) => s.session_id !== 'global');
        if (realSessions.length === 0) { if (!cancelled) setStatus('disconnected'); return; }
        const isLive = (s: any) => {
          const ph = String(s.phase || '').toLowerCase();
          return ph !== 'halted' && ph !== 'completed' && ph !== 'aborted';
        };
        const latestId = (realSessions.find(isLive) || realSessions[0]).session_id;
        if (!cancelled) setSessionId(latestId);
      } catch (e) {
        console.error("Failed to fetch sessions for network health", e);
        if (!cancelled) setStatus('disconnected');
      }
    })();
    return () => { cancelled = true; };
  }, [sessionId, setSessionId]);

  // Own the socket lifecycle: (re)connect whenever the selected engagement changes.
  useEffect(() => {
    if (!sessionId) return;
    let cancelled = false;
    const net = new NetworkService((newStatus) => { if (!cancelled) setStatus(newStatus); });
    net.connect(sessionId);
    net.hydrate(sessionId);
    const interval = setInterval(() => { if (!cancelled) setMetrics(net.getMetrics()); }, 1000);
    return () => {
      cancelled = true;
      net.disconnect();
      clearInterval(interval);
    };
  }, [sessionId]);

  const getStatusColor = () => {
    switch (status) {
      case 'connected': return 'text-primary-fixed';
      case 'reconnecting': return 'text-secondary';
      case 'error': return 'text-error';
      default: return 'text-on-surface-variant';
    }
  };

  const getStatusIcon = () => {
    switch (status) {
      case 'connected': return <Wifi size={14} />;
      case 'reconnecting': return <RefreshCcw size={14} className="animate-spin" />;
      case 'error': return <WifiOff size={14} />;
      default: return <WifiOff size={14} />;
    }
  };

  return (
    <div className="bg-surface-container-low border border-outline-variant p-3 flex items-center justify-between gap-6">
      <div className={`flex items-center gap-2 font-label-caps text-[10px] ${getStatusColor()}`}>
        {getStatusIcon()}
        {status?.toUpperCase()}
      </div>
      
      <div className="flex gap-4 items-center">
        <div className="flex flex-col items-end">
          <span className="text-[8px] font-label-caps text-on-surface-variant">LATENCY</span>
          <span className="text-[10px] font-code-sm text-primary">{metrics.latency}MS</span>
        </div>
        <div className="flex flex-col items-end border-l border-outline-variant pl-4">
          <span className="text-[8px] font-label-caps text-on-surface-variant">THROUGHPUT</span>
          <span className="text-[10px] font-code-sm text-primary">{metrics.throughput} EV/S</span>
        </div>
      </div>
    </div>
  );
};

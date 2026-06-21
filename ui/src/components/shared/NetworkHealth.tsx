import React, { useEffect, useState } from 'react';
import { NetworkService, ConnectionStatus } from '../../services/network';
import { Activity, Wifi, WifiOff, RefreshCcw } from 'lucide-react';

export const NetworkHealth: React.FC = () => {
  const [status, setStatus] = useState<ConnectionStatus>('disconnected');
  const [metrics, setMetrics] = useState({ latency: 0, throughput: 0 });

  useEffect(() => {
    const fetchAndConnect = async () => {
      try {
        const response = await fetch('http://127.0.0.1:8200/engagements', {
            headers: { "Authorization": "Bearer dev-token" }
        });
        if (response.ok) {
          const sessions = await response.json();
          if (Array.isArray(sessions)) {
            const activeSessions = sessions.filter((s: any) => s.session_id !== 'global' && !s.session_id.includes('test'));
            const latestId = activeSessions.length > 0 ? activeSessions[0].session_id : "current-session";
            
            const net = new NetworkService((newStatus) => setStatus(newStatus));
            net.connect(latestId);
            net.hydrate(latestId);

            const interval = setInterval(() => {
              setMetrics(net.getMetrics());
            }, 1000);

            return () => {
              net.disconnect();
              clearInterval(interval);
            };
          }
        }
      } catch (e) {
        console.error("Failed to fetch sessions for network health", e);
        // Fallback to manual connect if API is down
        const net = new NetworkService((newStatus) => setStatus(newStatus));
        net.connect("current-session");
      }
    };

    fetchAndConnect();
  }, []);

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

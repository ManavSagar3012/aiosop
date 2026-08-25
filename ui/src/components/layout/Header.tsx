import React, { useState } from 'react';
import { API_BASE, AUTH_TOKEN, authHeaders } from '../../services/api';
import { useSwarmStore } from '../../store/useSwarmStore';
import { useIntelligenceStore } from '../../store/useIntelligenceStore';
import { useTheme } from '../../contexts/ThemeContext';
import { useToast } from '../../contexts/ToastContext';
import { Breadcrumbs } from '../shared/Breadcrumbs';
import {
  Bell, Moon, Sun, Plus, FileText, AlertTriangle,
} from 'lucide-react';
import { NewMissionModal } from '../shared/NewMissionModal';
import { ConnectionManager } from '../shared/ConnectionManager';

export const Header: React.FC = () => {
  const { currentPhase } = useSwarmStore();
  const [isModalOpen, setIsModalOpen] = useState(false);
  const currentSessionId = useIntelligenceStore((s) => s.sessionId);
  const setSessionId = useIntelligenceStore((s) => s.setSessionId);
  const [engagements, setEngagements] = useState<any[]>([]);
  const { theme, toggleTheme } = useTheme();
  const toast = useToast();

  React.useEffect(() => {
    const fetchList = async () => {
      try {
        const response = await fetch(`${API_BASE}/engagements`, {
          headers: authHeaders()
        });
        if (response.ok) {
          const sessions = await response.json();
          if (Array.isArray(sessions)) {
            setEngagements(sessions.filter((s: any) => s.session_id !== 'global'));
          }
        }
      } catch (e) {
        console.error("Failed to fetch engagements", e);
      }
    };
    fetchList();
  }, []);

  const handleLaunchMission = async (domain: string) => {
    try {
      const response = await fetch(`${API_BASE}/engagements`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${AUTH_TOKEN}`
        },
        body: JSON.stringify({
          engagement_id: `eng-${Date.now()}`,
          domains: [domain],
          approval_required_for: ["rce", "sqli", "tenant_escape"],
          roe: {
            max_depth: 5,
            scan_intensity: "thorough",
            allow_automated_exploitation: false
          }
        })
      });

      if (response.ok) {
        toast.success('Mission launched successfully');
        window.location.reload();
      } else {
        toast.error('Failed to launch mission');
      }
    } catch (e) {
      toast.error('Failed to launch mission');
    }
  };

  const handleHalt = async () => {
    if (!currentSessionId) return;
    if (!window.confirm("EMERGENCY: Are you sure you want to HALT all agents?")) return;

    try {
      await fetch(`${API_BASE}/engagements/${currentSessionId}/halt`, {
        method: 'POST',
        headers: authHeaders()
      });
      toast.success("Swarm halted successfully");
      window.location.reload();
    } catch (e) {
      toast.error("Halt failed");
    }
  };

  const handlePrintReport = async () => {
    if (!currentSessionId) return;
    window.open(`${API_BASE}/engagements/${currentSessionId}/report?token=${AUTH_TOKEN}`, '_blank');
  };

  return (
    <header
      className="flex items-center justify-between shrink-0"
      style={{
        height: 'var(--header-height)',
        background: 'var(--surface-0)',
        borderBottom: '1px solid var(--border)',
        padding: '0 20px',
        zIndex: 20,
      }}
    >
      {/* Left: Breadcrumbs + Phase */}
      <div className="flex items-center gap-6">
        <Breadcrumbs />

        {currentSessionId && (
          <div
            className="flex items-center gap-2"
            style={{
              padding: '4px 10px',
              background: 'var(--accent-bg)',
              border: '1px solid var(--accent-border)',
              borderRadius: 'var(--radius-full)',
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 10,
              fontWeight: 600,
              letterSpacing: '0.08em',
              color: 'var(--accent)',
              textTransform: 'uppercase',
            }}
          >
            <span
              style={{
                width: 6,
                height: 6,
                borderRadius: '50%',
                background: 'var(--accent)',
                animation: 'pulse-soft 2s ease-in-out infinite',
              }}
            />
            {currentPhase.replace(/_/g, ' ')}
          </div>
        )}
      </div>

      {/* Center: Engagement Selector */}
      <div className="flex items-center gap-3">
        {currentSessionId && (
          <div className="flex items-center gap-2">
            <select
              aria-label="Active engagement"
              value={currentSessionId ?? ''}
              onChange={(e) => setSessionId(e.target.value)}
              className="select"
              style={{ fontSize: 11, padding: '5px 28px 5px 10px', minWidth: 200 }}
            >
              {currentSessionId && !engagements.some((s) => s.session_id === currentSessionId) && (
                <option value={currentSessionId}>{currentSessionId}</option>
              )}
              {engagements.map((s) => {
                const ph = String(s.phase || '').toLowerCase();
                const live = ph !== 'halted' && ph !== 'completed' && ph !== 'aborted';
                return (
                  <option key={s.session_id} value={s.session_id}>
                    {live ? '● ' : '○ '}{s.session_id} · {String(s.phase || 'unknown').toUpperCase().replace(/_/g, ' ')}
                  </option>
                );
              })}
            </select>
          </div>
        )}
      </div>

      {/* Right: Actions */}
      <div className="flex items-center gap-2">
        <ConnectionManager />

        <div style={{ width: 1, height: 20, background: 'var(--border)', margin: '0 4px' }} />

        {/* Theme Toggle */}
        <button
          onClick={toggleTheme}
          className="btn btn-icon btn-ghost"
          title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
        >
          {theme === 'dark' ? <Moon size={16} /> : <Sun size={16} />}
        </button>

        {/* Notifications */}
        <button
          className="btn btn-icon btn-ghost"
          title="Notifications"
        >
          <Bell size={16} />
        </button>

        <div style={{ width: 1, height: 20, background: 'var(--border)', margin: '0 4px' }} />

        <button
          onClick={() => setIsModalOpen(true)}
          className="btn btn-primary btn-sm"
        >
          <Plus size={14} />
          New Mission
        </button>

        <button
          onClick={handlePrintReport}
          className="btn btn-ghost btn-sm"
        >
          <FileText size={14} />
          Report
        </button>

        <button
          onClick={handleHalt}
          className="btn btn-danger btn-sm"
        >
          <AlertTriangle size={14} />
          HALT
        </button>
      </div>

      <NewMissionModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onLaunch={handleLaunchMission}
      />
    </header>
  );
};

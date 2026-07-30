import React, { useState } from 'react';
import { API_BASE, AUTH_TOKEN, authHeaders } from '../../services/api';
import { useSwarmStore } from '../../store/useSwarmStore';
import { useIntelligenceStore } from '../../store/useIntelligenceStore';
import { Rocket } from 'lucide-react';
import { NewMissionModal } from '../shared/NewMissionModal';
import { useToast } from '../../hooks/useToast';

import { ConnectionManager } from '../shared/ConnectionManager';
export const Header: React.FC = () => {
  const { currentObjective, currentPhase, setObjective, setPhase } = useSwarmStore();
  const { addToast } = useToast();
  const [isModalOpen, setIsModalOpen] = useState(false);
  // AIOSOP-UI-ENGAGEMENT-SELECTOR-2026-07-03: the active engagement is the shared
  // store's sessionId (owned/derived by NetworkHealth). The Header only lists the
  // available engagements and lets the operator switch which one the dashboard
  // tracks — selecting a past engagement re-points the socket + hydration to it.
  const currentSessionId = useIntelligenceStore((s) => s.sessionId);
  const setSessionId = useIntelligenceStore((s) => s.setSessionId);
  const lastEventAt = useIntelligenceStore((s) => s.lastEventAt);
  const [engagements, setEngagements] = useState<any[]>([]);

  // Populate the selector's options (does NOT choose the active one — NetworkHealth
  // derives the initial selection so both components agree on a single source).
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
          engagement_id: `dash-mission-${Date.now()}`,
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
        const engagement = await response.json();
        const sessionId = engagement.session_id || engagement.engagement_id;
        setObjective(domain);
        setPhase(engagement.phase || 'initialized');
        if (sessionId) {
          setSessionId(sessionId);
          setEngagements((current) => [
            engagement,
            ...current.filter((item) => item.session_id !== sessionId),
          ]);
        }
        addToast('Mission launched. Connecting the command core to the new engagement.', 'success');
      } else {
        addToast('Mission launch was rejected by the API.', 'error');
      }
    } catch (e) {
      console.error("Failed to launch mission", e);
      addToast('Mission launch failed. Check API connectivity and try again.', 'error');
    }
  };

  const handleHalt = async () => {
     if (!currentSessionId) return;
     if (!window.confirm("EMERGENCY: Are you sure you want to HALT all agents?")) return;
     
     try {
        const response = await fetch(`${API_BASE}/engagements/${currentSessionId}/halt`, {
           method: 'POST',
           headers: authHeaders()
        });
        if (!response.ok) {
          throw new Error(`Halt request failed with status ${response.status}`);
        }
        setPhase('halted');
        addToast('Swarm halted successfully.', 'success');
     } catch (e) {
        console.error("Halt failed", e);
        addToast('Unable to halt the swarm. Check API connectivity and try again.', 'error');
     }
  };

  const handlePrintReport = async () => {
     if (!currentSessionId) return;
     try {
       // Fetch with the Authorization header (NOT a ?token= query param, which
       // would leak the bearer token into browser history, logs, and Referer).
       const resp = await fetch(`${API_BASE}/engagements/${currentSessionId}/report`, {
         headers: authHeaders()
       });
       if (!resp.ok) throw new Error(`Report fetch failed (${resp.status})`);
       const data = await resp.json();
       const html = data.html || data.body_html;
       const blob = html
         ? new Blob([html], { type: 'text/html' })
         : new Blob([data.markdown || ''], { type: 'text/markdown' });
       const url = URL.createObjectURL(blob);
       const win = window.open(url, '_blank');
       if (!win) addToast('Popup blocked. Allow popups to view the report.', 'warning');
       // Revoke after the new window loads to free the blob.
       setTimeout(() => URL.revokeObjectURL(url), 60_000);
     } catch (e) {
       addToast('Report generation failed. Checking connectivity.', 'error');
     }
  };

  return (
    <header className="h-20 bg-background border-b border-outline-variant flex items-center justify-between px-8 shrink-0 relative z-20">
      <div className="flex items-center gap-8">
        <div className="font-display-lg text-display-lg text-primary-fixed tracking-tighter uppercase whitespace-nowrap">
          AI-OSOP // COMMAND CORE
        </div>
        <div className="flex flex-col min-w-[240px]">
          <div className="flex justify-between items-end mb-1 gap-2">
            <span className="font-label-caps text-label-caps text-on-surface-variant whitespace-nowrap">TARGET: {currentObjective.toUpperCase()}</span>
            <span className="font-label-caps text-label-caps text-primary-container whitespace-nowrap">PHASE: {currentPhase.toUpperCase().replace(/_/g, ' ')}</span>
          </div>
          {lastEventAt && (
            <span className="font-code-sm text-[9px] text-on-surface-variant/60 mb-0.5 whitespace-nowrap">
              DATA AS OF {lastEventAt.toLocaleTimeString('en-GB', { hour12: false })}
            </span>
          )}
          <select
            aria-label="Active engagement"
            value={currentSessionId ?? ''}
            onChange={(e) => setSessionId(e.target.value)}
            className="bg-surface-container-low border border-outline-variant text-primary-container font-code-sm text-[10px] px-2 py-1 focus:outline-none focus:border-primary-container cursor-pointer"
          >
            {currentSessionId === null && <option value="">NO ACTIVE ENGAGEMENT</option>}
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
      </div>
      
      <div className="flex items-center gap-4">
        <ConnectionManager />
        <div className="h-6 w-px bg-outline-variant" />
        <button 
          onClick={() => setIsModalOpen(true)}
          className="bg-primary-container text-on-primary-fixed px-6 py-2 font-label-caps text-label-caps hover:brightness-110 transition-all active:scale-95 flex items-center gap-2"
        >
          <Rocket size={14} />
          NEW MISSION
        </button>
        <button onClick={handlePrintReport} className="border border-outline text-on-surface px-4 py-2 font-label-caps text-label-caps hover:bg-surface-container-high transition-all">
          PRINT REPORT
        </button>
        <button onClick={handleHalt} className="bg-error text-white px-4 py-2 font-label-caps text-label-caps glow-red hover:brightness-125 transition-all">
          EMERGENCY HALT
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

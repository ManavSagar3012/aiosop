import React, { useState } from 'react';
import { useSwarmStore } from '../../store/useSwarmStore';
import { Bell, Activity, PauseCircle, Rocket } from 'lucide-react';
import { NewMissionModal } from '../shared/NewMissionModal';

export const Header: React.FC = () => {
  const { currentObjective, currentPhase, setObjective } = useSwarmStore();
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [currentSessionId, setCurrentSessionId] = useState<string | null>(null);

  // Sync session ID
  React.useEffect(() => {
    const fetchLatest = async () => {
      try {
        const response = await fetch('http://127.0.0.1:8200/engagements', {
          headers: { 'Authorization': 'Bearer dev-token' }
        });
        if (response.ok) {
          const sessions = await response.json();
          if (sessions.length > 0) setCurrentSessionId(sessions[0].session_id);
        }
      } catch (e) {}
    };
    fetchLatest();
  }, []);

  const handleLaunchMission = async (domain: string) => {
    try {
      const response = await fetch('http://127.0.0.1:8200/engagements', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': 'Bearer dev-token'
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
        setObjective(domain);
        // Refresh the whole UI context to connect to new session
        window.location.reload(); 
      }
    } catch (e) {
      console.error("Failed to launch mission", e);
    }
  };

  const handleHalt = async () => {
     if (!currentSessionId) return;
     if (!window.confirm("EMERGENCY: Are you sure you want to HALT all agents?")) return;
     
     try {
        await fetch(`http://127.0.0.1:8200/engagements/${currentSessionId}/halt`, {
           method: 'POST',
           headers: { 'Authorization': 'Bearer dev-token' }
        });
        alert("Swarm halted successfully.");
        window.location.reload();
     } catch (e) {
        console.error("Halt failed", e);
     }
  };

  const handlePrintReport = async () => {
     if (!currentSessionId) return;
     window.open(`http://127.0.0.1:8200/engagements/${currentSessionId}/report?token=dev-token`, '_blank');
  };

  return (
    <header className="h-20 bg-background border-b border-outline-variant flex items-center justify-between px-8 shrink-0 relative z-20">
      <div className="flex items-center gap-8">
        <div className="font-display-lg text-primary-fixed tracking-tighter uppercase whitespace-nowrap">
          AI-OSOP // COMMAND CORE
        </div>
        <div className="flex flex-col min-w-[200px]">
          <div className="flex justify-between items-end mb-1">
            <span className="font-label-caps text-on-surface-variant text-[9px]">TARGET: {currentObjective.toUpperCase()}</span>
            <span className="font-label-caps text-primary-container text-[9px]">ID: {currentSessionId?.split('-').pop()?.toUpperCase()} // PHASE: {currentPhase.toUpperCase().replace(/_/g, ' ')}</span>
          </div>
          <div className="w-full h-1 bg-surface-variant relative overflow-hidden">
            <div className="absolute top-0 left-0 h-full bg-primary-container glow-cyan animate-pulse" style={{ width: '65%' }}></div>
          </div>
        </div>
      </div>
      
      <div className="flex items-center gap-4">
        <button 
          onClick={() => setIsModalOpen(true)}
          className="bg-primary-container text-on-primary-fixed px-6 py-2 font-label-caps hover:brightness-110 transition-all active:scale-95 flex items-center gap-2"
        >
          <Rocket size={14} />
          NEW MISSION
        </button>
        <button onClick={handlePrintReport} className="border border-outline text-on-surface px-4 py-2 font-label-caps hover:bg-surface-container-high transition-all">
          PRINT REPORT
        </button>
        <button onClick={handleHalt} className="bg-error text-white px-4 py-2 font-label-caps glow-red hover:brightness-125 transition-all">
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

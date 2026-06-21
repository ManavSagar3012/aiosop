import React, { useEffect, useState } from 'react';
import { API_BASE } from '../services/api';
import { Card } from '../components/shared/Card';
import { BookOpen, Zap, Target, DollarSign, Layers, Search, BarChart, Activity } from 'lucide-react';

interface SkillStats {
  loaded_skills: number;
  activated_skills: number;
  findings_contributed: number;
  total_revenue: number;
  revenue_roi: number;
  top_skills: Array<{
    id: string;
    name: string;
    usage: number;
    reputation: number;
    revenue_roi: number;
    acceptance_rate: number;
    total_payout: number;
    hypothesis_rate?: number;
    verified_findings?: number;
    roi?: number;
    recall?: number;
  }>;
  recent_executions: Array<{
    timestamp: string;
    skill_id: string;
    agent_id: string;
    reason: string;
    stage: string;
    payout: number;
    accepted: boolean;
    provenance?: string;
  }>;
}

export const SkillIntelligence: React.FC = () => {
  const [stats, setStats] = useState<SkillStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sessionId, setSessionId] = useState<string | null>(null);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const sessionResponse = await fetch(`${API_BASE}/engagements`, {
          headers: { 'Authorization': 'Bearer dev-token' }
        });
        if (sessionResponse.ok) {
          const sessions = await sessionResponse.json();
          if (sessions.length > 0) setSessionId(sessions[0].session_id);
        }

        const response = await fetch(`${API_BASE}/system/skills/stats`, {
          headers: { 'Authorization': 'Bearer dev-token' }
        });
        if (response.ok) {
          const data = await response.json();
          
          // V6.5 Fix: Filter out unrelated historical skills (Disk Imaging, Active Directory, etc)
          const relevantCategories = ["web", "auth", "logic", "graphql", "api", "mobile", "recon", "explo", "bypass", "reset", "oauth", "mfa", "session"];
          const filtered = (data.top_skills || []).filter((s: any) => 
             relevantCategories.some(cat => s.id.toLowerCase().includes(cat))
          );
          
          setStats({...data, top_skills: filtered});
          setError(null);
        } else {
          setError(`API Error: ${response.status}`);
        }
      } catch (e: any) {
        console.error("Failed to fetch skill stats", e);
        setError(e.message || "Network error");
      } finally {
        setLoading(false);
      }
    };
    fetchStats();
    const interval = setInterval(fetchStats, 10000);
    return () => clearInterval(interval);
  }, []);

  if (loading && !stats) {
    return (
      <div className="h-full flex flex-col items-center justify-center gap-4 bg-black/20 animate-pulse">
        <Search className="text-primary-fixed animate-bounce" size={48} />
        <div className="font-code-sm text-primary tracking-widest uppercase">INITIALIZING SKILL INTELLIGENCE CORE...</div>
      </div>
    );
  }

  const safeStats = stats || {
    loaded_skills: 0,
    activated_skills: 0,
    findings_contributed: 0,
    total_revenue: 0,
    revenue_roi: 0,
    top_skills: [],
    recent_executions: []
  };

  return (
    <div className="flex flex-col gap-6 h-full p-2">
      <div className="grid grid-cols-4 gap-6 shrink-0">
        <Card title="Revenue ROI" glow="cyan">
          <div className="flex items-center gap-4">
            <DollarSign className="text-primary-fixed" size={32} />
            <div>
              <div className="font-display-lg text-primary-fixed text-[32px]">
                {(safeStats.revenue_roi || 0).toFixed(1)}x
              </div>
              <div className="font-code-sm text-on-surface-variant text-[10px] uppercase">Payout / LLM Cost</div>
            </div>
          </div>
        </Card>
        <Card title="Total Bounty" glow="cyan">
          <div className="flex items-center gap-4">
            <Target className="text-secondary" size={32} />
            <div>
              <div className="font-display-lg text-secondary text-[32px]">${(safeStats.total_revenue || 0).toLocaleString()}</div>
              <div className="font-code-sm text-on-surface-variant text-[10px] uppercase">Verified → Accepted</div>
            </div>
          </div>
        </Card>
        <Card title="Skill Funnel" glow="red">
          <div className="flex items-center gap-4">
            <Zap className="text-error" size={32} />
            <div>
              <div className="font-display-lg text-error text-[32px]">{safeStats.findings_contributed || 0}</div>
              <div className="font-code-sm text-on-surface-variant text-[10px] uppercase">Verified Findings</div>
            </div>
          </div>
        </Card>
        <Card title="Playbook Engine">
          <div className="flex items-center gap-4">
            <Layers className="text-on-surface-variant" size={32} />
            <div>
              <div className="font-display-lg text-on-surface-variant text-[32px]">ACTIVE</div>
              <div className="font-code-sm text-on-surface-variant text-[10px] uppercase">Chain Reputation Enabled</div>
            </div>
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-2 gap-6 flex-1 min-h-0">
        <Card title="Skill Reputation Leaderboard (Relevant to Target)" className="flex flex-col">
          <div className="flex-1 overflow-y-auto pr-2 custom-scrollbar space-y-6 py-2">
            {(safeStats.top_skills || []).map(skill => (
              <div key={skill.id} className="bg-black/40 border border-outline-variant p-4 relative overflow-hidden group hover:border-primary-fixed/30 transition-all">
                <div className="absolute top-0 right-0 p-2 opacity-10 group-hover:opacity-20 transition-opacity">
                   <Zap size={40} className="text-primary-fixed" />
                </div>

                <div className="flex justify-between items-start mb-2 relative z-10">
                  <div className="font-headline-md text-primary-fixed text-[14px] uppercase tracking-wider">{skill.id.replace(/-/g, ' ')}</div>
                  <div className="font-code-sm text-secondary text-[11px] bg-secondary/10 px-2 py-0.5 border border-secondary/20">
                     REPUTATION: {(skill.reputation || 0).toFixed(1)} / 10
                  </div>
                </div>
                
                <div className="grid grid-cols-3 gap-4 mb-4 relative z-10">
                   <div>
                      <div className="text-[8px] font-label-caps text-on-surface-variant opacity-60 uppercase">ROI</div>
                      <div className="text-[12px] font-code-sm text-on-surface">{(skill.roi || skill.revenue_roi || 1.2).toFixed(1)}x</div>
                   </div>
                   <div>
                      <div className="text-[8px] font-label-caps text-on-surface-variant opacity-60 uppercase">Recall</div>
                      <div className="text-[12px] font-code-sm text-on-surface">{((skill.recall || skill.acceptance_rate || 0.8) * 100).toFixed(0)}%</div>
                   </div>
                   <div>
                      <div className="text-[8px] font-label-caps text-on-surface-variant opacity-60 uppercase">Findings</div>
                      <div className="text-[12px] font-code-sm text-primary-fixed">{skill.verified_findings || 0} VERIFIED</div>
                   </div>
                </div>

                <div className="text-right mt-2">
                   <div className="px-2 py-0.5 bg-primary-fixed text-black font-label-caps text-[8px] font-bold inline-block">
                      {(skill.verified_findings || 0) > 0 ? 'LIVE IN MISSION' : 'AVAILABLE'}
                   </div>
                </div>
              </div>
            ))}
          </div>
        </Card>

        <Card title="Outcome Intelligence Log" className="flex flex-col">
          <div className="flex-1 overflow-y-auto pr-2 custom-scrollbar space-y-3 py-2">
            {(safeStats.recent_executions || []).map((log, i) => (
              <div key={i} className={`flex items-start gap-4 p-3 border-l-2 ${log.accepted ? 'border-primary-fixed bg-primary-fixed/5' : 'border-outline-variant bg-surface-container-high/50'} transition-all`}>
                <div className="font-code-sm text-[10px] text-on-surface-variant w-16 shrink-0 mt-0.5 opacity-60">
                  {new Date(log.timestamp).toLocaleTimeString([], { hour12: false })}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex justify-between items-center mb-1">
                    <span className="font-label-caps text-[10px] text-primary truncate pr-2">{log.skill_id}</span>
                    <div className="flex items-center gap-2 shrink-0">
                       <span className={`px-1.5 py-0.5 rounded-sm font-label-caps text-[7px] border ${
                          log.provenance === 'live' ? 'border-primary-fixed/30 text-primary-fixed' : 'border-error/30 text-error'
                       }`}>
                          {log.provenance?.toUpperCase() || 'LIVE'}
                       </span>
                       <span className={`font-label-caps text-[9px] ${log.accepted ? 'text-primary-fixed' : 'text-on-surface-variant opacity-50'}`}>
                         {log.accepted ? 'ACCEPTED' : String(log.stage || 'EXECUTION').toUpperCase()}
                       </span>
                    </div>
                  </div>

                  <div className="font-code-sm text-[10px] text-on-surface-variant">
                    <span className="text-secondary">{log.agent_id}</span> // {log.reason}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
};

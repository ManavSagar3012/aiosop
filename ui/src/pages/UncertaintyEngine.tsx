import React, { useState } from 'react';
import { API_BASE, authHeaders } from '../services/api';
import { Card } from '../components/shared/Card';
import { StatTile } from '../components/shared/StatTile';
import { EmptyState } from '../components/shared/EmptyState';
import { ErrorState } from '../components/shared/ErrorState';
import { useIntelligenceStore } from '../store/useIntelligenceStore';
import { AlertOctagon, Lightbulb, Search, ArrowRight } from 'lucide-react';

export const UncertaintyEngine: React.FC = () => {
  const { uncertainties, sessionId } = useIntelligenceStore();
  const [launchError, setLaunchError] = useState<string | null>(null);

  const handleLaunchSwarm = async () => {
     if (!sessionId) return;
     setLaunchError(null);
     try {
        await fetch(`${API_BASE}/engagements/${sessionId}/discovery/trigger`, {
           method: 'POST',
           headers: authHeaders()
        });
        alert("Discovery swarm successfully deployed to target asset.");
     } catch (e) {
        console.error("Discovery trigger failed", e);
        setLaunchError("Failed to deploy discovery swarm. Check target connectivity and retry.");
     }
  };

  const blockedPathsCount = uncertainties.reduce((acc, curr) => acc + (curr.blockedPaths?.length || 0), 0);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex justify-between items-center bg-surface-container p-4 border border-outline-variant">
         <div className="flex flex-col">
            <span className="font-label-caps text-label-xs text-on-surface-variant mb-1 uppercase">Reasoning Mode</span>
            <span className="font-code-sm text-primary text-[14px]">SKEPTICAL_OPTIMISM (FORMAL TRACKING OF UNKNOWNS)</span>
         </div>
         <div className="flex gap-4">
            <StatTile label="TOTAL UNKNOWNS" value={uncertainties?.length || 0} accent="secondary" />
            <StatTile label="BLOCKED PATHS" value={blockedPathsCount} accent="error" />
         </div>
      </div>

      <div className="grid grid-cols-2 gap-6 flex-1 min-h-0">
        <Card title="Knowledge Boundaries (What the AI is Missing)" className="overflow-y-auto">
           <div className="space-y-6 h-[600px] custom-scrollbar pr-2">
              {launchError && (
                <ErrorState message={launchError} onRetry={handleLaunchSwarm} />
              )}
              {uncertainties.length > 0 ? uncertainties.map(unc => (
                <div key={unc.id} className="bg-surface-container-high border border-outline-variant p-5">
                   <div className="flex items-center gap-3 mb-4">
                      <AlertOctagon className="text-secondary" size={20} />
                      <div className="font-headline-md text-headline-md text-primary">{unc.target}</div>
                   </div>

                   <div className="grid grid-cols-2 gap-8">
                      <div>
                         <div className="font-label-caps text-label-xs text-on-surface-variant mb-3 uppercase tracking-widest">Formal Unknowns</div>
                         <div className="space-y-2">
                            {(unc.unknowns || []).map(u => (
                              <div key={u} className="flex items-center gap-2 text-[11px] font-code-sm text-on-surface">
                                 <div className="w-1.5 h-1.5 rounded-full bg-secondary"></div> {u}
                              </div>
                            ))}
                         </div>
                      </div>
                      <div>
                         <div className="font-label-caps text-label-xs text-on-surface-variant mb-3 uppercase tracking-widest">Blocked Discovery Paths</div>
                         <div className="space-y-2">
                            {(unc.blockedPaths || []).map(p => (
                              <div key={p} className="flex items-center gap-2 text-[11px] font-code-sm text-error">
                                 <div className="w-1.5 h-1.5 bg-error"></div> {p}
                              </div>
                            ))}
                         </div>
                      </div>
                   </div>

                   <div className="mt-8 pt-4 border-t border-outline-variant/30 flex justify-between items-center">
                      <div className="flex items-center gap-2 text-[10px] font-code-sm text-on-surface-variant italic">
                         <Lightbulb size={14} className="text-primary-fixed" /> Recommended Action: Manual session injection or high-depth crawling.
                      </div>
                      <button onClick={handleLaunchSwarm} className="flex items-center gap-2 px-4 py-1.5 bg-secondary-container text-on-secondary-container font-label-caps text-[10px] hover:brightness-110 active:scale-95 transition-all">
                         LAUNCH DISCOVERY SWARM <ArrowRight size={12} />
                      </button>
                   </div>
                </div>
              )) : (
                  <EmptyState message="No knowledge boundaries identified yet." icon={<Search size={48} />} />
              )}
           </div>
        </Card>

        <Card title="Reasoning Transparency (Brain Dump)">
           <div className="h-full font-code-sm text-[11px] text-on-surface-variant leading-relaxed space-y-4">
              <div className="bg-black/60 p-4 border border-outline-variant rounded">
                 <p className="text-primary font-bold mb-2 uppercase tracking-tighter text-[10px]">SWARM_GOVERNOR // RATIONALE:</p>
                 <p>
                    {uncertainties.length > 0 ? (
                        <>"The current uncertainty regarding <span className="text-secondary underline italic">{uncertainties[0].unknowns?.[0] || 'Target Context'}</span> has halted exploitation attempts.
                        We lack confirmation of the state transition for <span className="text-on-surface italic">{uncertainties[0].target}</span>.
                        Escalating to <span className="text-primary-fixed italic font-bold text-[13px]">VisualContextAgent</span> to identify hidden iframe triggers."</>
                    ) : (
                        <>"Swarm reasoning is currently deterministic. No high-uncertainty state transitions detected in the last cycle.
                        Continuing <span className="text-secondary">Mission Discovery</span> phase."</>
                    )}
                 </p>
              </div>

              <div className="grid grid-cols-2 gap-4 mt-6">
                 <div className="border border-outline-variant p-3">
                    <div className="font-label-caps text-label-xs text-primary-fixed mb-2">MOST UNCERTAIN STACK</div>
                    <div className="text-on-surface">Cloudflare Turnstile + Custom WebGL</div>
                 </div>
                 <div className="border border-outline-variant p-3">
                    <div className="font-label-caps text-label-xs text-primary-fixed mb-2">HIGHEST DATA GAP</div>
                    <div className="text-on-surface">Organization Admin Credentials</div>
                 </div>
              </div>

              <div className="mt-auto pt-6 text-center opacity-30">
                 <Search className="mx-auto mb-2" size={40} />
                 <p className="italic">Scanning for latent knowledge boundaries...</p>
              </div>
           </div>
        </Card>
      </div>
    </div>
  );
};

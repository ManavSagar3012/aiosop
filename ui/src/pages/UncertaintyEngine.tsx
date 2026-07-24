import React, { useState } from 'react';
import { API_BASE, authHeaders } from '../services/api';
import { Card } from '../components/shared/Card';
import { EmptyState } from '../components/shared/EmptyState';
import { ErrorState } from '../components/shared/ErrorState';
import { useIntelligenceStore } from '../store/useIntelligenceStore';
import { useToast } from '../hooks/useToast';
import { AlertOctagon, Lightbulb, Search, ArrowRight } from 'lucide-react';

export const UncertaintyEngine: React.FC = () => {
  const { addToast } = useToast();
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
        addToast("Discovery swarm successfully deployed to target asset.", "success");
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
            <div className="bg-black/40 px-4 py-2 border border-outline-variant text-center">
               <div className="font-code-sm text-secondary text-[14px] font-bold">{uncertainties?.length || 0}</div>
               <div className="font-label-caps text-on-surface-variant text-label-xs">TOTAL UNKNOWNS</div>
            </div>
            <div className="bg-black/40 px-4 py-2 border border-outline-variant text-center">
               <div className="font-code-sm text-error text-[14px] font-bold">{blockedPathsCount}</div>
               <div className="font-label-caps text-on-surface-variant text-label-xs">BLOCKED PATHS</div>
            </div>
         </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 flex-1 min-h-0">
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

        <Card title="Reasoning Transparency">
           <div className="h-full font-code-sm text-[11px] text-on-surface-variant leading-relaxed space-y-4">
              <div className="bg-black/60 p-4 border border-outline-variant rounded">
                 <p className="text-primary font-bold mb-2 uppercase tracking-tighter text-[10px]">REASONING LOOP // STATUS:</p>
                 <p>
                    {uncertainties.length > 0 ? (
                        <>The current uncertainty regarding <span className="text-secondary underline italic">{uncertainties[0].unknowns?.[0] || 'Target Context'}</span> has halted exploitation attempts.
                        We lack confirmation of the state transition for <span className="text-on-surface italic">{uncertainties[0].target}</span>.
                        The reasoning loop will generate an info-seeking hypothesis to resolve this.</>
                    ) : (
                        <>No open uncertainties detected. The reasoning loop is in steady state — all detected unknowns have been resolved or are being actively investigated.</>
                    )}
                 </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-6">
                 <div className="border border-outline-variant p-3">
                    <div className="font-label-caps text-label-xs text-primary-fixed mb-2">OPEN UNCERTAINTIES</div>
                    <div className="text-on-surface">{uncertainties.length}</div>
                 </div>
                 <div className="border border-outline-variant p-3">
                    <div className="font-label-caps text-label-xs text-primary-fixed mb-2">BLOCKED PATHS</div>
                    <div className="text-on-surface">{uncertainties.reduce((acc: number, u: any) => acc + (u.blockedPaths?.length || 0), 0)}</div>
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

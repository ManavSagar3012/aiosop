import React, { useState } from 'react';
import { API_BASE, authHeaders } from '../services/api';
import { Card } from '../components/shared/Card';
import { EmptyState } from '../components/shared/EmptyState';
import { ErrorState } from '../components/shared/ErrorState';
import { Shield, Lock, Eye } from 'lucide-react';
import { useIntelligenceStore } from '../store/useIntelligenceStore';
import { useToast } from '../hooks/useToast';

export const DifferentialAuth: React.FC = () => {
  const { diffAuthFindings, sessionId } = useIntelligenceStore();
  const [activeFindingIdx, setActiveFindingIdx] = useState(0);
  const [activeIdentity, setActiveIdentity] = useState<'user_a' | 'user_b' | 'admin'>('user_b');
  const { addToast } = useToast();
  const [validateError, setValidateError] = useState<string | null>(null);

  const currentFinding = diffAuthFindings[activeFindingIdx];

  const handleValidate = async () => {
      if (!currentFinding || !sessionId) return;
      setValidateError(null);
      try {
          await fetch(`${API_BASE}/engagements/${sessionId}/findings/${currentFinding.id}/replay`, {
              method: 'POST',
              headers: authHeaders()
          });
          addToast("Exploit validation task queued.", "success");
      } catch (e) {
          setValidateError('Failed to queue exploit validation task.');
      }
  };

  return (
    <div className="flex flex-col h-full gap-6">
      <div className="flex justify-between items-center bg-surface-container p-4 border border-outline-variant">
         <div className="flex flex-col">
            <span className="font-label-caps text-label-xs text-on-surface-variant mb-1 uppercase">Target Resource</span>
            <span className="font-code-sm text-[14px] text-primary">
                {currentFinding?.resource_id || "AWAITING ANOMALY..."} // {currentFinding?.category?.toUpperCase()}
            </span>
         </div>
         <div className="flex gap-2">
            {diffAuthFindings.length > 1 && (
                <div className="flex gap-1 mr-4">
                    {diffAuthFindings.map((_, i) => (
                        <button key={i} onClick={() => setActiveFindingIdx(i)} aria-label={`Show finding ${i + 1}`} className={`w-2 h-2 ${activeFindingIdx === i ? 'bg-primary-fixed' : 'bg-surface-variant'}`}></button>
                    ))}
                </div>
            )}
            {['user_a', 'user_b', 'admin'].map(id => (
              <button
                key={id}
                onClick={() => setActiveIdentity(id as any)}
                className={`px-4 py-1.5 font-label-caps text-[10px] border transition-all ${
                  activeIdentity === id
                    ? 'bg-primary-container/10 border-primary-fixed text-primary-fixed glow-cyan'
                    : 'bg-surface-container-high border-outline-variant text-on-surface-variant hover:bg-surface-variant'
                }`}
              >
                {id.replace('_', ' ')?.toUpperCase()}
              </button>
            ))}
         </div>
      </div>

      {diffAuthFindings.length === 0 ? (
        <div className="flex-1 min-h-0">
          <EmptyState
            message="No differential authorization findings recorded yet."
            icon={<Shield size={32} />}
            hint="Awaiting anomaly detection from the active engagement."
          />
        </div>
      ) : (
      <div className="flex-1 grid grid-cols-1 lg:grid-cols-2 gap-6 min-h-0">
        {/* Baseline (User A) */}
        <Card title="Baseline Observation (Expected Identity)" className="flex flex-col overflow-hidden">
           <div className="flex-1 overflow-y-auto space-y-4 font-code-sm text-[11px]">
              <div className="bg-black/40 p-3 border border-outline-variant">
                 <div className="text-primary-fixed mb-2 font-bold uppercase tracking-widest text-label-xs">HTTP Response</div>
                 <div className="text-on-surface">HTTP/1.1 200 OK</div>
                 <div className="text-on-surface-variant opacity-60">Content-Type: application/json</div>
                 <div className="mt-2 text-on-surface">{`{ "id": "${currentFinding?.resource_id || 'res-123'}", "status": "active" }`}</div>
              </div>

              <div className="bg-black/40 p-3 border border-outline-variant">
                 <div className="text-primary-fixed mb-2 font-bold uppercase tracking-widest text-label-xs">DOM Semantics</div>
                 <div className="flex flex-wrap gap-2">
                    <span className="px-2 py-0.5 border border-primary-fixed/30 text-primary-fixed bg-primary-fixed/5">BUTTON: DELETE</span>
                    <span className="px-2 py-0.5 border border-primary-fixed/30 text-primary-fixed bg-primary-fixed/5">BUTTON: EDIT</span>
                 </div>
              </div>

              <div className="aspect-video bg-black flex items-center justify-center border border-outline-variant group cursor-zoom-in">
                 <Eye className="text-on-surface-variant opacity-20 group-hover:opacity-100 transition-opacity" size={48} />
                 <span className="absolute bottom-2 right-2 font-label-caps text-label-xs text-on-surface-variant">SCREENSHOT: BASELINE_VIEW.PNG</span>
              </div>
           </div>
        </Card>

        {/* Comparison (Active Identity) */}
        <Card title={`Test Observation (${activeIdentity?.toUpperCase()})`} glow={activeIdentity === 'user_b' ? 'red' : 'none'} className="flex flex-col overflow-hidden">
           <div className="flex-1 overflow-y-auto space-y-4 font-code-sm text-[11px]">
              <div className={`p-3 border ${activeIdentity === 'user_b' && currentFinding ? 'bg-error-container/10 border-error animate-pulse' : 'bg-black/40 border-outline-variant'}`}>
                 <div className={`${activeIdentity === 'user_b' && currentFinding ? 'text-error' : 'text-primary-fixed'} mb-2 font-bold uppercase tracking-widest text-label-xs`}>HTTP Response</div>
                 <div className="text-on-surface">
                    {activeIdentity === 'user_b' && currentFinding ? `HTTP/1.1 ${currentFinding.observed_result}` : 'HTTP/1.1 200 OK'}
                 </div>
                 <div className="text-on-surface-variant opacity-60 italic">
                    Expected: {currentFinding?.expected_result || '200 OK'}
                 </div>
                 <div className="mt-2 text-on-surface">{`{ "id": "${currentFinding?.resource_id || 'res-123'}", "data": "..." }`}</div>
              </div>

              <div className="bg-black/40 p-3 border border-outline-variant">
                 <div className="text-primary-fixed mb-2 font-bold uppercase tracking-widest text-label-xs">DOM Semantics (Diff Detected)</div>
                 <div className="flex flex-wrap gap-2">
                    {currentFinding ? (
                        <span className="px-2 py-0.5 border border-error text-error bg-error-container/5">UNAUTHORIZED VISIBILITY DETECTED</span>
                    ) : (
                        <span className="px-2 py-0.5 border border-outline-variant text-on-surface-variant opacity-30">NO DIFF RECORDED</span>
                    )}
                 </div>
              </div>

              <div className="aspect-video bg-black flex items-center justify-center border border-outline-variant">
                 <div className="text-center">
                    {currentFinding ? (
                        <>
                            <Shield className="text-error mx-auto mb-2" size={48} />
                            <span className="text-[10px] font-label-caps text-error">{currentFinding.category.toUpperCase()}</span>
                        </>
                    ) : (
                        <div className="opacity-20 italic">Awaiting findings...</div>
                    )}
                 </div>
              </div>
           </div>
        </Card>
      </div>
      )}

      {validateError && (
        <div className="bg-surface-container border border-outline-variant">
          <ErrorState message={validateError} onRetry={handleValidate} />
        </div>
      )}

      <div className="h-24 bg-surface-container border border-outline-variant p-4 flex items-center justify-between">
         <div className="flex items-center gap-4">
            <div className={`w-12 h-12 ${currentFinding ? 'bg-error-container/20 text-error' : 'bg-surface-variant text-on-surface-variant'} border border-current/40 flex items-center justify-center`}>
               <Lock size={24} />
            </div>
            <div>
               <div className={`font-headline-md text-headline-md ${currentFinding ? 'text-error' : 'text-on-surface-variant'}`}>
                   Differential Verdict: {currentFinding ? 'Anomaly Detected' : 'No Anomalies'}
               </div>
               <div className="font-code-sm text-on-surface-variant text-[11px]">
                   {currentFinding ? `Confidence: ${(currentFinding.confidence * 100).toFixed(1)}% // ${currentFinding.test_identity_id} accessed restricted resource.` : 'All observed identities respect baseline authorization boundaries.'}
                   {currentFinding && <span onClick={handleValidate} className="text-primary underline cursor-pointer ml-2">PROVE EXPLOITABILITY</span>}
               </div>
            </div>
         </div>
         <div className="flex gap-3">
            <button disabled={!currentFinding} onClick={handleValidate} className="px-6 py-2 bg-error text-on-primary font-label-caps text-[11px] glow-red hover:brightness-110 active:scale-95 transition-all disabled:opacity-30">
               VALIDATE HYPOTHESIS
            </button>
            <button disabled={!currentFinding} className="px-6 py-2 border border-outline text-on-surface font-label-caps text-[11px] hover:bg-surface-variant transition-all disabled:opacity-30">
               SAVE EVIDENCE
            </button>
         </div>
      </div>
    </div>
  );
};

import React, { useState } from 'react';
import { Card } from '../components/shared/Card';
import { StatTile } from '../components/shared/StatTile';
import { ErrorState } from '../components/shared/ErrorState';
import { Settings, Shield, Cpu } from 'lucide-react';
import { API_BASE, authHeaders } from '../services/api';

export const Administration: React.FC = () => {
  const [actionError, setActionError] = useState<{ message: string; retry: () => void } | null>(null);

  const haltEngagement = () => {
    const id = (document.getElementById('eng-id-input') as HTMLInputElement).value;
    fetch(`${API_BASE}/engagements/${id}/halt`, { method: 'POST', headers: authHeaders() })
      .then(() => setActionError(null))
      .catch(() => setActionError({ message: `Failed to halt engagement "${id}".`, retry: haltEngagement }));
  };

  const transitionPhase = () => {
    const id = (document.getElementById('eng-id-input') as HTMLInputElement).value;
    const phase = (document.getElementById('phase-input') as HTMLInputElement).value;
    fetch(`${API_BASE}/engagements/${id}/transition`, {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({ phase }),
    })
      .then(() => setActionError(null))
      .catch(() => setActionError({
        message: `Failed to transition engagement "${id}" to phase "${phase}".`,
        retry: transitionPhase,
      }));
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-3 gap-6">
        <Card title="Swarm Configuration">
           <div className="space-y-4">
              <div className="flex items-center justify-between">
                 <div className="flex items-center gap-2 text-on-surface font-code-sm text-[12px]">
                    <Cpu size={16} className="text-primary-fixed" /> Max Parallel Agents
                 </div>
                 <input type="number" defaultValue={5} className="w-16 bg-black border border-outline-variant text-primary-fixed p-1 text-center font-code-sm text-[12px]" />
              </div>
              <div className="flex items-center justify-between">
                 <div className="flex items-center gap-2 text-on-surface font-code-sm text-[12px]">
                    <Settings size={16} className="text-error" /> Evidence Integrity Mode
                 </div>
                 <select className="bg-black border border-outline-variant text-error p-1 font-code-sm text-[11px]">
                    <option selected>STRICT (100% LIVE)</option>
                    <option>BALANCED (ALLOW DERIVED)</option>
                    <option className="text-on-surface-variant opacity-50">DEV (ALLOW MOCKS)</option>
                 </select>
              </div>
              <div className="flex items-center justify-between">
                 <div className="flex items-center gap-2 text-on-surface font-code-sm text-[12px]">
                    <Shield size={16} className="text-primary-fixed" /> Verification Strictness
                 </div>
                 <select className="bg-black border border-outline-variant text-primary-fixed p-1 font-code-sm text-[11px]">
                    <option>Loose (1 Source)</option>
                    <option selected>Balanced (2 Sources)</option>
                    <option>Strict (3+ Sources)</option>
                 </select>
              </div>
           </div>
        </Card>

        <Card title="Budget & Limits">
           <div className="space-y-4">
              <div className="flex flex-col gap-1">
                 <span className="text-label-xs font-label-caps text-on-surface-variant">MAX ENGAGEMENT BUDGET (USD)</span>
                 <input type="text" defaultValue="500.00" className="bg-black border border-outline-variant text-secondary p-2 font-code-sm text-[14px]" />
              </div>
              <div className="flex flex-col gap-1">
                 <span className="text-label-xs font-label-caps text-on-surface-variant">S2 ESCALATION THRESHOLD (EV)</span>
                 <input type="text" defaultValue="7.5" className="bg-black border border-outline-variant text-secondary p-2 font-code-sm text-[14px]" />
              </div>
              <button className="w-full py-2 bg-primary-container text-on-primary-fixed font-label-caps text-[11px] hover:brightness-110 active:scale-95 transition-all">
                 SAVE GLOBAL POLICIES
              </button>
           </div>
        </Card>

        <Card title="Provider API Keys">
           <div className="space-y-3">
              <div className="flex items-center justify-between border-b border-outline-variant/30 pb-2">
                 <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-primary-fixed"></div>
                    <span className="font-code-sm text-[12px] text-on-surface">OPENAI_GPT4O</span>
                 </div>
                 <span className="text-[10px] text-on-surface-variant">••••••••sk-4a</span>
              </div>
              <div className="flex items-center justify-between border-b border-outline-variant/30 pb-2">
                 <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-primary-fixed"></div>
                    <span className="font-code-sm text-[12px] text-on-surface">ANTHROPIC_CLAUDE3</span>
                 </div>
                 <span className="text-[10px] text-on-surface-variant">••••••••key-f2</span>
              </div>
              <div className="flex items-center justify-between opacity-40">
                 <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-on-surface-variant"></div>
                    <span className="font-code-sm text-[12px] text-on-surface">SHODAN_API_KEY</span>
                 </div>
                 <span className="text-[10px] text-error">NOT CONFIGURED</span>
              </div>
              <button className="w-full py-2 border border-outline text-on-surface font-label-caps text-[10px] hover:bg-surface-variant transition-all mt-2">
                 CONFIGURE VAULT
              </button>
           </div>
        </Card>
      </div>

      <div className="grid grid-cols-2 gap-6">
        <Card title="Operational Stress Testing">
            <div className="flex items-center justify-between p-4 bg-black/40 border border-outline-variant">
               <div>
                  <div className="font-code-sm text-primary text-[14px]">Simulation: High-Velocity Swarm</div>
                  <div className="text-[10px] text-on-surface-variant italic uppercase mt-1">Target: 1,000 Events / Second</div>
               </div>
               <div className="flex gap-4">
                  <button
                    onClick={() => {
                        import('../services/load_test').then(m => m.loadTester.start(1000));
                    }}
                    className="px-6 py-2 bg-error text-on-primary font-label-caps text-[11px] glow-red hover:brightness-110"
                  >
                    START STRESS TEST
                  </button>
                  <button
                    onClick={() => {
                        import('../services/load_test').then(m => m.loadTester.stop());
                    }}
                    className="px-6 py-2 border border-outline text-on-surface font-label-caps text-[11px] hover:bg-surface-variant"
                  >
                    HALT
                  </button>
               </div>
            </div>
        </Card>

        <Card title="Historical Learning Policy">
         <div className="grid grid-cols-2 gap-8">
            <div>
               <div className="text-on-surface-variant font-code-sm text-[11px] leading-relaxed">
                  The Swarm is currently configured to share <span className="text-primary-fixed font-bold underline cursor-help">SEMANTIC MEMORY</span> across all engagements. This means patterns learned in Target A will inform prioritization in Target B.
               </div>
               <div className="mt-4 flex items-center gap-2">
                  <input type="checkbox" defaultChecked className="w-4 h-4 bg-black border border-outline-variant rounded-none accent-primary-fixed" />
                  <span className="text-[11px] font-label-caps text-on-surface">Enable Cross-Engagement Pattern Learning</span>
               </div>
            </div>
            <div className="bg-black/40 p-4 border border-outline-variant border-dashed">
               <div className="text-on-surface-variant font-code-sm text-[10px] uppercase mb-2 tracking-widest">Active Knowledge Base Statistics</div>
               <div className="grid grid-cols-2 gap-4">
                  <StatTile label="VALIDATED OUTCOMES" value="1,245" accent="primary" />
                  <StatTile label="FAILURE PATTERNS" value="842" accent="primary" />
                  <StatTile label="FINGERPRINTED STACKS" value="52" accent="primary" />
               </div>
            </div>
         </div>
        </Card>
        <Card title="Dead Letter Queue">
           <div className="flex flex-col gap-3">
               <button className="w-full py-2 border border-outline text-on-surface hover:bg-surface-container-high transition-all">VIEW DLQ ENTRIES</button>
               <button className="w-full py-2 border border-outline text-on-surface hover:bg-surface-container-high transition-all">REQUEUE ALL PENDING</button>
           </div>
        </Card>
        <Card title="Engagement Control Panel">
           <div className="flex flex-col gap-3">
               {actionError && (
                 <ErrorState message={actionError.message} onRetry={actionError.retry} />
               )}
               <input type="text" placeholder="Engagement ID" className="w-full p-2 bg-black/40 border border-outline" id="eng-id-input" />
               <button className="w-full py-2 border border-red-500 text-red-500 hover:bg-red-500/10 transition-all" onClick={haltEngagement}>HALT ENGAGEMENT</button>
               <input type="text" placeholder="Phase (e.g., exploitation)" className="w-full p-2 bg-black/40 border border-outline" id="phase-input" />
               <button className="w-full py-2 border border-outline text-on-surface hover:bg-surface-container-high transition-all" onClick={transitionPhase}>TRANSITION PHASE</button>
           </div>
        </Card>
      </div>
    </div>
  );
};

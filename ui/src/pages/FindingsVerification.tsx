import React from 'react';
import { API_BASE } from '../services/api';
import { Card } from '../components/shared/Card';
import { useIntelligenceStore } from '../store/useIntelligenceStore';
import { ShieldCheck, UserCheck, Microscope, FileText, Package, Rocket, TrendingUp, Link as LinkIcon, Zap } from 'lucide-react';
import { useParams, Link } from 'react-router-dom';
import { EvidenceVaultModal } from '../components/shared/EvidenceVaultModal';

const VALIDATION_STAGES = [
  "Reproduction", 
  "Exploitation", 
  "Confidentiality", 
  "Integrity", 
  "Authorization"
];

export const FindingsVerification: React.FC = () => {
  const { findings, verifications, sessionId } = useIntelligenceStore();
  const [vaultOpen, setVaultOpen] = React.useState(false);
  const [selectedFinding, setSelectedFinding] = React.useState<any>(null);
  const [vaultData, setVaultData] = React.useState<any>(null);

  const openVault = async (finding: any) => {
     if (!sessionId) return;
     setSelectedFinding(finding);
     try {
        const res = await fetch(`${API_BASE}/engagements/${sessionId}/findings/${finding.id}/vault`, {
           headers: { 'Authorization': 'Bearer dev-token' }
        });
        if (res.ok) {
           setVaultData(await res.json());
           setVaultOpen(true);
        }
     } catch (e) {
        console.error("Failed to fetch vault data", e);
     }
  };

  const handleVerify = async (fid: string) => {
     if (!sessionId) return;
     try {
        await fetch(`${API_BASE}/engagements/${sessionId}/findings/${fid}/verify`, {
           method: 'POST',
           headers: { 'Authorization': 'Bearer dev-token' }
        });
        alert("Finding manually verified in graph ledger.");
        window.location.reload();
     } catch (e) {
        console.error("Verification failed", e);
     }
  };

  const handleReplay = async (fid: string) => {
     if (!sessionId) return;
     try {
        await fetch(`${API_BASE}/engagements/${sessionId}/findings/${fid}/replay`, {
           method: 'POST',
           headers: { 'Authorization': 'Bearer dev-token' }
        });
        alert("Replay task queued in execution sandbox.");
     } catch (e) {
        console.error("Replay failed", e);
     }
  };

  return (
    <div className="flex flex-col gap-gutter">
      {/* Session Action Header */}
      {sessionId && (
        <div className="flex justify-between items-center bg-primary-fixed/5 border border-primary-fixed/20 p-4 mb-2">
           <div className="flex items-center gap-4">
              <div className="p-2 bg-primary-fixed/10 border border-primary-fixed/20 text-primary-fixed">
                 <ShieldCheck size={18} />
              </div>
              <div>
                 <div className="font-label-caps text-[10px] text-on-surface-variant uppercase tracking-widest">Active Verification Mission</div>
                 <div className="font-code-sm text-[14px] text-primary-fixed uppercase">{sessionId}</div>
              </div>
           </div>
           <div className="flex gap-2">
              <Link 
                  to={`/report/${sessionId}`}
                  className="flex items-center gap-2 px-4 py-2 bg-surface-container border border-outline-variant text-[11px] font-label-caps hover:bg-surface-variant transition-all"
              >
                  <FileText size={14} /> VIEW MISSION REPORT
              </Link>
              <button className="flex items-center gap-2 px-4 py-2 bg-primary-fixed text-black font-label-caps text-[11px] font-bold hover:brightness-110 transition-all shadow-lg glow-cyan">
                  <Zap size={14} /> TRIGGER VALIDATION SWARM
              </button>
           </div>
        </div>
      )}

      {/* Evidence Integrity Stats */}
      <div className="grid grid-cols-4 gap-gutter mb-2">
         <div className="bg-surface-container p-4 border-l-4 border-primary-fixed">
            <div className="flex items-center gap-2 mb-1">
               <TrendingUp size={14} className="text-primary-fixed" />
               <span className="font-label-caps text-[10px] text-on-surface-variant uppercase">Avg Acceptance Prob</span>
            </div>
            <div className="font-display-lg text-primary-fixed text-[24px]">92.4%</div>
         </div>
         <div className="bg-surface-container p-4 border-l-4 border-secondary">
            <div className="flex items-center gap-2 mb-1">
               <Link size={14} className="text-secondary" />
               <span className="font-label-caps text-[10px] text-on-surface-variant uppercase">Evidence Chain Score</span>
            </div>
            <div className="font-display-lg text-secondary text-[24px]">88/100</div>
         </div>
         <div className="bg-surface-container p-4 border-l-4 border-primary-fixed/50">
            <div className="flex items-center gap-2 mb-1">
               <ShieldCheck size={14} className="text-primary-fixed" />
               <span className="font-label-caps text-[10px] text-on-surface-variant uppercase">Verified Findings</span>
            </div>
            <div className="font-display-lg text-on-surface text-[24px]">{findings.filter(f => f.status === 'verified').length}</div>
         </div>
         <div className="bg-surface-container p-4 border-l-4 border-error">
            <div className="flex items-center gap-2 mb-1">
               <Package size={14} className="text-error" />
               <span className="font-label-caps text-[10px] text-on-surface-variant uppercase">Live Provenance</span>
            </div>
            <div className="font-display-lg text-error text-[24px]">{findings.filter(f => f.provenance === 'live').length}</div>
         </div>
      </div>

      <div className="grid grid-cols-3 gap-6">
        <Card title="Finding Validation Pipeline (RAPTOR Methodology)" className="col-span-2">
           <div className="space-y-4">
              {findings.map(f => (
                <div key={f.id} className="bg-surface-container-high border border-outline-variant p-5 hover:border-primary-fixed/30 transition-all cursor-pointer group">
                  <div className="flex justify-between items-center mb-4">
                    <div className="flex items-center gap-3">
                      <span className={`w-2 h-2 rounded-full ${f.status === 'verified' ? 'bg-primary-fixed glow-green' : 'bg-secondary glow-cyan'}`}></span>
                      <span className="font-headline-md text-[18px] text-primary group-hover:text-primary-fixed transition-colors">{f.title}</span>
                    </div>
                    <div className="flex gap-4 items-center">
                       <div className="text-right">
                          <div className="font-label-caps text-[8px] text-on-surface-variant opacity-60 uppercase">ACCEPTANCE PROB</div>
                          <div className={`font-code-sm text-[11px] ${f.confidence > 0.8 ? 'text-primary-fixed' : 'text-secondary'}`}>
                             {((f.confidence || 0) * 100).toFixed(0)}%
                          </div>
                       </div>
                       <span className="font-code-sm text-secondary text-[11px] bg-black/40 px-3 py-1 border border-outline-variant">CHAIN: {f.evScore || 0}/100</span>
                    </div>
                  </div>
                  
                  {/* Stage Progress Bars */}
                  <div className="grid grid-cols-5 gap-1 mb-5">
                    {VALIDATION_STAGES.map(stage => (
                      <div key={stage} className="space-y-1">
                        <div className={`h-1.5 ${f.status === 'verified' ? 'bg-primary-fixed' : 'bg-surface-variant'}`}></div>
                        <div className="text-[8px] font-label-caps text-on-surface-variant opacity-40 uppercase truncate">{stage}</div>
                      </div>
                    ))}
                  </div>

                  <div className="flex gap-6 items-center">
                     <div className="flex items-center gap-1.5 text-on-surface-variant font-code-sm text-[10px]">
                        <Microscope size={12} className="text-secondary" /> EVIDENCE: {f.evidenceCount}
                     </div>
                     <div className="flex items-center gap-1.5 text-on-surface-variant font-code-sm text-[10px]">
                        <UserCheck size={12} className="text-primary-fixed" /> CONSENSUS: {f.agentConsensus?.length || 0} AGENTS
                     </div>
                     <div className="flex items-center gap-2 ml-4">
                        <span className={`px-2 py-0.5 rounded-full font-label-caps text-[8px] border ${
                           f.provenance === 'live' ? 'border-primary-fixed text-primary-fixed bg-primary-fixed/5' :
                           f.provenance === 'historical' ? 'border-secondary text-secondary bg-secondary/5' :
                           f.provenance === 'simulated' ? 'border-tertiary text-tertiary bg-tertiary/5' :
                           'border-error text-error bg-error/5 glow-red'
                        }`}>
                           {(f.provenance || 'LIVE').toUpperCase()}
                        </span>
                        {f.engagement_id !== sessionId ? (
                           <span className="px-2 py-0.5 rounded-full font-label-caps text-[8px] border border-outline-variant text-on-surface-variant bg-surface-variant/20">
                              HISTORICAL BENCHMARK
                           </span>
                        ) : (
                           <span className="px-2 py-0.5 rounded-full font-label-caps text-[8px] border border-primary-fixed/30 text-primary-fixed bg-primary-fixed/10">
                              CURRENT MISSION
                           </span>
                        )}
                     </div>
                     <div className="ml-auto flex items-center gap-3">
                        <button onClick={() => handleReplay(f.id)} className="flex items-center gap-1.5 px-3 py-1 bg-secondary-container/20 border border-secondary/30 hover:border-secondary text-[9px] font-label-caps text-secondary-fixed transition-all">
                           <Rocket size={12} /> REPLAY ATTACK
                        </button>
                        <button onClick={() => openVault(f)} className="flex items-center gap-1.5 px-3 py-1 bg-surface-container-highest border border-outline-variant hover:border-primary-fixed/50 text-[9px] font-label-caps text-primary-fixed transition-all">
                           <Package size={12} /> VIEW EVIDENCE VAULT
                        </button>
                        <span className={`font-label-caps text-[10px] px-3 py-1 border ${f.status === 'verified' ? 'border-primary-fixed text-primary-fixed bg-primary-fixed/10' : 'border-outline text-on-surface-variant opacity-50'}`}>
                          {f.status?.toUpperCase() || 'VALIDATING'}
                        </span>
                     </div>
                  </div>
                </div>
              ))}
           </div>
        </Card>
        
        {/* Verification Board Sidebar */}
        <Card title="Pending Verifications" glow="cyan">
           <div className="space-y-4">
              {verifications.map(v => (
                <div key={v.id} className="border-l-2 border-primary-fixed pl-4 py-1">
                   <div className="font-code-sm text-primary text-[13px] mb-2">{v.title}</div>
                   <div className="space-y-3">
                      <div>
                        <div className="font-label-caps text-[9px] text-on-surface-variant mb-1 uppercase">Agreed Agents</div>
                        <div className="flex gap-2">
                          {(v.agreedAgents || []).map(a => <span key={a} className="px-2 py-0.5 bg-primary-container/10 text-primary-fixed font-code-sm text-[9px] border border-primary-container/30">{a?.toUpperCase()}</span>)}
                        </div>
                      </div>
                      <div className="pt-2">
                        <div className="flex justify-between text-[9px] font-label-caps text-on-surface-variant mb-1">
                          <span>Consensus Progress</span>
                          <span>{v.agreedAgents?.length || 0} / {v.requiredSources || 1}</span>
                        </div>
                        <div className="h-1 bg-surface-variant w-full">
                          <div className="h-full bg-primary-fixed glow-cyan" style={{ width: `${((v.agreedAgents?.length || 0) / (v.requiredSources || 1)) * 100}%` }}></div>
                        </div>
                      </div>
                      <button onClick={() => handleVerify(v.findingId || v.id)} className="w-full py-2 bg-surface-container-high border border-primary-fixed/30 text-primary-fixed font-label-caps text-[10px] hover:bg-primary-fixed/10 transition-all">
                         FORCE VERIFICATION
                      </button>
                   </div>
                </div>
              ))}
           </div>
        </Card>
      </div>

      <EvidenceVaultModal 
        isOpen={vaultOpen}
        onClose={() => setVaultOpen(false)}
        findingTitle={selectedFinding?.title || ''}
        packageData={vaultData}
        replayabilityScore={selectedFinding?.replayabilityScore || selectedFinding?.confidence * 100 || 0}
      />
    </div>
  );
};

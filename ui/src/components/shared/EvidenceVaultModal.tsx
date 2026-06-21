import React from 'react';
import { Shield, FileText, Play, CheckCircle2, XCircle, Code, Camera } from 'lucide-react';

interface EvidencePackage {
  id: string;
  finding_id: string;
  raw_requests: string[];
  raw_responses: string[];
  screenshots: string[];
  workflow_trace: any[];
  replay_script?: string;
  integrity_hash: string;
}

interface Props {
  isOpen: boolean;
  onClose: () => void;
  findingTitle: string;
  packageData: EvidencePackage | null;
  replayabilityScore: number;
}

export const EvidenceVaultModal: React.FC<Props> = ({ isOpen, onClose, findingTitle, packageData, replayabilityScore }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-8 bg-black/80 backdrop-blur-sm">
      <div className="bg-surface-container border border-outline-variant w-full max-w-5xl h-full max-h-[800px] flex flex-col shadow-2xl overflow-hidden animate-in fade-in zoom-in duration-200">
        
        {/* Header */}
        <div className="h-16 border-b border-outline-variant flex items-center justify-between px-8 bg-black/40">
           <div className="flex items-center gap-4">
              <Shield className="text-primary-fixed" size={20} />
              <div>
                <div className="font-headline-md text-primary text-[16px] uppercase tracking-wider">{findingTitle}</div>
                <div className="font-code-sm text-[10px] text-on-surface-variant uppercase tracking-tighter opacity-60">Evidence Vault Package // {packageData?.id}</div>
              </div>
           </div>
           <button onClick={onClose} className="p-2 hover:bg-surface-variant transition-all text-on-surface-variant"><XCircle size={20} /></button>
        </div>

        {/* Content Grid */}
        <div className="flex-1 overflow-hidden grid grid-cols-12">
           
           {/* Sidebar: Metadata & Scoring */}
           <div className="col-span-3 border-r border-outline-variant p-6 space-y-8 bg-surface-container-high/30">
              <div>
                 <div className="font-label-caps text-[9px] text-on-surface-variant mb-3 uppercase tracking-widest">Submission Readiness</div>
                 <div className="space-y-4">
                    <div className="bg-black/40 p-4 border border-outline-variant">
                       <div className="flex justify-between items-end mb-2">
                          <span className="text-[10px] font-code-sm text-on-surface-variant">REPLAYABILITY</span>
                          <span className={`text-[18px] font-display-lg ${replayabilityScore > 80 ? 'text-primary-fixed' : 'text-secondary'}`}>{replayabilityScore}%</span>
                       </div>
                       <div className="h-1 bg-surface-variant w-full overflow-hidden">
                          <div className={`h-full ${replayabilityScore > 80 ? 'bg-primary-fixed glow-green' : 'bg-secondary glow-cyan'}`} style={{ width: `${replayabilityScore}%` }}></div>
                       </div>
                    </div>
                    <div className="flex items-center gap-2 text-[11px] font-code-sm text-primary-fixed">
                       <CheckCircle2 size={14} /> 100% LIVE PROVENANCE
                    </div>
                 </div>
              </div>

              <div>
                 <div className="font-label-caps text-[9px] text-on-surface-variant mb-3 uppercase tracking-widest">Artifact Manifest</div>
                 <div className="space-y-2">
                    <div className="flex items-center gap-3 text-on-surface font-code-sm text-[11px]">
                       <FileText size={14} className="text-secondary" /> {packageData?.raw_requests.length} RAW REQUESTS
                    </div>
                    <div className="flex items-center gap-3 text-on-surface font-code-sm text-[11px]">
                       <Camera size={14} className="text-secondary" /> {packageData?.screenshots.length || 0} SCREENSHOTS
                    </div>
                    <div className="flex items-center gap-3 text-on-surface font-code-sm text-[11px]">
                       <Play size={14} className="text-secondary" /> 1 REPLAY SCRIPT
                    </div>
                 </div>
              </div>

              <div className="pt-6 border-t border-outline-variant/30">
                 <div className="font-label-caps text-[8px] text-on-surface-variant mb-2 uppercase">Integrity Hash</div>
                 <div className="font-code-sm text-[9px] text-on-surface-variant break-all bg-black/40 p-2 border border-outline-variant leading-tight">
                    {packageData?.integrity_hash}
                 </div>
              </div>
           </div>

           {/* Main Viewer */}
           <div className="col-span-9 flex flex-col overflow-hidden bg-black/20">
              <div className="flex-1 overflow-y-auto p-8 custom-scrollbar space-y-8">
                 
                 {/* Raw Request Section */}
                 <section>
                    <div className="flex items-center gap-2 mb-4">
                       <Code size={16} className="text-primary-fixed" />
                       <h3 className="font-label-caps text-[11px] text-primary tracking-widest">Primary Exploit Request</h3>
                    </div>
                    <pre className="p-4 bg-surface-container-high border border-outline-variant font-code-sm text-[12px] text-primary leading-relaxed overflow-x-auto whitespace-pre-wrap">
                       {packageData?.raw_requests[0]}
                    </pre>
                 </section>

                 {/* Workflow Trace Section */}
                 <section>
                    <div className="flex items-center gap-2 mb-4">
                       <Play size={16} className="text-secondary" />
                       <h3 className="font-label-caps text-[11px] text-secondary tracking-widest">Autonomous Workflow Trace</h3>
                    </div>
                    <div className="space-y-2">
                       {(packageData?.workflow_trace || []).map((step, i) => (
                          <div key={i} className="flex items-center gap-4 p-3 bg-black/40 border border-outline-variant border-l-2 border-l-secondary">
                             <span className="font-code-sm text-[10px] text-on-surface-variant w-8">0{i+1}</span>
                             <span className="font-code-sm text-[12px] text-on-surface flex-1">{step.step}</span>
                             <span className={`font-label-caps text-[9px] ${step.status === 'exploit' ? 'text-error' : 'text-primary-fixed'}`}>{step.status?.toUpperCase()}</span>
                          </div>
                       ))}
                    </div>
                 </section>

              </div>

              {/* Action Footer */}
              <div className="h-20 border-t border-outline-variant bg-black/40 px-8 flex items-center justify-end gap-4">
                 <button onClick={onClose} className="px-6 py-2 border border-outline text-on-surface font-label-caps text-[11px] hover:bg-surface-variant">CLOSE VAULT</button>
                 <button className="px-8 py-2 bg-primary-fixed text-black font-label-caps text-[11px] font-bold glow-green hover:brightness-110 active:scale-95 transition-all flex items-center gap-2">
                    <Play size={14} /> EXPORT BUG BOUNTY PACKAGE
                 </button>
              </div>
           </div>

        </div>

      </div>
    </div>
  );
};

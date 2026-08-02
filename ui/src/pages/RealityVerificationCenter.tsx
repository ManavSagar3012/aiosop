import React from 'react';
import { Card } from '../components/shared/Card';
import { StatusBadge } from '../components/shared/StatusBadge';
import { DataTable, Column } from '../components/shared/DataTable';
import { EmptyState } from '../components/shared/EmptyState';
import { useIntelligenceStore } from '../store/useIntelligenceStore';
import { ShieldCheck, Fingerprint, Crosshair } from 'lucide-react';

interface LedgerFinding {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: number;
}

// Same content previously hard-coded as two individual cards; reshaped into
// row data so it can flow through the shared DataTable primitive.
const findingLedger: LedgerFinding[] = [
  { id: 'tenant-escape-invoice-export', title: 'Tenant Escape via Invoice Export', severity: 'critical', confidence: 98 },
  { id: 'public-s3-bucket-avatars', title: 'Public AWS S3 Bucket (Avatars)', severity: 'medium', confidence: 100 },
];

const ledgerColumns: Column<LedgerFinding>[] = [
  {
    key: 'title',
    header: 'Finding',
    render: (f) => (
      <span className="font-code-sm text-code-sm text-on-surface font-bold uppercase">{f.title}</span>
    ),
  },
  {
    key: 'status',
    header: 'Status',
    render: () => <StatusBadge value="verified" />,
  },
  {
    key: 'severity',
    header: 'Severity',
    render: (f) => <StatusBadge value={f.severity} kind="severity" />,
  },
  {
    key: 'confidence',
    header: 'Confidence',
    render: (f) => <span className="font-code-sm text-label-xs text-on-surface-variant tabular-nums">{f.confidence}%</span>,
  },
];

export const RealityVerificationCenter: React.FC = () => {
  const { verifications, sessionId, hasCheckedSession } = useIntelligenceStore();
  const rows = verifications || [];

  // Loading skeleton while waiting for first data
  if (!sessionId) {
    if (!hasCheckedSession) {
      return (
        <div className="flex flex-col gap-6">
          <div className="bg-surface-container-low border border-outline-variant p-5 animate-pulse">
            <div className="flex justify-between items-center">
              <div className="space-y-2">
                <div className="h-3 w-36 bg-surface-container-high/60"></div>
                <div className="h-5 w-72 bg-surface-container-high/60"></div>
              </div>
              <div className="flex gap-6">
                <div className="h-10 w-24 bg-surface-container-high/60"></div>
                <div className="h-10 w-24 bg-surface-container-high/60"></div>
              </div>
            </div>
          </div>
          <div className="grid grid-cols-3 gap-6 min-h-0">
            <div className="col-span-2 bg-surface-container-low border border-outline-variant p-5 animate-pulse h-[500px]">
              <div className="h-5 w-36 bg-surface-container-high/60 mb-6"></div>
              {[1,2].map(i => (
                <div key={i} className="h-48 bg-surface-container-high/60 border border-outline-variant/40 mb-4"></div>
              ))}
            </div>
            <div className="bg-surface-container-low border border-outline-variant p-5 animate-pulse h-[500px]">
              <div className="h-5 w-36 bg-surface-container-high/60 mb-6"></div>
              {[1,2,3].map(i => (
                <div key={i} className="h-12 bg-surface-container-high/60 border border-outline-variant/40 mb-3"></div>
              ))}
            </div>
          </div>
        </div>
      );
    }
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] bg-surface-container border border-outline-variant p-8 rounded-sm">
        <EmptyState 
          message="No active engagement found in the database. Use 'NEW MISSION' in the header to start a new offensive security orchestration run." 
          icon={<Crosshair size={48} />}
          hint="Awaiting target configuration..."
        />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex justify-between items-center bg-surface-container p-4 border border-outline-variant">
         <div className="flex flex-col">
            <span className="font-label-caps text-label-caps text-on-surface-variant mb-1 uppercase">Governance Policy</span>
            <span className="font-code-sm text-primary text-[14px]">BALANCED_CONSENSUS (REQUIRES 2+ INDEPENDENT AGENTS)</span>
         </div>
         <div className="flex items-center gap-6">
            <div className="text-right">
               <div className="font-code-sm text-primary text-[14px]">82%</div>
               <div className="font-label-caps text-label-caps text-on-surface-variant">OVERALL VERIFICATION RATE</div>
            </div>
            <div className="text-right border-l border-outline-variant pl-6">
               <div className="font-code-sm text-error text-[14px]">3</div>
               <div className="font-label-caps text-label-caps text-on-surface-variant">REJECTED HYPOTHESES</div>
            </div>
         </div>
      </div>

      <div className="grid grid-cols-3 gap-6 flex-1 min-h-0">
        <Card title="Verification Queue" className="col-span-2 overflow-y-auto">
           {rows.length === 0 ? (
             <EmptyState
               message="No verification requests pending — the swarm has not escalated any findings for consensus review."
               icon={<Fingerprint size={28} />}
             />
           ) : (
           <div className="space-y-4">
              {rows.map((v: any) => (
                <div key={v.id} className="bg-surface-container-high border border-outline-variant p-5">
                   <div className="flex justify-between items-start mb-6">
                      <div className="flex items-center gap-4">
                         <div className="w-12 h-12 bg-secondary/10 border border-secondary/30 flex items-center justify-center text-secondary">
                            <Fingerprint size={24} />
                         </div>
                         <div>
                            <div className="font-headline-md text-headline-md text-primary">{v.title}</div>
                            <div className="font-code-sm text-on-surface-variant text-label-xs mt-1 uppercase italic">Awaiting Final Consensus</div>
                         </div>
                      </div>
                      <div className="text-right">
                         <div className="font-label-caps text-label-xs text-on-surface-variant mb-1">STRENGTH</div>
                         <div className="font-code-sm text-primary-fixed text-[18px]">HIGH</div>
                      </div>
                   </div>

                   <div className="grid grid-cols-3 gap-6 mb-6">
                      <div className="col-span-2">
                        <div className="flex justify-between items-center mb-3">
                           <div className="font-label-caps text-label-caps text-on-surface-variant uppercase">Verification Timeline</div>
                           <div className="flex items-center gap-2">
                              <span className={`px-2 py-0.5 rounded-sm font-label-caps text-label-xs border ${
                                 v.provenance === 'live' ? 'border-primary-fixed text-primary-fixed bg-primary-fixed/5' :
                                 v.provenance === 'derived' ? 'border-secondary text-secondary bg-secondary/5' :
                                 'border-error text-error bg-error/5 glow-red animate-pulse'
                              }`}>
                                 {v.provenance?.toUpperCase() || 'LIVE'} PROVENANCE
                              </span>
                           </div>
                        </div>
                        <div className="space-y-4">
                           {(v.stages || []).map((stage: any, i: number) => (
                              <div key={i} className="flex gap-4 group">
                                 <div className="flex flex-col items-center">
                                    <div className={`w-2.5 h-2.5 rounded-full border ${stage.status === 'passed' ? 'bg-primary-fixed border-primary-fixed glow-green' : 'bg-surface-variant border-outline'}`}></div>
                                    <div className="w-px h-6 bg-outline-variant group-last:hidden"></div>
                                 </div>
                                 <div className="flex-1 flex justify-between items-center -mt-1">
                                    <span className={`font-code-sm text-[11px] ${stage.status === 'passed' ? 'text-on-surface' : 'text-on-surface-variant opacity-50'}`}>{stage.name}</span>
                                    <span className={`font-label-caps text-label-xs ${stage.status === 'passed' ? 'text-primary-fixed' : 'text-on-surface-variant opacity-30'}`}>{stage.status?.toUpperCase()}</span>
                                 </div>
                              </div>
                           ))}
                        </div>
                      </div>

                      <div className="space-y-6">
                        <div>
                           <div className="font-label-caps text-label-caps text-on-surface-variant mb-3 uppercase">Evidence Integrity</div>
                           <div className="bg-black/40 border border-outline-variant p-4 space-y-3">
                              <div className="flex justify-between items-end">
                                 <span className="text-label-xs font-code-sm text-on-surface-variant">CHAIN STRENGTH</span>
                                 <span className={`text-[16px] font-display-lg ${v.evidenceChainScore > 80 ? 'text-primary-fixed' : v.evidenceChainScore > 50 ? 'text-secondary' : 'text-error'}`}>
                                    {v.evidenceChainScore || 0}%
                                 </span>
                              </div>
                              <div className="h-1.5 bg-surface-variant w-full overflow-hidden">
                                 <div className={`h-full transition-all duration-1000 ${v.evidenceChainScore > 80 ? 'bg-primary-fixed glow-green' : v.evidenceChainScore > 50 ? 'bg-secondary glow-cyan' : 'bg-error glow-red'}`}
                                      style={{ width: `${v.evidenceChainScore || 0}%` }}></div>
                              </div>
                              <div className="flex gap-2">
                                 {v.replayable && <span className="text-label-xs font-code-sm text-primary-fixed flex items-center gap-1"><ShieldCheck size={10} /> REPLAYABLE</span>}
                                 <span className="text-label-xs font-code-sm text-on-surface-variant opacity-50">SOURCES: {v.evidenceSources?.length || 0}</span>
                              </div>
                           </div>
                        </div>

                        <div>
                           <div className="font-label-caps text-label-caps text-on-surface-variant mb-3 uppercase">Evidence Provenance</div>
                           <div className="bg-black/40 border border-outline-variant p-3 space-y-2">
                              {(v.evidenceSources || []).map((s: string) => (
                                <div key={s} className="flex items-center gap-2 text-[10px] font-code-sm text-primary">
                                   <ShieldCheck size={12} className="text-primary-fixed" /> {s?.toUpperCase()}
                                </div>
                              ))}
                           </div>
                        </div>
                      </div>
                   </div>

                   <div className="flex gap-4">
                      <button className="flex-1 py-2 bg-primary-container text-on-primary-fixed font-label-caps text-[11px] hover:brightness-110">APPROVE AS VERIFIED</button>
                      <button className="flex-1 py-2 border border-outline text-on-surface font-label-caps text-[11px] hover:bg-surface-variant">REQUEST RE-SCAN</button>
                      <button className="flex-1 py-2 border border-error text-error font-label-caps text-[11px] hover:bg-error/5">DISMISS AS FALSE POSITIVE</button>
                   </div>
                </div>
              ))}
           </div>
           )}
        </Card>

        <Card title="Finding Quality Ledger">
           <DataTable<LedgerFinding>
             columns={ledgerColumns}
             rows={findingLedger}
             rowKey={(f) => f.id}
             empty={<EmptyState message="No verified findings yet." icon={<ShieldCheck size={28} />} />}
           />
        </Card>
      </div>
    </div>
  );
};

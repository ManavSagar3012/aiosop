import React from 'react';
import { Card } from '../components/shared/Card';
import { EmptyState } from '../components/shared/EmptyState';
import { Clock, Shield, Zap, Search, CheckCircle2 } from 'lucide-react';
import { useIntelligenceStore } from '../store/useIntelligenceStore';

export const MissionTimeline: React.FC = () => {
  const { auditLog, sessionId } = useIntelligenceStore();

  const getEventIcon = (type: string) => {
    if (type.includes('finding') || type.includes('vulnerability')) return <Shield size={16} className="text-error" />;
    if (type.includes('task')) return <Zap size={16} className="text-secondary" />;
    if (type.includes('verification')) return <CheckCircle2 size={16} className="text-primary-fixed" />;
    return <Clock size={16} className="text-on-surface-variant" />;
  };

  return (
    <div className="flex flex-col gap-6 h-full p-2">
      <div className="flex justify-between items-center bg-surface-container p-4 border border-outline-variant shrink-0">
         <div className="flex flex-col">
            <span className="font-label-caps text-label-xs text-on-surface-variant mb-1 uppercase">Chronological Record</span>
            <span className="font-code-sm text-primary text-[14px]">MISSION AUDIT TRAIL // {sessionId?.toUpperCase()}</span>
         </div>
         <div className="flex gap-4">
            <div className="bg-black/40 px-4 py-2 border border-outline-variant text-center">
               <div className="font-code-sm text-secondary text-[14px] font-bold">{auditLog.length}</div>
               <div className="font-label-caps text-on-surface-variant text-label-xs">TOTAL EVENTS</div>
            </div>
         </div>
      </div>

      <Card title="Live Operation Timeline" className="flex-1 overflow-hidden">
         <div className="h-full overflow-y-auto pr-4 custom-scrollbar space-y-4 py-4">
            {auditLog.length === 0 ? (
               <div className="h-full flex items-center justify-center">
                  <EmptyState message="Awaiting operational events..." icon={<Search size={32} />} />
               </div>
            ) : (
               auditLog.map((evt, i) => (
                  <div key={evt.id || i} className="flex gap-6 group">
                     <div className="flex flex-col items-center shrink-0 w-16 pt-1">
                        <span className="font-code-sm text-[10px] text-on-surface-variant">{new Date(evt.timestamp).toLocaleTimeString([], { hour12: false })}</span>
                        <div className="w-px h-full bg-outline-variant mt-2 group-last:hidden"></div>
                     </div>
                     
                     <div className={`flex-1 p-4 border-l-2 bg-surface-container-high/40 hover:bg-surface-container-high transition-all ${
                        evt.severity === 'critical' ? 'border-error glow-red' :
                        evt.severity === 'high' ? 'border-error/50' :
                        evt.severity === 'medium' ? 'border-secondary' : 'border-outline-variant'
                     }`}>
                        <div className="flex justify-between items-center mb-2">
                           <div className="flex items-center gap-2">
                              {getEventIcon(evt.event_type || '')}
                              <span className="font-label-caps text-[11px] text-primary tracking-widest">{(evt.event_type || 'SYSTEM').replace(/_/g, ' ').toUpperCase()}</span>
                           </div>
                           <span className="font-code-sm text-label-xs text-on-surface-variant bg-black/40 px-2 py-0.5 border border-outline-variant">{evt.actor_id || 'SYSTEM'}</span>
                        </div>
                        
                        <div className="font-code-sm text-[11px] text-on-surface leading-relaxed">
                           {typeof evt.action === 'string' ? evt.action : JSON.stringify(evt.action || evt.result || evt.details || {})}
                        </div>
                     </div>
                  </div>
               ))
            )}
         </div>
      </Card>
    </div>
  );
};

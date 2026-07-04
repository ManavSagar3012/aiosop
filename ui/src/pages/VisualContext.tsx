import React from 'react';
import { Card } from '../components/shared/Card';
import { DataTable, Column } from '../components/shared/DataTable';
import { Maximize2, Layers, MessageSquare } from 'lucide-react';

interface ActiveElement {
  id: string;
  name: string;
  source: 'VISUAL' | 'DOM';
}

// Same content previously hard-coded as two individual rows; reshaped into
// row data so it can flow through the shared DataTable primitive.
const ACTIVE_ELEMENTS: ActiveElement[] = [
  { id: 'delete-button', name: 'Delete Button', source: 'VISUAL' },
  { id: 'api-key-input', name: 'API Key Input', source: 'DOM' },
];

const activeElementColumns: Column<ActiveElement>[] = [
  {
    key: 'name',
    header: 'Element',
    render: (e) => (
      <span className={`font-code-sm text-[11px] ${e.source === 'VISUAL' ? 'text-primary-fixed' : 'text-on-surface'}`}>{e.name}</span>
    ),
  },
  {
    key: 'source',
    header: 'Source',
    width: 'w-20',
    render: (e) => (
      <span className={`font-code-sm text-label-xs px-1 border ${e.source === 'VISUAL' ? 'border-primary-fixed/30 text-primary-fixed' : 'border-outline text-on-surface'}`}>{e.source}</span>
    ),
  },
];

interface AgentObservation {
  id: string;
  agent: string;
  quote: string;
  accent: 'primary' | 'secondary';
}

// Same content previously hard-coded as two individual rows; reshaped into
// row data so it can flow through the shared DataTable primitive.
const AGENT_OBSERVATIONS: AgentObservation[] = [
  { id: 'visual-agent-ocr', agent: 'VISUAL_AGENT', quote: '"Found hidden administrative panel in footer via OCR"', accent: 'primary' },
  { id: 'gql-agent-auditlog', agent: 'GQL_AGENT', quote: '"Identified unauthorized access to field \'auditLog\'"', accent: 'secondary' },
];

const observationColumns: Column<AgentObservation>[] = [
  {
    key: 'agent',
    header: 'Agent',
    width: 'w-32',
    render: (o) => (
      <span className="flex items-center gap-2">
        <span className={`w-1 h-3 ${o.accent === 'primary' ? 'bg-primary-fixed' : 'bg-secondary'}`} />
        <span className="font-code-sm text-label-xs text-on-surface-variant">{o.agent}</span>
      </span>
    ),
  },
  {
    key: 'quote',
    header: 'Observation',
    render: (o) => <span className="font-code-sm text-[11px] text-on-surface italic">{o.quote}</span>,
  },
];

export const VisualContext: React.FC = () => {
  return (
    <div className="flex flex-col h-full gap-6">
      <div className="flex-1 grid grid-cols-4 gap-6 min-h-0">
        {/* Playwright Canvas */}
        <Card title="Playwright Visual Analysis" className="col-span-3 flex flex-col relative overflow-hidden bg-black">
           <div className="absolute top-4 left-4 z-20 flex gap-2">
              <span className="px-3 py-1 bg-black/80 border border-primary-fixed/50 text-primary-fixed font-code-sm text-[10px] backdrop-blur-md">ROLE: GUEST</span>
              <span className="px-3 py-1 bg-black/80 border border-secondary/50 text-secondary font-code-sm text-[10px] backdrop-blur-md">WORKFLOW: ORG_ADMIN</span>
           </div>

           <div className="flex-1 relative group overflow-hidden">
              <div className="absolute inset-0 bg-[url('https://images.unsplash.com/photo-1557683316-973673baf926?q=80&w=2000')] bg-cover bg-center opacity-80 grayscale group-hover:grayscale-0 transition-all duration-700"></div>

              {/* Semantic Bounding Boxes */}
              <div className="absolute top-[20%] left-[10%] w-[150px] h-[40px] border-2 border-error bg-error/10 flex items-center justify-center group/box cursor-help animate-pulse-neon">
                 <div className="opacity-0 group-hover/box:opacity-100 absolute -top-8 left-0 bg-error text-white font-label-caps text-label-xs px-2 py-0.5 whitespace-nowrap z-30">
                    CRITICAL: DELETE_ORG_BUTTON (S2 ESCALATION RECOMMENDED)
                 </div>
              </div>

              <div className="absolute top-[45%] left-[30%] w-[200px] h-[60px] border-2 border-primary-fixed bg-primary-fixed/10 flex items-center justify-center group/box cursor-help">
                 <div className="opacity-0 group-hover/box:opacity-100 absolute -top-8 left-0 bg-primary-fixed text-black font-label-caps text-label-xs px-2 py-0.5 whitespace-nowrap z-30">
                    SEMANTIC: REGISTRATION_FORM
                 </div>
              </div>
           </div>

           <div className="h-12 border-t border-outline-variant/50 flex items-center px-4 gap-6">
              <div className="flex items-center gap-2 text-on-surface-variant font-code-sm text-[10px]">
                 <Maximize2 size={12} /> FULLSCREEN ANALYZER
              </div>
              <div className="flex items-center gap-2 text-on-surface-variant font-code-sm text-[10px]">
                 <Layers size={12} /> TOGGLE DOM OVERLAY
              </div>
           </div>
        </Card>

        {/* Context Sidebar */}
        <div className="flex flex-col gap-6 h-full overflow-y-auto pr-2 custom-scrollbar">
           <Card title="Fused Context">
              <div className="font-code-sm text-[11px] space-y-4">
                 <div>
                    <div className="text-on-surface-variant text-label-xs mb-1 uppercase">Inferred System</div>
                    <div className="text-secondary-fixed">Organization Administration Portal</div>
                 </div>
                 <div>
                    <div className="text-on-surface-variant text-label-xs mb-1 uppercase">Active Elements</div>
                    <DataTable<ActiveElement>
                      columns={activeElementColumns}
                      rows={ACTIVE_ELEMENTS}
                      rowKey={(e) => e.id}
                      empty={<span className="font-code-sm text-[11px] text-on-surface-variant/60 italic">No active elements detected.</span>}
                    />
                 </div>
              </div>
           </Card>

           <Card title="GraphQL Correlation">
              <div className="font-code-sm text-[11px] space-y-3">
                 <div className="bg-primary-container/10 p-2 border border-primary-fixed/20 text-primary-fixed">
                    Matched UI Label "Delete" to mutation <span className="underline italic">deleteOrg(id)</span>
                 </div>
                 <div className="text-on-surface-variant italic opacity-60">
                    Confidence: 0.98
                 </div>
              </div>
           </Card>

           <Card title="Agent Observations">
              <DataTable<AgentObservation>
                columns={observationColumns}
                rows={AGENT_OBSERVATIONS}
                rowKey={(o) => o.id}
                empty={<span className="font-code-sm text-[11px] text-on-surface-variant/60 italic">No agent observations recorded yet.</span>}
              />
           </Card>
        </div>
      </div>

      <div className="h-20 bg-surface-container border border-outline-variant px-6 flex items-center gap-4">
         <div className="w-10 h-10 bg-primary-container/20 flex items-center justify-center text-primary-fixed">
            <MessageSquare size={20} />
         </div>
         <div className="flex-1">
            <div className="font-label-caps text-label-xs text-on-surface-variant">OPERATOR INSTRUCTION</div>
            <input
              type="text"
              placeholder="Ask the Swarm about this view (e.g. 'Is the Delete button interactive for this user?')..."
              className="w-full bg-transparent border-none outline-none focus:ring-0 text-primary font-code-sm text-body-md"
            />
         </div>
      </div>
    </div>
  );
};

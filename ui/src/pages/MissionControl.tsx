import React from 'react';
import { Card } from '../components/shared/Card';
import { useSwarmStore } from '../store/useSwarmStore';
import { useIntelligenceStore } from '../store/useIntelligenceStore';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from 'recharts';

export const MissionControl: React.FC = () => {
  const { agents, budget } = useSwarmStore();
  const { auditLog } = useIntelligenceStore();

  const costData = [
    { name: 'System 1', value: budget.system1Requests * 0.001 },
    { name: 'System 2', value: budget.system2Requests * 0.15 },
  ];

  const COLORS = ['#39ff14', '#00f1fd'];

  // Filter for governance-relevant events
  const governanceEvents = auditLog.filter(e => 
    e.event_type === 'phase_transition' || 
    e.event_type === 'budget_update' || 
    e.event_type?.includes('approval') ||
    e.severity === 'high' ||
    e.severity === 'critical'
  ).slice(0, 5);

  return (
    <div className="flex flex-col gap-gutter">
      <div className="grid grid-cols-3 gap-gutter">
        <Card title="Agent Utilization" className="col-span-2">
          <div className="space-y-4 max-h-96 overflow-y-auto pr-2 custom-scrollbar">
            {agents.length > 0 ? agents.map(agent => (
              <div key={agent.id} className="bg-surface-container-high p-4 border border-outline-variant flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className={`w-3 h-3 rounded-full ${agent.status === 'running' ? 'bg-primary-fixed animate-pulse' : 'bg-on-surface-variant'}`}></div>
                  <div>
                    <div className="font-code-sm text-primary text-[14px]">{agent.id?.toUpperCase()}</div>
                    <div className="font-label-caps text-on-surface-variant text-[10px]">{agent.type?.replace(/_/g, ' ')?.toUpperCase()}</div>
                  </div>
                </div>
                <div className="text-right">
                  <div className="font-code-sm text-secondary-fixed text-[14px]">${(agent.cost_incurred || 0).toFixed(2)}</div>
                  <div className="font-label-caps text-on-surface-variant text-[9px]">TOTAL SPEND</div>
                </div>
              </div>
            )) : (
                <div className="text-center py-10 opacity-30 font-code-sm uppercase tracking-widest">Initializing Swarm Personas...</div>
            )}
          </div>
        </Card>

        <Card title="Cost Allocation (System 1 vs 2)">
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={costData}
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {costData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: '#131314', border: '1px solid #2a2a2d' }}
                  itemStyle={{ color: '#e5e2e3' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="flex justify-center gap-6 font-label-caps text-[10px]">
            <div className="flex items-center gap-2"><div className="w-2 h-2 bg-primary-fixed"></div> SYSTEM 1</div>
            <div className="flex items-center gap-2"><div className="w-2 h-2 bg-secondary"></div> SYSTEM 2</div>
          </div>
        </Card>
      </div>
      
      <div className="grid grid-cols-2 gap-6">
        <Card title="Resource Consumption Over Time">
            <div className="h-64 w-full">
                <ResponsiveContainer width="100%" height="100%">
                   <BarChart data={agents}>
                      <XAxis dataKey="id" hide />
                      <YAxis hide />
                      <Tooltip 
                         contentStyle={{ backgroundColor: '#111', border: '1px solid #333' }}
                         itemStyle={{ color: '#00f1fd' }}
                      />
                      <Bar dataKey="cost_incurred" fill="#39ff14" radius={[2, 2, 0, 0]} />
                   </BarChart>
                </ResponsiveContainer>
            </div>
        </Card>

        <Card title="Swarm Governance Log">
            <div className="font-code-sm text-[11px] text-on-surface space-y-3">
               {governanceEvents.length > 0 ? governanceEvents.map((evt, i) => (
                 <div key={evt.id || i} className={`border-l-2 pl-3 ${evt.severity === 'critical' || evt.severity === 'high' ? 'border-error' : 'border-primary-fixed'}`}>
                    <div className="text-on-surface-variant mb-1 uppercase text-[9px] tracking-tighter">
                        DECISION: {evt.event_type?.toUpperCase().replace(/_/g, ' ')}
                    </div>
                    <div>
                        {typeof evt.action === 'string' ? evt.action : (evt.details?.reason || evt.result?.summary || `Event triggered by ${evt.actor_id}`)}
                    </div>
                 </div>
               )) : (
                   <div className="text-center py-10 opacity-30 italic">Awaiting swarm governance decisions...</div>
               )}
            </div>
        </Card>
      </div>
    </div>
  );
};

import React, { useMemo } from 'react';
import { Card } from '../components/shared/Card';
import { ApprovalQueue } from '../components/shared/ApprovalQueue';
import { EmptyState } from '../components/shared/EmptyState';
import { useSwarmStore } from '../store/useSwarmStore';
import { useIntelligenceStore } from '../store/useIntelligenceStore';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from 'recharts';
import { Crosshair } from 'lucide-react';

// Recharts sets colors as raw SVG attributes (fill=/stroke=), so a bare
// var(--x) string or Tailwind class won't resolve there — we need a
// literal color string. Read the design tokens straight off the root
// element (single source of truth = styles.css) and fall back to the
// historical literals only if computed styles are unavailable.
const cssVar = (name: string, fallback: string) => {
  if (typeof document === 'undefined') return fallback;
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fallback;
};

export const MissionControl: React.FC = () => {
  const { agents, budget } = useSwarmStore();
  const { auditLog, sessionId, hasCheckedSession } = useIntelligenceStore();

  const palette = useMemo(() => ({
    primary:      cssVar('--primary', '#22d3ee'),                    // verified / operational
    secondary:    cssVar('--secondary', '#38bdf8'),                  // active / interactive
    onSurface:    cssVar('--on-surface', '#e5e2e3'),
    tooltipBg:    cssVar('--surface-container', '#131314'),
    tooltipBorder: cssVar('--surface-container-highest', '#2a2a2d'),
  }), []);

  const tooltipStyle = useMemo(() => ({
    backgroundColor: palette.tooltipBg,
    border: `1px solid ${palette.tooltipBorder}`,
  }), [palette]);

  const costData = [
    { name: 'System 1', value: budget.system1Requests * 0.001 },
    { name: 'System 2', value: budget.system2Requests * 0.15 },
  ];

  const COLORS = [palette.primary, palette.secondary];

  // Filter for governance-relevant events
  const governanceEvents = auditLog.filter(e => 
    e.event_type === 'phase_transition' || 
    e.event_type === 'budget_update' || 
    e.event_type?.includes('approval') ||
    e.severity === 'high' ||
    e.severity === 'critical'
  ).slice(0, 5);

  // Loading skeleton while waiting for store data
  if (!sessionId) {
    if (!hasCheckedSession) {
      return (
        <div className="flex flex-col gap-gutter">
          <div className="bg-surface-container-low border border-outline-variant p-5 animate-pulse">
            <div className="flex justify-between items-center">
              <div className="space-y-2">
                <div className="h-3 w-32 bg-surface-container-high/60"></div>
                <div className="h-6 w-48 bg-surface-container-high/60"></div>
              </div>
              <div className="flex gap-2">
                <div className="h-10 w-28 bg-surface-container-high/60"></div>
                <div className="h-10 w-28 bg-surface-container-high/60"></div>
              </div>
            </div>
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-gutter">
            <div className="col-span-2 bg-surface-container-low border border-outline-variant p-5 animate-pulse h-[400px]">
              <div className="h-5 w-40 bg-surface-container-high/60 mb-6"></div>
              {[1,2,3].map(i => (
                <div key={i} className="h-16 bg-surface-container-high/60 border border-outline-variant/40 mb-4"></div>
              ))}
            </div>
            <div className="bg-surface-container-low border border-outline-variant p-5 animate-pulse h-[400px]">
              <div className="h-5 w-36 bg-surface-container-high/60 mb-6"></div>
              <div className="h-64 bg-surface-container-high/60 rounded-full mx-auto w-64"></div>
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
    <div className="flex flex-col gap-gutter">
      <ApprovalQueue />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-gutter">
        <Card title="Agent Utilization" className="col-span-2">
          <div className="space-y-4 max-h-96 overflow-y-auto pr-2 custom-scrollbar">
            {agents.length > 0 ? agents.map(agent => (
              <div key={agent.id} className="bg-surface-container-high p-4 border border-outline-variant flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className={`w-3 h-3 rounded-full ${agent.status === 'running' ? 'bg-primary-fixed animate-pulse' : 'bg-on-surface-variant'}`}></div>
                  <div>
                    <div className="font-code-sm text-primary text-body-md">{agent.id?.toUpperCase()}</div>
                    <div className="font-label-caps text-on-surface-variant text-label-xs">{agent.type?.replace(/_/g, ' ')?.toUpperCase()}</div>
                  </div>
                </div>
                <div className="text-right">
                  <div className="font-code-sm text-secondary-fixed text-body-md">${(agent.cost_incurred || 0).toFixed(2)}</div>
                  <div className="font-label-caps text-on-surface-variant text-label-xs">TOTAL SPEND</div>
                </div>
              </div>
            )) : (
                <EmptyState message="Initializing Swarm Personas..." hint="Awaiting agent telemetry" />
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
                  {costData.map((_, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={tooltipStyle}
                  itemStyle={{ color: palette.onSurface }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="flex justify-center gap-6 font-label-caps text-label-xs">
            <div className="flex items-center gap-2"><div className="w-2 h-2 bg-primary-fixed"></div> SYSTEM 1</div>
            <div className="flex items-center gap-2"><div className="w-2 h-2 bg-secondary"></div> SYSTEM 2</div>
          </div>
        </Card>
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card title="Resource Consumption Over Time">
            <div className="h-64 w-full">
                {agents.length === 0 ? (
                  <EmptyState message="Awaiting resource telemetry..." hint="No agent cost data yet" />
                ) : (
                <ResponsiveContainer width="100%" height="100%">
                   <BarChart data={agents}>
                      <XAxis dataKey="id" hide />
                      <YAxis hide />
                      <Tooltip
                         contentStyle={tooltipStyle}
                         itemStyle={{ color: palette.secondary }}
                      />
                      <Bar dataKey="cost_incurred" fill={palette.primary} radius={[2, 2, 0, 0]} />
                   </BarChart>
                </ResponsiveContainer>
                )}
            </div>
        </Card>

        <Card title="Swarm Governance Log">
            <div className="font-code-sm text-[11px] text-on-surface space-y-3">
               {governanceEvents.length > 0 ? governanceEvents.map((evt, i) => (
                 <div key={evt.id || i} className={`border-l-2 pl-3 ${evt.severity === 'critical' || evt.severity === 'high' ? 'border-error' : 'border-primary-fixed'}`}>
                    <div className="font-label-caps text-on-surface-variant mb-1 uppercase text-label-xs tracking-tighter">
                        DECISION: {evt.event_type?.toUpperCase().replace(/_/g, ' ')}
                    </div>
                    <div>
                        {typeof evt.action === 'string' ? evt.action : (evt.details?.reason || evt.result?.summary || `Event triggered by ${evt.actor_id}`)}
                    </div>
                 </div>
               )) : (
                   <EmptyState message="Awaiting swarm governance decisions..." />
               )}
            </div>
        </Card>
      </div>
    </div>
  );
};

import React, { useMemo } from 'react';
import { Card } from '../components/shared/Card';
import { ApprovalQueue } from '../components/shared/ApprovalQueue';
import { EmptyState } from '../components/shared/EmptyState';
import { useSwarmStore } from '../store/useSwarmStore';
import { useIntelligenceStore } from '../store/useIntelligenceStore';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';
import { Cpu } from 'lucide-react';

const cssVar = (name: string, fallback: string) => {
  if (typeof document === 'undefined') return fallback;
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fallback;
};

export const MissionControl: React.FC = () => {
  const { agents, budget } = useSwarmStore();
  const { auditLog } = useIntelligenceStore();

  const palette = useMemo(() => ({
    accent: cssVar('--accent', '#39ff14'),
    interactive: cssVar('--interactive', '#00e5f0'),
    danger: cssVar('--danger', '#ef4444'),
    textPrimary: cssVar('--text-primary', '#f0f0f2'),
    textSecondary: cssVar('--text-secondary', '#a0a3ab'),
    surface2: cssVar('--surface-2', '#18181b'),
    surface3: cssVar('--surface-3', '#1f1f23'),
    border: cssVar('--border', '#27272a'),
  }), []);

  const tooltipStyle = useMemo(() => ({
    background: palette.surface2,
    border: `1px solid ${palette.border}`,
    borderRadius: 'var(--radius-md)',
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: 11,
  }), [palette]);

  const costData = [
    { name: 'System 1', value: budget.system1Requests * 0.001 },
    { name: 'System 2', value: budget.system2Requests * 0.15 },
  ];

  const COLORS = [palette.accent, palette.interactive];

  const governanceEvents = auditLog.filter((e: any) =>
    e.event_type === 'phase_transition' ||
    e.event_type === 'budget_update' ||
    e.event_type?.includes('approval') ||
    e.severity === 'high' ||
    e.severity === 'critical'
  ).slice(0, 5);

  return (
    <div className="flex flex-col" style={{ gap: 16 }}>
      <ApprovalQueue />

      <div className="grid grid-cols-3" style={{ gap: 16 }}>
        <div className="col-span-2">
          <Card title="Agent Utilization" subtitle={`${agents.length} persona specialists registered`}>
            <div style={{ maxHeight: 384, overflowY: 'auto' }} className="custom-scrollbar">
              {agents.length > 0 ? (
                <div className="flex flex-col" style={{ gap: 8 }}>
                  {agents.map(agent => (
                    <div
                      key={agent.id}
                      className="flex items-center justify-between"
                      style={{
                        padding: '12px 16px',
                        background: 'var(--surface-2)',
                        border: '1px solid var(--border)',
                        borderRadius: 'var(--radius-md)',
                        transition: 'border-color var(--duration-fast)',
                      }}
                    >
                      <div className="flex items-center gap-3">
                        <div
                          style={{
                            width: 8,
                            height: 8,
                            borderRadius: '50%',
                            background: agent.status === 'running' ? 'var(--accent)' : 'var(--text-disabled)',
                            boxShadow: agent.status === 'running' ? 'var(--shadow-glow)' : 'none',
                          }}
                        />
                        <div>
                          <div
                            style={{
                              fontFamily: "'JetBrains Mono', monospace",
                              fontSize: 13,
                              fontWeight: 600,
                              color: 'var(--accent)',
                            }}
                          >
                            {agent.id?.toUpperCase()}
                          </div>
                          <div
                            style={{
                              fontFamily: "'JetBrains Mono', monospace",
                              fontSize: 10,
                              color: 'var(--text-tertiary)',
                              letterSpacing: '0.08em',
                              textTransform: 'uppercase',
                            }}
                          >
                            {agent.type?.replace(/_/g, ' ')}
                          </div>
                        </div>
                      </div>
                      <div className="text-right">
                        <div
                          style={{
                            fontFamily: "'JetBrains Mono', monospace",
                            fontSize: 13,
                            fontWeight: 600,
                            color: 'var(--interactive)',
                            fontVariantNumeric: 'tabular-nums',
                          }}
                        >
                          ${(agent.cost_incurred || 0).toFixed(2)}
                        </div>
                        <div
                          style={{
                            fontFamily: "'JetBrains Mono', monospace",
                            fontSize: 9,
                            color: 'var(--text-disabled)',
                            letterSpacing: '0.1em',
                            textTransform: 'uppercase',
                          }}
                        >
                          COST
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState
                  message="No agents active — awaiting swarm initialization"
                  icon={<Cpu size={24} />}
                />
              )}
            </div>
          </Card>
        </div>

        <Card title="Cost Allocation" subtitle="System 1 vs System 2">
          <div style={{ height: 256 }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={costData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {costData.map((_, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} stroke="none" />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={tooltipStyle}
                  formatter={(value: number) => [`$${value.toFixed(2)}`, '']}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="flex justify-center" style={{ gap: 20 }}>
            <div className="flex items-center gap-2">
              <div style={{ width: 8, height: 8, borderRadius: 2, background: palette.accent }} />
              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: 'var(--text-tertiary)', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                SYSTEM 1
              </span>
            </div>
            <div className="flex items-center gap-2">
              <div style={{ width: 8, height: 8, borderRadius: 2, background: palette.interactive }} />
              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: 'var(--text-tertiary)', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                SYSTEM 2
              </span>
            </div>
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-2" style={{ gap: 16 }}>
        <Card title="Resource Consumption" subtitle="Cost per agent over time">
          <div style={{ height: 256 }}>
            {agents.length === 0 ? (
              <EmptyState message="No agent cost data yet" icon={<Cpu size={24} />} />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={agents} margin={{ top: 4, right: 8, left: 8, bottom: 4 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" vertical={false} />
                  <XAxis
                    dataKey="id"
                    tick={{ fill: 'var(--text-tertiary)', fontSize: 9, fontFamily: "'JetBrains Mono', monospace" }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <YAxis
                    tick={{ fill: 'var(--text-tertiary)', fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }}
                    axisLine={false}
                    tickLine={false}
                    tickFormatter={(v) => `$${v}`}
                  />
                  <Tooltip
                    contentStyle={tooltipStyle}
                    formatter={(value: number) => [`$${value.toFixed(2)}`, 'Cost']}
                    cursor={{ fill: 'var(--surface-hover)' }}
                  />
                  <Bar dataKey="cost_incurred" radius={[4, 4, 0, 0]} barSize={24}>
                    {agents.map((agent) => (
                      <Cell
                        key={agent.id}
                        fill={agent.status === 'running' ? palette.accent : '#45474f'}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>

        <Card title="Governance Log" subtitle="Phase transitions and critical events">
          <div style={{ maxHeight: 280, overflowY: 'auto' }} className="custom-scrollbar">
            {governanceEvents.length > 0 ? (
              <div className="flex flex-col" style={{ gap: 10 }}>
                {governanceEvents.map((evt: any, i: number) => {
                  const isHigh = evt.severity === 'critical' || evt.severity === 'high';
                  const borderColor = isHigh ? 'var(--danger)' : 'var(--accent)';
                  return (
                    <div
                      key={evt.id || i}
                      style={{
                        borderLeft: `3px solid ${borderColor}`,
                        paddingLeft: 12,
                        paddingTop: 4,
                        paddingBottom: 4,
                      }}
                    >
                      <div
                        style={{
                          fontFamily: "'JetBrains Mono', monospace",
                          fontSize: 9,
                          fontWeight: 700,
                          letterSpacing: '0.1em',
                          textTransform: 'uppercase',
                          color: 'var(--text-tertiary)',
                          marginBottom: 4,
                        }}
                      >
                        {evt.event_type?.toUpperCase().replace(/_/g, ' ')}
                      </div>
                      <div
                        style={{
                          fontFamily: "'JetBrains Mono', monospace",
                          fontSize: 12,
                          color: 'var(--text-primary)',
                          lineHeight: 1.5,
                        }}
                      >
                        {typeof evt.action === 'string'
                          ? evt.action
                          : (evt.details?.reason || evt.result?.summary || `Event by ${evt.actor_id}`)}
                      </div>
                      <div
                        style={{
                          fontFamily: "'JetBrains Mono', monospace",
                          fontSize: 10,
                          color: 'var(--text-disabled)',
                          marginTop: 2,
                        }}
                      >
                        {evt.timestamp ? new Date(evt.timestamp).toLocaleString() : ''}
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <EmptyState message="No governance events yet" />
            )}
          </div>
        </Card>
      </div>
    </div>
  );
};

import React, { useMemo } from 'react';
import { Card } from '../components/shared/Card';
import { StatTile } from '../components/shared/StatTile';
import { EmptyState } from '../components/shared/EmptyState';
import { MissionBriefing } from '../components/shared/MissionBriefing';
import { FindingDetail } from '../components/shared/FindingDetail';
import { AttackTimeline } from '../components/shared/AttackTimeline';
import { useSwarmStore } from '../store/useSwarmStore';
import { useIntelligenceStore } from '../store/useIntelligenceStore';
import {
  ShieldAlert, Cpu, Crosshair, Radar,
  Clock, Users, Zap
} from 'lucide-react';
import { Link } from 'react-router-dom';
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Legend,
} from 'recharts';

// Read CSS variables for Recharts (SVG attributes can't use var())
const cssVar = (name: string, fallback: string) => {
  if (typeof document === 'undefined') return fallback;
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fallback;
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f59e0b',
  medium: '#00e5f0',
  low: '#a0a3ab',
  info: '#6b6e78',
};

const STATUS_COLORS: Record<string, string> = {
  verified: '#39ff14',
  validated: '#00e5f0',
  hypothesis: '#3b82f6',
  report_ready: '#f59e0b',
  rejected: '#6b6e78',
};

export const Overview: React.FC = () => {
  const { agents, budget } = useSwarmStore();
  const { findings, verifications } = useIntelligenceStore();

  const verifiedCount = (findings || []).filter(f => f.status === 'verified').length;
  const pendingCount = (verifications || []).length;
  const criticalCount = (findings || []).filter(f => f.severity === 'critical').length;
  const rejectedCount = (findings || []).filter(f => f.status === 'validated').length;
  const activeAgents = (agents || []).filter(a => a.status === 'running').length;

  const total = (findings || []).length;
  const conversion = total > 0 ? ((verifiedCount / total) * 100).toFixed(0) : '0';
  const fpr = total > 0 ? ((rejectedCount / total) * 100).toFixed(1) : '0.0';
  const spent = (budget?.spent || 0) + (agents || []).reduce((acc, a) => acc + (a.cost_incurred || 0), 0);
  const cap = budget?.total || 1000;
  const spendPct = Math.min(100, (spent / (cap || 1)) * 100);

  // ── Chart data ─────────────────────────────────────────────────────
  const severityData = useMemo(() => {
    const counts: Record<string, number> = {};
    (findings || []).forEach(f => {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
    });
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [findings]);

  const statusData = useMemo(() => {
    const counts: Record<string, number> = {};
    (findings || []).forEach(f => {
      counts[f.status] = (counts[f.status] || 0) + 1;
    });
    return Object.entries(counts).map(([name, value]) => ({
      name: name.replace(/_/g, ' ').toUpperCase(),
      value,
      fill: STATUS_COLORS[name] || '#6b6e78',
    }));
  }, [findings]);

  const agentCostData = useMemo(() => {
    return (agents || []).map(a => ({
      name: a.id?.replace(/eng-.*-/, '').slice(0, 12) || a.id,
      cost: a.cost_incurred || 0,
      status: a.status,
    }));
  }, [agents]);

  const tooltipStyle = useMemo(() => ({
    background: 'var(--surface-2)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-md)',
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: 11,
  }), []);

  return (
    <div className="flex flex-col" style={{ gap: 20 }}>
      {/* ── Mission Briefing ───────────────────────────────────────── */}
      <MissionBriefing />

      {/* ── KPI Grid ────────────────────────────────────────────────── */}
      <div className="grid grid-cols-4" style={{ gap: 16 }}>
        <StatTile
          label="Verified Findings"
          value={verifiedCount}
          caption={`${conversion}% conversion rate`}
          accent="primary"
          icon={<Crosshair size={16} />}
          delay={0}
        />
        <StatTile
          label="Critical Findings"
          value={criticalCount}
          caption="High-severity confirmed"
          accent="error"
          icon={<ShieldAlert size={16} />}
          delay={60}
        />
        <StatTile
          label="Pending Approvals"
          value={pendingCount}
          caption="Awaiting operator decision"
          accent="warning"
          icon={<Clock size={16} />}
          delay={120}
        />
        <StatTile
          label="Active Agents"
          value={activeAgents}
          caption={`${(agents || []).length} total persona specialists`}
          accent="secondary"
          icon={<Users size={16} />}
          delay={180}
        />
      </div>

      {/* ── Charts Row: Severity + Status ───────────────────────────── */}
      <div className="grid grid-cols-3" style={{ gap: 16 }}>
        <div className="reveal-up" style={{ animationDelay: '200ms' }}>
          <Card title="Severity Distribution" subtitle="Findings by risk level">
            {severityData.length > 0 ? (
              <div style={{ height: 220 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={severityData}
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={80}
                      paddingAngle={3}
                      dataKey="value"
                    >
                      {severityData.map((entry) => (
                        <Cell
                          key={entry.name}
                          fill={SEVERITY_COLORS[entry.name] || '#6b6e78'}
                          stroke="none"
                        />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={tooltipStyle}
                      itemStyle={{ color: 'var(--text-primary)' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
                <div className="flex justify-center flex-wrap" style={{ gap: 12, marginTop: 4 }}>
                  {severityData.map((entry) => (
                    <div key={entry.name} className="flex items-center gap-1.5">
                      <div
                        style={{
                          width: 8,
                          height: 8,
                          borderRadius: 2,
                          background: SEVERITY_COLORS[entry.name] || '#6b6e78',
                        }}
                      />
                      <span
                        style={{
                          fontFamily: "'JetBrains Mono', monospace",
                          fontSize: 10,
                          color: 'var(--text-tertiary)',
                          textTransform: 'uppercase',
                        }}
                      >
                        {entry.name} ({entry.value})
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <EmptyState message="No findings to chart" icon={<Radar size={24} />} />
            )}
          </Card>
        </div>

        <div className="reveal-up" style={{ animationDelay: '260ms' }}>
          <Card title="Status Pipeline" subtitle="Findings by verification stage">
            {statusData.length > 0 ? (
              <div style={{ height: 220 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={statusData} layout="vertical" margin={{ left: 0, right: 16 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" horizontal={false} />
                    <XAxis type="number" hide />
                    <YAxis
                      type="category"
                      dataKey="name"
                      width={90}
                      tick={{ fill: 'var(--text-tertiary)', fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <Tooltip
                      contentStyle={tooltipStyle}
                      cursor={{ fill: 'var(--surface-hover)' }}
                    />
                    <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={18}>
                      {statusData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.fill} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <EmptyState message="No findings to chart" icon={<Radar size={24} />} />
            )}
          </Card>
        </div>

        <div className="reveal-up" style={{ animationDelay: '320ms' }}>
          <Card title="Agent Cost" subtitle="Spend per persona specialist">
            {agentCostData.length > 0 ? (
              <div style={{ height: 220 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={agentCostData} margin={{ top: 4, right: 8, left: 8, bottom: 4 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" vertical={false} />
                    <XAxis
                      dataKey="name"
                      tick={{ fill: 'var(--text-tertiary)', fontSize: 9, fontFamily: "'JetBrains Mono', monospace" }}
                      axisLine={false}
                      tickLine={false}
                      interval={0}
                      angle={-30}
                      textAnchor="end"
                      height={50}
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
                    <Bar dataKey="cost" radius={[4, 4, 0, 0]} barSize={24}>
                      {agentCostData.map((entry) => (
                        <Cell
                          key={entry.name}
                          fill={entry.status === 'running' ? '#39ff14' : '#45474f'}
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <EmptyState message="No agent cost data" icon={<Cpu size={24} />} />
            )}
          </Card>
        </div>
      </div>

      {/* ── Findings + Timeline ────────────────────────────────────── */}
      <div className="grid grid-cols-3" style={{ gap: 16 }}>
        <div className="col-span-2 reveal-up" style={{ animationDelay: '360ms' }}>
          <Card title="Recent Findings" subtitle={`${total} total findings discovered`}>
            <div style={{ maxHeight: 440, overflowY: 'auto' }} className="custom-scrollbar">
              {(findings || []).length > 0 ? (
                <div className="flex flex-col" style={{ gap: 8 }}>
                  {(findings || []).slice(0, 6).map((f) => (
                    <FindingDetail key={f.id} finding={f} />
                  ))}
                </div>
              ) : (
                <EmptyState
                  message="No findings yet — swarm is scanning the attack surface"
                  icon={<Radar size={24} />}
                />
              )}
            </div>
          </Card>
        </div>

        <div className="reveal-up" style={{ animationDelay: '420ms' }}>
          <AttackTimeline />
        </div>
      </div>

      {/* ── Agent Performance + Budget ─────────────────────────────── */}
      <div className="grid grid-cols-3" style={{ gap: 16 }}>
        <div className="col-span-2 reveal-up" style={{ animationDelay: '480ms' }}>
          <Card title="Agent Performance" subtitle="Cost allocation across persona specialists">
            <div className="flex flex-col" style={{ gap: 8 }}>
              {(agents || []).length > 0 ? (
                (agents || []).map(agent => (
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
                ))
              ) : (
                <EmptyState
                  message="No agents active — awaiting swarm initialization"
                  icon={<Cpu size={24} />}
                />
              )}
            </div>
          </Card>
        </div>

        <div className="reveal-up" style={{ animationDelay: '540ms' }}>
          <Card title="Budget Utilization" accent={spendPct > 80 ? 'danger' : 'success'}>
            <div className="flex flex-col" style={{ gap: 16 }}>
              {/* Spend bar */}
              <div>
                <div className="flex justify-between items-end mb-2">
                  <div
                    style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: 11,
                      color: 'var(--text-tertiary)',
                    }}
                  >
                    SPENT
                  </div>
                  <div className="flex items-baseline gap-2">
                    <span
                      style={{
                        fontFamily: "'Space Grotesk', sans-serif",
                        fontSize: 24,
                        fontWeight: 800,
                        color: spendPct > 80 ? 'var(--danger)' : 'var(--accent)',
                        fontVariantNumeric: 'tabular-nums',
                      }}
                    >
                      ${spent.toFixed(2)}
                    </span>
                    <span
                      style={{
                        fontFamily: "'JetBrains Mono', monospace",
                        fontSize: 11,
                        color: 'var(--text-tertiary)',
                      }}
                    >
                      / ${cap.toFixed(2)}
                    </span>
                  </div>
                </div>
                <div className="progress">
                  <div
                    className="progress-bar"
                    style={{
                      width: `${spendPct}%`,
                      background: spendPct > 80 ? 'var(--danger)' : 'var(--accent)',
                    }}
                  />
                </div>
                <div className="flex justify-between mt-1">
                  <span
                    style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: 10,
                      color: 'var(--text-disabled)',
                    }}
                  >
                    {spendPct.toFixed(0)}% UTILIZED
                  </span>
                  <span
                    style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: 10,
                      color: 'var(--text-disabled)',
                    }}
                  >
                    ${(cap - spent).toFixed(2)} REMAINING
                  </span>
                </div>
              </div>

              {/* Quick stats */}
              <div className="grid grid-cols-2" style={{ gap: 8 }}>
                <div
                  style={{
                    padding: '10px 12px',
                    background: 'var(--surface-2)',
                    border: '1px solid var(--border)',
                    borderRadius: 'var(--radius-md)',
                  }}
                >
                  <div
                    style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: 9,
                      color: 'var(--text-disabled)',
                      letterSpacing: '0.1em',
                      textTransform: 'uppercase',
                      marginBottom: 4,
                    }}
                  >
                    FALSE POSITIVE RATE
                  </div>
                  <div
                    style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: 16,
                      fontWeight: 700,
                      color: parseFloat(fpr) < 10 ? 'var(--accent)' : 'var(--warning)',
                      fontVariantNumeric: 'tabular-nums',
                    }}
                  >
                    {fpr}%
                  </div>
                </div>
                <div
                  style={{
                    padding: '10px 12px',
                    background: 'var(--surface-2)',
                    border: '1px solid var(--border)',
                    borderRadius: 'var(--radius-md)',
                  }}
                >
                  <div
                    style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: 9,
                      color: 'var(--text-disabled)',
                      letterSpacing: '0.1em',
                      textTransform: 'uppercase',
                      marginBottom: 4,
                    }}
                  >
                    TOTAL FINDINGS
                  </div>
                  <div
                    style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: 16,
                      fontWeight: 700,
                      color: 'var(--interactive)',
                      fontVariantNumeric: 'tabular-nums',
                    }}
                  >
                    {total}
                  </div>
                </div>
              </div>

              {/* Quick actions */}
              <div className="flex gap-2">
                <Link to="/findings" className="btn btn-secondary btn-sm flex-1" style={{ justifyContent: 'center' }}>
                  <ShieldAlert size={12} />
                  View Findings
                </Link>
                <Link to="/admin" className="btn btn-ghost btn-sm flex-1" style={{ justifyContent: 'center' }}>
                  <Zap size={12} />
                  Admin Panel
                </Link>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};

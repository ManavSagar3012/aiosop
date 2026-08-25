import React from 'react';
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

      {/* ── Findings + Timeline ────────────────────────────────────── */}
      <div className="grid grid-cols-3" style={{ gap: 16 }}>
        <div className="col-span-2 reveal-up" style={{ animationDelay: '240ms' }}>
          <Card title="Recent Findings" subtitle={`${total} total findings discovered`}>
            <div style={{ maxHeight: 440, overflowY: 'auto' }} className="custom-scrollbar">
              {(findings || []).length > 0 ? (
                <div className="flex flex-col" style={{ gap: 8 }}>
                  {(findings || []).slice(0, 8).map((f) => (
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

        <div className="reveal-up" style={{ animationDelay: '300ms' }}>
          <AttackTimeline />
        </div>
      </div>

      {/* ── System Health + Budget ──────────────────────────────────── */}
      <div className="grid grid-cols-3" style={{ gap: 16 }}>
        <div className="col-span-2 reveal-up" style={{ animationDelay: '360ms' }}>
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

        <div className="reveal-up" style={{ animationDelay: '420ms' }}>
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

import React from 'react';
import { Card } from '../components/shared/Card';
import { StatTile } from '../components/shared/StatTile';
import { StatusBadge } from '../components/shared/StatusBadge';
import { DataTable, Column } from '../components/shared/DataTable';
import { EmptyState } from '../components/shared/EmptyState';
import { MissionBriefing } from '../components/shared/MissionBriefing';
import { FindingDetail } from '../components/shared/FindingDetail';
import { AttackTimeline } from '../components/shared/AttackTimeline';
import { useSwarmStore } from '../store/useSwarmStore';
import { useIntelligenceStore, Finding } from '../store/useIntelligenceStore';
import {
  Activity, ShieldAlert, FileText, Cpu, Crosshair, Radar,
  ArrowUpRight, Terminal
} from 'lucide-react';
import { Link } from 'react-router-dom';

const ledgerColumns: Column<Finding>[] = [
  {
    key: 'title',
    header: 'Finding',
    render: (f) => (
      <span className="text-primary font-bold group-hover:text-primary-fixed transition-colors">{f.title}</span>
    ),
  },
  {
    key: 'category',
    header: 'Type',
    render: (f) => (
      <span className="text-on-surface-variant uppercase text-label-xs tracking-wide">
        {f.category?.replace(/_/g, ' ')}
      </span>
    ),
  },
  {
    key: 'evScore',
    header: 'EV Score',
    width: 'w-32',
    render: (f) => (
      <div className="flex items-center gap-2">
        <div className="h-1 w-16 bg-surface-variant overflow-hidden">
          <div
            className="h-full bg-secondary"
            style={{ width: `${Math.min(100, f.evScore || 0)}%` }}
          />
        </div>
        <span className="text-secondary tabular-nums">{(f.evScore || 0).toFixed(0)}</span>
      </div>
    ),
  },
  {
    key: 'status',
    header: 'Status',
    render: (f) => <StatusBadge value={f.status} />,
  },
];

export const Overview: React.FC = () => {
  const { agents, budget } = useSwarmStore();
  const { findings, verifications, sessionId } = useIntelligenceStore();

  const verifiedCount = (findings || []).filter(f => f.status === 'verified').length;
  const pendingCount = (verifications || []).length;
  const criticalCount = (findings || []).filter(f => f.severity === 'critical').length;
  const rejectedCount = (findings || []).filter(f => f.status === 'rejected').length;

  const total = (findings || []).length;
  const conversion = total > 0 ? ((verifiedCount / total) * 100).toFixed(0) : '0';
  const fpr = total > 0 ? ((rejectedCount / total) * 100).toFixed(1) : '0.0';
  const spent = (budget?.spent || 0) + (agents || []).reduce((acc, a) => acc + (a.cost_incurred || 0), 0);
  const cap = budget?.total || 1000;
  const spendPct = Math.min(100, (spent / (cap || 1)) * 100);

  return (
    <div className="flex flex-col gap-gutter">
      {/* ── Mission Briefing ───────────────────────────────────────── */}
      <MissionBriefing />

      {/* ── KPI grid ────────────────────────────────────────────────── */}
      <div className="grid grid-cols-4 gap-gutter">
        <StatTile
          label="Operational Success" value={verifiedCount} caption="Verified Findings"
          accent="primary" icon={<Crosshair size={16} />} meta={`${conversion}% CONV`} delay={60}
        />
        <StatTile
          label="Risk Exposure" value={criticalCount} caption="Critical Assets Leaked"
          accent="error" icon={<ShieldAlert size={16} />} delay={120}
        />
        <StatTile
          label="Pending Triage" value={pendingCount} caption="Awaiting Consensus"
          accent="secondary" icon={<Radar size={16} />} delay={180}
        />
        <StatTile
          label="Precision Audit" value={rejectedCount} caption="Rejected / Duplicates"
          accent="muted" icon={<Activity size={16} />} meta={`FPR ${fpr}%`} delay={240}
        />
      </div>

      {/* ── Timeline + Findings ────────────────────────────────────── */}
      <div className="grid grid-cols-3 gap-6">
        <div className="reveal-up col-span-2" style={{ animationDelay: '300ms' }}>
          <Card title="Findings" className="min-h-[400px] overflow-hidden">
            <div className="max-h-[420px] space-y-3">
              {(findings || []).length > 0 ? (
                (findings || []).slice(0, 10).map((f) => (
                  <FindingDetail key={f.id} finding={f} />
                ))
              ) : (
                <EmptyState
                  message="No findings yet — swarm is scanning the attack surface…"
                  icon={<Radar size={28} />}
                />
              )}
            </div>
          </Card>
        </div>

        <div className="reveal-up" style={{ animationDelay: '360ms' }}>
          <AttackTimeline />
        </div>
      </div>

      {/* ── Ledger + Health ─────────────────────────────────────────── */}
      <div className="grid grid-cols-3 gap-6">
        <div className="reveal-up col-span-2" style={{ animationDelay: '400ms' }}>
          <Card title="Swarm Activity Ledger" className="min-h-[300px] overflow-hidden">
            <div className="max-h-[320px]">
              <DataTable<Finding>
                columns={ledgerColumns}
                rows={findings || []}
                rowKey={(f) => f.id}
                empty={
                  <EmptyState
                    message="No findings yet"
                    icon={<Radar size={28} />}
                  />
                }
              />
            </div>
          </Card>
        </div>

        <div className="reveal-up" style={{ animationDelay: '460ms' }}>
          <Card title="System Health Monitoring">
            <div className="space-y-5 py-1">
              <div className="hud-corners bg-black/40 border border-outline-variant p-4">
                <div className="font-label-caps text-label-caps text-on-surface-variant mb-3 uppercase">
                  Active Swarm Engine
                </div>
                <div className="flex items-center gap-4">
                  <Cpu size={22} className="text-primary-fixed animate-pulse-neon" />
                  <div className="font-display-lg text-display-lg text-primary-fixed leading-none">
                    {(agents || []).length}
                  </div>
                  <div className="font-code-sm text-on-surface-variant text-label-xs uppercase leading-tight">
                    Persona<br />Specialists Active
                  </div>
                </div>
              </div>

              <div className="bg-black/40 border border-outline-variant p-4">
                <div className="font-label-caps text-label-caps text-on-surface-variant mb-3 uppercase">
                  Operational Spend
                </div>
                <div className="flex items-center justify-between mb-2 font-code-sm text-[11px]">
                  <span className="text-on-surface-variant">${spent.toFixed(2)} <span className="opacity-50">SPENT</span></span>
                  <span className="text-primary-fixed">${cap.toFixed(2)} <span className="opacity-50">CAP</span></span>
                </div>
                <div className="h-1.5 bg-surface-variant w-full overflow-hidden">
                  <div className="h-full bg-primary-fixed glow-cyan transition-all duration-500" style={{ width: `${spendPct}%` }} />
                </div>
                <div className="mt-1.5 text-right font-code-sm text-label-xs text-on-surface-variant/60 tabular-nums">
                  {spendPct.toFixed(0)}% UTILIZED
                </div>
              </div>

              <div className="flex items-center gap-2 pt-1 text-on-surface-variant/50">
                <span className="w-1.5 h-1.5 rounded-full bg-primary-fixed live-dot" />
                <p className="font-code-sm text-label-xs italic">Monitoring live swarm telemetry…</p>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};

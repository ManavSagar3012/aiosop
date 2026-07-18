import React from 'react';
import { Card } from '../components/shared/Card';
import { StatTile } from '../components/shared/StatTile';
import { StatusBadge } from '../components/shared/StatusBadge';
import { DataTable, Column } from '../components/shared/DataTable';
import { EmptyState } from '../components/shared/EmptyState';
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
  const spent = budget?.spent || 0;
  const cap = budget?.total || 0;
  const spendPct = Math.min(100, (spent / (cap || 1)) * 100);

  // Show loading skeleton while waiting for first data
  if (!sessionId && findings.length === 0) {
    return (
      <div className="flex flex-col gap-gutter">
        <div className="bg-surface-container-low border border-outline-variant p-5 animate-pulse">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-surface-container-high/60 border border-outline-variant/40"></div>
            <div className="space-y-2">
              <div className="h-7 w-64 bg-surface-container-high/60"></div>
              <div className="h-4 w-48 bg-surface-container-high/60"></div>
            </div>
          </div>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-gutter">
          {[1,2,3,4].map(i => (
            <div key={i} className="bg-surface-container-low border border-outline-variant p-5 animate-pulse" style={{animationDelay: i * 80 + 'ms'}}>
              <div className="h-3 w-24 bg-surface-container-high/60 mb-3"></div>
              <div className="h-8 w-16 bg-surface-container-high/60 mb-2"></div>
              <div className="h-3 w-32 bg-surface-container-high/60"></div>
            </div>
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="col-span-2 bg-surface-container-low border border-outline-variant p-5 animate-pulse h-[400px]">
            <div className="h-5 w-48 bg-surface-container-high/60 mb-6"></div>
            <div className="space-y-4">
              {[1,2,3].map(i => (
                <div key={i} className="h-16 bg-surface-container-high/60 border border-outline-variant/40"></div>
              ))}
            </div>
          </div>
          <div className="bg-surface-container-low border border-outline-variant p-5 animate-pulse h-[400px]">
            <div className="h-5 w-40 bg-surface-container-high/60 mb-6"></div>
            <div className="space-y-4">
              {[1,2,3].map(i => (
                <div key={i} className="h-20 bg-surface-container-high/60 border border-outline-variant/40"></div>
              ))}
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-gutter">
      {/* ── Command bar ─────────────────────────────────────────────── */}
      <header className="reveal-up hud-corners relative bg-surface-container-low border border-outline-variant overflow-hidden">
        <div className="absolute inset-0 terminal-grid opacity-[0.06] pointer-events-none" />
        {/* ambient sweep */}
        <div className="absolute top-0 left-0 h-px w-1/4 bg-gradient-to-r from-transparent via-primary-fixed to-transparent sweep-line pointer-events-none" />
        <div className="relative flex items-center justify-between p-5">
          <div className="flex items-center gap-4">
            <div className="relative p-2.5 bg-primary-fixed/10 border border-primary-fixed/30 text-primary-fixed">
              <Terminal size={20} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="font-display-lg text-display-lg text-on-surface tracking-tight">
                  COMMAND CORE
                </h1>
                <span className="w-1.5 h-1.5 rounded-full bg-primary-fixed live-dot" />
              </div>
              {sessionId ? (
                <div className="font-code-sm text-[11px] text-on-surface-variant mt-0.5">
                  ACTIVE SESSION <span className="text-primary-fixed">{sessionId}</span>
                </div>
              ) : (
                <div className="font-code-sm text-[11px] text-on-surface-variant/60 mt-0.5 italic">
                  Standing by — no active research session
                </div>
              )}
            </div>
          </div>
          {sessionId && (
            <Link
              to={`/report/${sessionId}`}
              className="flex items-center gap-2 px-4 py-2 bg-primary-fixed text-black font-label-caps text-[11px] font-bold hover:brightness-110 active:scale-95 transition-all glow-cyan"
            >
              <FileText size={14} /> MISSION REPORT <ArrowUpRight size={13} />
            </Link>
          )}
        </div>
      </header>

      {/* ── KPI grid ────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-gutter">
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

      {/* ── Ledger + Health ─────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="reveal-up col-span-2" style={{ animationDelay: '300ms' }}>
          <Card title="Swarm Activity Ledger" className="min-h-[400px] overflow-hidden">
            <div className="max-h-[420px]">
              <DataTable<Finding>
                columns={ledgerColumns}
                rows={findings || []}
                rowKey={(f) => f.id}
                empty={
                  <EmptyState
                    message="No findings yet — swarm is scanning the attack surface…"
                    icon={<Radar size={28} />}
                  />
                }
              />
            </div>
          </Card>
        </div>

        <div className="reveal-up" style={{ animationDelay: '360ms' }}>
          <Card title="System Health Monitoring">
            <div className="space-y-5 py-1">
              {/* Active swarm */}
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

              {/* Spend */}
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

              {/* Telemetry */}
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

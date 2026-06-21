import React from 'react';
import { Card } from '../components/shared/Card';
import { useSwarmStore } from '../store/useSwarmStore';
import { useIntelligenceStore } from '../store/useIntelligenceStore';
import {
  Activity, ShieldAlert, FileText, Cpu, Crosshair, Radar,
  ArrowUpRight, Terminal
} from 'lucide-react';
import { Link } from 'react-router-dom';

// ── Local presentational helpers (no new deps; data still flows from stores) ──

interface KpiProps {
  label: string;
  value: number;
  caption: string;
  accent: 'primary' | 'error' | 'secondary' | 'muted';
  icon: React.ReactNode;
  meta?: string;
  delay: number;
}

const ACCENT: Record<KpiProps['accent'], { text: string; border: string }> = {
  primary:   { text: 'text-primary-fixed',      border: 'border-t-primary-fixed' },
  error:     { text: 'text-error',              border: 'border-t-error' },
  secondary: { text: 'text-secondary',          border: 'border-t-secondary' },
  muted:     { text: 'text-on-surface-variant', border: 'border-t-outline-variant' },
};

const KpiTile: React.FC<KpiProps> = ({ label, value, caption, accent, icon, meta, delay }) => {
  const a = ACCENT[accent];
  return (
    <div
      className={`reveal-up hud-corners group relative bg-surface-container border border-outline-variant border-t-2 ${a.border} p-5 overflow-hidden transition-all duration-300 hover:border-primary-fixed/40`}
      style={{ animationDelay: `${delay}ms` }}
    >
      <div className="absolute inset-0 terminal-grid opacity-[0.04] pointer-events-none" />
      <div className="relative flex items-start justify-between">
        <div className="font-label-caps text-[9px] text-on-surface-variant uppercase tracking-widest">{label}</div>
        <div className={`${a.text} opacity-40 group-hover:opacity-90 transition-opacity`}>{icon}</div>
      </div>
      <div className="relative mt-4 flex items-end gap-3">
        <div className={`font-display-lg ${a.text} leading-none tabular-nums`} style={{ fontSize: '40px' }}>
          {value}
        </div>
        {meta && (
          <div className="mb-1.5 font-code-sm text-[10px] text-on-surface-variant">
            {meta}
          </div>
        )}
      </div>
      <div className="relative mt-2 font-code-sm text-[10px] text-on-surface-variant/80 uppercase tracking-wide">
        {caption}
      </div>
    </div>
  );
};

const StatusPill: React.FC<{ status?: string }> = ({ status }) => {
  const map: Record<string, string> = {
    verified:  'border-primary-fixed text-primary-fixed bg-primary-fixed/5',
    validated: 'border-secondary text-secondary bg-secondary/5',
  };
  const cls = map[status || ''] || 'border-outline text-on-surface-variant opacity-50';
  return (
    <span className={`px-2 py-0.5 border font-label-caps text-[9px] ${cls}`}>
      {(status || 'pending').toUpperCase()}
    </span>
  );
};

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
                <h1 className="font-display-lg text-on-surface tracking-tight" style={{ fontSize: '22px' }}>
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
      <div className="grid grid-cols-4 gap-gutter">
        <KpiTile
          label="Operational Success" value={verifiedCount} caption="Verified Findings"
          accent="primary" icon={<Crosshair size={16} />} meta={`${conversion}% CONV`} delay={60}
        />
        <KpiTile
          label="Risk Exposure" value={criticalCount} caption="Critical Assets Leaked"
          accent="error" icon={<ShieldAlert size={16} />} delay={120}
        />
        <KpiTile
          label="Pending Triage" value={pendingCount} caption="Awaiting Consensus"
          accent="secondary" icon={<Radar size={16} />} delay={180}
        />
        <KpiTile
          label="Precision Audit" value={rejectedCount} caption="Rejected / Duplicates"
          accent="muted" icon={<Activity size={16} />} meta={`FPR ${fpr}%`} delay={240}
        />
      </div>

      {/* ── Ledger + Health ─────────────────────────────────────────── */}
      <div className="grid grid-cols-3 gap-6">
        <div className="reveal-up col-span-2" style={{ animationDelay: '300ms' }}>
          <Card title="Swarm Activity Ledger" className="min-h-[400px] overflow-hidden">
            <div className="max-h-[420px] overflow-y-auto custom-scrollbar -mx-2">
              <table className="w-full text-left font-code-sm text-[11px]">
                <thead className="sticky top-0 z-10">
                  <tr className="text-on-surface-variant bg-surface-container-high">
                    <th className="px-3 py-2.5 font-normal tracking-widest text-[9px] uppercase">Finding</th>
                    <th className="px-3 py-2.5 font-normal tracking-widest text-[9px] uppercase">Type</th>
                    <th className="px-3 py-2.5 font-normal tracking-widest text-[9px] uppercase w-32">EV Score</th>
                    <th className="px-3 py-2.5 font-normal tracking-widest text-[9px] uppercase">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {(findings || []).map((f) => (
                    <tr
                      key={f.id}
                      className="border-b border-outline-variant/30 hover:bg-surface-container-high/60 transition-colors group"
                    >
                      <td className="px-3 py-2.5">
                        <span className="text-primary font-bold group-hover:text-primary-fixed transition-colors">{f.title}</span>
                      </td>
                      <td className="px-3 py-2.5 text-on-surface-variant uppercase text-[10px] tracking-wide">
                        {f.category?.replace(/_/g, ' ')}
                      </td>
                      <td className="px-3 py-2.5">
                        <div className="flex items-center gap-2">
                          <div className="h-1 w-16 bg-surface-variant overflow-hidden">
                            <div
                              className="h-full bg-secondary"
                              style={{ width: `${Math.min(100, f.evScore || 0)}%` }}
                            />
                          </div>
                          <span className="text-secondary tabular-nums">{(f.evScore || 0).toFixed(0)}</span>
                        </div>
                      </td>
                      <td className="px-3 py-2.5"><StatusPill status={f.status} /></td>
                    </tr>
                  ))}
                  {(findings || []).length === 0 && (
                    <tr>
                      <td colSpan={4} className="px-3 py-16 text-center">
                        <Radar size={28} className="mx-auto mb-3 text-on-surface-variant opacity-20 animate-pulse-neon" />
                        <div className="font-code-sm text-[11px] text-on-surface-variant/50 italic">
                          No findings yet — swarm is scanning the attack surface…
                        </div>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </Card>
        </div>

        <div className="reveal-up" style={{ animationDelay: '360ms' }}>
          <Card title="System Health Monitoring">
            <div className="space-y-5 py-1">
              {/* Active swarm */}
              <div className="hud-corners bg-black/40 border border-outline-variant p-4">
                <div className="text-[9px] font-label-caps text-on-surface-variant mb-3 uppercase tracking-widest">
                  Active Swarm Engine
                </div>
                <div className="flex items-center gap-4">
                  <Cpu size={22} className="text-primary-fixed animate-pulse-neon" />
                  <div className="font-display-lg text-primary-fixed leading-none" style={{ fontSize: '34px' }}>
                    {(agents || []).length}
                  </div>
                  <div className="font-code-sm text-on-surface-variant text-[10px] uppercase leading-tight">
                    Persona<br />Specialists Active
                  </div>
                </div>
              </div>

              {/* Spend */}
              <div className="bg-black/40 border border-outline-variant p-4">
                <div className="text-[9px] font-label-caps text-on-surface-variant mb-3 uppercase tracking-widest">
                  Operational Spend
                </div>
                <div className="flex items-center justify-between mb-2 font-code-sm text-[11px]">
                  <span className="text-on-surface-variant">${spent.toFixed(2)} <span className="opacity-50">SPENT</span></span>
                  <span className="text-primary-fixed">${cap.toFixed(2)} <span className="opacity-50">CAP</span></span>
                </div>
                <div className="h-1.5 bg-surface-variant w-full overflow-hidden">
                  <div className="h-full bg-primary-fixed glow-cyan transition-all duration-500" style={{ width: `${spendPct}%` }} />
                </div>
                <div className="mt-1.5 text-right font-code-sm text-[9px] text-on-surface-variant/60 tabular-nums">
                  {spendPct.toFixed(0)}% UTILIZED
                </div>
              </div>

              {/* Telemetry */}
              <div className="flex items-center gap-2 pt-1 text-on-surface-variant/50">
                <span className="w-1.5 h-1.5 rounded-full bg-primary-fixed live-dot" />
                <p className="font-code-sm text-[10px] italic">Monitoring live swarm telemetry…</p>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};

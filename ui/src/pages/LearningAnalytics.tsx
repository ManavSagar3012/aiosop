import React, { useMemo } from 'react';
import { Card } from '../components/shared/Card';
import { StatTile } from '../components/shared/StatTile';
import { EmptyState } from '../components/shared/EmptyState';
import { Skeleton } from '../components/shared/Skeleton';
import {
    LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
    BarChart, Bar, Legend, PieChart, Pie, Cell
} from 'recharts';
import { TrendingUp, DollarSign, Target, UserCheck, ShieldCheck, Activity } from 'lucide-react';
import { useIntelligenceStore } from '../store/useIntelligenceStore';
import { useSwarmStore } from '../store/useSwarmStore';

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

export const LearningAnalytics: React.FC = () => {
  const { skillStats, findings } = useIntelligenceStore();
  const { agents } = useSwarmStore();

  const palette = useMemo(() => ({
    primary:   cssVar('--primary', '#39ff14'),                    // success / operational (green)
    secondary: cssVar('--secondary', '#00f1fd'),                  // active / interactive (cyan)
    error:     cssVar('--error', '#ff3131'),                      // critical (red)
    warning:   cssVar('--warning', '#ff9f00'),                    // warning / medium (amber)
    purple:    '#a259ff',                                         // 5th qualitative series — no dedicated token
    axis:      cssVar('--on-surface-variant', '#baccb0'),         // muted axis/legend text
    grid:      cssVar('--surface-container-highest', '#2a2a2d'),  // grid lines
    tooltipBg: cssVar('--surface-container', '#131314'),          // tooltip background
  }), []);

  const tooltipStyle = useMemo(() => ({
    backgroundColor: palette.tooltipBg,
    border: `1px solid ${palette.grid}`,
  }), [palette]);

  const safeStats = skillStats || {
    total_revenue: 0,
    revenue_roi: 0,
    findings_contributed: 0,
    top_skills: [],
    recent_executions: []
  };

  // 1. Accepted Findings Breakdown (derived from findings)
  const acceptanceData = [
    { name: 'Accepted', value: findings.filter(f => f.status === 'verified').length, color: palette.primary },
    { name: 'Validated', value: findings.filter(f => f.status === 'validated').length, color: palette.secondary },
    { name: 'Hypothesis', value: findings.filter(f => f.status === 'hypothesis').length, color: palette.warning },
    { name: 'Rejected', value: findings.filter(f => f.status === 'rejected').length, color: palette.error },
  ].filter(d => d.value > 0);

  // 2. Skill ROI (mapping top_skills to chart format)
  const skillBreakdown = (safeStats.top_skills || []).slice(0, 7).map(s => ({
    category: s.name.length > 15 ? s.id.toUpperCase() : s.name,
    recall: (s.acceptance_rate || 0) * 100,
    cost: s.revenue_roi
  }));

  // 3. Efficiency Curve (Keep mock for trend visualization if live data unavailable)
  const efficiencyCurve = [
    { hours: 1, ai: 5, human: 1 },
    { hours: 2, ai: 12, human: 3 },
    { hours: 4, ai: 25, human: 8 },
    { hours: 8, ai: 45, human: 15 },
    { hours: 16, ai: 85, human: 30 },
    { hours: 24, ai: 120, human: 45 },
  ];

  // 4. Persona ROI (derived from agents and skill usage)
  const personaROI = (safeStats.top_skills || []).slice(0, 4).map(s => ({
    name: s.name.split(' ')[0] + ' Hunter',
    bounty: s.total_payout,
    findings: s.verified_findings || 0,
    efficiency: Math.round((s.reputation || 0) * 10)
  }));

  return (
    <div className="flex flex-col gap-6">
      {/* Top Strategic KPIs */}
      {!skillStats ? (
        <div className="grid grid-cols-4 gap-6">
          <Skeleton className="h-28" />
          <Skeleton className="h-28" />
          <Skeleton className="h-28" />
          <Skeleton className="h-28" />
        </div>
      ) : (
        <div className="grid grid-cols-4 gap-6">
          <StatTile
            label="Engagement ROI" value={`$${(safeStats.total_revenue || 0).toLocaleString()}`}
            caption="Total Bounty Captured" accent="primary" icon={<DollarSign size={16} />}
          />
          <StatTile
            label="Report Acceptance"
            value={`${findings.length > 0 ? ((findings.filter(f => f.status === 'verified').length / findings.length) * 100).toFixed(1) : "0.0"}%`}
            caption="Verified → Accepted Rate" accent="secondary" icon={<ShieldCheck size={16} />}
          />
          <StatTile
            label="Discovery Efficiency" value="18.5x"
            caption="Vs Human Baseline (Speed)" accent="primary" icon={<TrendingUp size={16} />}
          />
          <StatTile
            label="Variant Yield" value={`${(safeStats.revenue_roi || 1).toFixed(1)}x`}
            caption="Revenue / Cost Ratio" accent="error" icon={<Activity size={16} />}
          />
        </div>
      )}

      {/* Persona ROI Section */}
      <div className="grid grid-cols-1">
        <Card title="Research Persona Performance (ROI Breakdown)">
           <div className="grid grid-cols-4 gap-8 py-4">
              {personaROI.length > 0 ? personaROI.map(p => (
                <div key={p.name} className="bg-black/40 border border-outline-variant p-5 relative overflow-hidden group hover:border-primary-fixed/30 transition-all">
                   <div className="flex justify-between items-start mb-4">
                      <div>
                         <div className="font-headline-md text-primary-fixed text-[16px] uppercase tracking-wider">{p.name}</div>
                         <div className="font-code-sm text-on-surface-variant text-[10px]">VERIFIED FINDINGS: {p.findings}</div>
                      </div>
                      <div className="font-display-lg text-on-surface text-[18px]">${p.bounty.toLocaleString()}</div>
                   </div>

                   <div className="space-y-1">
                      <div className="flex justify-between text-label-xs font-label-caps text-on-surface-variant mb-1">
                         <span>Skill Reputation</span>
                         <span className="text-primary-fixed">{p.efficiency}%</span>
                      </div>
                      <div className="h-1 bg-surface-variant w-full overflow-hidden">
                         <div className="h-full bg-primary-fixed glow-cyan" style={{ width: `${p.efficiency}%` }}></div>
                      </div>
                   </div>
                </div>
              )) : (
                <div className="col-span-4">
                   <EmptyState message="Awaiting persona performance data..." hint="No skill telemetry recorded yet" />
                </div>
              )}
           </div>
        </Card>
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* 1. Skill Performance Breakdown */}
        <Card title="Skill Engine Performance Breakdown" className="col-span-2">
           <div className="h-72 w-full">
              {skillBreakdown.length === 0 ? (
                <EmptyState message="No skill telemetry recorded yet" hint="Awaiting skill executions" />
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                   <BarChart data={skillBreakdown}>
                      <CartesianGrid strokeDasharray="3 3" stroke={palette.grid} vertical={false} />
                      <XAxis dataKey="category" stroke={palette.axis} fontSize={10} />
                      <YAxis yAxisId="left" orientation="left" stroke={palette.primary} fontSize={10} label={{ value: 'Recall %', angle: -90, position: 'insideLeft', fill: palette.primary, fontSize: 10 }} />
                      <YAxis yAxisId="right" orientation="right" stroke={palette.secondary} fontSize={10} label={{ value: 'ROI', angle: 90, position: 'insideRight', fill: palette.secondary, fontSize: 10 }} />
                      <Tooltip contentStyle={tooltipStyle} />
                      <Legend />
                      <Bar yAxisId="left" dataKey="recall" fill={palette.primary} radius={[2, 2, 0, 0]} name="Acceptance Rate (%)" />
                      <Bar yAxisId="right" dataKey="cost" fill={palette.secondary} radius={[2, 2, 0, 0]} name="Revenue ROI" />
                   </BarChart>
                </ResponsiveContainer>
              )}
           </div>
        </Card>

        {/* 2. Acceptance Pie */}
        <Card title="Mission Outcome Quality">
           <div className="h-72 w-full flex flex-col">
              {acceptanceData.length === 0 ? (
                <EmptyState message="No findings recorded yet" hint="Awaiting swarm telemetry" />
              ) : (
                <>
                  <ResponsiveContainer width="100%" height="100%">
                     <PieChart>
                        <Pie
                           data={acceptanceData}
                           cx="50%"
                           cy="50%"
                           innerRadius={60}
                           outerRadius={80}
                           paddingAngle={5}
                           dataKey="value"
                        >
                           {acceptanceData.map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={entry.color} />
                           ))}
                        </Pie>
                        <Tooltip contentStyle={tooltipStyle} />
                     </PieChart>
                  </ResponsiveContainer>
                  <div className="grid grid-cols-2 gap-2 px-4 pb-4">
                     {acceptanceData.map(d => (
                        <div key={d.name} className="flex items-center gap-2">
                           <div className="w-2 h-2" style={{ backgroundColor: d.color }}></div>
                           <span className="text-[10px] font-code-sm text-on-surface-variant uppercase">{d.name}</span>
                        </div>
                     ))}
                  </div>
                </>
              )}
           </div>
        </Card>
      </div>

      <div className="grid grid-cols-2 gap-6">
         {/* 3. AI-OSOP vs Human Efficiency */}
         <Card title="Discovery Velocity (AI-OSOP vs Human)">
            <div className="h-64 w-full">
               <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={efficiencyCurve}>
                     <CartesianGrid strokeDasharray="3 3" stroke={palette.grid} />
                     <XAxis dataKey="hours" stroke={palette.axis} fontSize={10} label={{ value: 'Operation Hours', position: 'insideBottom', offset: -5, fill: palette.axis, fontSize: 10 }} />
                     <YAxis stroke={palette.axis} fontSize={10} label={{ value: 'Verified Findings', angle: -90, position: 'insideLeft', fill: palette.axis, fontSize: 10 }} />
                     <Tooltip contentStyle={tooltipStyle} />
                     <Legend verticalAlign="top" height={36}/>
                     <Line type="monotone" dataKey="ai" stroke={palette.primary} strokeWidth={2} dot={{ r: 4 }} activeDot={{ r: 6 }} name="AI-OSOP V5 Swarm" />
                     <Line type="monotone" dataKey="human" stroke={palette.axis} strokeWidth={2} strokeDasharray="5 5" name="Human Researcher" />
                  </LineChart>
               </ResponsiveContainer>
            </div>
         </Card>

         {/* 4. Strategic Recommendation Engine */}
         <Card title="Strategic Guidance // SWARM_GOVERNOR">
            <div className="space-y-6">
               <div className="bg-primary-container/10 border border-primary-container/30 p-4">
                  <div className="font-label-caps text-primary-fixed text-[10px] mb-2 uppercase tracking-widest flex items-center gap-2">
                     <Target size={14} /> Optimization Target
                  </div>
                  <p className="text-[11px] text-on-surface leading-relaxed font-code-sm">
                     {safeStats.top_skills.length > 0 ? (
                        <>High reputation on <span className="text-secondary">{safeStats.top_skills[0].name}</span> suggest prioritizing related attack vectors.
                        Recommend scaling <span className="text-primary-fixed">Discovery Swarm</span> for maximum variant yield.</>
                     ) : (
                        <>Awaiting swarm telemetry to generate strategic guidance. Current focus: <span className="text-secondary">Mission Reconnaissance</span>.</>
                     )}
                  </p>
               </div>

               <div className="grid grid-cols-2 gap-4">
                  <div className="bg-surface-container-high border border-outline-variant p-3">
                     <div className="text-label-xs font-label-caps text-on-surface-variant mb-1 uppercase">Top Earning Class</div>
                     <div className="text-[14px] font-headline-md text-primary-fixed">
                        {safeStats.top_skills.length > 0 ? safeStats.top_skills[0].id.toUpperCase().replace(/-/g, ' ') : 'N/A'}
                     </div>
                  </div>
                  <div className="bg-surface-container-high border border-outline-variant p-3">
                     <div className="text-label-xs font-label-caps text-on-surface-variant mb-1 uppercase">Active Findings</div>
                     <div className="text-[14px] font-headline-md text-secondary">{findings.length}</div>
                  </div>
               </div>

               <div className="pt-2">
                  <div className="flex justify-between items-end mb-2">
                     <span className="font-label-caps text-on-surface-variant text-label-xs uppercase tracking-tighter">Budget-to-Value Calibration</span>
                     <span className="font-label-caps text-primary-fixed text-[11px]">
                        {safeStats.revenue_roi > 1 ? 'OPTIMIZED' : 'CALIBRATING'}
                     </span>
                  </div>
                  <div className="h-1.5 bg-surface-variant w-full overflow-hidden">
                     <div className="h-full bg-primary-fixed glow-cyan shadow-[0_0_10px_rgba(57,255,20,0.5)]" style={{ width: `${Math.min(100, (safeStats.revenue_roi || 0.1) * 50)}%` }}></div>
                  </div>
               </div>
            </div>
         </Card>
      </div>
    </div>
  );
};

import React from 'react';
import { Card } from '../components/shared/Card';
import { 
    LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
    BarChart, Bar, Legend, PieChart, Pie, Cell
} from 'recharts';
import { TrendingUp, DollarSign, Target, UserCheck, ShieldCheck, Activity } from 'lucide-react';
import { useIntelligenceStore } from '../store/useIntelligenceStore';
import { useSwarmStore } from '../store/useSwarmStore';

const COLORS = ['#39ff14', '#00f1fd', '#ff3131', '#ff9f00', '#a259ff'];

export const LearningAnalytics: React.FC = () => {
  const { skillStats, findings } = useIntelligenceStore();
  const { agents } = useSwarmStore();

  const safeStats = skillStats || {
    total_revenue: 0,
    revenue_roi: 0,
    findings_contributed: 0,
    top_skills: [],
    recent_executions: []
  };

  // 1. Accepted Findings Breakdown (derived from findings)
  const acceptanceData = [
    { name: 'Accepted', value: findings.filter(f => f.status === 'verified').length, color: '#39ff14' },
    { name: 'Validated', value: findings.filter(f => f.status === 'validated').length, color: '#00f1fd' },
    { name: 'Hypothesis', value: findings.filter(f => f.status === 'hypothesis').length, color: '#ff9f00' },
    { name: 'Rejected', value: findings.filter(f => f.status === 'rejected').length, color: '#ff3131' },
  ].filter(d => d.value > 0);

  if (acceptanceData.length === 0) {
    acceptanceData.push({ name: 'No Findings', value: 1, color: '#2a2a2d' });
  }

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
      <div className="grid grid-cols-4 gap-6">
        <Card title="Engagement ROI" glow="cyan">
           <div className="flex items-center gap-4">
              <DollarSign className="text-primary-fixed" size={32} />
              <div>
                 <div className="font-display-lg text-primary-fixed">${(safeStats.total_revenue || 0).toLocaleString()}</div>
                 <div className="font-code-sm text-on-surface-variant text-[10px]">TOTAL BOUNTY CAPTURED</div>
              </div>
           </div>
        </Card>
        <Card title="Report Acceptance">
           <div className="flex items-center gap-4">
              <ShieldCheck className="text-secondary" size={32} />
              <div>
                 <div className="font-display-lg text-secondary">
                    {findings.length > 0 ? ((findings.filter(f => f.status === 'verified').length / findings.length) * 100).toFixed(1) : "0.0"}%
                 </div>
                 <div className="font-code-sm text-on-surface-variant text-[10px]">VERIFIED → ACCEPTED RATE</div>
              </div>
           </div>
        </Card>
        <Card title="Discovery Efficiency">
           <div className="flex items-center gap-4">
              <TrendingUp className="text-primary-fixed" size={32} />
              <div>
                 <div className="font-display-lg text-primary-fixed">18.5x</div>
                 <div className="font-code-sm text-on-surface-variant text-[10px]">VS HUMAN BASELINE (SPEED)</div>
              </div>
           </div>
        </Card>
        <Card title="Variant Yield">
           <div className="flex items-center gap-4">
              <Activity className="text-error" size={32} />
              <div>
                 <div className="font-display-lg text-error">{(safeStats.revenue_roi || 1).toFixed(1)}x</div>
                 <div className="font-code-sm text-on-surface-variant text-[10px]">REVENUE / COST RATIO</div>
              </div>
           </div>
        </Card>
      </div>

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
                      <div className="flex justify-between text-[9px] font-label-caps text-on-surface-variant mb-1">
                         <span>Skill Reputation</span>
                         <span className="text-primary-fixed">{p.efficiency}%</span>
                      </div>
                      <div className="h-1 bg-surface-variant w-full overflow-hidden">
                         <div className="h-full bg-primary-fixed glow-cyan" style={{ width: `${p.efficiency}%` }}></div>
                      </div>
                   </div>
                </div>
              )) : (
                <div className="col-span-4 text-center py-10 opacity-30 font-code-sm">AWAITING PERSONA PERFORMANCE DATA...</div>
              )}
           </div>
        </Card>
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* 1. Skill Performance Breakdown */}
        <Card title="Skill Engine Performance Breakdown" className="col-span-2">
           <div className="h-72 w-full">
              <ResponsiveContainer width="100%" height="100%">
                 <BarChart data={skillBreakdown}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#2a2a2d" vertical={false} />
                    <XAxis dataKey="category" stroke="#baccb0" fontSize={10} />
                    <YAxis yAxisId="left" orientation="left" stroke="#39ff14" fontSize={10} label={{ value: 'Recall %', angle: -90, position: 'insideLeft', fill: '#39ff14', fontSize: 9 }} />
                    <YAxis yAxisId="right" orientation="right" stroke="#00f1fd" fontSize={10} label={{ value: 'ROI', angle: 90, position: 'insideRight', fill: '#00f1fd', fontSize: 9 }} />
                    <Tooltip contentStyle={{ backgroundColor: '#131314', border: '1px solid #2a2a2d' }} />
                    <Legend />
                    <Bar yAxisId="left" dataKey="recall" fill="#39ff14" radius={[2, 2, 0, 0]} name="Acceptance Rate (%)" />
                    <Bar yAxisId="right" dataKey="cost" fill="#00f1fd" radius={[2, 2, 0, 0]} name="Revenue ROI" />
                 </BarChart>
              </ResponsiveContainer>
           </div>
        </Card>

        {/* 2. Acceptance Pie */}
        <Card title="Mission Outcome Quality">
           <div className="h-72 w-full flex flex-col">
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
                    <Tooltip contentStyle={{ backgroundColor: '#131314', border: '1px solid #2a2a2d' }} />
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
           </div>
        </Card>
      </div>

      <div className="grid grid-cols-2 gap-6">
         {/* 3. AI-OSOP vs Human Efficiency */}
         <Card title="Discovery Velocity (AI-OSOP vs Human)">
            <div className="h-64 w-full">
               <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={efficiencyCurve}>
                     <CartesianGrid strokeDasharray="3 3" stroke="#2a2a2d" />
                     <XAxis dataKey="hours" stroke="#baccb0" fontSize={10} label={{ value: 'Operation Hours', position: 'insideBottom', offset: -5, fill: '#baccb0', fontSize: 9 }} />
                     <YAxis stroke="#baccb0" fontSize={10} label={{ value: 'Verified Findings', angle: -90, position: 'insideLeft', fill: '#baccb0', fontSize: 9 }} />
                     <Tooltip contentStyle={{ backgroundColor: '#131314', border: '1px solid #2a2a2d' }} />
                     <Legend verticalAlign="top" height={36}/>
                     <Line type="monotone" dataKey="ai" stroke="#39ff14" strokeWidth={2} dot={{ r: 4 }} activeDot={{ r: 6 }} name="AI-OSOP V5 Swarm" />
                     <Line type="monotone" dataKey="human" stroke="#baccb0" strokeWidth={2} strokeDasharray="5 5" name="Human Researcher" />
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
                     <div className="text-[9px] font-label-caps text-on-surface-variant mb-1 uppercase">Top Earning Class</div>
                     <div className="text-[14px] font-headline-md text-primary-fixed">
                        {safeStats.top_skills.length > 0 ? safeStats.top_skills[0].id.toUpperCase().replace(/-/g, ' ') : 'N/A'}
                     </div>
                  </div>
                  <div className="bg-surface-container-high border border-outline-variant p-3">
                     <div className="text-[9px] font-label-caps text-on-surface-variant mb-1 uppercase">Active Findings</div>
                     <div className="text-[14px] font-headline-md text-secondary">{findings.length}</div>
                  </div>
               </div>

               <div className="pt-2">
                  <div className="flex justify-between items-end mb-2">
                     <span className="font-label-caps text-on-surface-variant text-[9px] uppercase tracking-tighter">Budget-to-Value Calibration</span>
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

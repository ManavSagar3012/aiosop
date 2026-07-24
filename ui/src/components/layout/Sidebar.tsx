import React from 'react';
import { NavLink } from 'react-router-dom';
import {
    LayoutDashboard,
    Crosshair,
    Brain,
    Network,
    ShieldCheck,
    LineChart,
    Settings,
    Fingerprint,
    HelpCircle,
    Clock,
    FileText,
    Lock,
    Eye,
    Activity,
    Zap
} from 'lucide-react';
import { NetworkHealth } from '../shared/NetworkHealth';
import { useIntelligenceStore } from '../../store/useIntelligenceStore';

export const Sidebar: React.FC = () => {
  const { sessionId } = useIntelligenceStore();
  
  const navItems = [
    { path: '/', label: 'Overview', icon: <LayoutDashboard size={18} /> },
    { path: '/mission-control', label: 'Mission Control', icon: <Crosshair size={18} /> },
    { path: '/timeline', label: 'Mission Timeline', icon: <Clock size={18} /> },
    { path: '/intelligence', label: 'Research Intelligence', icon: <Brain size={18} /> },
    { path: '/knowledge-graphs', label: 'Knowledge Graphs', icon: <Network size={18} /> },
    { path: '/skills', label: 'Skill Intelligence', icon: <Brain size={18} /> },
    { path: '/auth-audit', label: 'Authorization Audit', icon: <ShieldCheck size={18} /> },
    { path: '/differential-auth', label: 'Differential Auth', icon: <Lock size={18} /> },
    { path: '/findings', label: 'Finding Pipeline', icon: <ShieldCheck size={18} /> },
    { path: '/verification', label: 'Reality Verification', icon: <Fingerprint size={18} /> },
    { path: '/visual-context', label: 'Visual Context', icon: <Eye size={18} /> },
    { path: '/uncertainty', label: 'Uncertainty Engine', icon: <HelpCircle size={18} /> },
    { path: '/reasoning', label: 'Reasoning Trace', icon: <Activity size={18} /> },
    { path: '/cognition', label: 'Cognition Dashboard', icon: <Zap size={18} /> },
    { path: '/learning', label: 'Learning & Analytics', icon: <LineChart size={18} /> },
    { path: '/admin', label: 'Administration', icon: <Settings size={18} /> },
  ];

  if (sessionId) {
    navItems.splice(3, 0, { path: `/report/${sessionId}`, label: 'Mission Report', icon: <FileText size={18} /> });
  }

  return (
    <aside className="w-64 bg-surface-container border-r border-outline-variant h-full flex flex-col shrink-0">
      <div className="p-6 border-b border-outline-variant flex items-center gap-3">
        <div className="w-8 h-8 bg-primary-fixed/20 border border-primary-fixed/50 rounded flex items-center justify-center text-primary-fixed font-bold text-[14px]">
          V5
        </div>
        <div className="font-display-lg text-[18px] text-primary-fixed tracking-tighter uppercase leading-none">
          AI-OSOP <br/><span className="text-on-surface-variant text-[10px] font-code-sm">Runtime</span>
        </div>
      </div>
      
      <nav className="flex-1 py-6 flex flex-col gap-1 px-4">
        {navItems.map(item => (
          <NavLink
            key={item.path}
            to={item.path}
            className={({ isActive }) => 
              `flex items-center gap-3 px-4 py-2.5 rounded-md font-label-caps text-[11px] transition-all ${
                isActive 
                  ? 'bg-secondary/10 text-secondary border border-secondary/30 glow-cyan shadow-[inset_0_0_10px_rgba(0,241,253,0.1)]' 
                  : 'text-on-surface-variant hover:bg-surface-variant hover:text-on-surface'
              }`
            }
          >
            {item.icon}
            {item.label?.toUpperCase()}
          </NavLink>
        ))}
      </nav>
      
      <div className="p-6 border-t border-outline-variant">
        <NetworkHealth />
      </div>
    </aside>
  );
};

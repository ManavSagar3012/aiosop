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
    Zap,
    X,
    Lightbulb,
    GitBranch,
    Route,
    Cpu
} from 'lucide-react';
import { NetworkHealth } from '../shared/NetworkHealth';
import { useIntelligenceStore } from '../../store/useIntelligenceStore';

interface SidebarProps {
  open: boolean;
  onClose: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ open, onClose }) => {
  const { sessionId } = useIntelligenceStore();

  const navItems = [
    { path: '/', label: 'Overview', icon: <LayoutDashboard size={18} /> },
    { path: '/mission-control', label: 'Mission Control', icon: <Crosshair size={18} /> },
    { path: '/timeline', label: 'Mission Timeline', icon: <Clock size={18} /> },
    { path: '/intelligence', label: 'Research Intelligence', icon: <Brain size={18} /> },
    { path: '/knowledge-graphs', label: 'Knowledge Graphs', icon: <Network size={18} /> },
    { path: '/skills', label: 'Skill Intelligence', icon: <Zap size={18} /> },
    { path: '/auth-audit', label: 'Authorization Audit', icon: <ShieldCheck size={18} /> },
    { path: '/differential-auth', label: 'Differential Auth', icon: <Lock size={18} /> },
    { path: '/findings', label: 'Finding Pipeline', icon: <FileText size={18} /> },
    { path: '/verification', label: 'Reality Verification', icon: <Fingerprint size={18} /> },
    { path: '/visual-context', label: 'Visual Context', icon: <Eye size={18} /> },
    { path: '/uncertainty', label: 'Uncertainty Engine', icon: <HelpCircle size={18} /> },
    { path: '/hypotheses', label: 'Hypotheses', icon: <Lightbulb size={18} /> },
    { path: '/attack-chains', label: 'Attack Chains', icon: <GitBranch size={18} /> },
    { path: '/reasoning', label: 'Reasoning Trace', icon: <Activity size={18} /> },
    { path: '/cognition', label: 'Cognition Dashboard', icon: <Cpu size={18} /> },
    { path: '/learning', label: 'Learning & Analytics', icon: <LineChart size={18} /> },
    { path: '/admin', label: 'Administration', icon: <Settings size={18} /> },
  ];

  if (sessionId) {
    navItems.splice(3, 0, { path: `/report/${sessionId}`, label: 'Mission Report', icon: <Route size={18} /> });
  }

  return (
    <>
      {/* Mobile backdrop */}
      {open && (
        <div
          className="fixed inset-0 bg-black/70 z-30 lg:hidden"
          onClick={onClose}
          aria-hidden="true"
        />
      )}

      <aside className={`
        bg-surface-container border-r border-outline-variant h-full flex flex-col w-64 shrink-0
        fixed inset-y-0 left-0 z-40 transform transition-transform duration-200 ease-in-out
        lg:static lg:translate-x-0
        ${open ? 'translate-x-0' : '-translate-x-full'}
      `}>
        <div className="p-6 border-b border-outline-variant flex items-center gap-3">
          <div className="w-8 h-8 bg-primary-fixed/20 border border-primary-fixed/50 rounded flex items-center justify-center text-primary-fixed font-bold text-[14px]">
            V5
          </div>
          <div className="font-display-lg text-[18px] text-primary-fixed tracking-tighter uppercase leading-none flex-1">
            AI-OSOP <br/><span className="text-on-surface-variant text-[10px] font-code-sm">Runtime</span>
          </div>
          <button
            onClick={onClose}
            className="lg:hidden text-on-surface-variant hover:text-on-surface p-1"
            aria-label="Close navigation"
          >
            <X size={20} />
          </button>
        </div>

        <nav className="flex-1 py-6 flex flex-col gap-1 px-4 overflow-y-auto custom-scrollbar">
          {navItems.map(item => (
            <NavLink
              key={item.path}
              to={item.path}
              onClick={onClose}
              className={({ isActive }) =>
                `flex items-center gap-3 px-4 py-2.5 rounded-md font-label-caps text-[11px] transition-all ${
                  isActive
                    ? 'bg-secondary/10 text-secondary border border-secondary/30 shadow-sm'
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
    </>
  );
};

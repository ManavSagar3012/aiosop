import React, { useState } from 'react';
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
  Zap,
  Search,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import { NetworkHealth } from '../shared/NetworkHealth';

interface NavItem {
  path: string;
  label: string;
  icon: React.ReactNode;
  section?: string;
}

const NAV_ITEMS: NavItem[] = [
  { path: '/', label: 'Overview', icon: <LayoutDashboard size={18} />, section: 'Operations' },
  { path: '/mission-control', label: 'Mission Control', icon: <Crosshair size={18} />, section: 'Operations' },
  { path: '/timeline', label: 'Mission Timeline', icon: <Clock size={18} />, section: 'Operations' },
  { path: '/findings', label: 'Findings', icon: <ShieldCheck size={18} />, section: 'Intelligence' },
  { path: '/verification', label: 'Reality Verification', icon: <Fingerprint size={18} />, section: 'Intelligence' },
  { path: '/intelligence', label: 'Research Intelligence', icon: <Brain size={18} />, section: 'Intelligence' },
  { path: '/knowledge-graphs', label: 'Knowledge Graphs', icon: <Network size={18} />, section: 'Analysis' },
  { path: '/skills', label: 'Skill Intelligence', icon: <Zap size={18} />, section: 'Analysis' },
  { path: '/auth-audit', label: 'Authorization Audit', icon: <ShieldCheck size={18} />, section: 'Analysis' },
  { path: '/uncertainty', label: 'Uncertainty Engine', icon: <HelpCircle size={18} />, section: 'Analysis' },
  { path: '/learning', label: 'Learning & Analytics', icon: <LineChart size={18} />, section: 'Analytics' },
  { path: '/admin', label: 'Administration', icon: <Settings size={18} />, section: 'System' },
];

export const Sidebar: React.FC = () => {
  const [collapsed, setCollapsed] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const filteredItems = NAV_ITEMS.filter(item =>
    !searchQuery || item.label.toLowerCase().includes(searchQuery.toLowerCase())
  );

  // Group by section
  const sections = filteredItems.reduce<Record<string, NavItem[]>>((acc, item) => {
    const section = item.section || 'Other';
    if (!acc[section]) acc[section] = [];
    acc[section].push(item);
    return acc;
  }, {});

  return (
    <aside
      className="h-full flex flex-col shrink-0 transition-all duration-300"
      style={{
        width: collapsed ? 'var(--sidebar-width-collapsed)' : 'var(--sidebar-width)',
        background: 'var(--surface-0)',
        borderRight: '1px solid var(--border)',
      }}
    >
      {/* Logo */}
      <div
        className="flex items-center gap-3 shrink-0 transition-all duration-300"
        style={{
          padding: collapsed ? '20px 12px' : '20px 16px',
          borderBottom: '1px solid var(--border)',
        }}
      >
        <div
          className="flex items-center justify-center shrink-0 transition-all"
          style={{
            width: 32,
            height: 32,
            background: 'var(--accent-bg)',
            border: '1px solid var(--accent-border)',
            borderRadius: 'var(--radius-md)',
            color: 'var(--accent)',
            fontWeight: 700,
            fontSize: 13,
          }}
        >
          V5
        </div>
        {!collapsed && (
          <div className="animate-fade-in">
            <div
              style={{
                fontFamily: "'Space Grotesk', sans-serif",
                fontSize: 15,
                fontWeight: 700,
                color: 'var(--accent)',
                letterSpacing: '0.03em',
                lineHeight: 1.1,
              }}
            >
              AI-OSOP
            </div>
            <div
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 9,
                color: 'var(--text-tertiary)',
                letterSpacing: '0.12em',
                textTransform: 'uppercase',
                marginTop: 2,
              }}
            >
              Command Center
            </div>
          </div>
        )}
      </div>

      {/* Search (expanded only) */}
      {!collapsed && (
        <div className="px-3 pt-3 animate-fade-in">
          <div
            className="flex items-center gap-2"
            style={{
              background: 'var(--surface-1)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius-md)',
              padding: '6px 10px',
            }}
          >
            <Search size={14} style={{ color: 'var(--text-tertiary)', flexShrink: 0 }} />
            <input
              type="text"
              placeholder="Search navigation..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-transparent border-none outline-none flex-1"
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 12,
                color: 'var(--text-primary)',
              }}
            />
          </div>
        </div>
      )}

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto custom-scrollbar" style={{ padding: collapsed ? '8px 6px' : '12px 12px' }}>
        {Object.entries(sections).map(([section, items]) => (
          <div key={section} style={{ marginBottom: collapsed ? 4 : 16 }}>
            {!collapsed && (
              <div
                className="mb-1.5"
                style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 9,
                  fontWeight: 700,
                  letterSpacing: '0.12em',
                  textTransform: 'uppercase',
                  color: 'var(--text-disabled)',
                  padding: '0 8px',
                }}
              >
                {section}
              </div>
            )}
            <div className="flex flex-col gap-0.5">
              {items.map(item => (
                <NavLink
                  key={item.path}
                  to={item.path}
                  data-tooltip={collapsed ? item.label : undefined}
                  className={`flex items-center gap-2.5 transition-all duration-fast ${collapsed ? 'justify-center px-2 py-2.5' : 'px-3 py-2'}`}
                  style={({ isActive: active }) => ({
                    borderRadius: 'var(--radius-md)',
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: collapsed ? 11 : 12,
                    fontWeight: 500,
                    letterSpacing: collapsed ? 0 : '0.03em',
                    color: active ? 'var(--accent)' : 'var(--text-secondary)',
                    background: active ? 'var(--accent-bg)' : 'transparent',
                    borderLeft: active && !collapsed ? '2px solid var(--accent)' : '2px solid transparent',
                  })}
                >
                  <span style={{ flexShrink: 0 }}>{item.icon}</span>
                  {!collapsed && (
                    <span className="truncate">{item.label}</span>
                  )}
                </NavLink>
              ))}
            </div>
          </div>
        ))}
      </nav>

      {/* Network Health */}
      <div style={{ padding: collapsed ? '8px' : '12px', borderTop: '1px solid var(--border)' }}>
        <NetworkHealth collapsed={collapsed} />
      </div>

      {/* Collapse Toggle */}
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="flex items-center justify-center transition-all"
        style={{
          height: 32,
          background: 'transparent',
          border: 'none',
          borderTop: '1px solid var(--border)',
          color: 'var(--text-tertiary)',
          cursor: 'pointer',
        }}
      >
        {collapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
      </button>
    </aside>
  );
};

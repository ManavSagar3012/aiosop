import React from 'react';
import { useLocation, Link } from 'react-router-dom';
import { ChevronRight, Home } from 'lucide-react';

const ROUTE_LABELS: Record<string, string> = {
  '': 'Overview',
  'mission-control': 'Mission Control',
  'timeline': 'Mission Timeline',
  'intelligence': 'Research Intelligence',
  'knowledge-graphs': 'Knowledge Graphs',
  'skills': 'Skill Intelligence',
  'auth-audit': 'Authorization Audit',
  'findings': 'Findings',
  'verification': 'Reality Verification',
  'uncertainty': 'Uncertainty Engine',
  'learning': 'Learning & Analytics',
  'differential-auth': 'Differential Auth',
  'visual-context': 'Visual Context',
  'admin': 'Administration',
  'report': 'Mission Report',
};

export const Breadcrumbs: React.FC = () => {
  const location = useLocation();
  const segments = location.pathname.split('/').filter(Boolean);

  if (segments.length === 0) {
    return (
      <nav className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--text-tertiary)' }}>
        <Home size={12} />
        <span style={{ color: 'var(--text-secondary)' }}>Overview</span>
      </nav>
    );
  }

  return (
    <nav className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--text-tertiary)' }}>
      <Link
        to="/"
        className="flex items-center gap-1 hover:text-accent transition-colors"
        style={{ color: 'var(--text-tertiary)' }}
      >
        <Home size={12} />
      </Link>
      {segments.map((segment, i) => {
        const path = '/' + segments.slice(0, i + 1).join('/');
        const label = ROUTE_LABELS[segment] || segment.replace(/-/g, ' ');
        const isLast = i === segments.length - 1;
        return (
          <React.Fragment key={path}>
            <ChevronRight size={10} style={{ color: 'var(--text-disabled)' }} />
            {isLast ? (
              <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>
                {label}
              </span>
            ) : (
              <Link
                to={path}
                className="hover:text-accent transition-colors"
                style={{ color: 'var(--text-tertiary)' }}
              >
                {label}
              </Link>
            )}
          </React.Fragment>
        );
      })}
    </nav>
  );
};

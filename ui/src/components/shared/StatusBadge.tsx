import React from 'react';

type Kind = 'status' | 'severity';

const STATUS: Record<string, string> = {
  verified:  'border-primary-fixed text-primary-fixed bg-primary-fixed/5',
  validated: 'border-secondary text-secondary bg-secondary/5',
  pending:   'border-outline text-on-surface-variant',
  rejected:  'border-outline text-on-surface-variant opacity-50 line-through',
};

const SEVERITY: Record<string, string> = {
  critical: 'border-error text-error bg-error/10',
  high:     'border-warning text-warning bg-warning/10',
  medium:   'border-warning text-warning bg-warning/5',
  low:      'border-secondary text-secondary bg-secondary/5',
  info:     'border-outline text-on-surface-variant',
};

export const StatusBadge: React.FC<{ value?: string; kind?: Kind }> = ({ value, kind = 'status' }) => {
  const key = (value || '').toLowerCase();
  const map = kind === 'severity' ? SEVERITY : STATUS;
  const cls = map[key] || 'border-outline text-on-surface-variant opacity-50';
  return (
    <span className={`px-2 py-0.5 border font-label-caps text-label-xs uppercase ${cls}`}>
      {(value || 'pending').toUpperCase()}
    </span>
  );
};

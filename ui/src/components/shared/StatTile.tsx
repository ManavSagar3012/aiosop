import React from 'react';

type Accent = 'primary' | 'error' | 'secondary' | 'warning' | 'muted';

const ACCENT: Record<Accent, { text: string; border: string }> = {
  primary:   { text: 'text-primary-fixed',      border: 'border-t-primary-fixed' },
  error:     { text: 'text-error',              border: 'border-t-error' },
  secondary: { text: 'text-secondary',          border: 'border-t-secondary' },
  warning:   { text: 'text-warning',            border: 'border-t-warning' },
  muted:     { text: 'text-on-surface-variant', border: 'border-t-outline-variant' },
};

export interface StatTileProps {
  label: string;
  value: React.ReactNode;
  caption?: string;
  accent?: Accent;
  icon?: React.ReactNode;
  meta?: string;
  delay?: number;
}

export const StatTile: React.FC<StatTileProps> = ({
  label, value, caption, accent = 'primary', icon, meta, delay = 0,
}) => {
  const a = ACCENT[accent];
  return (
    <div
      className={`reveal-up hud-corners group relative bg-surface-container border border-outline-variant border-t-2 ${a.border} p-5 overflow-hidden transition-all duration-300 hover:border-primary-fixed/40`}
      style={{ animationDelay: `${delay}ms` }}
    >
      <div className="absolute inset-0 terminal-grid opacity-[0.04] pointer-events-none" />
      <div className="relative flex items-start justify-between">
        <div className="font-label-caps text-on-surface-variant uppercase">{label}</div>
        {icon && <div className={`${a.text} opacity-40 group-hover:opacity-90 transition-opacity`}>{icon}</div>}
      </div>
      <div className="relative mt-4 flex items-end gap-3">
        <div className={`font-display-lg ${a.text} leading-none tabular-nums`}>{value}</div>
        {meta && <div className="mb-1.5 font-code-sm text-on-surface-variant">{meta}</div>}
      </div>
      {caption && <div className="relative mt-2 font-code-sm text-on-surface-variant/80 uppercase">{caption}</div>}
    </div>
  );
};

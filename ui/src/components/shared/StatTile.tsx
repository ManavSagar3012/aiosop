import React from 'react';

type Accent = 'primary' | 'error' | 'secondary' | 'warning' | 'muted' | 'info';

const ACCENT_CONFIG: Record<Accent, {
  text: string;
  bg: string;
  border: string;
  iconBg: string;
}> = {
  primary:   { text: 'var(--accent)',     bg: 'var(--accent-bg)',   border: 'var(--accent-border)',   iconBg: 'var(--accent-bg)' },
  error:     { text: 'var(--danger)',     bg: 'var(--danger-bg)',   border: 'var(--danger-border)',   iconBg: 'var(--danger-bg)' },
  secondary: { text: 'var(--interactive)', bg: 'var(--interactive-bg)', border: 'var(--interactive-border)', iconBg: 'var(--interactive-bg)' },
  warning:   { text: 'var(--warning)',    bg: 'var(--warning-bg)',  border: 'var(--warning-border)',  iconBg: 'var(--warning-bg)' },
  muted:     { text: 'var(--text-secondary)', bg: 'var(--surface-2)', border: 'var(--border)', iconBg: 'var(--surface-2)' },
  info:      { text: 'var(--info)',       bg: 'var(--info-bg)',     border: 'var(--info-border)',     iconBg: 'var(--info-bg)' },
};

export interface StatTileProps {
  label: string;
  value: React.ReactNode;
  caption?: string;
  accent?: Accent;
  icon?: React.ReactNode;
  meta?: string;
  delay?: number;
  trend?: { value: number; direction: 'up' | 'down' | 'flat' };
}

export const StatTile: React.FC<StatTileProps> = ({
  label, value, caption, accent = 'primary', icon, meta, delay = 0, trend,
}) => {
  const config = ACCENT_CONFIG[accent];

  return (
    <div
      className="card reveal-up group"
      style={{
        padding: '20px',
        borderTop: `2px solid ${config.border}`,
        animationDelay: `${delay}ms`,
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Background accent glow */}
      <div
        className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-fast"
        style={{ background: config.bg }}
      />

      <div className="relative">
        {/* Header */}
        <div className="flex items-start justify-between mb-3">
          <div
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 10,
              fontWeight: 700,
              letterSpacing: '0.1em',
              textTransform: 'uppercase',
              color: 'var(--text-tertiary)',
            }}
          >
            {label}
          </div>
          {icon && (
            <div
              className="flex items-center justify-center"
              style={{
                width: 28,
                height: 28,
                borderRadius: 'var(--radius-md)',
                background: config.iconBg,
                color: config.text,
              }}
            >
              {icon}
            </div>
          )}
        </div>

        {/* Value */}
        <div className="flex items-end gap-3 mb-1">
          <div
            style={{
              fontFamily: "'Space Grotesk', sans-serif",
              fontSize: 28,
              fontWeight: 800,
              lineHeight: 1,
              color: config.text,
              letterSpacing: '-0.02em',
              fontVariantNumeric: 'tabular-nums',
            }}
          >
            {value}
          </div>
          {meta && (
            <div
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 11,
                color: 'var(--text-tertiary)',
                marginBottom: 4,
              }}
            >
              {meta}
            </div>
          )}
        </div>

        {/* Trend */}
        {trend && (
          <div
            className="flex items-center gap-1"
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 11,
              color: trend.direction === 'up' ? 'var(--accent)' : trend.direction === 'down' ? 'var(--danger)' : 'var(--text-tertiary)',
              marginBottom: 4,
            }}
          >
            {trend.direction === 'up' ? '↑' : trend.direction === 'down' ? '↓' : '→'}
            {Math.abs(trend.value)}%
          </div>
        )}

        {/* Caption */}
        {caption && (
          <div
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 11,
              color: 'var(--text-tertiary)',
              marginTop: 4,
            }}
          >
            {caption}
          </div>
        )}
      </div>
    </div>
  );
};

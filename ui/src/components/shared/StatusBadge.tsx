import React from 'react';

type Kind = 'status' | 'severity' | 'phase';

const STATUS_STYLES: Record<string, { color: string; bg: string; border: string; dot?: string }> = {
  verified:     { color: 'var(--accent)',       bg: 'var(--accent-bg)',       border: 'var(--accent-border)',     dot: 'var(--accent)' },
  validated:    { color: 'var(--interactive)',   bg: 'var(--interactive-bg)',  border: 'var(--interactive-border)', dot: 'var(--interactive)' },
  pending:      { color: 'var(--warning)',       bg: 'var(--warning-bg)',      border: 'var(--warning-border)',    dot: 'var(--warning)' },
  hypothesis:   { color: 'var(--info)',          bg: 'var(--info-bg)',         border: 'var(--info-border)',       dot: 'var(--info)' },
  rejected:     { color: 'var(--text-disabled)',  bg: 'var(--surface-2)',       border: 'var(--border)',            dot: 'var(--text-disabled)' },
  report_ready: { color: 'var(--accent)',        bg: 'var(--accent-bg)',       border: 'var(--accent-border)',     dot: 'var(--accent)' },
};

const SEVERITY_STYLES: Record<string, { color: string; bg: string; border: string; dot?: string }> = {
  critical: { color: 'var(--danger)',     bg: 'var(--danger-bg)',     border: 'var(--danger-border)',     dot: 'var(--danger)' },
  high:     { color: 'var(--warning)',    bg: 'var(--warning-bg)',    border: 'var(--warning-border)',    dot: 'var(--warning)' },
  medium:   { color: 'var(--warning)',    bg: 'var(--warning-bg)',    border: 'var(--warning-border)',    dot: 'var(--warning)' },
  low:      { color: 'var(--interactive)', bg: 'var(--interactive-bg)', border: 'var(--interactive-border)', dot: 'var(--interactive)' },
  info:     { color: 'var(--text-secondary)', bg: 'var(--surface-2)', border: 'var(--border)',             dot: 'var(--text-secondary)' },
};

const PHASE_STYLES: Record<string, { color: string; bg: string; border: string; dot?: string }> = {
  reconnaissance:       { color: 'var(--interactive)', bg: 'var(--interactive-bg)', border: 'var(--interactive-border)', dot: 'var(--interactive)' },
  vulnerability_discovery: { color: 'var(--warning)',  bg: 'var(--warning-bg)',    border: 'var(--warning-border)',    dot: 'var(--warning)' },
  exploitation:         { color: 'var(--danger)',      bg: 'var(--danger-bg)',      border: 'var(--danger-border)',      dot: 'var(--danger)' },
  post_exploitation:    { color: 'var(--info)',        bg: 'var(--info-bg)',        border: 'var(--info-border)',        dot: 'var(--info)' },
  reporting:            { color: 'var(--accent)',      bg: 'var(--accent-bg)',      border: 'var(--accent-border)',      dot: 'var(--accent)' },
  completed:            { color: 'var(--accent)',      bg: 'var(--accent-bg)',      border: 'var(--accent-border)',      dot: 'var(--accent)' },
  halted:               { color: 'var(--danger)',      bg: 'var(--danger-bg)',      border: 'var(--danger-border)',      dot: 'var(--danger)' },
};

const FALLBACK = { color: 'var(--text-secondary)', bg: 'var(--surface-2)', border: 'var(--border)', dot: 'var(--text-secondary)' };

export const StatusBadge: React.FC<{
  value?: string;
  kind?: Kind;
  size?: 'sm' | 'md';
}> = ({ value, kind = 'status', size = 'sm' }) => {
  const key = (value || '').toLowerCase();
  const map = kind === 'severity' ? SEVERITY_STYLES : kind === 'phase' ? PHASE_STYLES : STATUS_STYLES;
  const style = map[key] || FALLBACK;

  const fontSize = size === 'sm' ? 10 : 11;
  const padding = size === 'sm' ? '2px 8px' : '3px 10px';

  return (
    <span
      className="inline-flex items-center gap-1.5"
      style={{
        padding,
        fontFamily: "'JetBrains Mono', monospace",
        fontSize,
        fontWeight: 600,
        letterSpacing: '0.08em',
        textTransform: 'uppercase',
        color: style.color,
        background: style.bg,
        border: `1px solid ${style.border}`,
        borderRadius: 'var(--radius-full)',
        lineHeight: 1.4,
      }}
    >
      {style.dot && (
        <span
          style={{
            width: 5,
            height: 5,
            borderRadius: '50%',
            background: style.dot,
            flexShrink: 0,
          }}
        />
      )}
      {(value || 'pending').replace(/_/g, ' ').toUpperCase()}
    </span>
  );
};

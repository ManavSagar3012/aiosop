import React from 'react';

export interface PanelProps {
  title?: string;
  subtitle?: string;
  action?: React.ReactNode;
  variant?: 'default' | 'inset';
  accent?: 'none' | 'success' | 'warning' | 'danger' | 'info';
  className?: string;
  children: React.ReactNode;
  noPadding?: boolean;
}

export const Panel: React.FC<PanelProps> = ({
  title, subtitle, action, variant = 'default', accent = 'none', className = '', children, noPadding = false,
}) => {
  const accentColors: Record<string, string> = {
    none: 'transparent',
    success: 'var(--accent)',
    warning: 'var(--warning)',
    danger: 'var(--danger)',
    info: 'var(--info)',
  };

  return (
    <div
      className={`card ${className}`}
      style={{
        background: variant === 'inset' ? 'var(--surface-2)' : 'var(--surface-1)',
        borderTop: accent !== 'none' ? `2px solid ${accentColors[accent]}` : undefined,
      }}
    >
      {title && (
        <div
          className="flex justify-between items-center"
          style={{
            padding: noPadding ? '16px 20px 0' : '16px 20px',
            borderBottom: subtitle ? '1px solid var(--border)' : undefined,
          }}
        >
          <div>
            <div
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 11,
                fontWeight: 700,
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
                color: 'var(--text-secondary)',
              }}
            >
              {title}
            </div>
            {subtitle && (
              <div
                style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 11,
                  color: 'var(--text-tertiary)',
                  marginTop: 2,
                }}
              >
                {subtitle}
              </div>
            )}
          </div>
          {action}
        </div>
      )}
      <div style={{ padding: noPadding ? 0 : '16px 20px 20px' }}>
        {children}
      </div>
    </div>
  );
};

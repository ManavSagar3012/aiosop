import React from 'react';

export interface PanelProps {
  title?: string;
  action?: React.ReactNode;
  variant?: 'default' | 'inset';
  glow?: 'green' | 'cyan' | 'red' | 'none';
  className?: string;
  children: React.ReactNode;
}

export const Panel: React.FC<PanelProps> = ({
  title, action, variant = 'default', glow = 'none', className = '', children,
}) => {
  const base = variant === 'inset' ? 'bg-black/40' : 'bg-surface-container';
  const glowClass = glow === 'none' ? '' : `glow-${glow}`;
  return (
    <div className={`${base} border border-outline-variant p-6 flex flex-col relative overflow-hidden ${glowClass} ${className}`}>
      {title && (
        <div className="font-label-caps text-on-surface-variant mb-4 border-b border-outline-variant/30 pb-2 flex justify-between items-center uppercase opacity-80">
          <span>{title}</span>
          {action}
        </div>
      )}
      <div className="flex-1">{children}</div>
    </div>
  );
};

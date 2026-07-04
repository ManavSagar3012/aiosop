import React from 'react';
export const SectionHeader: React.FC<{ title: string; subtitle?: string; action?: React.ReactNode }> = ({ title, subtitle, action }) => (
  <div className="flex items-end justify-between mb-4">
    <div>
      <h2 className="font-display-lg text-display-lg text-on-surface tracking-tight">{title}</h2>
      {subtitle && <div className="font-code-sm text-on-surface-variant/70 mt-0.5">{subtitle}</div>}
    </div>
    {action}
  </div>
);

import React from 'react';
export const EmptyState: React.FC<{ message: string; icon?: React.ReactNode; hint?: string }> = ({ message, icon, hint }) => (
  <div className="flex flex-col items-center justify-center py-16 text-center">
    {icon && <div className="mb-3 text-on-surface-variant opacity-20 animate-pulse">{icon}</div>}
    <div className="font-code-sm text-code-sm text-on-surface-variant/60 italic">{message}</div>
    {hint && <div className="mt-1 font-label-caps text-label-xs text-on-surface-variant/40 uppercase">{hint}</div>}
  </div>
);

import React from 'react';
export const Skeleton: React.FC<{ className?: string }> = ({ className = '' }) => (
  <div className={`bg-surface-container-high/60 border border-outline-variant/40 animate-pulse ${className}`} />
);

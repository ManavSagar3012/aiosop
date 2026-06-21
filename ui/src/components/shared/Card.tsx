import React from 'react';

interface CardProps {
  title: string;
  children: React.ReactNode;
  className?: string;
  glow?: 'cyan' | 'red' | 'green' | 'none';
}

export const Card: React.FC<CardProps> = ({ title, children, className = '', glow = 'none' }) => {
  const glowClass = glow === 'none' ? '' : `glow-${glow}`;
  
  return (
    <div className={`bg-surface-container border border-outline-variant p-6 flex flex-col relative overflow-hidden rounded-md transition-all ${glowClass} ${className}`}>
      <div className="font-label-caps text-[11px] text-on-surface-variant mb-4 border-b border-outline-variant/30 pb-2 tracking-widest flex justify-between items-center opacity-80 uppercase">
        {title}
      </div>
      <div className="flex-1">
        {children}
      </div>
    </div>
  );
};

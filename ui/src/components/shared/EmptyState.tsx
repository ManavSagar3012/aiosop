import React from 'react';

interface EmptyStateProps {
  message: string;
  icon?: React.ReactNode;
  hint?: string;
  action?: { label: string; onClick: () => void };
}

export const EmptyState: React.FC<EmptyStateProps> = ({ message, icon, hint, action }) => (
  <div className="flex flex-col items-center justify-center py-16 text-center">
    {icon && (
      <div
        className="flex items-center justify-center mb-4"
        style={{
          width: 56,
          height: 56,
          borderRadius: 'var(--radius-xl)',
          background: 'var(--surface-2)',
          border: '1px solid var(--border)',
          color: 'var(--text-tertiary)',
        }}
      >
        {icon}
      </div>
    )}
    <div
      style={{
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: 13,
        color: 'var(--text-secondary)',
        maxWidth: 280,
      }}
    >
      {message}
    </div>
    {hint && (
      <div
        style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 11,
          color: 'var(--text-tertiary)',
          marginTop: 8,
        }}
      >
        {hint}
      </div>
    )}
    {action && (
      <button
        onClick={action.onClick}
        className="btn btn-secondary btn-sm"
        style={{ marginTop: 16 }}
      >
        {action.label}
      </button>
    )}
  </div>
);

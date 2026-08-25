import React from 'react';
import { AlertCircle, RefreshCw } from 'lucide-react';

interface ErrorStateProps {
  message: string;
  onRetry?: () => void;
  details?: string;
}

export const ErrorState: React.FC<ErrorStateProps> = ({ message, onRetry, details }) => (
  <div
    className="flex flex-col items-center justify-center py-12 text-center"
    style={{
      background: 'var(--danger-bg)',
      border: '1px solid var(--danger-border)',
      borderRadius: 'var(--radius-lg)',
      padding: 24,
    }}
  >
    <div
      className="flex items-center justify-center mb-3"
      style={{
        width: 40,
        height: 40,
        borderRadius: 'var(--radius-lg)',
        background: 'var(--danger-bg)',
        color: 'var(--danger)',
      }}
    >
      <AlertCircle size={20} />
    </div>
    <div
      style={{
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: 13,
        fontWeight: 500,
        color: 'var(--danger)',
        marginBottom: 4,
      }}
    >
      {message}
    </div>
    {details && (
      <div
        style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 11,
          color: 'var(--text-tertiary)',
          marginBottom: 12,
          maxWidth: 400,
        }}
      >
        {details}
      </div>
    )}
    {onRetry && (
      <button onClick={onRetry} className="btn btn-ghost btn-sm">
        <RefreshCw size={12} />
        Retry
      </button>
    )}
  </div>
);

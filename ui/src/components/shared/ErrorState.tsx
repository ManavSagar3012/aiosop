import React from 'react';
import { AlertTriangle } from 'lucide-react';
export const ErrorState: React.FC<{ message: string; onRetry?: () => void }> = ({ message, onRetry }) => (
  <div className="flex flex-col items-center justify-center py-16 text-center">
    <AlertTriangle size={26} className="mb-3 text-error opacity-70" />
    <div className="font-code-sm text-error/80">{message}</div>
    {onRetry && (
      <button onClick={onRetry} className="mt-4 px-4 py-1.5 border border-error text-error font-label-caps uppercase hover:bg-error/10 focus-visible:outline focus-visible:outline-2 focus-visible:outline-error transition-colors">
        Retry
      </button>
    )}
  </div>
);

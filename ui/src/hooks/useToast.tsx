import React, { createContext, useContext, useState, useCallback, useRef } from 'react';

export type ToastVariant = 'success' | 'error' | 'info' | 'warning';

export interface Toast {
  id: string;
  message: string;
  variant: ToastVariant;
  duration?: number;
}

interface ToastContextValue {
  toasts: Toast[];
  addToast: (message: string, variant?: ToastVariant, duration?: number) => void;
  removeToast: (id: string) => void;
}

const ToastContext = createContext<ToastContextValue>({
  toasts: [],
  addToast: () => {},
  removeToast: () => {},
});

export const useToast = () => useContext(ToastContext);

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const counterRef = useRef(0);

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const addToast = useCallback(
    (message: string, variant: ToastVariant = 'info', duration: number = 4000) => {
      const id = `toast-${++counterRef.current}`;
      setToasts((prev) => [...prev, { id, message, variant, duration }]);
      if (duration > 0) {
        setTimeout(() => removeToast(id), duration);
      }
    },
    [removeToast]
  );

  return (
    <ToastContext.Provider value={{ toasts, addToast, removeToast }}>
      {children}
      <div
        className="fixed bottom-6 right-6 z-[9999] flex flex-col gap-3 pointer-events-none"
        role="alert"
        aria-live="polite"
      >
        {toasts.map((t) => (
          <ToastItem key={t.id} toast={t} onDismiss={removeToast} />
        ))}
      </div>
    </ToastContext.Provider>
  );
};

const variantStyles: Record<ToastVariant, { bg: string; border: string; text: string; icon: string }> = {
  success: { bg: 'bg-primary-fixed/10', border: 'border-primary-fixed/40', text: 'text-primary-fixed', icon: 'check' },
  error: { bg: 'bg-error/10', border: 'border-error/40', text: 'text-error', icon: 'cross' },
  info: { bg: 'bg-secondary/10', border: 'border-secondary/40', text: 'text-secondary', icon: 'info' },
  warning: { bg: 'bg-warning/10', border: 'border-warning/40', text: 'text-warning', icon: 'warning' },
};

const iconSymbols: Record<string, string> = {
  check: '\u2713',
  cross: '\u2715',
  info: '\u2139',
  warning: '\u26A0',
};

const ToastItem: React.FC<{ toast: Toast; onDismiss: (id: string) => void }> = ({ toast: t, onDismiss }) => {
  const vs = variantStyles[t.variant];
  return (
    <div
      className={`pointer-events-auto min-w-[320px] max-w-[480px] ${vs.bg} border ${vs.border} backdrop-blur-md shadow-2xl animate-reveal-up flex items-start gap-3 p-4 cursor-pointer hover:brightness-110 transition-all`}
      onClick={() => onDismiss(t.id)}
    >
      <span className={`font-mono text-[16px] font-bold ${vs.text} shrink-0 mt-0.5`}>
        {iconSymbols[vs.icon]}
      </span>
      <span className={`font-code-sm text-[12px] ${vs.text} leading-relaxed`}>{t.message}</span>
      <button
        onClick={(e) => { e.stopPropagation(); onDismiss(t.id); }}
        className={`ml-auto shrink-0 opacity-40 hover:opacity-100 ${vs.text} transition-opacity`}
        aria-label="Dismiss toast"
      >
        {iconSymbols['cross']}
      </button>
    </div>
  );
};

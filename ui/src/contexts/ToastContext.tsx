import React, { createContext, useContext, useState, useCallback } from 'react';
import { X, CheckCircle, AlertTriangle, AlertCircle, Info } from 'lucide-react';

export type ToastType = 'success' | 'warning' | 'danger' | 'info';

interface Toast {
  id: string;
  type: ToastType;
  message: string;
  duration?: number;
}

interface ToastContextValue {
  addToast: (type: ToastType, message: string, duration?: number) => void;
  success: (message: string) => void;
  warning: (message: string) => void;
  error: (message: string) => void;
  info: (message: string) => void;
  dismiss: (id: string) => void;
}

const ToastContext = createContext<ToastContextValue>({
  addToast: () => {},
  success: () => {},
  warning: () => {},
  error: () => {},
  info: () => {},
  dismiss: () => {},
});

export const useToast = () => useContext(ToastContext);

const ICONS: Record<ToastType, React.ReactNode> = {
  success: <CheckCircle size={16} />,
  warning: <AlertTriangle size={16} />,
  danger:  <AlertCircle size={16} />,
  info:    <Info size={16} />,
};

const COLORS: Record<ToastType, string> = {
  success: 'var(--success)',
  warning: 'var(--warning)',
  danger:  'var(--danger)',
  info:    'var(--info)',
};

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const dismiss = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  const addToast = useCallback((type: ToastType, message: string, duration = 5000) => {
    const id = `toast-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    setToasts(prev => [...prev, { id, type, message, duration }]);
    if (duration > 0) {
      setTimeout(() => dismiss(id), duration);
    }
  }, [dismiss]);

  const success = useCallback((msg: string) => addToast('success', msg), [addToast]);
  const warning = useCallback((msg: string) => addToast('warning', msg), [addToast]);
  const error = useCallback((msg: string) => addToast('danger', msg, 8000), [addToast]);
  const info = useCallback((msg: string) => addToast('info', msg), [addToast]);

  return (
    <ToastContext.Provider value={{ addToast, success, warning, error, info, dismiss }}>
      {children}
      <div className="toast-container">
        {toasts.map(toast => (
          <div key={toast.id} className={`toast toast-${toast.type}`}>
            <span style={{ color: COLORS[toast.type], flexShrink: 0 }}>
              {ICONS[toast.type]}
            </span>
            <span className="flex-1">{toast.message}</span>
            <button
              onClick={() => dismiss(toast.id)}
              className="flex-shrink-0 p-1 rounded hover:bg-surface-3 transition-colors"
              style={{ color: 'var(--text-tertiary)' }}
            >
              <X size={12} />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
};

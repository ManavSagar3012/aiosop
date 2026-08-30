import { useNotifications } from '../components/shared/NotificationProvider';

export const useAlertService = () => {
  const { addNotification } = useNotifications();

  const triggerAlert = (message: string, type: 'error' | 'warning' | 'info' = 'error') => {
    addNotification({ message, type });
    // In a real production system, this would also push to Sentry, PagerDuty, etc.
    console.error(`[Alert] ${type.toUpperCase()}: ${message}`);
  };

  return { triggerAlert };
};

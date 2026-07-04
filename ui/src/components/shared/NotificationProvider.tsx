import React, { createContext, useContext, useState, useEffect } from 'react';

interface Notification {
  id: string;
  message: string;
  type: 'error' | 'warning' | 'info';
}

const NotificationContext = createContext({
  addNotification: (n: Omit<Notification, 'id'>) => {},
});

export const NotificationProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [notifications, setNotifications] = useState<Notification[]>([]);

  const addNotification = (n: Omit<Notification, 'id'>) => {
    const id = Math.random().toString(36).substr(2, 9);
    setNotifications(prev => [...prev, { ...n, id }]);
    setTimeout(() => setNotifications(prev => prev.filter(x => x.id !== id)), 5000);
  };

  return (
    <NotificationContext.Provider value={{ addNotification }}>
      {children}
      <div className="fixed bottom-4 right-4 flex flex-col gap-2 z-50">
        {notifications.map(n => (
          <div key={n.id} className={`p-4 rounded-sm border ${n.type === 'error' ? 'bg-red-900 border-red-500' : 'bg-yellow-900 border-yellow-500'}`}>
            {n.message}
          </div>
        ))}
      </div>
    </NotificationContext.Provider>
  );
};

export const useNotifications = () => useContext(NotificationContext);

import React from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Header } from './Header';
import { ToastProvider } from '../../hooks/useToast';

export const Layout: React.FC = () => {
  return (
    <ToastProvider>
      <div className="flex h-screen w-full bg-background overflow-hidden relative">
        <div className="scanline"></div>
        <Sidebar />
        <div className="flex flex-col flex-1 overflow-hidden z-20">
          <Header />
          <main className="flex-1 overflow-y-auto p-8 bg-surface-container-lowest custom-scrollbar">
            <Outlet />
          </main>
        </div>
      </div>
    </ToastProvider>
  );
};

import React from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Header } from './Header';

export const Layout: React.FC = () => {
  return (
    <div
      className="flex h-screen w-full overflow-hidden"
      style={{ background: 'var(--bg-app)' }}
    >
      {/* Subtle scanline overlay */}
      <div className="scanline-effect" />

      {/* Sidebar */}
      <Sidebar />

      {/* Main content area */}
      <div className="flex flex-col flex-1 overflow-hidden" style={{ zIndex: 1 }}>
        <Header />
        <main
          className="flex-1 overflow-y-auto custom-scrollbar"
          style={{
            padding: 24,
            background: 'var(--bg-page)',
          }}
        >
          <div className="mx-auto" style={{ maxWidth: 'var(--container-max, 1440px)' }}>
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
};

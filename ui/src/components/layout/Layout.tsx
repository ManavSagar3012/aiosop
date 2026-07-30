import React, { useState, useEffect, useCallback } from 'react';
import { Outlet, useNavigate, useLocation } from 'react-router-dom';
import { Menu } from 'lucide-react';
import { Sidebar } from './Sidebar';
import { Header } from './Header';
import { ToastProvider } from '../../hooks/useToast';
import { useIntelligenceStore } from '../../store/useIntelligenceStore';

const SHORTCUTS: Record<string, string> = {
  'g o': '/',
  'g m': '/mission-control',
  'g t': '/timeline',
  'g i': '/intelligence',
  'g k': '/knowledge-graphs',
  'g f': '/findings',
  'g v': '/verification',
  'g u': '/uncertainty',
  'g s': '/skills',
  'g a': '/auth-audit',
  'g d': '/differential-auth',
  'g l': '/learning',
  'g c': '/visual-context',
  'g h': '/hypotheses',
  'g r': '/reasoning',
  'g g': '/cognition',
  'g x': '/attack-chains',
  'n': '/admin?new_mission=1',
};

export const Layout: React.FC = () => {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [showShortcuts, setShowShortcuts] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const sessionId = useIntelligenceStore((s) => s.sessionId);

  // Close sidebar on route change (mobile)
  useEffect(() => {
    setSidebarOpen(false);
  }, [location.pathname]);

  const handleKey = useCallback((e: KeyboardEvent) => {
    const target = e.target as HTMLElement;
    if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable) return;

    if (e.key === 'Escape') {
      setSidebarOpen(false);
      setShowShortcuts(false);
      return;
    }

    // Build sequence buffer for multi-key shortcuts like "g o"
    const buf = (window as any).__osopKeyBuf || '';
    const next = (buf + ' ' + e.key).trim().split(' ').slice(-2).join(' ');
    (window as any).__osopKeyBuf = next;

    // Single-key shortcuts
    if (e.key === '?' || (e.shiftKey && e.key === '/')) {
      e.preventDefault();
      setShowShortcuts(s => !s);
      (window as any).__osopKeyBuf = '';
      return;
    }

    if (SHORTCUTS[next]) {
      e.preventDefault();
      navigate(SHORTCUTS[next]);
      (window as any).__osopKeyBuf = '';
      return;
    }

    if (e.key === 'n' && !e.ctrlKey && !e.metaKey && !e.altKey) {
      e.preventDefault();
      // The header's NEW MISSION flow is modal-based; shortcut surfaces a hint.
      document.querySelector<HTMLButtonElement>('[data-shortcut="new-mission"]')?.click();
      (window as any).__osopKeyBuf = '';
    }

    // Clear buffer after timeout
    setTimeout(() => { (window as any).__osopKeyBuf = ''; }, 1000);
  }, [navigate]);

  useEffect(() => {
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [handleKey]);

  return (
    <ToastProvider>
      <div className="flex h-screen w-full bg-background overflow-hidden relative">
        <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />

        <div className="flex flex-col flex-1 overflow-hidden z-20 min-w-0">
          <Header />

          {/* Mobile top bar with hamburger */}
          <div className="lg:hidden flex items-center justify-between px-4 py-3 border-b border-outline-variant bg-surface-container shrink-0">
            <button
              onClick={() => setSidebarOpen(true)}
              className="text-on-surface-variant hover:text-on-surface p-2 -ml-2"
              aria-label="Open navigation"
            >
              <Menu size={22} />
            </button>
            <span className="font-label-caps text-[10px] text-on-surface-variant">
              {location.pathname === '/' ? 'OVERVIEW' : location.pathname.replace(/\//g, ' / ').toUpperCase()}
            </span>
            <div className="w-8" /> {/* spacer for centering */}
          </div>

          <main className="flex-1 overflow-y-auto p-4 md:p-8 bg-surface-container-lowest custom-scrollbar">
            <Outlet />
          </main>
        </div>

        {/* Shortcut reference overlay */}
        {showShortcuts && (
          <div
            className="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4"
            onClick={() => setShowShortcuts(false)}
          >
            <div
              className="bg-surface-container border border-outline-variant max-w-lg w-full p-6 space-y-4"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex justify-between items-center border-b border-outline-variant pb-3">
                <h2 className="font-display-lg text-[16px] text-primary-fixed uppercase tracking-tight">Keyboard Shortcuts</h2>
                <button onClick={() => setShowShortcuts(false)} className="text-on-surface-variant hover:text-on-surface text-xl leading-none">&times;</button>
              </div>
              <div className="grid grid-cols-2 gap-x-6 gap-y-2 font-code-sm text-[11px]">
                <div className="text-on-surface-variant">g then o</div><div>Overview</div>
                <div className="text-on-surface-variant">g then m</div><div>Mission Control</div>
                <div className="text-on-surface-variant">g then t</div><div>Mission Timeline</div>
                <div className="text-on-surface-variant">g then i</div><div>Research Intelligence</div>
                <div className="text-on-surface-variant">g then k</div><div>Knowledge Graphs</div>
                <div className="text-on-surface-variant">g then f</div><div>Findings Pipeline</div>
                <div className="text-on-surface-variant">g then v</div><div>Reality Verification</div>
                <div className="text-on-surface-variant">g then u</div><div>Uncertainty Engine</div>
                <div className="text-on-surface-variant">g then s</div><div>Skill Intelligence</div>
                <div className="text-on-surface-variant">g then a</div><div>Auth Audit</div>
                <div className="text-on-surface-variant">g then d</div><div>Differential Auth</div>
                <div className="text-on-surface-variant">g then l</div><div>Learning & Analytics</div>
                <div className="text-on-surface-variant">g then c</div><div>Visual Context</div>
                <div className="text-on-surface-variant">g then h</div><div>Hypotheses</div>
                <div className="text-on-surface-variant">g then r</div><div>Reasoning Trace</div>
                <div className="text-on-surface-variant">g then g</div><div>Cognition Dashboard</div>
                <div className="text-on-surface-variant">g then x</div><div>Attack Chains</div>
                <div className="text-on-surface-variant">n</div><div>New Mission</div>
                <div className="text-on-surface-variant">?</div><div>Toggle this reference</div>
                <div className="text-on-surface-variant">Esc</div><div>Close overlays / sidebar</div>
              </div>
              {sessionId && (
                <div className="border-t border-outline-variant pt-3 text-[10px] text-on-surface-variant font-code-sm">
                  SESSION: {sessionId}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </ToastProvider>
  );
};

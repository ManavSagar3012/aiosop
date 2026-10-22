import React, { useState } from 'react';
import { useSwarmStore } from '../../store/useSwarmStore';
import { Rocket } from 'lucide-react';
import {
  API_BASE, authHeaders, currentOperator, signIn, revokeAndSignOut, subscribeOperator,
  type OperatorIdentity,
} from '../../services/api';
import { NetworkService } from '../../services/network';
import { useIntelligenceStore } from '../../store/useIntelligenceStore';
import {
  NewMissionModal, buildSignedEngagementRequest, type NewMissionInput,
} from '../shared/NewMissionModal';

interface MissionReport {
  markdown?: unknown;
  html?: unknown;
  body_html?: unknown;
  report_id?: unknown;
}

export const Header: React.FC = () => {
  const { currentObjective, currentPhase, setObjective, setPhase } = useSwarmStore();
  const [operator, setOperator] = useState<OperatorIdentity | null>(() => currentOperator());
  const [presentedToken, setPresentedToken] = useState('');
  const [signingIn, setSigningIn] = useState(false);
  const [signInError, setSignInError] = useState<string | null>(null);
  const activeNetwork = React.useRef<NetworkService | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [currentSessionId, setCurrentSessionId] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<'halt' | 'report' | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  React.useEffect(() => subscribeOperator(setOperator), []);

  const resetDisplay = () => {
    activeNetwork.current?.disconnect();
    activeNetwork.current = null;
    setIsModalOpen(false);
    setCurrentSessionId(null);
    useIntelligenceStore.setState({
      sessionId: null, findings: [], verifications: [], uncertainties: [],
      diffAuthFindings: [], skillStats: null, auditLog: [],
      graphData: { nodes: [], edges: [] },
    });
    useSwarmStore.setState({ agents: [], currentObjective: 'Awaiting operator sign-in', currentPhase: 'INITIALIZING' });
  };

  const connectMission = (id: string) => {
    if (!currentOperator()) return;
    if (!activeNetwork.current) activeNetwork.current = new NetworkService(() => {});
    useIntelligenceStore.getState().setSessionId(id);
    activeNetwork.current.connect(id);
    void activeNetwork.current.hydrate(id);
  };

  React.useEffect(() => {
    if (!operator) {
      resetDisplay();
      return;
    }
    let active = true;
    const fetchLatest = async () => {
      try {
        const response = await fetch(`${API_BASE}/engagements`, {
          headers: authHeaders(),
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const sessions: unknown = await response.json();
        if (active && Array.isArray(sessions)) {
          const latest = sessions.find(
            (session): session is { session_id: string } =>
              session !== null && typeof session === 'object' &&
              typeof (session as { session_id?: unknown }).session_id === 'string',
          );
          const id = latest?.session_id ?? null;
          setCurrentSessionId(id);
          if (id) connectMission(id);
        }
      } catch {
        if (active) setActionError('Could not load missions. Verify your API connection and operator access.');
      }
    };
    void fetchLatest();
    // Cleans up the socket when a user changes or signs out.
    return () => {
      active = false;
      activeNetwork.current?.disconnect();
      activeNetwork.current = null;
    };
  }, [operator]);

  const handleSignIn = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSigningIn(true);
    setSignInError(null);
    try {
      await signIn(presentedToken);
      setPresentedToken('');
      setActionError(null);
    } catch (error) {
      setPresentedToken('');
      setSignInError(error instanceof Error ? error.message : 'Operator verification failed.');
    } finally {
      setSigningIn(false);
    }
  };

  const handleSignOut = async () => {
    activeNetwork.current?.disconnect();
    const acknowledged = await revokeAndSignOut();
    setPresentedToken('');
    setSignInError(null);
    resetDisplay();
    setActionError(acknowledged ? null :
      'Local sign-out completed, but server token revocation was not confirmed. The bearer may remain valid until expiry.');
  };

  const handleLaunchMission = async (mission: NewMissionInput): Promise<void> => {
    // Derive ALL request fields from the pasted, externally signed policy.
    // Re-parse at dispatch; mutable preview metadata is never authorization.
    const requestBody = buildSignedEngagementRequest(mission.rawEnvelopeJson);

    let response: Response;
    try {
      response = await fetch(`${API_BASE}/engagements`, {
        method: 'POST',
        headers: authHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(requestBody),
      });
    } catch {
      throw new Error('Cannot reach the API. Mission was not created.');
    }

    if (!response.ok) {
      throw new Error(`Mission creation was rejected (HTTP ${response.status}). Check authorization, target scope and budget.`);
    }
    const created: unknown = await response.json();
    if (!created || typeof created !== 'object' || !('session_id' in created) ||
        created.session_id !== requestBody.engagement_id) {
      throw new Error('Mission creation returned an unexpected engagement ID. Verify server state.');
    }
    setCurrentSessionId(requestBody.engagement_id);
    setObjective(requestBody.domains[0] || requestBody.ips[0] || requestBody.engagement_id);
    setPhase('initialized');
    connectMission(requestBody.engagement_id);
    setActionError(null);
  };

  const handleHalt = async () => {
    if (!currentSessionId || busyAction) return;
    if (!window.confirm('EMERGENCY: Halt all agents for this engagement? Senior operator access is required.')) return;
    const reason = window.prompt('Reason for emergency halt (10–500 characters):');
    if (reason === null) return;
    const cleanReason = reason.trim();
    if (cleanReason.length < 10 || cleanReason.length > 500) {
      setActionError('Enter an emergency halt reason between 10 and 500 characters.');
      return;
    }

    setActionError(null);
    setBusyAction('halt');
    try {
      const url = `${API_BASE}/engagements/${encodeURIComponent(currentSessionId)}/halt?${new URLSearchParams({ reason: cleanReason })}`;
      const response = await fetch(url, { method: 'POST', headers: authHeaders() });
      if (!response.ok) {
        throw new Error(response.status === 403
          ? 'Emergency halt requires senior operator access (HTTP 403).'
          : `Emergency halt failed (HTTP ${response.status}). No stop was confirmed.`);
      }
      const result: unknown = await response.json();
      if (!result || typeof result !== 'object' || !('status' in result) || result.status !== 'halted') {
        throw new Error('Emergency halt returned an unconfirmed status. Check the engagement.');
      }
      setPhase('halted');
      activeNetwork.current?.disconnect();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Emergency halt failed; status is unconfirmed.');
    } finally {
      setBusyAction(null);
    }
  };

  const handlePrintReport = async () => {
    if (!currentSessionId || busyAction) return;
    setActionError(null);
    // Opening synchronously preserves browser popup permissions. No token is
    // ever sent as a URL parameter; only the authenticated API call sees it.
    const reportWindow = window.open('', '_blank');
    if (!reportWindow) {
      setActionError('Allow popups to print an authenticated mission report.');
      return;
    }
    reportWindow.opener = null;
    setBusyAction('report');
    try {
      const response = await fetch(`${API_BASE}/engagements/${encodeURIComponent(currentSessionId)}/report`, {
        headers: authHeaders({ Accept: 'application/json' }),
      });
      if (!response.ok) {
        throw new Error(`Mission report is unavailable (HTTP ${response.status}).`);
      }
      const report: MissionReport = await response.json();
      const printable = typeof report.markdown === 'string' ? report.markdown
        : typeof report.body_html === 'string' ? report.body_html
          : typeof report.html === 'string' ? report.html : null;
      if (!printable) throw new Error('The mission report has no printable content.');

      const document = reportWindow.document;
      document.title = `Mission Report - ${currentSessionId}`;
      const heading = document.createElement('h1');
      heading.textContent = `Mission Report: ${currentSessionId}`;
      const text = document.createElement('pre');
      text.style.whiteSpace = 'pre-wrap';
      text.style.overflowWrap = 'anywhere';
      text.style.fontFamily = 'sans-serif';
      text.textContent = printable; // Never execute report-provided HTML.
      document.body.replaceChildren(heading, text);
      reportWindow.focus();
      reportWindow.print();
    } catch (error) {
      reportWindow.close();
      setActionError(error instanceof Error ? error.message : 'Could not print the mission report.');
    } finally {
      setBusyAction(null);
    }
  };

  return (
    <header className="h-20 bg-background border-b border-outline-variant flex items-center justify-between px-8 shrink-0 relative z-20">
      <div className="flex items-center gap-8">
        <div className="font-display-lg text-primary-fixed tracking-tighter uppercase whitespace-nowrap">
          AI-OSOP // COMMAND CORE
        </div>
        <div className="flex flex-col min-w-[200px]">
          <div className="flex justify-between items-end mb-1">
            <span className="font-label-caps text-on-surface-variant text-[9px]">TARGET: {currentObjective.toUpperCase()}</span>
            <span className="font-label-caps text-primary-container text-[9px]">ID: {currentSessionId?.split('-').pop()?.toUpperCase()} // PHASE: {currentPhase.toUpperCase().replace(/_/g, ' ')}</span>
          </div>
          <div className="w-full h-1 bg-surface-variant relative overflow-hidden">
            <div className="absolute top-0 left-0 h-full bg-primary-container glow-cyan animate-pulse" style={{ width: '65%' }} />
          </div>
          {actionError && <span role="alert" className="text-error text-[10px] max-w-[420px]">{actionError}</span>}
        </div>
      </div>

      <div className="flex items-center gap-4">
        {operator && <span className="font-label-caps text-on-surface-variant text-[10px]" aria-label="Verified operator identity">
          {operator.sub} / {operator.role}
        </span>}
        {operator && <button type="button" onClick={handleSignOut}
          className="border border-outline px-3 py-2 font-label-caps text-on-surface hover:bg-surface-container-high">SIGN OUT</button>}
        <button onClick={() => setIsModalOpen(true)} disabled={Boolean(busyAction)}
          className="bg-primary-container text-on-primary-fixed px-6 py-2 font-label-caps hover:brightness-110 transition-all active:scale-95 flex items-center gap-2 disabled:opacity-50">
          <Rocket size={14} /> NEW MISSION
        </button>
        <button onClick={() => void handlePrintReport()} disabled={!currentSessionId || Boolean(busyAction)}
          className="border border-outline text-on-surface px-4 py-2 font-label-caps hover:bg-surface-container-high transition-all disabled:opacity-50">
          {busyAction === 'report' ? 'LOADING REPORT...' : 'PRINT REPORT'}
        </button>
        <button onClick={() => void handleHalt()} disabled={!currentSessionId || Boolean(busyAction)}
          className="bg-error text-white px-4 py-2 font-label-caps glow-red hover:brightness-125 disabled:opacity-50">
          {busyAction === 'halt' ? 'HALTING...' : 'EMERGENCY HALT'}
        </button>
      </div>

      <NewMissionModal key={operator?.sub ?? 'signed-out'} isOpen={isModalOpen} onClose={() => setIsModalOpen(false)} onLaunch={handleLaunchMission} />
      {!operator && (
        <div className="fixed inset-0 z-[999] bg-background flex items-center justify-center p-6" role="dialog" aria-modal="true" aria-labelledby="operator-sign-in-heading">
          <form onSubmit={(event) => void handleSignIn(event)} className="w-full max-w-lg bg-surface-container border border-outline p-8 space-y-5">
            <h1 id="operator-sign-in-heading" className="text-primary-fixed font-display-lg">OPERATOR SIGN-IN</h1>
            <p className="text-on-surface-variant text-sm">Paste your issued operator bearer token. The API must verify your identity and role before this console is available. Reloading or opening another tab requires sign-in again.</p>
            <label htmlFor="operator-token" className="block font-label-caps text-sm">OPERATOR TOKEN</label>
            <input id="operator-token" type="password" autoComplete="off" spellCheck={false} autoFocus
              value={presentedToken} onChange={(event) => setPresentedToken(event.target.value)}
              className="w-full bg-surface-container-low border border-outline p-3 text-on-surface font-mono"
              placeholder="Paste bearer token" maxLength={4096} required />
            {signInError && <p role="alert" className="text-error text-sm">{signInError}</p>}
            <button type="submit" disabled={signingIn || !presentedToken.trim()}
              className="bg-primary-container text-on-primary-fixed px-6 py-3 font-label-caps disabled:opacity-50">
              {signingIn ? 'VERIFYING OPERATOR...' : 'VERIFY AND SIGN IN'}
            </button>
            <p className="text-on-surface-variant text-xs">Secure HTTPS required except local loopback development. Enterprise SSO/OIDC and credential revocation are not yet integrated.</p>
          </form>
        </div>
      )}
    </header>
  );
};

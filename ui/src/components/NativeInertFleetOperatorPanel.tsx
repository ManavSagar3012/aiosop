import { useCallback, useEffect, useRef, useState } from 'react';
import { Card } from './shared/Card';
import { currentOperator, subscribeOperator } from '../services/api';
import { readNativeInertFleetStatus, type NativeInertFleetStatus } from '../services/nativeInertFleetOperator';

/** Never give web-origin calls access to host-only process start/stop APIs. */
export function NativeInertFleetOperatorPanel() {
  const [view, setView] = useState<NativeInertFleetStatus | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const epoch = useRef(0);
  const refresh = useCallback(async () => {
    const index = ++epoch.current;
    setBusy(true); setView(null); setError('');
    try {
      const answer = await readNativeInertFleetStatus();
      if (index === epoch.current) setView(answer);
    } catch (cause) {
      if (index === epoch.current) setError(cause instanceof Error ? cause.message : 'Native fleet unverified.');
    } finally { if (index === epoch.current) setBusy(false); }
  }, []);
  useEffect(() => {
    if (currentOperator()?.role === 'senior_operator') void refresh();
    const unsub = subscribeOperator(identity => {
      ++epoch.current; setBusy(false); setView(null); setError('');
      if (identity?.role === 'senior_operator') void refresh();
    });
    return () => { ++epoch.current; unsub(); };
  }, [refresh]);
  return <Card title="Owned native Go fleet — process-only readback">
    <div className="space-y-3 text-xs">
      <p>Six native Go MCP processes are inert: even an owned PID or HTTP health response does not establish a signed 0033 witness, permitted scanning, or target effects.</p>
      <button type="button" disabled={busy || currentOperator()?.role !== 'senior_operator'}
        className="rounded border border-outline p-2 disabled:opacity-40" onClick={() => void refresh()}>
        {busy ? 'Checking host-owned status…' : 'Refresh inert process status (GET only)'}
      </button>
      {error && <p role="alert" className="text-error">{error}</p>}
      <p role="status">{view ? `Process lifecycle: ${view.lifecycle.replace(/_/g, ' ')}` : 'No independently verified native process readback.'}</p>
      {view?.processes.map(item => <p key={item.server_id} className="font-mono">
        {item.server_id}: {item.observed ? 'host-local inert PID observed — execution DENIED' : 'not independently observed'}
      </p>)}
      <p className="text-on-surface-variant">Starting or stopping host-pinned binaries requires an independent trusted operator channel, never browser-supplied paths, ports or grants. Configured 11-service readiness remains separate and unverified.</p>
      <p className="text-error">NOT PRODUCTION CERTIFIED / NOT READY</p>
    </div>
  </Card>;
}

import { useEffect, useRef, useState } from 'react';
import { Card } from './shared/Card';
import { currentOperator, subscribeOperator } from '../services/api';
import {
  readPythonInertTurboStatus, type PythonInertTurboStatus,
} from '../services/pythonInertTurboReadback';

export function PythonInertTurboOperatorPanel() {
  const [status, setStatus] = useState<PythonInertTurboStatus | null>(null);
  const [problem, setProblem] = useState('');
  const [busy, setBusy] = useState(false);
  const epoch = useRef(0);

  async function refresh(): Promise<void> {
    if (busy || currentOperator()?.role !== 'senior_operator') return;
    const initial = currentOperator();
    const current = ++epoch.current;
    setBusy(true); setStatus(null); setProblem('');
    try {
      const result = await readPythonInertTurboStatus();
      if (current === epoch.current && currentOperator()?.sub === initial?.sub) setStatus(result);
    } catch (cause) {
      if (current === epoch.current) setProblem(cause instanceof Error ? cause.message : 'Host process UNVERIFIED.');
    } finally {
      if (current === epoch.current) setBusy(false);
    }
  }
  useEffect(() => {
    const unsubscribe = subscribeOperator(() => {
      ++epoch.current; setBusy(false); setStatus(null); setProblem('');
    });
    return () => { ++epoch.current; unsubscribe(); };
  }, []);
  return <Card title="Disabled Turbo Intruder — independently owned process only">
    <div className="space-y-3 text-xs">
      <p>Explicitly pinned Python process ownership can be inspected by a signed senior.
        Turbo Intruder execution stays disabled even when its local server is running.</p>
      <button type="button" className="rounded border border-outline p-2 disabled:opacity-40"
        disabled={busy || currentOperator()?.role !== 'senior_operator'} onClick={() => void refresh()}>
        {busy ? 'Inspecting disabled Python MCP…' : 'Read disabled Turbo process status'}
      </button>
      {problem && <p role="alert" className="text-error">{problem}</p>}
      <p role="status">{status ? `Process: ${status.lifecycle.replace(/_/g, ' ')}` : 'No current process witness.'}</p>
      {status?.process_owned && <p>Owned local PID/listener observed; signed Action: no, native attacks: disabled, target effect: unverified.</p>}
      <p>Starting and stopping the disabled process requires a separately enrolled, host-only senior channel.
        Browser input never supplies executable paths, hashes, ports, targets or actions.</p>
      <p className="text-error">NOT PRODUCTION CERTIFIED / NOT READY</p>
    </div>
  </Card>;
}

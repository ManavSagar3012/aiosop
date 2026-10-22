import { useEffect, useRef, useState } from 'react';
import { Card } from '../shared/Card';
import { currentOperator, subscribeOperator } from '../../services/api';
import {
  readSignedFlowMcpProviderReadiness,
  type SignedMcpProviderReadiness,
} from '../../services/flowMcpProviderReadiness';

export interface FlowMcpProviderReadinessPanelProps {
  flowId: string;
  engagementId: string;
  revision: number;
  flowStatus: string;
  authorizationId?: string | null;
}

/** Durable Action and locally negotiated registry admission diagnostics only.
 * Not a health probe, approval, tool run, report verifier or provider receipt.
 */
export function FlowMcpProviderReadinessPanel({
  flowId, engagementId, revision, flowStatus, authorizationId,
}: FlowMcpProviderReadinessPanelProps) {
  const [actor, setActor] = useState(() => currentOperator());
  const [inventory, setInventory] = useState<SignedMcpProviderReadiness | null>(null);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const run = useRef(0);
  const enabled = !!authorizationId && ['running','pending'].includes(flowStatus)
    && ['operator','senior_operator'].includes(actor?.role ?? '');

  useEffect(() => {
    ++run.current;
    setInventory(null);
    setMessage('');
    setBusy(false);
    return () => { ++run.current; };
  }, [flowId, engagementId, revision, flowStatus, authorizationId]);
  useEffect(() => subscribeOperator(next => {
    ++run.current;
    setInventory(null);
    setMessage('Current operator changed; re-read the signed provider inventory.');
    setBusy(false);
    setActor(next);
  }), []);

  async function inspect(): Promise<void> {
    if (!enabled || busy || !authorizationId) return;
    const sequence = ++run.current;
    setBusy(true);
    setInventory(null);
    setMessage('');
    try {
      const observed = await readSignedFlowMcpProviderReadiness(
        engagementId, flowId, revision, authorizationId,
      );
      if (run.current === sequence) setInventory(observed);
    } catch {
      if (run.current === sequence) {
        setMessage('Current signed MCP runtime/Action ledger unavailable or changed. No provider is certified ready.');
      }
    } finally {
      if (run.current === sequence) setBusy(false);
    }
  }

  return <Card title="Signed MCP provider/Action inventory — unverified">
    <div className="space-y-2 text-xs" aria-label="Signed MCP provider readiness diagnostics">
      <p>Join the current PostgreSQL MCP Action ledger with this API replica's registered MCP declarations.
        No HTTP provider check, service initialization, approval, scan, network call, byte transfer,
        credential activation, remote-effect verification, or safe-to-dispatch decision is performed.</p>
      <button type="button" className="border border-outline px-3 py-2 disabled:opacity-40"
        disabled={!enabled || busy} onClick={() => void inspect()}>
        {busy ? 'READING SIGNED ACTION LEDGER…' : 'READ CURRENT MCP PROVIDER/LEDGER STATUS (GET ONLY)'}
      </button>
      {message && <p role="alert">{message}</p>}
      {inventory && <div role="status" className="space-y-2">
        <p>Flow revision {inventory.flow_revision}; ROE version {inventory.authorization_version}.
          Provider contact: NO; runtime health independently verified: NO; execution authorized: NO.</p>
        <div className="grid gap-2 md:grid-cols-2">
          {inventory.servers.map(s => <div key={s.server_id} className="border border-outline p-2 space-y-1">
            <p><strong>{s.server_id}</strong> — {s.registered_in_process ? 'registered locally' : 'not registered'}
              {' · '}{s.manifest_initialized ? 'manifest initialized' : 'no negotiated manifest'}
              {' · '}circuit {s.circuit_state}</p>
            <p>Declared tools {s.declared_tool_count} · prepared Actions {s.prepared_actions}
              {' · '}UNKNOWN {s.unknown_actions} · reserved {s.reserved_actions}</p>
            <p>Finished {s.finished_actions} · cancelled {s.cancelled_actions}
              {' · '}stale prepared declarations {s.stale_prepared_declarations}</p>
            <p>Provider-side signed admission: NOT VERIFIED · independently verified effect: NO</p>
          </div>)}
        </div>
        <p>For an existing prepared Action, use the separate signed Action preflight. A successful preflight
          remains a momentary eligibility observation and never guarantees dispatch or target effect.</p>
      </div>}
    </div>
  </Card>;
}

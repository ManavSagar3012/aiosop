import { useCallback, useEffect, useRef, useState } from 'react';
import { currentOperator, subscribeOperator } from '../services/api';
import {
  readMcpFleetOperatorReadiness, unverifiedMcpFleetRows,
  type McpFleetOperatorSnapshot,
} from '../services/mcpFleetOperatorReadiness';

/**
 * Optional standalone senior-only fleet READBACK. Not mounted by this change.
 *
 * Administration.tsx already includes a complete process-only 11-service
 * fleet panel; don't mount this alongside it. No remote tools, private ports,
 * raw server response, credentials, running actions or execute controls.
 */
export function McpFleetOperatorReadinessPanel() {
  const [senior, setSenior] = useState(
    () => currentOperator()?.role === 'senior_operator',
  );
  const [snapshot, setSnapshot] = useState<McpFleetOperatorSnapshot | null>(null);
  const [reading, setReading] = useState(false);
  const [notice, setNotice] = useState(
    'Current senior-only MCP fleet observation unavailable; every service is unverified.',
  );
  const epoch = useRef(0);
  const controller = useRef<AbortController | null>(null);

  const clear = useCallback(() => {
    epoch.current += 1;
    controller.current?.abort();
    controller.current = null;
    setSnapshot(null);
    setReading(false);
    setNotice('Current senior-only MCP fleet observation unavailable; no service is assumed ready.');
  }, []);

  const refresh = useCallback(async () => {
    if (currentOperator()?.role !== 'senior_operator') {
      clear();
      return;
    }
    const request = ++epoch.current;
    controller.current?.abort();
    const abort = new AbortController();
    controller.current = abort;
    setSnapshot(null);
    setReading(true);
    setNotice('Reading process-only fleet inventory (GET ONLY).');
    try {
      const next = await readMcpFleetOperatorReadiness(abort.signal);
      if (epoch.current !== request || abort.signal.aborted
        || currentOperator()?.role !== 'senior_operator') return;
      setSnapshot(next);
      setNotice(
        'Only local process registration and initialization were observed. ' +
        'No provider execution, signed authorization, target effect or release was verified.',
      );
    } catch {
      if (epoch.current === request && !abort.signal.aborted) {
        setSnapshot(null);
        setNotice('Readback unavailable or denied. No process, authority or target effect is assumed verified.');
      }
    } finally {
      if (epoch.current === request) {
        controller.current = null;
        setReading(false);
      }
    }
  }, [clear]);

  useEffect(() => {
    const unsub = subscribeOperator(identity => {
      clear();
      const allowed = identity?.role === 'senior_operator';
      setSenior(allowed);
      if (allowed) void refresh();
    });
    if (currentOperator()?.role === 'senior_operator') void refresh();
    return () => {
      epoch.current += 1;
      controller.current?.abort();
      controller.current = null;
      unsub();
    };
  }, [clear, refresh]);

  const services = snapshot?.services ?? unverifiedMcpFleetRows();

  return (
    <section
      aria-label="MCP fleet operator readiness"
      className="rounded-lg border border-outline-variant bg-surface p-4 space-y-3"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-on-surface">11 configured MCP services</h2>
          <p className="text-xs text-on-surface-variant">
            Senior-only · READ-ONLY GET · process registry, not verified execution
          </p>
        </div>
        <button
          type="button"
          disabled={!senior || reading}
          onClick={() => { void refresh(); }}
          className="rounded border border-outline-variant px-3 py-1.5 text-xs text-on-surface disabled:opacity-50"
          aria-label="Refresh process-only MCP fleet readback"
        >
          {reading ? 'Reading…' : 'Refresh GET only'}
        </button>
      </div>
      <p className="font-semibold text-sm text-error" role="status">
        NOT PRODUCTION CERTIFIED / NOT READY
      </p>
      <p className="text-sm text-on-surface-variant">
        {senior ? notice : 'Verified senior operator sign-in required. No fleet telemetry is accessible.'}
      </p>
      <p className="text-xs text-on-surface-variant">
        Registration, initialization and circuit state are process observations only.
        They do not establish current signed authorization, provider admission,
        independently authenticated target effects or a production release.
      </p>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[620px] text-left text-xs" aria-label="Eleven non-certified MCP service statuses">
          <thead className="border-b border-outline-variant">
            <tr>
              <th scope="col" className="p-2 font-semibold">Configured service</th>
              <th scope="col" className="p-2 font-semibold">Process observation</th>
              <th scope="col" className="p-2 font-semibold">Current authorization</th>
              <th scope="col" className="p-2 font-semibold">Independent target effect</th>
              <th scope="col" className="p-2 font-semibold">Certification</th>
            </tr>
          </thead>
          <tbody>
            {services.map(row => (
              <tr key={row.server_id} className="border-b border-outline-variant/40">
                <th scope="row" className="p-2 font-medium text-on-surface">
                  {row.server_id}
                  <span className="block font-normal text-on-surface-variant">
                    {row.importance}
                  </span>
                </th>
                <td className="p-2 text-on-surface-variant">
                  {!snapshot
                    ? 'Unknown — no current readback'
                    : !row.process_registered
                      ? 'Not registered (no reachability conclusion)'
                      : row.process_initialized
                        ? `Registered / initialized / circuit ${row.process_circuit}`
                        : `Registered / not initialized / circuit ${row.process_circuit}`}
                  <span className="block">Runtime health: not verified</span>
                </td>
                <td className="p-2 text-on-surface-variant">Not verified</td>
                <td className="p-2 text-on-surface-variant">Not verified</td>
                <td className="p-2 text-on-surface-variant">Not certified</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="text-xs text-on-surface-variant">
        No private endpoints, tool catalogs, credentials or execution controls are included.
        Failed and stale reads display UNKNOWN, never a cached ready state.
      </p>
    </section>
  );
}

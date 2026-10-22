import React, { useState, useEffect } from 'react';
import { Card } from '../components/shared/Card';
import { ProviderCredentialAdministrationPanel } from '../components/ProviderCredentialAdministrationPanel';
import { NativeInertFleetOperatorPanel } from '../components/NativeInertFleetOperatorPanel';
import { ProviderVaultOperatorStatusPanel } from '../components/ProviderVaultOperatorStatusPanel';
import { BrowserCurrentCustodyPanel } from '../components/BrowserCurrentCustodyPanel';
import { Settings, Shield, Cpu, RefreshCw, Radio, CheckCircle2, AlertTriangle, XCircle, Wrench } from 'lucide-react';
import { Link } from 'react-router-dom';
import { API_BASE, authHeaders, currentOperator, isSecureApiBase, isSecureBrowserOrigin, subscribeOperator } from '../services/api';
import { MCP_FLEET_IDS } from '../services/mcpFleetOperatorReadiness';

interface MCPManifest {
  tool_name: string;
  version: string;
  side_effect_class: 'READ_ONLY' | 'RECON_ACTIVE' | 'INVASIVE_EXPLOIT';
  timeout_seconds: number;
  required_permissions: string[];
  description: string;
}

interface MCPServerInfo {
  server_id: string;
  host: string;
  port: number;
  circuit_state: 'closed' | 'open' | 'half_open';
  failure_count: number;
  success_count: number;
  last_success_at?: string;
  last_failure_at?: string;
  recovery_attempts: number;
  consecutive_successes: number;
  initialized: boolean;
  manifests?: MCPManifest[];
  latency_ms?: number;
}

interface MCPFleetVisibility {
  server_id: string;
  importance: 'critical' | 'optional';
  process_registered: boolean;
  process_initialized: boolean | null;
  qualification: 'not_verified' | 'process_registration_only';
  runtime_health_verified: false;
  current_authorized_operation_verified: false;
  independent_target_effect_verified: false;
  production_certified: false;
}

export const Administration: React.FC = () => {
  // An unavailable backend must never become an apparent fleet of running
  // scanners, measured latencies or successful/approved vulnerability tools.
  const [servers, setServers] = useState<MCPServerInfo[]>([]);
  const [fleet, setFleet] = useState<MCPFleetVisibility[]>([]);
  const [effectiveTransport, setEffectiveTransport] = useState<Record<string, string>>({});
  const [fleetNotice, setFleetNotice] = useState('Independent fleet qualification unavailable.');
  const [actor, setActor] = useState(() => currentOperator());
  const [loading, setLoading] = useState(false);
  const [reconciling, setReconciling] = useState<string | null>(null);
  const [actionMsg, setActionMsg] = useState<string | null>(null);

  const fetchHealth = async (preserveAction = false) => {
    try {
      setLoading(true);
      setFleet([]);
      setEffectiveTransport({});
      setFleetNotice('Independent fleet qualification unavailable.');
      const principal = currentOperator();
      if (!principal || principal.role !== 'senior_operator'
          || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()) throw new Error('Operator not signed in');
      const headers = authHeaders({ Accept: 'application/json' });
      const bearer = headers.Authorization;
      if (typeof bearer !== 'string' || !/^Bearer \S+$/.test(bearer)) throw new Error('No operator bearer');
      const res = await fetch(`${API_BASE}/system/mcp/health`, {
        method: 'GET', headers, cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer',
      });
      if (!res.ok) throw new Error('MCP health not available');
      const data: unknown = await res.json();
      if (!data || typeof data !== 'object' || Array.isArray(data) ||
          !Array.isArray((data as { servers?: unknown }).servers) ||
          (data as { servers: unknown[] }).servers.length > 32)
        throw new Error('Invalid MCP health');
      const sanitized: MCPServerInfo[] = (data as { servers: unknown[] }).servers.map(raw => {
        if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('Invalid MCP server');
        const item = raw as Record<string, unknown>;
        if (typeof item.server_id !== 'string' || !/^[A-Za-z][A-Za-z0-9_.-]{0,79}$/.test(item.server_id)
          || !['closed', 'open', 'half_open'].includes(String(item.circuit_state))
          || !Number.isSafeInteger(item.failure_count) || !Number.isSafeInteger(item.success_count)
          || !Number.isSafeInteger(item.recovery_attempts) || !Number.isSafeInteger(item.consecutive_successes)
          || typeof item.initialized !== 'boolean') throw new Error('Unsafe MCP health metadata');
        return { server_id: item.server_id, host: 'redacted', port: 0,
          circuit_state: item.circuit_state as MCPServerInfo['circuit_state'],
          failure_count: item.failure_count as number, success_count: item.success_count as number,
          recovery_attempts: item.recovery_attempts as number,
          consecutive_successes: item.consecutive_successes as number,
          initialized: item.initialized as boolean };
      });
      if (currentOperator()?.sub !== principal.sub || currentOperator()?.role !== principal.role
          || authHeaders().Authorization !== bearer) throw new Error('Operator changed');
      setServers(sanitized);
      if (!preserveAction) setActionMsg(null);
      try {
        const fleetResponse = await fetch(`${API_BASE}/system/mcp/fleet-readiness`, {
          method: 'GET', headers, cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer',
        });
        if (!fleetResponse.ok) throw new Error('Fleet readiness unavailable');
        const fleetPayload: unknown = await fleetResponse.json();
        if (!fleetPayload || typeof fleetPayload !== 'object' || Array.isArray(fleetPayload))
          throw new Error('Invalid fleet data');
        const result = fleetPayload as Record<string, unknown>;
        if (result.catalog_scope !== 'configured_fleet_process_visibility_only'
          || result.configured_count !== 11 || result.production_certified !== false
          || result.release_decision !== 'NOT PRODUCTION CERTIFIED / NOT READY'
          || !Array.isArray(result.services) || result.services.length !== 11)
          throw new Error('Unverified fleet data');
        const verified: MCPFleetVisibility[] = result.services.map((value: unknown) => {
          if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid fleet entry');
          const entry = value as Record<string, unknown>;
          if (typeof entry.server_id !== 'string' || !/^[a-z][a-z0-9-]{1,79}$/.test(entry.server_id)
            || !['critical', 'optional'].includes(String(entry.importance))
            || typeof entry.process_registered !== 'boolean'
            || (entry.process_initialized !== null && typeof entry.process_initialized !== 'boolean')
            || !['not_verified', 'process_registration_only'].includes(String(entry.qualification))
            || entry.runtime_health_verified !== false || entry.current_authorized_operation_verified !== false
            || entry.independent_target_effect_verified !== false || entry.production_certified !== false)
            throw new Error('Unsafe fleet telemetry');
          return entry as unknown as MCPFleetVisibility;
        });
        if (new Set(verified.map(item => item.server_id)).size !== 11
          || currentOperator()?.sub !== principal.sub || currentOperator()?.role !== 'senior_operator'
          || authHeaders().Authorization !== bearer)
          throw new Error('Fleet identity invalidated');
        setFleet(verified);
        setFleetNotice('All 11 configured services: process telemetry only; no authorized provider or target effect verified.');
        try {
          const transportReply = await fetch(`${API_BASE}/system/mcp/transport-diagnostics`, {
            method: 'GET', headers, credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
          });
          if (!transportReply.ok) throw new Error('Effective transport unavailable');
          const transportBody: unknown = await transportReply.json();
          if (!transportBody || typeof transportBody !== 'object' || Array.isArray(transportBody)) throw new Error('Invalid transport');
          const snapshot = transportBody as Record<string, unknown>;
          if (snapshot.catalog_scope !== 'configured_eleven_effective_transport_observation_only'
            || snapshot.configured_count !== 11 || snapshot.production_certified !== false
            || snapshot.independently_verified_operations !== null || !Array.isArray(snapshot.services)
            || snapshot.services.length !== 11) throw new Error('Unverified transport roster');
          const statuses: Record<string, string> = {};
          const expected = new Set(verified.map(item => item.server_id));
          const allowed = new Set([
            'unverified_nonnumeric_or_nonlocal_http', 'not_registered', 'registry_identity_mismatch',
            'no_current_http_session', 'connected_without_valid_current_declaration',
            'registry_initialized_bootstrap_stale', 'initialized_transport_declaration_only',
          ]);
          for (const value of snapshot.services) {
            if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Malformed transport row');
            const row = value as Record<string, unknown>;
            if (typeof row.server_id !== 'string' || !expected.has(row.server_id)
              || row.current_signed_action_verified !== false || row.independently_verified_target_effect !== false
              || row.native_go_current_process_owned_verified !== false || row.safe_to_retry_unknown_action !== false
              || row.production_certified !== false || row.provider_schema_independently_verified !== false
              || typeof row.effective_transport_status !== 'string'
              || !allowed.has(row.effective_transport_status) || row.server_id in statuses)
              throw new Error('Overstated or duplicate transport record');
            statuses[row.server_id] = row.effective_transport_status;
          }
          if (currentOperator()?.sub !== principal.sub || authHeaders().Authorization !== bearer) throw new Error('Operator changed');
          setEffectiveTransport(statuses);
        } catch {
          setEffectiveTransport({});
        }
      } catch {
        setFleet([]);
        setEffectiveTransport({});
        setFleetNotice('Fleet readiness not independently available. No service is assumed ready.');
      }
    } catch {
      setServers([]);
      setFleet([]);
      setEffectiveTransport({});
      setActionMsg('Authenticated MCP health unavailable; no server is assumed connected or verified.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void fetchHealth();
    return subscribeOperator(next => { setActor(next); setServers([]); setFleet([]); setEffectiveTransport({}); setActionMsg(null); });
  }, []);

  const handlePing = async (serverId: string) => {
    try {
      setActionMsg(`Pinging ${serverId}...`);
      const identity = currentOperator();
      if (!identity || identity.role !== 'senior_operator'
        || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()
        || !/^[A-Za-z][A-Za-z0-9_.-]{0,79}$/.test(serverId)) throw new Error('Operator denied');
      const res = await fetch(`${API_BASE}/system/mcp/${encodeURIComponent(serverId)}/ping`, {
        method: 'POST', headers: authHeaders(), credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
      });
      if (res.ok) {
        const data: unknown = await res.json();
        if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Malformed provider telemetry');
        const probe = data as Record<string, unknown>;
        if (probe.server_id !== serverId || !Number.isSafeInteger(probe.latency_ms)
          || Number(probe.latency_ms) < 0 || Number(probe.latency_ms) > 300000
          || !['closed', 'open', 'half_open'].includes(String(probe.circuit_state)))
          throw new Error('Malformed provider telemetry');
        setServers(prev => prev.map(s => s.server_id === serverId ? {
          ...s, latency_ms: probe.latency_ms as number, circuit_state: probe.circuit_state as MCPServerInfo['circuit_state'],
        } : s));
        if (currentOperator()?.sub !== identity.sub) throw new Error('Operator changed');
        setActionMsg(`Ping returned provider telemetry for ${serverId}; reachability is NOT target-effect verification.`);
      } else {
        setActionMsg(`Ping ${serverId} failed`);
      }
    } catch {
      setActionMsg(`Ping ${serverId} unavailable; outcome UNKNOWN. No success or latency inferred.`);
    }
  };

  const handleResetCircuit = async (serverId: string) => {
    try {
      const identity = currentOperator();
      if (identity?.role !== 'senior_operator' || !/^[A-Za-z][A-Za-z0-9_.-]{0,79}$/.test(serverId)
        || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()
        || !window.confirm(`Reset only the local circuit for ${serverId}? This is not proof the provider or target is healthy.`))
        return;
      setActionMsg(`Resetting circuit for ${serverId}...`);
      const res = await fetch(`${API_BASE}/system/mcp/${encodeURIComponent(serverId)}/reset-circuit`, {
        method: 'POST', headers: authHeaders(), credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
      });
      if (res.ok) {
        if (currentOperator()?.sub !== identity.sub || currentOperator()?.role !== 'senior_operator')
          throw new Error('Operator changed');
        setActionMsg(`Local circuit reset accepted for ${serverId}; refresh for readback. Remote target outcome UNKNOWN.`);
        await fetchHealth();
      } else {
        setActionMsg(`Reset failed for ${serverId}`);
      }
    } catch {
      setActionMsg(`Circuit reset ${serverId} unavailable or UNKNOWN; refresh current signed status.`);
    }
  };

  const handleLocalReconcile = async (serverId: string) => {
    const principal = currentOperator();
    if (!principal || principal.role !== 'senior_operator'
      || !MCP_FLEET_IDS.some(id => id === serverId)
      || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()) return;
    if (!window.confirm(`Try ONE locally configured MCP health and initialization handshake for ${serverId}? This never executes a tool or retries an UNKNOWN Action, and does not certify a provider.`)) return;
    setReconciling(serverId);
    setActionMsg(`Checking configured loopback MCP ${serverId} (no tool execution)...`);
    try {
      const headers = authHeaders({ Accept: 'application/json' });
      const originalBearer = headers.Authorization;
      if (typeof originalBearer !== 'string' || !/^Bearer \S{1,4096}$/.test(originalBearer))
        throw new Error('Missing current senior token');
      const response = await fetch(`${API_BASE}/system/mcp/${encodeURIComponent(serverId)}/reconcile-local`, {
        method: 'POST', headers, credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
      });
      if (currentOperator()?.sub !== principal.sub || currentOperator()?.role !== 'senior_operator'
        || authHeaders().Authorization !== originalBearer) throw new Error('Senior identity changed');
      if (!response.ok) throw new Error('Configured local recovery unavailable');
      const body: unknown = await response.json();
      if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('Malformed reconciliation');
      const result = body as Record<string, unknown>;
      const expectedFields = [
        'server_id', 'status', 'runtime_health_verified',
        'current_authorized_operation_verified', 'independent_target_effect_verified',
        'safe_to_retry_unknown_action',
      ];
      if (Object.keys(result).length !== expectedFields.length
        || expectedFields.some(field => !(field in result))
        || result.server_id !== serverId
        || !['initialized_transport_only', 'already_initialized_unverified', 'unavailable'].includes(String(result.status))
        || result.runtime_health_verified !== false
        || result.current_authorized_operation_verified !== false
        || result.independent_target_effect_verified !== false
        || result.safe_to_retry_unknown_action !== false)
        throw new Error('Untrusted provider readiness response');
      setActionMsg(`MCP ${serverId}: ${String(result.status).replace(/_/g, ' ')}. Runtime, authorization, and target effects remain UNVERIFIED.`);
      await fetchHealth(true);
    } catch {
      setActionMsg(`MCP ${serverId}: local recovery unavailable or ambiguous; no Action was retried or verified.`);
    } finally {
      setReconciling(null);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <ProviderCredentialAdministrationPanel />
      <ProviderVaultOperatorStatusPanel />
      <NativeInertFleetOperatorPanel />
      <BrowserCurrentCustodyPanel />
      <div className="grid grid-cols-3 gap-6">
        <Card title="Swarm Configuration">
           <div className="space-y-4">
              <div className="flex items-center justify-between">
                 <div className="flex items-center gap-2 text-on-surface font-code-sm text-[12px]">
                    <Cpu size={16} className="text-primary-fixed" /> Max Parallel Agents
                 </div>
                 <span className="font-code-sm text-xs text-on-surface-variant">Configured server-side · not editable here</span>
              </div>
              <div className="flex items-center justify-between">
                 <div className="flex items-center gap-2 text-on-surface font-code-sm text-[12px]">
                    <Settings size={16} className="text-error" /> Evidence Integrity Mode
                 </div>
                 <span className="font-code-sm text-xs text-on-surface-variant">Independent real-target verification: NOT ESTABLISHED</span>
              </div>
              <div className="flex items-center justify-between">
                 <div className="flex items-center gap-2 text-on-surface font-code-sm text-[12px]">
                    <Shield size={16} className="text-primary-fixed" /> Verification Strictness
                 </div>
                 <span className="font-code-sm text-xs text-on-surface-variant">Signed ROE + independent target effect + separate human release</span>
              </div>
           </div>
        </Card>

        <Card title="Budget & Limits">
           <div className="space-y-4">
              <div className="flex flex-col gap-1">
                 <span className="text-[9px] font-label-caps text-on-surface-variant">MAX ENGAGEMENT BUDGET (USD)</span>
                 <span className="text-on-surface-variant text-xs">Not determined from this operator-wide view</span>
              </div>
              <div className="flex flex-col gap-1">
                 <span className="text-[9px] font-label-caps text-on-surface-variant">S2 ESCALATION THRESHOLD (EV)</span>
                 <span className="text-on-surface-variant text-xs">Not independently verified</span>
              </div>
              <p className="text-[10px] text-on-surface-variant">Actual spending limits are governed by the signed engagement budget. Nothing in this panel grants model or tool spending.</p>
           </div>
        </Card>

        <Card title="Provider API Keys">
           <div className="space-y-3">
              <div className="flex items-center justify-between border-b border-outline-variant/30 pb-2">
                 <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-primary-fixed"></div>
                    <span className="font-code-sm text-[12px] text-on-surface">OPENAI_GPT4O</span>
                 </div>
                    <span className="text-[10px] text-on-surface-variant">Presence and serving status UNKNOWN</span>
              </div>
              <div className="flex items-center justify-between border-b border-outline-variant/30 pb-2">
                 <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-primary-fixed"></div>
                    <span className="font-code-sm text-[12px] text-on-surface">ANTHROPIC_CLAUDE3</span>
                 </div>
                    <span className="text-[10px] text-on-surface-variant">Presence and serving status UNKNOWN</span>
              </div>
              <div className="flex items-center justify-between opacity-40">
                 <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-on-surface-variant"></div>
                    <span className="font-code-sm text-[12px] text-on-surface">SHODAN_API_KEY</span>
                 </div>
                 <span className="text-[10px] text-on-surface-variant">Not verified</span>
              </div>
              <p className="text-[10px] text-on-surface-variant">These names are examples only, NOT configured or validated credentials. Inspect actual declared routes through signed Flow controls; never display secrets.</p>
           </div>
        </Card>
      </div>

      {/* Work Package P3.3: MCP Tool Adapter Registry & Circuit Breakers Console */}
      <Card title="MCP Tool Adapter Registry & Circuit Breakers">
        <div className="space-y-4">
          <div className="flex items-center justify-between border-b border-outline-variant/40 pb-3">
            <div>
              <div className="text-on-surface font-code-sm text-[13px] flex items-center gap-2">
                <Radio size={16} className="text-primary-fixed" />
                Registered Model Context Protocol Servers (not target-verified)
              </div>
              <div className="text-on-surface-variant text-[11px] mt-0.5">
                Authenticated process-local telemetry only. Select a signed Flow for bounded tool declarations; neither provider health nor execution authorization is implied.
              </div>
            </div>
            <div className="flex items-center gap-3">
              {actionMsg && <span className="text-[11px] font-code-sm text-secondary">{actionMsg}</span>}
              <button
                onClick={() => { void fetchHealth(); }}
                disabled={loading}
                className="flex items-center gap-1.5 px-3 py-1 bg-surface-container-high border border-outline-variant text-on-surface hover:border-primary-fixed text-[11px] font-code-sm transition-all"
              >
                <RefreshCw size={12} className={loading ? 'animate-spin' : ''} /> Refresh
              </button>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left font-code-sm text-[12px]">
              <thead>
                <tr className="border-b border-outline-variant/30 text-on-surface-variant text-[10px] font-label-caps">
                  <th className="py-2 px-3">Server ID</th>
                  <th className="py-2 px-3">Endpoint</th>
                  <th className="py-2 px-3">Circuit State</th>
                  <th className="py-2 px-3">Latency</th>
                  <th className="py-2 px-3">Success / Fail</th>
                  <th className="py-2 px-3">Side-Effect Class</th>
                  <th className="py-2 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-outline-variant/20">
                {servers.map((s) => {
                  const isClosed = s.circuit_state === 'closed';
                  const isOpen = s.circuit_state === 'open';
                  const isHalfOpen = s.circuit_state === 'half_open';
                  const primaryClass = s.manifests?.[0]?.side_effect_class;

                  return (
                    <tr key={s.server_id} className="hover:bg-white/5 transition-colors">
                      <td className="py-3 px-3 font-semibold text-on-surface flex items-center gap-2">
                        <Wrench size={14} className="text-primary-fixed" />
                        {s.server_id}
                      </td>
                      <td className="py-3 px-3 text-on-surface-variant">
                        Hidden (server managed)
                      </td>
                      <td className="py-3 px-3">
                        <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 text-[10px] font-label-caps border ${
                          isClosed ? 'border-primary/50 bg-primary/10 text-primary-fixed' :
                          isOpen ? 'border-error/50 bg-error/10 text-error' :
                          'border-yellow-500/50 bg-yellow-500/10 text-yellow-400'
                        }`}>
                          {isClosed ? <CheckCircle2 size={10} /> : isOpen ? <XCircle size={10} /> : <AlertTriangle size={10} />}
                          {s.circuit_state.toUpperCase()}
                        </span>
                      </td>
                      <td className="py-3 px-3">
                        <span className="text-secondary">{s.latency_ms !== undefined ? `${s.latency_ms} ms` : '—'}</span>
                      </td>
                      <td className="py-3 px-3 text-on-surface-variant">
                        <span className="text-primary-fixed">{s.success_count}</span> / <span className={s.failure_count > 0 ? 'text-error font-bold' : ''}>{s.failure_count}</span>
                      </td>
                      <td className="py-3 px-3">
                        <span className={`px-2 py-0.5 text-[9px] font-label-caps rounded-sm ${
                          primaryClass === 'INVASIVE_EXPLOIT' ? 'bg-error/20 text-error border border-error/40' :
                          primaryClass === 'RECON_ACTIVE' ? 'bg-blue-900/30 text-blue-300 border border-blue-600/40' :
                          'bg-emerald-900/30 text-emerald-300 border border-emerald-600/40'
                        }`}>
                          {primaryClass ?? 'UNVERIFIED — inspect signed Flow'}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => handlePing(s.server_id)}
                            disabled={actor?.role !== 'senior_operator'}
                            className="px-2 py-1 bg-surface-container-high border border-outline-variant hover:border-secondary text-[10px] font-code-sm text-secondary transition-all"
                            title="Ping server"
                          >
                            Ping
                          </button>
                          {actor?.role === 'senior_operator' && (isOpen || isHalfOpen || s.failure_count > 0) && (
                            <button
                              onClick={() => handleResetCircuit(s.server_id)}
                              className="px-2 py-1 bg-error/20 border border-error hover:bg-error/30 text-[10px] font-code-sm text-error transition-all"
                              title="Reset circuit breaker to CLOSED"
                            >
                              Reset
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </Card>

      <Card title="All 11 MCP services — evidence and explicit local transport recovery">
        <div className="space-y-3 text-xs">
          <p className="text-on-surface-variant">
            {fleetNotice} Registration and initialization do not certify invocation, signed original evidence, target-side effects, or production release.
          </p>
          <p className="font-code-sm text-error">NOT PRODUCTION CERTIFIED / NOT READY</p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2" aria-label="Configured MCP fleet process visibility">
            {fleet.map(service => (
              <div key={service.server_id} className="flex items-center justify-between border border-outline-variant/40 p-2 gap-2">
                <span className="font-code-sm">{service.server_id} <span className="text-on-surface-variant">({service.importance})</span></span>
                <div className="flex items-center gap-2">
                  <span className="text-on-surface-variant text-[10px]">
                    {service.process_registered ? 'Registered only — unverified' : 'Not verified in process registry'}
                    <span className="block">Effective HTTP/schema: {effectiveTransport[service.server_id]?.replace(/_/g, ' ') ?? 'not independently observed'}</span>
                  </span>
                  <button type="button" disabled={loading || reconciling !== null || actor?.role !== 'senior_operator'}
                    onClick={() => { void handleLocalReconcile(service.server_id); }}
                    className="px-2 py-1 border border-outline-variant text-[10px] font-code-sm disabled:opacity-40 hover:border-primary-fixed"
                    title="Explicit one-time locally configured health/initialize only. Never execute an Action."
                    aria-label={`Reconcile local MCP ${service.server_id}`}>
                    {reconciling === service.server_id ? 'Checking…' : 'Reconcile local'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-2 gap-6">
        <Card title="Operational Stress Testing">
            <div className="flex items-center justify-between p-4 bg-black/40 border border-outline-variant">
               <div>
                  <div className="font-code-sm text-primary text-[14px]">Simulation: High-Velocity Swarm</div>
                  <div className="text-[10px] text-on-surface-variant italic uppercase mt-1">Target: 1,000 Events / Second</div>
               </div>
               <div className="flex gap-4">
                  <span className="text-[10px] text-on-surface-variant">Simulation is disabled in the operator dashboard to protect live metrics.</span>
               </div>
            </div>
        </Card>

        <Card title="Historical Learning Policy">
         <div className="grid grid-cols-2 gap-8">
            <div>
               <div className="text-on-surface-variant font-code-sm text-[11px] leading-relaxed">
                  Scoped knowledge is confined to the signed Flow and independently reviewed provenance. Cross-engagement pattern sharing is NOT established or enabled by this dashboard.
               </div>
               <div className="mt-4 flex items-center gap-2">
                  <input type="checkbox" disabled checked={false} readOnly className="w-4 h-4 bg-black border border-outline-variant rounded-none accent-primary-fixed" />
                  <span className="text-[11px] font-label-caps text-on-surface">Unverified cross-engagement learning cannot be enabled here</span>
               </div>
            </div>
            <div className="bg-black/40 p-4 border border-outline-variant border-dashed">
               <div className="text-on-surface-variant font-code-sm text-[10px] uppercase mb-2 tracking-widest">Active Knowledge Base Statistics</div>
               <div className="grid grid-cols-2 gap-4">
                  <div className="flex flex-col">
                     <span className="text-primary text-[18px] font-code-sm">—</span>
                     <span className="text-[9px] font-label-caps text-on-surface-variant">VALIDATED OUTCOMES</span>
                  </div>
                  <div className="flex flex-col">
                     <span className="text-primary text-[18px] font-code-sm">—</span>
                     <span className="text-[9px] font-label-caps text-on-surface-variant">FAILURE PATTERNS</span>
                  </div>
                  <div className="flex flex-col">
                     <span className="text-primary text-[18px] font-code-sm">—</span>
                     <span className="text-[9px] font-label-caps text-on-surface-variant">FINGERPRINTED STACKS</span>
                  </div>
               </div>
            </div>
         </div>
        </Card>
        <Card title="Dead Letter Queue">
           <div className="flex flex-col gap-3">
               <p className="text-xs text-on-surface-variant">Replaying unknown terminal effects is disabled. Inspect signed per-engagement recovery and review state; never bulk retry.</p>
               <Link to="/flows" className="w-full py-2 border border-outline text-on-surface text-center hover:bg-surface-container-high transition-all">OPEN SIGNED FLOW OPERATIONS</Link>
           </div>
        </Card>
        <Card title="Engagement Control Panel">
           <div className="flex flex-col gap-3">
               <p className="text-[11px] text-on-surface-variant">
                 Inspect an engagement and use role-protected controls with explicit confirmation and audit records.
               </p>
               <Link to="/flows" className="w-full py-2 border border-outline text-on-surface text-center hover:bg-surface-container-high transition-all">
                 OPEN FLOW OPERATIONS
               </Link>
           </div>
        </Card>
      </div>
    </div>
  );
};

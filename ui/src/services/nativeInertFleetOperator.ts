/** Human-visible *inert* Go PID lifecycle; never an MCP authorization grant. */
import {
  API_BASE, authHeaders, currentOperator, getRuntimeToken, isSecureApiBase, isSecureBrowserOrigin,
} from './api';

const SIX = [
  'recon-mcp', 'payload-mcp', 'nuclei-mcp', 'shodan-mcp',
  'threat-intel-mcp', 'security-bridge',
] as const;

export interface NativeInertFleetStatus {
  lifecycle: string;
  classification: 'host_local_inert_process_only';
  processes: { server_id: string; observed: boolean }[];
  mcp_initialized: false;
  signed_0033_witness_verified: false;
  native_target_execution_enabled: false;
  target_effect_verified: false;
  automatic_action_retry_authorized: false;
  production_certified: false;
}

/** Only GET; host-only start/stop are intentionally NOT exposed in web UI. */
export async function readNativeInertFleetStatus(): Promise<NativeInertFleetStatus> {
  const principal = currentOperator();
  const token = getRuntimeToken();
  if (principal?.role !== 'senior_operator' || !token || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()) {
    throw new Error('Verified senior operator and secure API origin required.');
  }
  const reply = await fetch(`${API_BASE}/system/native-inert-fleet/status`, {
    method: 'GET', headers: authHeaders({ Accept: 'application/json' }),
    credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
  });
  if (getRuntimeToken() !== token || currentOperator()?.sub !== principal.sub || principal.role !== currentOperator()?.role) {
    throw new Error('Senior operator changed during readback.');
  }
  if (!reply.ok) throw new Error(`Native inert process readback unavailable (${reply.status}).`);
  const size = reply.headers.get('content-length');
  if (size && (!/^\d+$/.test(size) || Number(size) > 4096)) throw new Error('Unbounded native process metadata denied.');
  const raw = await reply.text();
  if (raw.length > 4096 || getRuntimeToken() !== token) throw new Error('Stale or unbounded native process metadata.');
  let doc: unknown;
  try { doc = JSON.parse(raw); } catch { throw new Error('Malformed native process metadata.'); }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new Error('Unverified native process status.');
  const record = doc as Record<string, unknown>;
  const allowed = new Set([
    'lifecycle', 'classification', 'processes', 'mcp_initialized', 'signed_0033_witness_verified',
    'native_target_execution_enabled', 'target_effect_verified', 'automatic_action_retry_authorized',
    'production_certified',
  ]);
  if (Object.keys(record).length !== allowed.size || Object.keys(record).some(key => !allowed.has(key)) ||
      typeof record.lifecycle !== 'string' ||
      !['host_unconfigured', 'not_started', 'starting', 'running_inert_unavailable', 'stopped', 'unknown_closed'].includes(record.lifecycle) ||
      record.classification !== 'host_local_inert_process_only' ||
      record.mcp_initialized !== false || record.signed_0033_witness_verified !== false ||
      record.native_target_execution_enabled !== false || record.target_effect_verified !== false ||
      record.automatic_action_retry_authorized !== false || record.production_certified !== false ||
      !Array.isArray(record.processes) || (record.processes.length !== 0 && record.processes.length !== SIX.length)) {
    throw new Error('Process metadata attempts to imply unauthorized execution.');
  }
  for (const [index, item] of (record.processes as unknown[]).entries()) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error('Invalid native process entry.');
    const current = item as Record<string, unknown>;
    if (Object.keys(current).length !== 2 || current.server_id !== SIX[index] ||
        typeof current.observed !== 'boolean' ||
        (record.lifecycle === 'running_inert_unavailable') !== current.observed) {
      throw new Error('Native six-service observation cannot be trusted.');
    }
  }
  if (record.lifecycle === 'host_unconfigured' && record.processes.length !== 0) {
    throw new Error('Unconfigured fleet must not claim native process ownership.');
  }
  return record as unknown as NativeInertFleetStatus;
}

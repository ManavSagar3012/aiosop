/**
 * Senior-only, read-only view of the 11 configured MCP processes.
 *
 * Backend: GET /system/mcp/fleet-readiness (system.py:187).
 * The process registry is NOT a runtime health check, signed Flow authority,
 * target effect, tool catalog, or production release certificate.
 *
 * Uses only api.ts's in-tab, /auth/me-verified operator session. Never saves
 * the bearer, sends cookies, reads persistent storage, or sends a POST.
 */
import {
  API_BASE, authHeaders, currentOperator, isSecureApiBase, isSecureBrowserOrigin,
} from './api';

export const MCP_FLEET_IDS = [
  'burp-mcp', 'recon-mcp', 'payload-mcp', 'nuclei-mcp',
  'shodan-mcp', 'threat-intel-mcp', 'security-bridge', 'browser-mcp',
  'source-map-mcp', 'cloud-mcp', 'turbo-intruder-mcp',
] as const;

export type McpFleetId = typeof MCP_FLEET_IDS[number];
export type McpFleetImportance = 'critical' | 'optional';
export type McpFleetCircuit = 'closed' | 'open' | 'half_open' | null;

const CRITICAL = new Set<McpFleetId>([
  'nuclei-mcp', 'browser-mcp', 'source-map-mcp', 'cloud-mcp', 'turbo-intruder-mcp',
]);
const TOP_FIELDS = [
  'catalog_scope', 'services', 'configured_count',
  'independently_verified_operations', 'production_certified', 'release_decision',
] as const;
const SERVICE_FIELDS = [
  'server_id', 'importance', 'process_registered', 'process_initialized',
  'process_circuit', 'runtime_health_verified', 'current_authorized_operation_verified',
  'independent_target_effect_verified', 'production_certified', 'qualification',
] as const;
const MAX_RESPONSE_BYTES = 16_384;

export interface McpFleetOperatorRow {
  server_id: McpFleetId;
  importance: McpFleetImportance;
  process_registered: boolean;
  process_initialized: boolean | null;
  process_circuit: McpFleetCircuit;
  runtime_health_verified: false;
  current_authorized_operation_verified: false;
  independent_target_effect_verified: false;
  production_certified: false;
  qualification: 'process_registration_only' | 'not_verified';
}

export interface McpFleetOperatorSnapshot {
  catalog_scope: 'configured_fleet_process_visibility_only';
  services: McpFleetOperatorRow[];
  configured_count: 11;
  independently_verified_operations: null;
  production_certified: false;
  release_decision: 'NOT PRODUCTION CERTIFIED / NOT READY';
}

/** Fixed registry labels only, never a remote provider URL or tool name. */
export function unverifiedMcpFleetRows(): McpFleetOperatorRow[] {
  return MCP_FLEET_IDS.map(server_id => ({
    server_id,
    importance: CRITICAL.has(server_id) ? 'critical' : 'optional',
    process_registered: false,
    process_initialized: null,
    process_circuit: null,
    runtime_health_verified: false,
    current_authorized_operation_verified: false,
    independent_target_effect_verified: false,
    production_certified: false,
    qualification: 'not_verified',
  }));
}

function exactObject(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('MCP fleet response is not a bounded object.');
  const obj = value as Record<string, unknown>;
  if (Object.keys(obj).length !== keys.length
    || keys.some(key => !Object.prototype.hasOwnProperty.call(obj, key)))
    throw new Error('MCP fleet response includes missing or private fields.');
  return obj;
}

/** Reject ambiguous duplicate JSON keys BEFORE JSON.parse discards them. */
export function parseBoundedMcpFleetJson(raw: string): unknown {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_RESPONSE_BYTES)
    throw new Error('MCP fleet payload missing or exceeds the 16 KiB limit.');
  const stack: Array<Set<string>> = [];
  for (let i = 0; i < raw.length;) {
    if (raw[i] === '{') { stack.push(new Set<string>()); i++; continue; }
    if (raw[i] === '}') {
      if (!stack.length) throw new Error('Malformed MCP fleet JSON.');
      stack.pop(); i++; continue;
    }
    if (raw[i] === '"') {
      const start = i++;
      let closed = false;
      while (i < raw.length) {
        if (raw[i] === '\\') { i += 2; continue; }
        if (raw[i++] === '"') { closed = true; break; }
      }
      if (!closed) throw new Error('Malformed MCP fleet JSON string.');
      let next = i;
      while (/\s/.test(raw[next] ?? '')) next++;
      if (raw[next] === ':' && stack.length) {
        const key = JSON.parse(raw.slice(start, i)) as string;
        const current = stack[stack.length - 1];
        if (current.has(key)) throw new Error('Duplicate MCP fleet JSON property.');
        current.add(key);
      }
      continue;
    }
    i++;
  }
  if (stack.length) throw new Error('Malformed MCP fleet JSON nesting.');
  return JSON.parse(raw) as unknown;
}

/** Strict allowlist: no ports, credentials, manifests, or unverifiable proof. */
export function validateMcpFleetOperatorSnapshot(value: unknown): McpFleetOperatorSnapshot {
  const top = exactObject(value, TOP_FIELDS);
  if (top.catalog_scope !== 'configured_fleet_process_visibility_only'
    || top.configured_count !== 11
    || top.independently_verified_operations !== null
    || top.production_certified !== false
    || top.release_decision !== 'NOT PRODUCTION CERTIFIED / NOT READY'
    || !Array.isArray(top.services) || top.services.length !== MCP_FLEET_IDS.length) {
    throw new Error('MCP fleet is not a non-certified configured inventory.');
  }
  const observed = new Map<McpFleetId, McpFleetOperatorRow>();
  for (const raw of top.services) {
    const row = exactObject(raw, SERVICE_FIELDS);
    const server = row.server_id;
    if (typeof server !== 'string'
      || !MCP_FLEET_IDS.includes(server as McpFleetId)
      || observed.has(server as McpFleetId)
      || row.importance !== (CRITICAL.has(server as McpFleetId) ? 'critical' : 'optional')
      || typeof row.process_registered !== 'boolean'
      || (row.process_initialized !== null && typeof row.process_initialized !== 'boolean')
      || (row.process_circuit !== null
        && !['closed', 'open', 'half_open'].includes(String(row.process_circuit)))
      || row.runtime_health_verified !== false
      || row.current_authorized_operation_verified !== false
      || row.independent_target_effect_verified !== false
      || row.production_certified !== false
      || row.qualification !== (row.process_registered ? 'process_registration_only' : 'not_verified')
      || (row.process_registered
        ? (row.process_initialized === null || row.process_circuit === null)
        : (row.process_initialized !== null || row.process_circuit !== null))) {
      throw new Error('Untrusted or overstated MCP fleet process qualification.');
    }
    observed.set(server as McpFleetId, {
      server_id: server as McpFleetId,
      importance: row.importance as McpFleetImportance,
      process_registered: row.process_registered,
      process_initialized: row.process_initialized as boolean | null,
      process_circuit: row.process_circuit as McpFleetCircuit,
      runtime_health_verified: false,
      current_authorized_operation_verified: false,
      independent_target_effect_verified: false,
      production_certified: false,
      qualification: row.qualification as McpFleetOperatorRow['qualification'],
    });
  }
  if (observed.size !== MCP_FLEET_IDS.length) throw new Error('Incomplete 11-service MCP fleet.');
  return {
    catalog_scope: 'configured_fleet_process_visibility_only',
    services: MCP_FLEET_IDS.map(id => observed.get(id)!),
    configured_count: 11,
    independently_verified_operations: null,
    production_certified: false,
    release_decision: 'NOT PRODUCTION CERTIFIED / NOT READY',
  };
}

interface SeniorIdentity {
  sub: string;
  role: 'senior_operator';
  exp: number;
  bearer: string;
}

function currentSenior(): SeniorIdentity {
  const identity = currentOperator();
  const bearer = authHeaders().Authorization;
  if (!identity || identity.role !== 'senior_operator'
    || typeof identity.sub !== 'string' || !identity.sub.trim()
    || !Number.isSafeInteger(identity.exp) || identity.exp === null
    || identity.exp * 1000 <= Date.now()
    || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()
    || typeof bearer !== 'string' || !/^Bearer \S{1,4096}$/.test(bearer))
    throw new Error('Current senior-only signed session on a secure origin is required.');
  return { sub: identity.sub, role: 'senior_operator', exp: identity.exp, bearer };
}

function assertUnchangedSenior(initial: SeniorIdentity): void {
  const now = currentSenior();
  if (now.sub !== initial.sub || now.role !== initial.role
    || now.exp !== initial.exp || now.bearer !== initial.bearer)
    throw new Error('Senior operator session changed during MCP fleet readback.');
}

/** One GET only; any error denies with no cached partial result. */
export async function readMcpFleetOperatorReadiness(
  signal?: AbortSignal,
): Promise<McpFleetOperatorSnapshot> {
  const original = currentSenior();
  if (signal?.aborted) throw new Error('MCP fleet readback cancelled.');
  const response = await fetch(`${API_BASE}/system/mcp/fleet-readiness`, {
    method: 'GET',
    headers: { Authorization: original.bearer, Accept: 'application/json' },
    credentials: 'omit',
    cache: 'no-store',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
    signal,
  });
  assertUnchangedSenior(original);
  if (signal?.aborted || response.status !== 200 || !response.ok)
    throw new Error('Senior MCP fleet readback unavailable.');
  const length = response.headers?.get('content-length');
  if (length !== null && length !== undefined
    && (!/^\d+$/.test(length) || Number(length) > MAX_RESPONSE_BYTES))
    throw new Error('MCP fleet readback exceeds bounded metadata size.');
  const raw = await response.text();
  assertUnchangedSenior(original);
  if (signal?.aborted) throw new Error('MCP fleet readback cancelled.');
  const parsed = validateMcpFleetOperatorSnapshot(parseBoundedMcpFleetJson(raw));
  assertUnchangedSenior(original);
  return parsed;
}

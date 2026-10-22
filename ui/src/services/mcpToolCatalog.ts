/** Signed Flow-scoped MCP declarations; NEVER grants execution or probes tools. */
import { API_BASE, authHeaders, currentOperator, isSecureApiBase, isSecureBrowserOrigin } from './api';

const ENGAGEMENT = /^eng-[A-Za-z0-9._-]{1,60}$/;
const FLOW = /^flow-[A-Za-z0-9._-]{1,90}$/;
const NAME = /^[A-Za-z][A-Za-z0-9_.-]{0,79}$/;
const FIELDS = ['engagement_id', 'flow_id', 'flow_revision', 'authorization_version',
  'catalog_kind', 'execution_authorized', 'servers'];
const SERVER_FIELDS = ['server_id', 'manifest_initialized', 'circuit_state',
  'runtime_health_verified', 'tools'];
const TOOL_FIELDS = ['name', 'side_effect_class', 'declared_requires_approval',
  'declared_scope_check', 'signed_task_required_for_execution', 'execution_authorized',
  'runtime_health_verified'];

export interface DeclaredMcpTool {
  name: string;
  side_effect_class: 'READ_ONLY' | 'RECON_ACTIVE' | 'INVASIVE_EXPLOIT';
  declared_requires_approval: boolean;
  declared_scope_check: boolean;
  signed_task_required_for_execution: true;
  execution_authorized: false;
  runtime_health_verified: false;
}
export interface DeclaredMcpServer {
  server_id: string;
  manifest_initialized: boolean;
  circuit_state: 'closed' | 'open' | 'half_open';
  runtime_health_verified: false;
  tools: DeclaredMcpTool[];
}
export interface SignedToolCatalog {
  engagement_id: string;
  flow_id: string;
  flow_revision: number;
  authorization_version: number;
  catalog_kind: 'declarations_only_unverified';
  execution_authorized: false;
  servers: DeclaredMcpServer[];
}

function exact(value: unknown, expected: string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('Unsupported signed MCP declaration.');
  const obj = value as Record<string, unknown>;
  if (Object.keys(obj).length !== expected.length || expected.some(name => !Object.prototype.hasOwnProperty.call(obj, name)))
    throw new Error('Untrusted or private MCP metadata rejected.');
  return obj;
}

export async function readSignedToolCatalog(engagementId: string, flowId: string,
  flowRevision: number, authorizationVersion: number): Promise<SignedToolCatalog> {
  const actor = currentOperator();
  if (!actor || !['operator', 'senior_operator'].includes(actor.role)
    || !ENGAGEMENT.test(engagementId) || !FLOW.test(flowId)
    || !Number.isSafeInteger(flowRevision) || flowRevision < 0
    || !Number.isSafeInteger(authorizationVersion) || authorizationVersion < 1
    || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin())
    throw new Error('Current signed Flow and operator required to inspect tool declarations.');
  const headers = authHeaders({ Accept: 'application/json' });
  const bearer = headers.Authorization;
  if (typeof bearer !== 'string' || !/^Bearer \S+$/.test(bearer))
    throw new Error('Authenticated operator bearer required.');
  const query = new URLSearchParams({
    flow_id: flowId,
    expected_flow_revision: String(flowRevision),
    expected_authorization_version: String(authorizationVersion),
  });
  const response = await fetch(`${API_BASE}/engagements/${encodeURIComponent(engagementId)}/flow-tool-catalog?${query}`, {
    method: 'GET', headers, credentials: 'omit', cache: 'no-store',
    redirect: 'error', referrerPolicy: 'no-referrer',
  });
  if (!response.ok || response.status !== 200)
    throw new Error('Current signed MCP declarations unavailable; no tool authorized.');
  const raw = exact(await response.json() as unknown, FIELDS);
  if (raw.engagement_id !== engagementId || raw.flow_id !== flowId
    || raw.flow_revision !== flowRevision || raw.authorization_version !== authorizationVersion
    || raw.catalog_kind !== 'declarations_only_unverified' || raw.execution_authorized !== false
    || !Array.isArray(raw.servers) || raw.servers.length > 32)
    throw new Error('Stale or falsely executable tool catalog rejected.');
  let count = 0;
  const unique = new Set<string>();
  const servers = raw.servers.map(serverValue => {
    const server = exact(serverValue, SERVER_FIELDS);
    if (typeof server.server_id !== 'string' || !NAME.test(server.server_id)
      || unique.has(server.server_id) || typeof server.manifest_initialized !== 'boolean'
      || !['closed', 'open', 'half_open'].includes(String(server.circuit_state))
      || server.runtime_health_verified !== false
      || !Array.isArray(server.tools) || server.tools.length > 128
      || (!server.manifest_initialized && server.tools.length > 0))
      throw new Error('Unsupported declared MCP server.');
    unique.add(server.server_id);
    const seen = new Set<string>();
    const tools = server.tools.map(value => {
      const item = exact(value, TOOL_FIELDS);
      if (typeof item.name !== 'string' || !NAME.test(item.name) || seen.has(item.name)
        || !['READ_ONLY', 'RECON_ACTIVE', 'INVASIVE_EXPLOIT'].includes(String(item.side_effect_class))
        || typeof item.declared_requires_approval !== 'boolean'
        || typeof item.declared_scope_check !== 'boolean'
        || item.signed_task_required_for_execution !== true
        || item.execution_authorized !== false || item.runtime_health_verified !== false
        || ++count > 256)
        throw new Error('Unsafe or falsely verified MCP tool declaration.');
      seen.add(item.name);
      return {
        name: item.name,
        side_effect_class: item.side_effect_class as DeclaredMcpTool['side_effect_class'],
        declared_requires_approval: item.declared_requires_approval as boolean,
        declared_scope_check: item.declared_scope_check as boolean,
        signed_task_required_for_execution: true as const,
        execution_authorized: false as const,
        runtime_health_verified: false as const,
      };
    });
    return {
      server_id: server.server_id as string,
      manifest_initialized: server.manifest_initialized as boolean,
      circuit_state: server.circuit_state as DeclaredMcpServer['circuit_state'],
      runtime_health_verified: false as const, tools,
    };
  });
  const now = currentOperator();
  if (!now || now.sub !== actor.sub || now.role !== actor.role || now.exp !== actor.exp
    || authHeaders().Authorization !== bearer)
    throw new Error('Operator changed while reading signed MCP declarations.');
  return {
    engagement_id: engagementId, flow_id: flowId, flow_revision: flowRevision,
    authorization_version: authorizationVersion,
    catalog_kind: 'declarations_only_unverified', execution_authorized: false, servers,
  };
}

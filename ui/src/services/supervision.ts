/** Authenticated durable execution-supervision API; never synthesizes status. */
import { API_BASE, authHeaders } from './api';
import { FlowApiError } from './flows';

export interface SupervisionEvent {
  id: string;
  sequence: number;
  engagement_id: string;
  task_id: string | null;
  kind: string;
  actor_id: string;
  payload: Record<string, unknown>;
  created_at: string;
}

export interface ExecutionAttempt {
  id: string;
  engagement_id: string;
  task_id: string;
  attempt: number;
  status: string;
  external_id: string | null;
  receipt: Record<string, unknown> | null;
  revision: number;
  created_at: string;
  updated_at: string;
}

export interface MCPDispatchReceipt {
  server_id: string;
  request_id: string;
  task_id: string;
  tool_name: string;
  status: 'accepted_unconfirmed' | 'started_unknown' | 'outcome_unknown' |
    'provider_returned' | 'cancel_requested' | 'provider_running' |
    'confirmed_stopped' | 'confirmed_finished';
  authorization_version: number;
}

export interface TemporalObservation {
  task_id: string;
  observation: 'found' | 'not_found' | 'unknown' | 'not_applicable';
  provider_status: 'running' | 'completed' | 'failed' | 'canceled' |
    'terminated' | 'continued_as_new' | 'timed_out' | 'unknown';
  verified: boolean;
  durable_status_changed: false;
  safe_to_retry: false;
  external_effect_status: 'unknown';
}

export interface ModelUsageSummary {
  engagement_id: string;
  calls: number;
  settled_calls: number;
  unknown_calls: number;
  unpriced_calls: number;
  provider_reported_cost_usd: string | null;
  provider_reported_input_tokens: number | null;
  provider_reported_output_tokens: number | null;
  cost_complete: boolean;
  invoice_adjusted_cost_usd?: string | null;
  invoice_adjustment_total_usd?: string;
  operator_attested_invoice_cost_usd?: string | null;
  unreconciled_cost_calls?: number;
}

/** OpenAI admin Costs API aggregate for one configured provider project.
 * Read-only: not an invoice-per-call, signed model cap or execution receipt.
 */
export interface OpenAIProjectCostsObservation {
  engagement_id: string;
  source: 'openai_organization_costs_api';
  source_authenticated: true;
  source_scope: 'configured_openai_project';
  project_sha256: string;
  start_time: number;
  end_time: number;
  provider_cost_usd: string | null;
  provider_cost_data_present: boolean;
  source_checked_at_utc: number;
  currency: 'USD';
  pages: number;
  buckets: number;
  cost_lines: number;
  local_ledger_scope: 'engagement_lifetime';
  provider_project_comparable_to_engagement: false;
  provider_project_exclusivity_verified: false;
  project_access_binding: 'server_configured_engagement';
  individual_call_cost_verified: false;
  provider_hard_cost_cap_verified: false;
  execution_outcome: 'unknown';
  safe_to_retry: false;
  ledger_mutated: false;
  observation_recorded: boolean;
}

/** Manual evidence only. The server determines actor, role, signer and ownership. */
export interface InvoiceEvidenceInput {
  expected_task_id: string;
  expected_model: string;
  expected_operation: 'completion' | 'embedding';
  expected_authorization_version: number;
  provider: string;
  invoice_reference: string;
  invoice_line_id: string;
  invoice_sha256: string;
}

export interface InvoiceReconciliationInput extends InvoiceEvidenceInput {
  billed_cost_usd: string;
  input_tokens?: number | null;
  output_tokens?: number | null;
}

export interface InvoiceAdjustmentInput extends InvoiceEvidenceInput {
  adjustment_id: string;
  cost_delta_usd: string;
}

export interface InvoiceAttestationReceipt {
  call_id: string;
  status: 'reconciled' | 'already_reconciled' | 'recorded' | 'already_recorded';
  source: 'operator_attested';
  provider_verified: false;
  execution_outcome: 'unknown';
  safe_to_retry: false;
}

export interface UnreconciledModelCall {
  call_id: string;
  task_id: string | null;
  operation: 'completion' | 'embedding';
  status: 'reserved' | 'unknown';
  created_at: string | null;
  provider_cost_usd: null;
  safe_to_retry: false;
  invoice_reconciled: false;
}

export interface TerminalCallback {
  id: string;
  engagement_id: string;
  task_id: string;
  attempt_id: string;
  outcome: 'succeeded' | 'failed';
  status: 'pending' | 'leased' | 'done' | 'unknown';
  attempts: number;
  receipt: Record<string, unknown>;
  effect_steps?: {
    order: string[];
    states: Record<string, 'pending' | 'started' | 'done' | 'unknown'>;
  } | null;
  created_at: string;
  completed_at: string | null;
}

export interface ExecutionControl {
  request_id: string;
  engagement_id: string;
  task_id: string;
  action: string;
  actor_id: string;
  reason: string;
  status: 'pending' | 'acknowledged' | 'unknown' | 'confirmed_stopped';
  receipt: Record<string, unknown> | null;
  revision: number;
  created_at: string;
  updated_at: string;
}

export interface SupervisionMessage {
  id: string;
  engagement_id: string;
  session_id: string;
  task_id: string | null;
  role: string;
  actor_id: string;
  content: string;
  created_at: string;
  delivery_state?: 'pending' | 'leased' | 'consumed' | 'rejected';
  consumed_at?: string | null;
}

export interface PersistedSupervisionTask {
  task_id: string;
  task_type: string;
  status: string;
  retry_count: number;
  max_retries: number;
  assigned_agent_id?: string | null;
}

export interface AuthorizationStatus {
  status: 'active' | 'revoked' | 'expired' | 'unverified';
  version: number | null;
  key_id: string | null;
  expires_at: string | null;
  policy_sha256: string | null;
  remote_execution_outcome: 'unknown';
}

export interface AuthorizationRevocation {
  status: 'revoked';
  authorization_version: number;
  halt_request_accepted: boolean;
  remote_execution_outcome: 'unknown';
}

export function assertRevokeAuthorizationInput(expectedVersion: number, reason: string): string {
  const clean = reason.trim();
  if (!Number.isSafeInteger(expectedVersion) || expectedVersion <= 0) {
    throw new Error('Recheck the authoritative signed ROE version before revocation.');
  }
  if (clean.length < 10 || clean.length > 500) {
    throw new Error('Provide a meaningful revocation reason (10–500 characters).');
  }
  return clean;
}

function assertInvoiceEvidence(input: InvoiceEvidenceInput): void {
  if (!Number.isSafeInteger(input.expected_authorization_version)
    || input.expected_authorization_version < 1) {
    throw new Error('A current signed authorization version is required for invoice attestation.');
  }
  if (!/^[0-9a-f]{64}$/.test(input.invoice_sha256)) {
    throw new Error('The SHA-256 digest of the invoice document is required.');
  }
  const id = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/;
  for (const value of [input.expected_task_id, input.provider,
    input.invoice_reference, input.invoice_line_id]) {
    if (!id.test(value)) throw new Error('Invoice evidence has invalid identifiers.');
  }
  if (!/^[A-Za-z0-9_.:/-]{1,90}$/.test(input.expected_model)) {
    throw new Error('Invoice evidence has an invalid model.');
  }
}

function invoiceEvidenceBody(input: InvoiceEvidenceInput): InvoiceEvidenceInput {
  assertInvoiceEvidence(input);
  return {
    expected_task_id: input.expected_task_id,
    expected_model: input.expected_model,
    expected_operation: input.expected_operation,
    expected_authorization_version: input.expected_authorization_version,
    provider: input.provider,
    invoice_reference: input.invoice_reference,
    invoice_line_id: input.invoice_line_id,
    invoice_sha256: input.invoice_sha256,
  };
}

const path = (value: string): string => encodeURIComponent(value);
const prefix = (engagementId: string) =>
  '/supervision/engagements/' + path(engagementId);

async function request<T>(pathname: string, body?: object): Promise<T> {
  const response = await fetch(API_BASE + pathname, {
    method: body ? 'POST' : 'GET',
    headers: authHeaders(body ? { 'Content-Type': 'application/json' } : {}),
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const data: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = data && typeof data === 'object' && 'detail' in data
      ? (data as { detail?: unknown }).detail : undefined;
    throw new FlowApiError(
      response.status,
      typeof detail === 'string' ? detail : 'Supervision API returned HTTP ' + response.status,
    );
  }
  return data as T;
}

export const supervisionApi = {
  observeOpenAIProjectCosts: (
    engagementId: string, startTime: number, endTime: number,
  ) => {
    const utcDay = 86400;
    const valid = Number.isSafeInteger(startTime) && Number.isSafeInteger(endTime)
      && startTime >= 0 && endTime > startTime
      && startTime % utcDay === 0 && endTime % utcDay === 0
      && endTime - startTime <= 31 * utcDay
      && endTime <= Math.floor(Date.now() / 1000 / utcDay) * utcDay;
    if (!valid) throw new Error('Choose at most 31 fully completed UTC days.');
    return request<OpenAIProjectCostsObservation>(
      prefix(engagementId) + '/model-usage/provider-costs/openai/observe',
      { start_time: startTime, end_time: endTime },
    );
  },
  reconcileProviderInvoice: (
    engagementId: string, callId: string, input: InvoiceReconciliationInput,
  ) => {
    const amount = /^(?:0|[1-9][0-9]{0,9})(?:\.[0-9]{1,8})?$/;
    if (!amount.test(input.billed_cost_usd)) {
      throw new Error('Invoice charge must be an exact nonnegative USD decimal.');
    }
    for (const value of [input.input_tokens, input.output_tokens]) {
      if (value != null && (!Number.isSafeInteger(value) || value < 0)) {
        throw new Error('Invoice token counts must be nonnegative integers.');
      }
    }
    return request<InvoiceAttestationReceipt>(
      prefix(engagementId) + '/model-usage/calls/' + path(callId) + '/invoice/reconcile',
      {
        ...invoiceEvidenceBody(input),
        billed_cost_usd: input.billed_cost_usd,
        input_tokens: input.input_tokens ?? null,
        output_tokens: input.output_tokens ?? null,
      },
    );
  },
  adjustProviderInvoice: (
    engagementId: string, callId: string, input: InvoiceAdjustmentInput,
  ) => {
    if (!/^-?(?:0|[1-9][0-9]{0,9})(?:\.[0-9]{1,8})?$/.test(input.cost_delta_usd)) {
      throw new Error('Invoice adjustment must be an exact signed USD decimal.');
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/.test(input.adjustment_id)) {
      throw new Error('Invoice adjustment identity is invalid.');
    }
    return request<InvoiceAttestationReceipt>(
      prefix(engagementId) + '/model-usage/calls/' + path(callId) + '/invoice/adjust',
      {
        ...invoiceEvidenceBody(input),
        adjustment_id: input.adjustment_id,
        cost_delta_usd: input.cost_delta_usd,
      },
    );
  },
  reconcileTemporalExistence: (
    engagementId: string, taskId: string, expectedAuthorizationVersion: number,
  ) => {
    if (!Number.isSafeInteger(expectedAuthorizationVersion) || expectedAuthorizationVersion < 1) {
      throw new Error('Signed policy version is required for Temporal existence reconciliation');
    }
    return request<{
      task_id: string; reconciled_workflow_existence: boolean;
      provider_observation: 'found' | 'unknown';
      durable_task_status?: 'scheduled' | 'unchanged';
      safe_to_retry: false; external_effect_status: 'unknown';
    }>(
      prefix(engagementId) + '/tasks/' + path(taskId) + '/temporal/reconcile-existence',
      { expected_authorization_version: expectedAuthorizationVersion },
    );
  },
  unresolvedModelCalls: (engagementId: string) =>
    request<{ calls: UnreconciledModelCall[]; invoice_reconciled: false; safe_to_retry: false }>(
      prefix(engagementId) + '/model-usage/unreconciled?limit=100',
    ),
  observeTemporal: (engagementId: string, taskId: string) =>
    request<TemporalObservation>(
      prefix(engagementId) + '/tasks/' + path(taskId) + '/temporal/observe',
      {},
    ),
  reconcileMcpDispatch: (
    engagementId: string, taskId: string, serverId: string, requestId: string,
  ) => request<{
    status: 'unknown' | 'running' | 'confirmed_stopped' | 'confirmed_finished' |
      'not_supported' | 'denied';
    persisted_status: string;
    request_id: string;
    safe_to_retry: false;
    external_effect_status: 'unknown';
  }>(
    prefix(engagementId) + '/tasks/' + path(taskId) + '/mcp/reconcile',
    { server_id: serverId, request_id: requestId },
  ),
  observePendingMcpDispatches: (engagementId: string, taskId: string) =>
    request<{
      observed: Array<{
        server_id: string; request_id: string; status: string;
        persisted_status: string; safe_to_retry: false;
        external_effect_status: 'unknown';
      }>;
      remaining_unobserved: number;
      safe_to_retry: false;
      external_effect_status: 'unknown';
    }>(
      prefix(engagementId) + '/tasks/' + path(taskId) + '/mcp/reconcile-pending',
      { limit: 6 },
    ),
  cancelPersistedMcpDispatch: (
    engagementId: string, taskId: string, receipt: MCPDispatchReceipt,
    reason: string,
  ) => {
    if (
      receipt.task_id !== taskId
      || !Number.isSafeInteger(receipt.authorization_version)
      || receipt.authorization_version < 1
      || reason.trim().length < 10 || reason.trim().length > 500
      || !/^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/.test(receipt.server_id)
      || !/^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/.test(receipt.request_id)
    ) {
      throw new Error('Remote cancellation requires original persisted identity and meaningful human reason.');
    }
    return request<{
      status: 'unknown' | 'confirmed_stopped';
      persisted_status: string;
      provider_reported_stop: boolean;
      remote_stopped: false;
      safe_to_retry: false;
      external_effect_status: 'unknown';
    }>(
      prefix(engagementId) + '/tasks/' + path(taskId) + '/mcp/cancel-persisted',
      {
        server_id: receipt.server_id,
        request_id: receipt.request_id,
        expected_authorization_version: receipt.authorization_version,
        reason: reason.trim(),
      },
    );
  },
  mcpDispatches: (engagementId: string, taskId?: string) =>
    request<{ dispatches: MCPDispatchReceipt[] }>(
      prefix(engagementId) + '/mcp-dispatches?limit=100'
      + (taskId ? '&task_id=' + path(taskId) : ''),
    ),
  authorizationStatus: (engagementId: string) =>
    request<AuthorizationStatus>('/engagements/' + path(engagementId) + '/authorization/status'),
  revokeAuthorization: (
    engagementId: string, expectedVersion: number, reason: string,
  ) => request<AuthorizationRevocation>(
    '/engagements/' + path(engagementId) + '/authorization/revoke',
    { expected_version: expectedVersion, reason: assertRevokeAuthorizationInput(expectedVersion, reason) },
  ),
  modelUsage: (engagementId: string) =>
    request<{ usage: ModelUsageSummary }>(prefix(engagementId) + '/model-usage'),
  tasks: (engagementId: string) =>
    request<{ tasks: PersistedSupervisionTask[] }>(
      prefix(engagementId) + '/tasks?limit=200',
    ),
  events: (engagementId: string, taskId?: string) =>
    request<{ events: SupervisionEvent[] }>(
      prefix(engagementId) + '/events?limit=100'
      + (taskId ? '&task_id=' + path(taskId) : ''),
    ),
  attempts: (engagementId: string, taskId: string) =>
    request<{ attempts: ExecutionAttempt[] }>(
      prefix(engagementId) + '/tasks/' + path(taskId) + '/attempts',
    ),
  terminalCallbacks: (engagementId: string, taskId: string) =>
    request<{ callbacks: TerminalCallback[] }>(
      prefix(engagementId) + '/tasks/' + path(taskId) + '/terminal-callbacks',
    ),
  control: (engagementId: string, taskId: string) =>
    request<{ control: ExecutionControl | null }>(
      prefix(engagementId) + '/tasks/' + path(taskId) + '/control',
    ),
  requestControl: (
    engagementId: string,
    taskId: string,
    action: 'cancel' | 'pause' | 'resume',
    reason: string,
    requestId: string,
  ) => request<{ control: ExecutionControl; execution_stopped: boolean }>(
    prefix(engagementId) + '/tasks/' + path(taskId) + '/controls',
    { action, reason, request_id: requestId },
  ),
  messages: (engagementId: string, sessionId: string) =>
    request<{ messages: SupervisionMessage[] }>(
      prefix(engagementId) + '/sessions/' + path(sessionId) + '/messages',
    ),
  submitMessage: (
    engagementId: string, sessionId: string, taskId: string, content: string,
    requestId: string,
  ) => request<{ message: SupervisionMessage; delivery_status: string }>(
    prefix(engagementId) + '/sessions/' + path(sessionId) + '/messages',
    { task_id: taskId, content, request_id: requestId },
  ),
};

/**
 * Stream committed events with the SAME bearer-header authorization as REST.
 * Native EventSource cannot send Authorization and would otherwise encourage
 * passing credentials in the URL. A monotonically increasing PostgreSQL
 * sequence is the cursor; reconnect may redeliver a row, so clients dedupe.
 */
export async function streamSupervisionEvents(
  engagementId: string,
  taskId: string | undefined,
  afterSequence: number,
  signal: AbortSignal,
  onEvent: (event: SupervisionEvent) => void,
): Promise<void> {
  const params = new URLSearchParams({
    after_sequence: String(Math.max(0, Math.floor(afterSequence))),
  });
  if (taskId) params.set('task_id', taskId);
  const response = await fetch(
    API_BASE + prefix(engagementId) + '/events/stream?' + params.toString(),
    {
      method: 'GET',
      headers: authHeaders({ Accept: 'text/event-stream' }),
      cache: 'no-store',
      signal,
    },
  );
  if (!response.ok || !response.body) {
    throw new FlowApiError(
      response.status,
      'Live supervision stream returned HTTP ' + response.status,
    );
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  try {
    while (!signal.aborted) {
      const { done, value } = await reader.read();
      if (done) return;
      buffer += decoder.decode(value, { stream: true }).replace(/\r\n/g, '\n');
      if (buffer.length > 131072) throw new Error('Supervision stream event exceeded size limit');
      let end = buffer.indexOf('\n\n');
      while (end >= 0) {
        const chunk = buffer.slice(0, end);
        buffer = buffer.slice(end + 2);
        const kind = chunk.split('\n').find(line => line.startsWith('event:'))
          ?.slice(6).trim();
        if (kind === 'auth_required') {
          throw new FlowApiError(401, 'Supervision access expired or was revoked');
        }
        if (kind === 'unavailable') {
          throw new Error('Durable supervision event stream is unavailable');
        }
        const data = chunk.split('\n').filter(line => line.startsWith('data:'))
          .map(line => line.slice(5).trimStart()).join('\n');
        if (data) {
          const parsed: unknown = JSON.parse(data);
          const obj = (parsed && typeof parsed === 'object' && 'event' in parsed)
            ? (parsed as { event: unknown }).event : parsed;
          if (obj && typeof obj === 'object' && 'sequence' in obj
            && 'engagement_id' in obj && 'id' in obj) {
            const event = obj as SupervisionEvent;
            if (event.engagement_id === engagementId && (!taskId || event.task_id === taskId)
              && Number.isSafeInteger(event.sequence)) onEvent(event);
          }
        }
        end = buffer.indexOf('\n\n');
      }
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
}

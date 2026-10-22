/** Engagement-scoped signed budget and local capability explanation only.
 * This GET never reserves a model call, tests a provider, or verifies billing.
 */
import { API_BASE, authHeaders, currentOperator, isSecureApiBase, isSecureBrowserOrigin } from './api';

const ENGAGEMENT = /^eng-[A-Za-z0-9._-]{1,60}$/;
const MONEY = /^(?:0|[1-9][0-9]{0,9})(?:\.[0-9]{1,8})?$/;
const LABEL = /^[A-Za-z0-9][A-Za-z0-9._:\/-]{0,90}$/;
const REASONS = new Set([
  'signed_authorization_unavailable', 'signed_model_budget_missing',
  'signed_call_quota_exhausted', 'unreconciled_provider_outcome',
  'signed_precharge_missing', 'unpriced_provider_cost', 'cost_ledger_incomplete',
  'signed_cost_budget_exhausted', 'engagement_closed',
  'provider_routes_not_configured', 'trusted_v2_route_policy_missing',
  'no_locally_configured_deployment',
]);

export interface OperatorAdmissionExplanation {
  engagement_id: string;
  scope: 'engagement_not_individual_flow';
  status: 'unavailable' | 'blocked' | 'requires_atomic_admission';
  reasons: string[];
  routes: {
    provider: string; model: string; operations: string[];
    configured_capabilities: string[]; allowed_roles: string[];
    deployment: 'locally_configured' | 'unavailable';
    provider_served_model_verified: false; provider_capability_verified: false;
  }[];
  budget: null | {
    signed_call_limit: number | null; recorded_calls: number; unresolved_calls: number;
    unpriced_calls: number; signed_cost_limit_usd: string | null;
    signed_max_precharge_usd: string | null; known_adjusted_cost_usd: string | null;
    outstanding_precharge_usd: string; provider_native_cost_ceiling_verified: false;
  };
  signed_roe_current_at_read: boolean;
  admission_attempted: false;
  execution_admitted: false;
  provider_called: false;
  reservation_created: false;
  provider_native_cost_ceiling_verified: false;
}

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Malformed admission explanation.');
  return value as Record<string, unknown>;
}

function identifiers(value: unknown, limit: number): string[] {
  if (!Array.isArray(value) || value.length > limit || !value.every(entry =>
    typeof entry === 'string' && LABEL.test(entry))) throw new Error('Malformed admission declaration.');
  return value as string[];
}

function amount(value: unknown): value is string | null {
  return value === null || (typeof value === 'string' && MONEY.test(value));
}

export async function readOperatorAdmissionExplanation(engagementId: string): Promise<OperatorAdmissionExplanation> {
  const operator = currentOperator();
  if (!ENGAGEMENT.test(engagementId) || !operator || operator.role !== 'senior_operator'
    || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()) {
    throw new Error('Authenticated senior operator and engagement required for admission explanation.');
  }
  const headers = authHeaders({ Accept: 'application/json' });
  if (!/^Bearer \S+$/.test(headers.Authorization ?? '')) throw new Error('Verified bearer required.');
  const response = await fetch(
    `${API_BASE}/supervision/engagements/${encodeURIComponent(engagementId)}/model-usage/provider-admission-explanation`,
    { method: 'GET', headers, credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer' },
  );
  if (!response.ok) throw new Error(`Provider admission explanation unavailable (${response.status}).`);
  const value = record(await response.json());
  if (value.engagement_id !== engagementId || value.scope !== 'engagement_not_individual_flow'
    || !['unavailable', 'blocked', 'requires_atomic_admission'].includes(String(value.status))
    || !Array.isArray(value.reasons) || value.reasons.length > 20
    || !value.reasons.every(reason => typeof reason === 'string' && REASONS.has(reason))
    || !Array.isArray(value.routes) || value.routes.length > 16
    || typeof value.signed_roe_current_at_read !== 'boolean'
    || value.admission_attempted !== false || value.execution_admitted !== false
    || value.provider_called !== false || value.reservation_created !== false
    || value.provider_native_cost_ceiling_verified !== false) {
    throw new Error('Unsafe or malformed provider admission response.');
  }
  if (value.status === 'unavailable') {
    if (value.signed_roe_current_at_read !== false || value.budget !== null || value.routes.length !== 0
      || value.reasons.length !== 1 || value.reasons[0] !== 'signed_authorization_unavailable') {
      throw new Error('Unverified provider admission cannot report budget or capabilities.');
    }
  } else if (value.signed_roe_current_at_read !== true || value.budget === null
    || (value.status === 'blocked' && value.reasons.length === 0)
    || (value.status === 'requires_atomic_admission' && value.reasons.length !== 0)) {
    throw new Error('Incomplete signed provider admission explanation.');
  }
  const routes = value.routes.map(entry => {
    const route = record(entry);
    if (typeof route.provider !== 'string' || !LABEL.test(route.provider)
      || typeof route.model !== 'string' || !LABEL.test(route.model)
      || !['locally_configured', 'unavailable'].includes(String(route.deployment))
      || route.provider_served_model_verified !== false || route.provider_capability_verified !== false) {
      throw new Error('Provider admission route claims unsupported verification.');
    }
    return { provider: route.provider, model: route.model,
      operations: identifiers(route.operations, 2),
      configured_capabilities: identifiers(route.configured_capabilities, 16),
      allowed_roles: identifiers(route.allowed_roles, 24),
      deployment: route.deployment as 'locally_configured' | 'unavailable',
      provider_served_model_verified: false as const, provider_capability_verified: false as const };
  });
  let budget: OperatorAdmissionExplanation['budget'] = null;
  if (value.budget !== null) {
    const b = record(value.budget);
    for (const key of ['recorded_calls', 'unresolved_calls', 'unpriced_calls']) {
      if (!Number.isSafeInteger(b[key]) || Number(b[key]) < 0) throw new Error('Invalid budget ledger counts.');
    }
    if (!(b.signed_call_limit === null || (Number.isSafeInteger(b.signed_call_limit)
      && Number(b.signed_call_limit) >= 0))
      || Number(b.unresolved_calls) > Number(b.recorded_calls)
      || Number(b.unpriced_calls) > Number(b.recorded_calls)
      || !amount(b.signed_cost_limit_usd) || !amount(b.signed_max_precharge_usd)
      || !amount(b.known_adjusted_cost_usd)
      || !amount(b.outstanding_precharge_usd) || b.outstanding_precharge_usd === null
      || b.provider_native_cost_ceiling_verified !== false) {
      throw new Error('Malformed or falsely verified signed model budget.');
    }
    budget = b as unknown as NonNullable<OperatorAdmissionExplanation['budget']>;
  }
  const after = currentOperator();
  if (!after || after.sub !== operator.sub || after.role !== 'senior_operator'
    || after.exp !== operator.exp) throw new Error('Operator changed during signed budget readback.');
  return {
    engagement_id: engagementId, scope: 'engagement_not_individual_flow',
    status: value.status as OperatorAdmissionExplanation['status'],
    reasons: value.reasons as string[], routes, budget,
    signed_roe_current_at_read: value.signed_roe_current_at_read as boolean,
    admission_attempted: false, execution_admitted: false,
    provider_called: false, reservation_created: false,
    provider_native_cost_ceiling_verified: false,
  };
}

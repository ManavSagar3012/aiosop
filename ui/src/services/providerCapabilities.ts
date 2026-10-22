/** Senior-only readback of operator-declared routes, never live provider proof. */
import { API_BASE, authHeaders, currentOperator, isSecureApiBase, isSecureBrowserOrigin } from './api';

export interface ProviderCapabilityStatus {
  engagement_id: string;
  routes: { provider: string; model: string; deployment: string; operations: string[] }[];
  provider_currently_available_verified: false;
  provider_native_cost_ceiling_verified: false;
  signed_budget_admission_still_required: true;
}

const ID = /^eng-[A-Za-z0-9._-]{1,60}$/;

export async function readProviderCapabilities(engagementId: string): Promise<ProviderCapabilityStatus> {
  const identity = currentOperator();
  if (!ID.test(engagementId) || identity?.role !== 'senior_operator'
    || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()) {
    throw new Error('Current authenticated senior operator and engagement required.');
  }
  const headers = authHeaders({ Accept: 'application/json' });
  if (!/^Bearer \S+$/.test(headers.Authorization ?? '')) throw new Error('Authenticated bearer required.');
  const res = await fetch(`${API_BASE}/supervision/engagements/${encodeURIComponent(engagementId)}/model-usage/provider-capabilities`, {
    method: 'GET', headers, credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
  });
  if (!res.ok) throw new Error(`Provider capability declaration unavailable (${res.status}).`);
  const raw: unknown = await res.json();
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('Malformed provider capability declaration.');
  const value = raw as Record<string, unknown>;
  if (value.engagement_id !== engagementId || !Array.isArray(value.routes) || value.routes.length > 100
    || value.provider_currently_available_verified !== false
    || value.provider_native_cost_ceiling_verified !== false
    || value.signed_budget_admission_still_required !== true) {
    throw new Error('Stale or unsupported provider verification declaration.');
  }
  const routes = value.routes.map((entry: unknown) => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) throw new Error('Malformed declared route.');
    const route = entry as Record<string, unknown>;
    if (typeof route.provider !== 'string' || route.provider.length > 128
      || typeof route.model !== 'string' || route.model.length > 128
      || typeof route.deployment !== 'string' || route.deployment.length > 64
      || !Array.isArray(route.operations) || route.operations.length > 30
      || !route.operations.every((name: unknown) => typeof name === 'string' && name.length <= 64)
      || route.provider_catalog_verified === true || route.provider_served_model_verified === true
      || route.provider_capability_verified === true || route.provider_currently_available_verified === true
      || route.provider_native_cost_ceiling_verified === true) throw new Error('Untrusted route declared verified.');
    return { provider: route.provider, model: route.model, deployment: route.deployment,
      operations: route.operations as string[] };
  });
  if (currentOperator()?.sub !== identity.sub || currentOperator()?.role !== 'senior_operator') {
    throw new Error('Operator changed during capability readback.');
  }
  return { engagement_id: engagementId, routes, provider_currently_available_verified: false,
    provider_native_cost_ceiling_verified: false, signed_budget_admission_still_required: true };
}

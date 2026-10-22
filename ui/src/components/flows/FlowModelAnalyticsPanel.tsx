import { useEffect, useState } from 'react';

import { currentOperator, subscribeOperator } from '../../services/api';
import { flowApi, type FlowModelAnalytics } from '../../services/flows';
import { readOperatorAdmissionExplanation, type OperatorAdmissionExplanation } from '../../services/providerCapabilityAdmission';
import { Card } from '../shared/Card';

interface Props {
  engagementId: string;
  flowId: string;
  revision: number;
}

const admissionReasonText: Record<string, string> = {
  signed_authorization_unavailable: 'Current signed authorization could not be independently verified.',
  signed_model_budget_missing: 'Signed engagement does not authorize model spending.',
  signed_call_quota_exhausted: 'All signed model-call slots are already recorded.',
  unreconciled_provider_outcome: 'A provider call has an unresolved outcome or charge.',
  signed_precharge_missing: 'Signed worst-case cost precharge is missing.',
  unpriced_provider_cost: 'One or more provider costs remain unpriced.',
  cost_ledger_incomplete: 'The committed cost ledger cannot establish the remaining budget.',
  signed_cost_budget_exhausted: 'Next worst-case precharge exceeds the signed cost budget.',
  engagement_closed: 'The engagement is closed.',
  provider_routes_not_configured: 'No provider route policy is configured.',
  trusted_v2_route_policy_missing: 'Trusted role and capability policy v2 is required.',
  no_locally_configured_deployment: 'No declared provider deployment has a local credential.',
};

/** Inert display of PostgreSQL-attributed model calls; no provider requests. */
export function FlowModelAnalyticsPanel({ engagementId, flowId, revision }: Props) {
  const [role, setRole] = useState(() => currentOperator()?.role ?? '');
  const [value, setValue] = useState<FlowModelAnalytics | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [refresh, setRefresh] = useState(0);
  const [admission, setAdmission] = useState<OperatorAdmissionExplanation | null>(null);
  const [admissionError, setAdmissionError] = useState('');
  const [admissionLoading, setAdmissionLoading] = useState(false);
  const [admissionRefresh, setAdmissionRefresh] = useState(0);

  useEffect(() => subscribeOperator(operator => {
    setRole(operator?.role ?? '');
    setValue(null);
    setAdmission(null);
  }), []);

  useEffect(() => {
    let current = true;
    setAdmission(null);
    setAdmissionError('');
    if (role !== 'senior_operator' || !/^eng-[A-Za-z0-9._-]{1,60}$/.test(engagementId)) {
      setAdmissionLoading(false);
      return () => { current = false; };
    }
    setAdmissionLoading(true);
    void readOperatorAdmissionExplanation(engagementId).then(result => {
      if (current && currentOperator()?.role === 'senior_operator' && result.engagement_id === engagementId) {
        setAdmission(result);
      }
    }).catch(cause => {
      if (current) setAdmissionError(cause instanceof Error ? cause.message : 'Admission explanation unavailable.');
    }).finally(() => { if (current) setAdmissionLoading(false); });
    return () => { current = false; };
  }, [engagementId, role, revision, admissionRefresh]);

  useEffect(() => {
    let valid = true;
    setValue(null);
    setError('');
    if (!['operator', 'senior_operator'].includes(role)
      || !/^eng-[A-Za-z0-9._-]{1,60}$/.test(engagementId)
      || !/^flow-[A-Za-z0-9._-]{1,59}$/.test(flowId)) return;
    setLoading(true);
    void flowApi.getModelAnalytics(flowId).then(result => {
      if (!valid) return;
      if (result.engagement_id !== engagementId || result.flow_id !== flowId
        || result.source !== 'postgresql_task_attributed_model_ledger'
        || result.attribution !== 'same_tenant_task_flow_join_only'
        || result.provider_native_cost_verified !== false
        || result.provider_native_hard_cap_verified !== false
        || result.external_execution_outcome_verified !== false
        || result.complete_for_attributed_calls !== true
        || result.unattributed_model_calls_included !== false
        || !Number.isSafeInteger(result.calls) || result.calls < 0
        || !Array.isArray(result.groups) || result.groups.length > 200
        || result.group_count !== result.groups.length
        || result.groups.some(group => !group || typeof group.model !== 'string'
          || !Number.isSafeInteger(group.calls) || group.calls < 1
          || typeof group.known_ledger_cost_usd !== 'string'
          || !/^(?:0|[1-9][0-9]{0,9})\.[0-9]{8}$/.test(group.known_ledger_cost_usd))) {
        throw new Error('Flow model usage provenance is incomplete or malformed.');
      }
      setValue(result);
    }).catch(cause => {
      if (valid) setError(
        cause instanceof Error ? cause.message : 'Flow model usage is unavailable.',
      );
    }).finally(() => {
      if (valid) setLoading(false);
    });
    return () => { valid = false; };
  }, [role, engagementId, flowId, revision, refresh]);

  return (
    <Card title="Flow model usage · PostgreSQL">
      <div className="space-y-3 text-[12px]">
        <p className="text-on-surface-variant">
          Model and agent-type calls linked to this Flow by same-tenant PostgreSQL Tasks.
          Missing token or cost observations are UNKNOWN, not zero. These are ledger
          observations, not provider-certified invoices or hard spending limits.
        </p>
        <button type="button" className="border border-outline px-3 py-2 disabled:opacity-40"
          onClick={() => setRefresh(n => n + 1)}
          disabled={loading || !['operator', 'senior_operator'].includes(role)}>
          {loading ? 'READING AUTHORITATIVE USAGE…' : 'REFRESH FLOW MODEL USAGE'}
        </button>
        {error && <p role="alert" className="text-error">{error}</p>}
        {value && (
          <section aria-label="Flow model usage read only" className="space-y-2">
            <p role="status">
              Attributed calls: {value.calls} · Unresolved: {value.unknown_outcome_calls} ·
              Unpriced: {value.unpriced_calls}. Independently provider-verified cost: NO.
            </p>
            {value.groups.length === 0 ? (
              <p>No Task-attributed model calls have been recorded for this Flow.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-[11px]">
                  <thead><tr>
                    <th>Model / operation</th><th>Agent</th><th>Calls</th>
                    <th>Input tokens</th><th>Output tokens</th><th>Ledger USD*</th><th>Unknown outcomes</th>
                  </tr></thead>
                  <tbody>{value.groups.map(group => (
                    <tr key={`${group.model}:${group.operation}:${group.agent_type}`}>
                      <td>{group.model} · {group.operation}</td><td>{group.agent_type}</td>
                      <td>{group.calls}</td>
                      <td>{group.input_tokens ?? 'UNKNOWN'}</td>
                      <td>{group.output_tokens ?? 'UNKNOWN'}</td>
                      <td>{group.known_ledger_cost_usd}{group.total_cost_complete ? '' : ' + UNKNOWN'}</td>
                      <td>{group.unknown_outcome_calls}</td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
            )}
            <p className="text-on-surface-variant">
              *Known ledger subtotal; external billing verification and unattributed calls
              are excluded. Reading these numbers never starts or retries model inference.
            </p>
          </section>
        )}
        {role === 'senior_operator' && (
          <section aria-label="Provider admission explanation read only" className="space-y-2 border-t border-outline pt-3">
            <p className="font-semibold">Provider admission · signed engagement budget</p>
            <p className="text-on-surface-variant">
              Engagement-wide signed budget and local provider declarations; the Flow usage above
              counts only this Flow. This read never reserves spending, tests a provider or
              starts model inference. Any future call requires current Task, approval, Flow,
              lease and atomic PostgreSQL reservation checks.
            </p>
            <button type="button" className="border border-outline px-3 py-2 disabled:opacity-40"
              onClick={() => setAdmissionRefresh(n => n + 1)} disabled={admissionLoading}>
              {admissionLoading ? 'READING SIGNED ADMISSION…' : 'REFRESH PROVIDER ADMISSION EXPLANATION'}
            </button>
            {admissionError && <p role="alert" className="text-error">{admissionError}</p>}
            {admission && (
              <div className="space-y-2" role="status">
                <p>Read-only assessment: {admission.status === 'requires_atomic_admission'
                  ? 'No listed static blocker; atomic Task admission REQUIRED'
                  : admission.status === 'blocked' ? 'BLOCKED by recorded conditions' : 'UNKNOWN — signed authorization unavailable'}.</p>
                {admission.reasons.map(reason => (
                  <p key={reason}>{admissionReasonText[reason] ?? 'Unrecognized admission restriction.'}</p>
                ))}
                {admission.budget && <div>
                  <p>Signed model-call quota: {admission.budget.recorded_calls} recorded /
                    {admission.budget.signed_call_limit ?? 'not configured'} limit ·
                    {admission.budget.unresolved_calls} unresolved · {admission.budget.unpriced_calls} unpriced.</p>
                  <p>Signed cost budget: USD {admission.budget.signed_cost_limit_usd ?? 'not configured'} ·
                    precharge per call: USD {admission.budget.signed_max_precharge_usd ?? 'missing'} ·
                    known adjusted ledger cost: USD {admission.budget.known_adjusted_cost_usd ?? 'UNKNOWN'} ·
                    outstanding holds: USD {admission.budget.outstanding_precharge_usd}.</p>
                </div>}
                {admission.routes.length > 0 && (
                  <div className="space-y-1">
                    <p>Locally declared provider role and capabilities (unverified externally):</p>
                    {admission.routes.map(route => <p key={`${route.provider}/${route.model}`}>
                      {route.provider} / {route.model}: {route.deployment} · {route.operations.join(', ')} ·
                      roles: {route.allowed_roles.join(', ') || 'UNKNOWN'} ·
                      capabilities: {route.configured_capabilities.join(', ') || 'UNKNOWN'}
                    </p>)}
                  </div>
                )}
                <p>Provider model availability: NOT VERIFIED. Provider-native cost cap: NOT VERIFIED.
                  Cost verification and external execution outcome: UNKNOWN. No call was admitted or charged by this read.</p>
              </div>
            )}
          </section>
        )}
      </div>
    </Card>
  );
}

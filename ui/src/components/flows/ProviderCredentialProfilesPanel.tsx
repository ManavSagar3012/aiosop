import { useCallback, useEffect, useRef, useState } from 'react';
import { Card } from '../shared/Card';
import { currentOperator, subscribeOperator } from '../../services/api';
import {
  providerPolicyReviews, type ProviderPolicyReview,
} from '../../services/providerPolicyReviews';
import {
  providerCredentialProfiles, readCredentialScope, verifyCredentialScope,
  type ProviderCredentialProfile, type ProviderCredentialScope,
} from '../../services/providerCredentialProfiles';

export interface ProviderCredentialProfilesPanelProps {
  flowId: string;
  engagementId: string;
  revision: number;
  flowStatus: string;
  authorizationId?: string | null;
}

/** Symbolic profile references only; no credential entry, provider traffic, or activation. */
export function ProviderCredentialProfilesPanel({
  flowId, engagementId, revision, flowStatus, authorizationId,
}: ProviderCredentialProfilesPanelProps) {
  const [actor, setActor] = useState(() => currentOperator());
  const [scope, setScope] = useState<ProviderCredentialScope | null>(null);
  const [refs, setRefs] = useState<ProviderCredentialProfile[]>([]);
  const [approvedPolicies, setApprovedPolicies] = useState<ProviderPolicyReview[]>([]);
  const [policyId, setPolicyId] = useState('');
  const [slot, setSlot] = useState<'primary' | 'backup'>('primary');
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const epoch = useRef(0);
  const inFlight = useRef(false);
  const active = ['pending','running'].includes(flowStatus);
  const permitted = active && !!authorizationId
    && ['operator','senior_operator'].includes(actor?.role ?? '');
  const reviewer = permitted && actor?.role === 'senior_operator';

  const clear = useCallback(() => {
    setScope(null);
    setRefs([]);
    setApprovedPolicies([]);
    setPolicyId('');
  }, []);

  const currentScope = useCallback(async (
    original?: ProviderCredentialScope,
  ): Promise<ProviderCredentialScope> => {
    if (!permitted || !authorizationId) {
      throw new Error('Verified current Flow owner or reviewer and authorization required.');
    }
    const signed = await readCredentialScope(flowId, engagementId, revision, authorizationId);
    if (original && (
      signed.authorizationVersion !== original.authorizationVersion
      || signed.authorizationSha256 !== original.authorizationSha256
      || signed.authorizationId !== original.authorizationId
      || signed.flowId !== original.flowId
      || signed.engagementId !== original.engagementId
      || signed.flowRevision !== original.flowRevision
    )) {
      throw new Error('Signed Flow/ROE identity changed.');
    }
    return signed;
  }, [authorizationId, engagementId, flowId, permitted, revision]);

  const refresh = useCallback(async () => {
    if (!permitted || inFlight.current) return;
    const run = ++epoch.current;
    inFlight.current = true;
    setBusy(true);
    clear();
    setMessage('');
    try {
      const signed = await currentScope();
      const catalog = await providerCredentialProfiles.list(signed);
      // The 0025 policy itself is independently approved. A locally chosen
      // policy is only a hint: server revalidates the original signing.
      const policy = reviewer ? [] : await providerPolicyReviews.list(signed);
      await verifyCredentialScope(signed);
      await currentScope(signed);
      if (run !== epoch.current) return;
      setScope(signed);
      setRefs(catalog.items);
      setApprovedPolicies(policy.filter(item => item.status === 'approved'));
      setMessage(catalog.has_more
        ? 'First page only: more durable references exist. This is not an exhaustive list.'
        : 'Current signed reference metadata loaded. No provider or vault was contacted.');
    } catch {
      if (run === epoch.current) {
        clear();
        setMessage('Credential references or signed ROE unavailable. No profile or activation can be assumed.');
      }
    } finally {
      if (run === epoch.current) {
        inFlight.current = false;
        setBusy(false);
      }
    }
  }, [clear, currentScope, permitted, reviewer]);

  useEffect(() => {
    if (permitted) void refresh();
    else {
      ++epoch.current;
      inFlight.current = false;
      setBusy(false);
      clear();
    }
    return () => {
      ++epoch.current;
      inFlight.current = false;
    };
  }, [clear, permitted, refresh]);

  useEffect(() => subscribeOperator(next => {
    ++epoch.current;
    inFlight.current = false;
    setBusy(false);
    setActor(next);
    clear();
    setReason('');
    setMessage('Operator bearer changed. Manually reload current signed references.');
  }), [clear]);

  async function mutate(
    operation: 'register' | 'rotate' | 'approve' | 'revoke',
    item?: ProviderCredentialProfile,
  ): Promise<void> {
    if (!scope || !permitted || busy || inFlight.current) return;
    const choice = approvedPolicies.find(policy => policy.review_id === policyId);
    if (operation === 'register' && !choice) {
      setMessage('Choose an existing separately senior-approved provider policy first.');
      return;
    }
    if ((operation === 'approve' || operation === 'revoke') && !reviewer) return;
    const notice = operation === 'register'
      ? `Register symbolic ${choice?.policy.provider}/${slot} alias from approved policy ${policyId}?`
      : `${operation.toUpperCase()} exact reference ${item?.ref_id} at revision ${item?.reference_revision}?`;
    if (!window.confirm(`${notice}\nOnly durable signed metadata changes. No key, secret or vault link is stored.\n`
      + 'A signed policy and independent senior review are required. Approval is not activation. '
      + 'After any ambiguous response, NEVER retry automatically.')) return;

    const run = ++epoch.current;
    inFlight.current = true;
    setBusy(true);
    setMessage('');
    try {
      await currentScope(scope);
      await verifyCredentialScope(scope);
      let result: ProviderCredentialProfile;
      if (operation === 'register') {
        if (!choice) throw new Error('Policy unavailable.');
        result = await providerCredentialProfiles.register(scope, {
          provider: choice.policy.provider,
          slot,
          policyReviewId: choice.review_id,
          policySha256: choice.policy_sha256,
          confirmed: true,
        });
      } else {
        if (!item) throw new Error('Exact persisted reference is required.');
        const fresh = await providerCredentialProfiles.get(scope, item.ref_id);
        if (fresh.reference_revision !== item.reference_revision
          || fresh.reference_sha256 !== item.reference_sha256
          || fresh.status !== item.status) {
          throw new Error('Reference changed before mutation.');
        }
        if (operation === 'rotate') {
          result = await providerCredentialProfiles.rotate(scope, fresh, {
            provider: fresh.provider, slot: fresh.slot,
            policyReviewId: fresh.policy_review_id,
            policySha256: fresh.policy_sha256,
            confirmed: true,
          });
        } else {
          result = await providerCredentialProfiles.decide(scope, fresh, operation, reason.trim(), true);
        }
      }
      // No optimistic status updates: the service requires exact GET readback.
      const updated = await providerCredentialProfiles.list(scope);
      await verifyCredentialScope(scope);
      await currentScope(scope);
      if (!updated.items.some(candidate =>
        candidate.ref_id === result.ref_id
        && candidate.reference_sha256 === result.reference_sha256
        && candidate.reference_revision === result.reference_revision
        && candidate.status === result.status)) {
        throw new Error('Committed outcome absent from current page.');
      }
      if (run === epoch.current) {
        setRefs(updated.items);
        setReason('');
        setMessage(`${operation.toUpperCase()} reference revision ${result.reference_revision}: ${result.status}. `
          + 'Credential availability, external secret rotation and route activation remain UNVERIFIED.');
      }
    } catch {
      if (run === epoch.current) {
        clear();
        setReason('');
        setMessage('Reference mutation rejected or outcome UNKNOWN. Re-read the signed ledger manually; never retry a lost POST.');
      }
    } finally {
      if (run === epoch.current) {
        inFlight.current = false;
        setBusy(false);
      }
    }
  }

  return <Card title="Provider credential alias references — nonsecret operator workflow">
    <div className="space-y-3 text-xs">
      <p>Register symbolic primary/backup aliases tied to independently approved provider policy reviews.
        A profile is <strong>metadata only</strong>, not a credential, API key, vault connection,
        configured model route or permission to spend. Credential availability and route activation
        are NEVER verified by this workflow. Approval is a historical review status, not proof
        that the original policy remains currently approved.</p>
      <p>Flow {flowId} · revision {revision} · {flowStatus} · role {actor?.role ?? 'unverified'}</p>
      <button type="button" disabled={!permitted || busy}
        className="border border-outline px-3 py-2 disabled:opacity-40"
        onClick={() => void refresh()}>
        {busy ? 'READING SIGNED PROFILE REFERENCES…' : 'REFRESH SIGNED REFERENCES (GET ONLY)'}
      </button>
      {!permitted && <p role="status">Current authenticated operator, active Flow and signed ROE required.</p>}
      {message && <p role="alert">{message}</p>}
      {scope && <div className="border border-outline p-3 space-y-2">
        <p>Register a new pending alias reference. The existing provider intent must already
          be separately approved by a senior operator. This DOES NOT store or rotate a secret.</p>
        <label className="block">Approved signed provider policy
          <select aria-label="Approved provider policy review" value={policyId}
            className="block w-full border border-outline p-2"
            disabled={busy || reviewer}
            onChange={event => setPolicyId(event.target.value)}>
            <option value="">Select current independently approved 0025 policy</option>
            {approvedPolicies.map(policy => <option key={policy.review_id} value={policy.review_id}>
              {policy.policy.provider}/{policy.policy.model} · {policy.review_id}
            </option>)}
          </select>
        </label>
        <label className="block">Server-managed symbolic slot
          <select aria-label="Symbolic credential alias slot" value={slot}
            className="block w-full border border-outline p-2" disabled={busy || reviewer}
            onChange={event => setSlot(event.target.value as 'primary' | 'backup')}>
            <option value="primary">primary</option>
            <option value="backup">backup</option>
          </select>
        </label>
        <button type="button" disabled={!permitted || reviewer || busy || !policyId}
          className="border border-outline px-3 py-2 disabled:opacity-40"
          onClick={() => void mutate('register')}>
          REGISTER PENDING ALIAS REFERENCE (NO KEY)
        </button>
      </div>}
      <div className="space-y-2">
        <p>Current signed alias reference page: {refs.length} item(s).</p>
        {refs.map(item => <div key={item.ref_id} className="border border-outline p-3 space-y-1">
          <p><strong>{item.provider}/{item.slot}</strong> · {item.status.toUpperCase()} REFERENCE ONLY</p>
          <p>{item.ref_id} · revision {item.reference_revision} · generation {item.generation}</p>
          <p>0025 policy {item.policy_review_id}</p>
          <p className="break-all">Policy SHA-256: {item.policy_sha256}</p>
          <p className="break-all">Reference SHA-256: {item.reference_sha256}</p>
          <p>Independent senior review recorded: {item.senior_reviewed ? 'YES' : 'NO'}</p>
          <p>Historical review only: YES · current 0025 policy approval verified: NO</p>
          <p>Credential stored: NO · credential available verified: NO · actual key rotated: NO</p>
          <p>Provider contacted: NO · execution enabled: NO · route activated: NO</p>
          {!reviewer && item.status === 'approved' && scope && <button type="button"
            className="border border-outline px-3 py-2 disabled:opacity-40"
            disabled={busy} onClick={() => void mutate('rotate', item)}>
            ROTATE REFERENCE GENERATION (NO SECRET ROTATION)
          </button>}
          {reviewer && scope && item.status !== 'revoked' && <div className="space-y-2">
            <label className="block">Independent senior decision reason (10–160 nonsecret characters)
              <input aria-label="Independent senior nonsecret review reason"
                className="block w-full border border-outline p-2"
                value={reason} disabled={busy} maxLength={160}
                onChange={event => setReason(event.target.value)} />
            </label>
            {item.status === 'pending' && <button type="button"
              className="border border-outline px-3 py-2 disabled:opacity-40"
              disabled={busy || reason.trim().length < 10}
              onClick={() => void mutate('approve', item)}>
              SENIOR APPROVE REFERENCE ONLY (NOT ACTIVATION)
            </button>}
            <button type="button" className="border border-outline px-3 py-2 disabled:opacity-40"
              disabled={busy || reason.trim().length < 10}
              onClick={() => void mutate('revoke', item)}>
              SENIOR REVOKE REFERENCE
            </button>
          </div>}
        </div>)}
      </div>
      <p>Reference decisions cannot configure ProviderRoutes, store credential bytes, contact an
        LLM, activate routing, reserve budgets, or bypass independent signed execution checks.</p>
    </div>
  </Card>;
}

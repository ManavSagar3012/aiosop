import { useCallback, useEffect, useRef, useState } from 'react';
import { currentOperator, subscribeOperator } from '../services/api';
import {
  providerCredentialAdministration, PROVIDER_CREDENTIAL_ADMIN_NOTICE,
  type CredentialAdministrationPage,
} from '../services/providerCredentialAdministration';
import type { ProviderCredentialProfile } from '../services/providerCredentialProfiles';

/**
 * Standalone Administration mount: <ProviderCredentialAdministrationPanel />.
 *
 * No credential fields, bearer state, localStorage, provider transport or
 * credentials fetched from an external vault. The user supplies only the
 * current signed Flow binding; all versions/hashes are loaded and rechecked.
 */
export function ProviderCredentialAdministrationPanel() {
  const [identity, setIdentity] = useState(() => currentOperator());
  const [flowId, setFlowId] = useState('');
  const [engagementId, setEngagementId] = useState('');
  const [flowRevision, setFlowRevision] = useState('');
  const [authorizationId, setAuthorizationId] = useState('');
  const [page, setPage] = useState<CredentialAdministrationPage | null>(null);
  const [chosenPolicy, setChosenPolicy] = useState('');
  const [slot, setSlot] = useState<'primary' | 'backup'>('primary');
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('Select an authorized Flow to read the current signed reference ledger.');
  const requestEpoch = useRef(0);
  const inFlight = useRef(false);
  const used = useRef(new Set<string>());
  const reviewer = identity?.role === 'senior_operator';
  const permitted = identity?.role === 'operator' || reviewer;

  const invalidate = useCallback(() => {
    requestEpoch.current += 1;
    inFlight.current = false;
    setBusy(false);
    setPage(null);
    setChosenPolicy('');
    setReason('');
  }, []);

  useEffect(() => subscribeOperator(next => {
    invalidate();
    used.current.clear();
    setIdentity(next);
    setFlowId('');
    setEngagementId('');
    setFlowRevision('');
    setAuthorizationId('');
    setMessage('Signed operator session changed. Enter the current Flow binding again.');
  }), [invalidate]);

  useEffect(() => () => { requestEpoch.current += 1; }, []);

  const input = useCallback(() => {
    if (!/^\d{1,9}$/.test(flowRevision)) {
      throw new Error('Enter a nonnegative exact Flow revision.');
    }
    return {
      flowId: flowId.trim(), engagementId: engagementId.trim(),
      flowRevision: Number(flowRevision), authorizationId: authorizationId.trim(),
    };
  }, [flowId, engagementId, flowRevision, authorizationId]);

  const refresh = useCallback(async () => {
    if (!permitted || inFlight.current) return;
    const epoch = ++requestEpoch.current;
    inFlight.current = true;
    setBusy(true);
    setPage(null);
    setChosenPolicy('');
    setMessage('Reading current signed provider reference metadata…');
    try {
      const result = await providerCredentialAdministration.read(input());
      if (epoch !== requestEpoch.current) return;
      setPage(result);
      setMessage(result.hasMore
        ? 'Only the first 20 reference records are shown; this is not an exhaustive ledger.'
        : 'Current bounded reference metadata loaded. No vault or provider was contacted.');
    } catch {
      if (epoch === requestEpoch.current) {
        setPage(null);
        setMessage('Credential references or current signed authority unavailable. No profile state can be assumed.');
      }
    } finally {
      if (epoch === requestEpoch.current) {
        inFlight.current = false;
        setBusy(false);
      }
    }
  }, [input, permitted]);

  const changeBinding = (setter: (value: string) => void, value: string): void => {
    invalidate();
    setter(value);
    setMessage('Flow binding changed. Read current signed metadata before any action.');
  };

  const mutate = async (
    operation: 'register' | 'rotate' | 'approve' | 'revoke',
    existing?: ProviderCredentialProfile,
  ): Promise<void> => {
    if (!permitted || !page || busy || inFlight.current) return;
    const initial = page;
    const policy = initial.approvedPolicies.find(item => item.review_id === chosenPolicy);
    if (operation === 'register' && !policy) {
      setMessage('Select an independently approved 0025 provider intent review.');
      return;
    }
    if (operation !== 'register' && !existing) return;
    if ((operation === 'register' || operation === 'rotate') && identity?.role !== 'operator') return;
    if ((operation === 'approve' || operation === 'revoke') && !reviewer) return;
    // This UI tracks attempted semantics even after a lost HTTP acknowledgment.
    // A refreshed page can be inspected, but never replay that same intent.
    const requestKey = operation === 'register'
      ? `${initial.scope.authorizationSha256}|register|${chosenPolicy}|${slot}`
      : `${initial.scope.authorizationSha256}|${operation}|${existing?.ref_id}|${existing?.reference_revision}`;
    if (used.current.has(requestKey)) {
      setMessage('This reference operation was already attempted. Do not replay UNKNOWN outcomes.');
      return;
    }
    const description = operation === 'register'
      ? `Register a pending nonsecret alias for ${policy?.policy.provider}/${slot}?`
      : `${operation.toUpperCase()} reference ${existing?.ref_id} at expected revision ${existing?.reference_revision}?`;
    if (typeof window === 'undefined' || !window.confirm(
      `${description}\nOnly signed metadata changes. No provider call, vault verification, key upload or real credential rotation occurs.\n`+
      'After a lost acknowledgment inspect the signed ledger; never repeat this operation automatically.',
    )) return;

    const epoch = ++requestEpoch.current;
    inFlight.current = true;
    used.current.add(requestKey);
    setBusy(true);
    setMessage('Submitting one signed reference operation; no provider call…');
    try {
      let result: ProviderCredentialProfile;
      if (operation === 'register') {
        if (!policy) throw new Error('Approved policy unavailable');
        result = await providerCredentialAdministration.register(initial.scope, policy, slot, true);
      } else if (operation === 'rotate') {
        if (!existing) throw new Error('Exact reference unavailable');
        result = await providerCredentialAdministration.rotationIntent(
          initial.scope, existing, existing.reference_revision, true,
        );
      } else {
        if (!existing) throw new Error('Exact reference unavailable');
        result = await providerCredentialAdministration.decide(
          initial.scope, existing, existing.reference_revision, operation, reason.trim(), true,
        );
      }
      // The transport verifies the persisted detail after POST. We also
      // refresh the full page to avoid showing optimistic local readiness.
      const refreshed = await providerCredentialAdministration.read(input());
      if (refreshed.scope.authorizationSha256 !== initial.scope.authorizationSha256
          || refreshed.scope.authorizationVersion !== initial.scope.authorizationVersion
          || !refreshed.items.some(item => item.ref_id === result.ref_id
              && item.reference_sha256 === result.reference_sha256
              && item.reference_revision === result.reference_revision
              && item.status === result.status)) {
        throw new Error('Signed reference changed or vanished after operation');
      }
      if (epoch !== requestEpoch.current) return;
      setPage(refreshed);
      setReason('');
      setMessage(`${operation.toUpperCase()} reference revision ${result.reference_revision}: ${result.status}. `
        + 'No vault material was verified, and no provider was called.');
    } catch {
      if (epoch === requestEpoch.current) {
        setPage(null);
        setChosenPolicy('');
        setReason('');
        setMessage('Reference operation denied or outcome UNKNOWN. Manually read the current signed ledger; never replay the lost POST.');
      }
    } finally {
      if (epoch === requestEpoch.current) {
        inFlight.current = false;
        setBusy(false);
      }
    }
  };

  return <section aria-label="Provider credential administration" className="space-y-4 border border-outline-variant p-4">
    <div className="space-y-2">
      <h2 className="font-semibold text-lg">Provider credential reference administration</h2>
      <p role="status" className="font-code-sm text-error">{PROVIDER_CREDENTIAL_ADMIN_NOTICE}</p>
      <p className="text-xs text-on-surface-variant">
        Signed Flow-scoped primary/backup reference metadata and human review only. An approved reference
        records historical senior review, not current 0025 approval, a connected vault, usable API keys,
        a verified model endpoint, spending permission, or enabled dispatch.
      </p>
    </div>

    <div className="grid gap-3 sm:grid-cols-2">
      <label className="text-xs">Flow ID
        <input aria-label="Credential Flow ID" maxLength={64} autoComplete="off" spellCheck={false}
          value={flowId} disabled={busy} onChange={e => changeBinding(setFlowId, e.target.value)}
          placeholder="flow-…" className="block w-full border border-outline p-2 bg-transparent" />
      </label>
      <label className="text-xs">Engagement ID
        <input aria-label="Credential engagement ID" maxLength={64} autoComplete="off" spellCheck={false}
          value={engagementId} disabled={busy} onChange={e => changeBinding(setEngagementId, e.target.value)}
          placeholder="eng-…" className="block w-full border border-outline p-2 bg-transparent" />
      </label>
      <label className="text-xs">Expected Flow revision
        <input aria-label="Expected credential Flow revision" inputMode="numeric" maxLength={9}
          value={flowRevision} disabled={busy} onChange={e => changeBinding(setFlowRevision, e.target.value)}
          placeholder="0" className="block w-full border border-outline p-2 bg-transparent" />
      </label>
      <label className="text-xs">Signed authorization ID (nonsecret identifier)
        <input aria-label="Signed credential authorization ID" maxLength={128} autoComplete="off" spellCheck={false}
          value={authorizationId} disabled={busy} onChange={e => changeBinding(setAuthorizationId, e.target.value)}
          className="block w-full border border-outline p-2 bg-transparent" />
      </label>
    </div>
    <button type="button" disabled={!permitted || busy} onClick={() => void refresh()}
      className="border border-outline p-2 text-xs disabled:opacity-40">
      {busy ? 'CHECKING SIGNED REFERENCE…' : 'READ CURRENT SIGNED PROFILE (GET ONLY)'}
    </button>
    <p role="status" className="text-xs">{message}</p>
    {!permitted && <p role="alert">A verified operator or senior operator session is required.</p>}

    {page && <div className="space-y-3">
      <p className="text-xs">Flow {page.scope.flowId} · signed ROE revision {page.scope.authorizationVersion}
        · first-page count {page.items.length} · {identity?.role}</p>
      {identity?.role === 'operator' && <div className="space-y-2 border border-outline p-3">
        <p className="text-xs">Register a pending symbolic alias from a separately senior-approved provider policy.</p>
        <label className="text-xs block">Approved provider policy
          <select aria-label="Credential approved provider policy" value={chosenPolicy}
            disabled={busy} onChange={e => setChosenPolicy(e.target.value)}
            className="block w-full border border-outline bg-transparent p-2">
            <option value="">Select previously reviewed policy</option>
            {page.approvedPolicies.map(policy => <option key={policy.review_id} value={policy.review_id}>
              {policy.policy.provider} · {policy.policy.model} · {policy.review_id}
            </option>)}
          </select>
        </label>
        <label className="text-xs block">Symbolic slot
          <select aria-label="Credential symbolic slot" disabled={busy} value={slot}
            onChange={e => setSlot(e.target.value as 'primary' | 'backup')}
            className="block border border-outline bg-transparent p-2">
            <option value="primary">primary</option><option value="backup">backup</option>
          </select>
        </label>
        <button type="button" disabled={busy || !chosenPolicy}
          onClick={() => void mutate('register')} className="border border-outline p-2 text-xs disabled:opacity-40">
          REGISTER PENDING REFERENCE — NO CREDENTIAL
        </button>
      </div>}
      {page.items.map(item => <div key={item.ref_id} className="space-y-2 border border-outline p-3 text-xs">
        <p><strong>{item.provider}/{item.slot}</strong> · {item.status.toUpperCase()} REFERENCE ONLY</p>
        <p className="break-all">{item.ref_id} · expected CAS revision {item.reference_revision} · generation {item.generation}</p>
        <p className="break-all">0025 policy review: {item.policy_review_id}</p>
        <p className="break-all">Profile SHA-256: {item.reference_sha256}</p>
        <p>Senior review recorded: {item.senior_reviewed ? 'yes (historical only)' : 'no'}</p>
        <p>Credential stored: NO · vault material verified: NO · actual key rotated: NO · model called: NO</p>
        {identity?.role === 'operator' && item.status === 'approved' && <button type="button"
          disabled={busy} onClick={() => void mutate('rotate', item)}
          className="border border-outline p-2 disabled:opacity-40">
          ROTATION INTENT ONLY — EXPECTED REVISION {item.reference_revision}
        </button>}
        {reviewer && item.status !== 'revoked' && <div className="space-y-2">
          <label className="block">Independent senior review reason (nonsecret, 10–160 characters)
            <input aria-label="Credential senior review reason" value={reason}
              onChange={e => setReason(e.target.value)} disabled={busy} maxLength={160}
              autoComplete="off" className="block w-full border border-outline bg-transparent p-2" />
          </label>
          {item.status === 'pending' && <button type="button" disabled={busy || reason.trim().length < 10}
            onClick={() => void mutate('approve', item)} className="border border-outline p-2 disabled:opacity-40">
            SENIOR APPROVE REFERENCE ONLY
          </button>}
          <button type="button" disabled={busy || reason.trim().length < 10}
            onClick={() => void mutate('revoke', item)} className="border border-outline p-2 disabled:opacity-40">
            SENIOR REVOKE REFERENCE ONLY
          </button>
        </div>}
      </div>)}
      {page.hasMore && <p role="status">Further references exist; view the Flow ledger for other pages.</p>}
    </div>}
  </section>;
}

import { useCallback, useEffect, useRef, useState } from 'react';
import { Card } from '../shared/Card';
import { currentOperator, subscribeOperator } from '../../services/api';
import { supervisionApi } from '../../services/supervision';
import {
  providerPolicyReviews,
  type ProviderPolicyReview, type ProviderPolicyIntent, type ProviderReviewScope,
} from '../../services/providerPolicyReviews';

interface Props {
  flowId: string;
  engagementId: string;
  revision: number;
  flowStatus: string;
  authorizationId?: string | null;
}

/** Authenticated, durable provider route INTENT review; NEVER makes an LLM/provider call. */
export function ProviderPolicyReviewPanel({ flowId, engagementId, revision, flowStatus, authorizationId }: Props) {
  const [actor, setActor] = useState(() => currentOperator());
  const [scope, setScope] = useState<ProviderReviewScope | null>(null);
  const [reviews, setReviews] = useState<ProviderPolicyReview[]>([]);
  const [model, setModel] = useState('');
  const [provider, setProvider] = useState<ProviderPolicyIntent['provider']>('openai');
  const [operation, setOperation] = useState<'completion' | 'embedding'>('completion');
  const [role, setRole] = useState('vuln_analysis');
  const [tokenLimit, setTokenLimit] = useState('1024');
  const [editing, setEditing] = useState<ProviderPolicyReview | null>(null);
  const [seniorReason, setSeniorReason] = useState('');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const epoch = useRef(0);
  const mutable = ['pending','running'].includes(flowStatus);
  const permitted = mutable && ['operator', 'senior_operator'].includes(actor?.role ?? '');

  const refresh = useCallback(async () => {
    const stamp = ++epoch.current;
    setLoading(true); setScope(null); setReviews([]); setEditing(null); setMessage('');
    try {
      const authority = await supervisionApi.authorizationStatus(engagementId);
      if (!authorizationId || authority.status !== 'active'
        || !Number.isSafeInteger(authority.version) || (authority.version ?? 0) < 1
        || typeof authority.policy_sha256 !== 'string') throw new Error('Signed authorization unavailable');
      const readScope: ProviderReviewScope = {
        flowId, engagementId, flowRevision: revision, authorizationVersion: authority.version!,
        authorizationId, authorizationSha256: authority.policy_sha256,
      };
      const list = await providerPolicyReviews.list(readScope);
      const checked = await supervisionApi.authorizationStatus(engagementId);
      if (checked.status !== 'active' || checked.version !== authority.version
        || checked.policy_sha256 !== authority.policy_sha256)
        throw new Error('Signed policy changed');
      if (stamp !== epoch.current) return;
      setScope(readScope); setReviews(list);
    } catch {
      if (stamp === epoch.current)
        setMessage('Signed provider intent reviews unavailable or revoked. No provider was tested, configured or enabled.');
    } finally {
      if (stamp === epoch.current) setLoading(false);
    }
  }, [authorizationId, engagementId, flowId, revision]);

  useEffect(() => {
    if (permitted) void refresh();
    return () => { ++epoch.current; };
  }, [permitted, refresh]);
  useEffect(() => subscribeOperator(next => {
    ++epoch.current; setActor(next); setScope(null); setReviews([]); setEditing(null);
    setMessage('Operator identity changed; refresh signed provider review.');
  }), []);

  async function create() {
    if (!scope || !permitted || loading || !model.trim()) return;
    const maximum = Number(tokenLimit);
    if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 16384) {
      setMessage('Enter an integer token ceiling (1–16384).'); return;
    }
    const normalizedModel = model.trim();
    const policy: ProviderPolicyIntent = {
      provider, model: normalizedModel, operations: [operation], allowed_roles: [role],
      capabilities: operation === 'completion' ? ['text_completion'] : ['embeddings'],
      max_output_tokens: maximum, budget_source: 'signed_postgres_roe',
    };
    if (!window.confirm(`${editing ? 'Revise exact PENDING' : 'Record new'} operator-declared provider INTENT ${provider}/${normalizedModel}?
No credential will be stored. Even senior approval does not configure or run a provider, verify serving, or authorize spending.`))
      return;
    const stamp = ++epoch.current;
    setLoading(true); setMessage('');
    try {
      const fresh = await supervisionApi.authorizationStatus(engagementId);
      if (fresh.status !== 'active' || fresh.version !== scope.authorizationVersion
        || fresh.policy_sha256 !== scope.authorizationSha256) throw new Error('Signer changed');
      const result = editing
        ? await providerPolicyReviews.update(scope, editing, policy)
        : await providerPolicyReviews.create(scope, policy);
      const list = await providerPolicyReviews.list(scope);
      const checked = await supervisionApi.authorizationStatus(engagementId);
      if (!list.some(item => item.review_id === result.review_id
        && item.status === 'pending' && item.policy_sha256 === result.policy_sha256
        && item.policy_revision === result.policy_revision)
        || checked.status !== 'active' || checked.version !== scope.authorizationVersion
        || checked.policy_sha256 !== scope.authorizationSha256) throw new Error('No exact signed readback');
      if (stamp === epoch.current) {
        setReviews(list); setEditing(null);
        setMessage(`Recorded pending intent revision ${result.policy_revision} of ${result.review_id}. No live provider configuration or spend.`);
      }
    } catch {
      if (stamp === epoch.current) {
        setReviews([]); setScope(null);
        setMessage('Provider intent outcome UNKNOWN or rejected. Manually re-read current Flow; never automatically retry.');
      }
    } finally { if (stamp === epoch.current) setLoading(false); }
  }

  async function decide(item: ProviderPolicyReview, decision: 'approve' | 'revoke') {
    const reason = seniorReason.trim();
    if (!scope || actor?.role !== 'senior_operator' || loading || reason.length < 10 || reason.length > 256) return;
    if (!window.confirm(`Senior ${decision} of exact revision ${item.policy_revision} of ${item.review_id}?
Requires explicit signed tenant delegation and a DIFFERENT senior than creator.
Review only — provider remains unverified, unconfigured and not billable.`))
      return;
    const stamp = ++epoch.current;
    setLoading(true); setMessage('');
    try {
      const fresh = await supervisionApi.authorizationStatus(engagementId);
      if (fresh.status !== 'active' || fresh.version !== scope.authorizationVersion
        || fresh.policy_sha256 !== scope.authorizationSha256) throw new Error('Signer changed');
      const result = await providerPolicyReviews.decide(scope, item, decision, reason);
      const list = await providerPolicyReviews.list(scope);
      const checked = await supervisionApi.authorizationStatus(engagementId);
      if (!list.some(candidate => candidate.review_id === item.review_id
        && candidate.policy_revision === result.policy_revision && candidate.status === result.status)
        || checked.status !== 'active' || checked.version !== scope.authorizationVersion
        || checked.policy_sha256 !== scope.authorizationSha256) throw new Error('Signed decision readback missing');
      if (stamp === epoch.current) {
        setReviews(list); setMessage(`Senior decision ${result.status} recorded for ${item.review_id}. Still NOT configured/served.`);
      }
    } catch {
      if (stamp === epoch.current) {
        setScope(null); setReviews([]);
        setMessage('Senior review UNKNOWN or denied. Check exact signed intent; never repeat a lost POST.');
      }
    } finally { if (stamp === epoch.current) setLoading(false); }
  }

  return <Card title="Provider policy lifecycle — durable INTENT only">
    <div className="space-y-3 text-xs" aria-label="Signed provider policy intents">
      <p>Compare declared provider/model role and capability policies. Records are inert human review material:
        no API secrets, provider network probes, model activation, authenticated target proof or spending.
        Production models still require an independently configured route and a signed Task/lease/budget reservation.</p>
      <p>Flow {flowId} · revision {revision} · operator role {actor?.role ?? 'unverified'}.</p>
      <button type="button" onClick={() => void refresh()} disabled={loading || !permitted}>REFRESH CURRENT SIGNED INTENTS (GET)</button>
      {message && <p role="alert">{message}</p>}
      <div className="grid gap-2 sm:grid-cols-2">
        <label>Provider<select className="block border p-2 w-full" value={provider} onChange={event => { setProvider(event.target.value as ProviderPolicyIntent['provider']); setModel(''); }}>
          <option value="openai">OpenAI</option><option value="anthropic">Anthropic</option>
          <option value="gemini">Gemini</option><option value="deepseek">DeepSeek</option>
        </select></label>
        <label>Exact model name<input className="block border p-2 w-full" value={model} maxLength={90}
          onChange={event => setModel(event.target.value)} placeholder={provider === 'openai' ? 'openai/model-name' : `${provider}/model-name`}/></label>
        <label>Declared operation<select className="block border p-2 w-full" value={operation}
          onChange={event => setOperation(event.target.value as typeof operation)}>
          <option value="completion">Completion (text only)</option>
          <option value="embedding">Embedding</option>
        </select></label>
        <label>Allowed agent role<select className="block border p-2 w-full" value={role} onChange={event => setRole(event.target.value)}>
          <option value="vuln_analysis">Vulnerability Analysis</option><option value="recon">Recon</option>
          <option value="reporting">Reporting</option><option value="context_manager">Context Manager</option>
        </select></label>
        <label>Operator-declared maximum output tokens<input className="block border p-2 w-full"
          inputMode="numeric" value={tokenLimit} maxLength={5} onChange={event => setTokenLimit(event.target.value)} /></label>
      </div>
      {editing && <p>Editing exact pending intent <code>{editing.review_id}</code>,
        revision {editing.policy_revision}. Updating uses PostgreSQL CAS and does not activate model routing.</p>}
      <button type="button" disabled={!scope || !permitted || loading || !model.trim()}
        onClick={() => void create()}>{editing ? 'UPDATE EXACT PENDING REVISION (NO DISPATCH)' : 'CREATE PENDING PROVIDER INTENT (NO DISPATCH)'}</button>
      {editing && <button type="button" disabled={loading} onClick={() => setEditing(null)}>
        CANCEL EDIT
      </button>}
      <p role="status">{reviews.length} matching current signed revision records (first page only; refresh to revalidate).</p>
      <div className="space-y-2">
        {reviews.map(item => <div key={item.review_id} className="border border-outline p-2">
          <p><strong>{item.policy.provider}/{item.policy.model}</strong> · revision {item.policy_revision} · {item.status}</p>
          <p>Declared operations: {item.policy.operations.join(', ')} · capabilities: {item.policy.capabilities.join(', ')}</p>
          <p className="break-all">Policy SHA-256: {item.policy_sha256}</p>
          <p>Served model verified: NO · provider capability verified: NO · execution enabled: NO · credentials stored: NO.</p>
          {item.status === 'pending' && <button type="button" disabled={!scope || loading}
            onClick={() => {
              setEditing(item);
              setProvider(item.policy.provider); setModel(item.policy.model);
              setOperation(item.policy.operations[0] ?? 'completion');
              setRole(item.policy.allowed_roles[0] ?? 'recon');
              setTokenLimit(String(item.policy.max_output_tokens));
              setMessage('Editing current pending intent only; no provider settings or credentials are changed.');
            }}>EDIT EXACT PENDING POLICY REVISION</button>}
          {actor?.role === 'senior_operator' && <div className="space-y-1">
            <label>Separate senior decision reason (10–256 chars)<input className="block w-full border p-2"
              value={seniorReason} maxLength={256} onChange={event => setSeniorReason(event.target.value)} /></label>
            <button type="button" disabled={loading || !scope || item.status !== 'pending' || seniorReason.trim().length < 10}
              onClick={() => void decide(item, 'approve')}>SENIOR APPROVE DECLARATION ONLY</button>
            <button type="button" disabled={loading || !scope || item.status === 'revoked' || seniorReason.trim().length < 10}
              onClick={() => void decide(item, 'revoke')}>SENIOR REVOKE DECLARATION</button>
          </div>}
        </div>)}
      </div>
    </div>
  </Card>;
}

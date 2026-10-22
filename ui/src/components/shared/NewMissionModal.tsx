import React, { useMemo, useState } from 'react';
import { X, Rocket, Shield, Globe, FileCheck2 } from 'lucide-react';

/** UI syntax checks are NOT cryptographic authorization verification. */
type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };
type JsonObject = { [key: string]: JsonValue };

export interface SignedROEPolicy {
  engagement_id: string;
  created_by: string;
  domains: string[];
  ips: string[];
  exclusions: string[];
  allowed_techniques: string[];
  restrictions: string[];
  approval_required_for: string[];
  testing_window_start: string;
  testing_window_end: string;
  roe: JsonObject;
  issued_at: string;
  not_before: string;
  expires_at: string;
  version: number;
  authorization_id: string;
  key_id: string;
}

export interface SignedROEEnvelope {
  version: number;
  policy: SignedROEPolicy;
  signature: string;
}

export interface NewMissionInput {
  /** Retain the external signed envelope; parse again at POST to avoid mutations. */
  rawEnvelopeJson: string;
  engagementId: string;
  createdBy: string;
  authorizationId: string;
  keyId: string;
  version: number;
  domains: string[];
  ips: string[];
  testingWindowStart: string;
  testingWindowEnd: string;
  llmCallBudgetTotal?: number;
  llmCostBudgetUsd?: number;
}

export interface CreateSignedEngagementRequest {
  engagement_id: string;
  domains: string[];
  ips: string[];
  exclusions: string[];
  allowed_techniques: string[];
  restrictions: string[];
  approval_required_for: string[];
  testing_window_start: string;
  testing_window_end: string;
  authorization_ref: string;
  roe: JsonObject;
  signed_roe: SignedROEEnvelope;
}

const policyFields = [
  'engagement_id', 'created_by', 'domains', 'ips', 'exclusions',
  'allowed_techniques', 'restrictions', 'approval_required_for',
  'testing_window_start', 'testing_window_end', 'roe',
  'issued_at', 'not_before', 'expires_at',
  'version', 'authorization_id', 'key_id',
] as const;
const arrayFields = [
  'domains', 'ips', 'exclusions', 'allowed_techniques',
  'restrictions', 'approval_required_for',
] as const;
const utcPattern = /^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,6})?Z$/;
const domainPattern = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/;
const keyIdPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const signaturePattern = /^[A-Za-z0-9_-]{86}$/;
const maxEnvelopeLength = 131072;

const isObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

const exactKeys = (value: Record<string, unknown>, keys: readonly string[]): boolean =>
  Object.keys(value).length === keys.length && Object.keys(value).every((key) => keys.includes(key));

const isSafeIdentifier = (value: unknown, pattern = identifierPattern): value is string =>
  typeof value === 'string' && pattern.test(value);

const strictStringList = (value: unknown): value is string[] =>
  Array.isArray(value) && value.length <= 200 &&
  value.every((item) => typeof item === 'string' && item.length > 0 && item.length <= 253) &&
  new Set(value).size === value.length;

function parseUtc(value: unknown): number {
  if (typeof value !== 'string' || !utcPattern.test(value)) {
    throw new Error('Signed policy dates must use UTC RFC3339 timestamps ending in Z.');
  }
  const millis = Date.parse(value);
  if (!Number.isFinite(millis)) {
    throw new Error('Signed policy contains an invalid UTC date.');
  }
  // Date.parse can normalize invalid calendar days. Reject that rather than
  // reinterpret the signed authorization's effective window.
  const originalDay = value.slice(0, 10);
  if (new Date(millis).toISOString().slice(0, 10) !== originalDay) {
    throw new Error('Signed policy contains an invalid calendar date.');
  }
  return millis;
}

function assertPolicy(value: unknown): asserts value is SignedROEPolicy {
  if (!isObject(value) || !exactKeys(value, policyFields)) {
    throw new Error('The signed policy has missing or unexpected fields.');
  }
  if (!isSafeIdentifier(value.engagement_id) || !value.engagement_id.startsWith('eng-') ||
      !isSafeIdentifier(value.created_by) || !isSafeIdentifier(value.authorization_id) ||
      !isSafeIdentifier(value.key_id, keyIdPattern)) {
    throw new Error('Signed engagement ID, owner, authorization ID or signing key ID is invalid.');
  }
  if (!Number.isSafeInteger(value.version) || (value.version as number) <= 0) {
    throw new Error('Signed policy version must be a positive integer.');
  }
  for (const field of arrayFields) {
    if (!strictStringList(value[field])) {
      throw new Error(`Signed policy has an invalid ${field} list.`);
    }
  }
  if (!(value.domains as string[]).length && !(value.ips as string[]).length) {
    throw new Error('Signed policy must contain at least one domain or IP range.');
  }
  if (!(value.domains as string[]).every(
    (domain) => domain.length <= 253 && domainPattern.test(domain),
  )) {
    throw new Error('Signed domains must be exact lowercase hostnames without wildcards or paths.');
  }
  if (!isObject(value.roe) || Object.keys(value.roe).some((key) => ['__proto__', 'prototype', 'constructor'].includes(key))) {
    throw new Error('Signed ROE quota settings must be a JSON object.');
  }
  const calls = value.roe.llm_call_budget_total;
  if (!Number.isSafeInteger(calls) || (calls as number) <= 0) {
    throw new Error('Signed ROE must explicitly authorize a positive whole-number LLM call budget.');
  }
  const dollars = value.roe.llm_cost_budget_usd;
  if (dollars !== undefined && (typeof dollars !== 'number' || !Number.isFinite(dollars) || dollars <= 0)) {
    throw new Error('Signed USD model budget must be a positive finite amount.');
  }
  const issuedAt = parseUtc(value.issued_at);
  const notBefore = parseUtc(value.not_before);
  const expiresAt = parseUtc(value.expires_at);
  const testingStart = parseUtc(value.testing_window_start);
  const testingEnd = parseUtc(value.testing_window_end);
  if (issuedAt > notBefore || notBefore >= expiresAt || testingStart >= testingEnd) {
    throw new Error('Signed authorization or testing window dates are inconsistent.');
  }
}

/** Parse external JSON for display only. The backend verifies Ed25519 trust and signature. */
export function parseNewMissionInput(rawEnvelopeJson: string): NewMissionInput {
  if (typeof rawEnvelopeJson !== 'string' || !rawEnvelopeJson.trim() ||
      rawEnvelopeJson.length > maxEnvelopeLength) {
    throw new Error('Paste an externally signed ROE JSON envelope (maximum 128 KiB).');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawEnvelopeJson);
  } catch {
    throw new Error('The signed ROE envelope is not valid JSON.');
  }
  if (!isObject(parsed) || !exactKeys(parsed, ['version', 'policy', 'signature'])) {
    throw new Error('Signed ROE must contain exactly version, policy and signature.');
  }
  assertPolicy(parsed.policy);
  if (!Number.isSafeInteger(parsed.version) || parsed.version !== parsed.policy.version) {
    throw new Error('Envelope and signed policy versions must match.');
  }
  if (typeof parsed.signature !== 'string' || !signaturePattern.test(parsed.signature)) {
    throw new Error('Signed ROE requires a strict unpadded Ed25519 base64url signature.');
  }
  return {
    rawEnvelopeJson,
    engagementId: parsed.policy.engagement_id,
    createdBy: parsed.policy.created_by,
    authorizationId: parsed.policy.authorization_id,
    keyId: parsed.policy.key_id,
    version: parsed.policy.version,
    domains: [...parsed.policy.domains],
    ips: [...parsed.policy.ips],
    testingWindowStart: parsed.policy.testing_window_start,
    testingWindowEnd: parsed.policy.testing_window_end,
    ...(typeof parsed.policy.roe.llm_call_budget_total === 'number' ? {
      llmCallBudgetTotal: parsed.policy.roe.llm_call_budget_total,
    } : {}),
    ...(typeof parsed.policy.roe.llm_cost_budget_usd === 'number' ? {
      llmCostBudgetUsd: parsed.policy.roe.llm_cost_budget_usd,
    } : {}),
  };
}

/** Build a fully policy-matched POST payload; no editable overrides or defaults. */
export function buildSignedEngagementRequest(rawEnvelopeJson: string): CreateSignedEngagementRequest {
  // Validate again at request time, so mutations of any preview data cannot
  // broaden scope, assign extra budget or change the engagement ID.
  parseNewMissionInput(rawEnvelopeJson);
  const envelope = JSON.parse(rawEnvelopeJson) as SignedROEEnvelope;
  const policy = envelope.policy;
  return {
    engagement_id: policy.engagement_id,
    domains: [...policy.domains],
    ips: [...policy.ips],
    exclusions: [...policy.exclusions],
    allowed_techniques: [...policy.allowed_techniques],
    restrictions: [...policy.restrictions],
    approval_required_for: [...policy.approval_required_for],
    testing_window_start: policy.testing_window_start,
    testing_window_end: policy.testing_window_end,
    authorization_ref: policy.authorization_id,
    roe: JSON.parse(JSON.stringify(policy.roe)) as JsonObject,
    signed_roe: envelope,
  };
}

interface NewMissionModalProps {
  isOpen: boolean;
  onClose: () => void;
  onLaunch: (input: NewMissionInput) => Promise<void>;
}

export const NewMissionModal: React.FC<NewMissionModalProps> = ({ isOpen, onClose, onLaunch }) => {
  const [envelopeJson, setEnvelopeJson] = useState('');
  const [isLaunching, setIsLaunching] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const preview = useMemo(() => {
    try {
      return envelopeJson.trim() ? parseNewMissionInput(envelopeJson) : null;
    } catch {
      return null;
    }
  }, [envelopeJson]);

  if (!isOpen) return null;

  const handleDismiss = () => {
    if (isLaunching) return;
    setEnvelopeJson('');
    setError(null);
    onClose();
  };

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (isLaunching) return;
    let input: NewMissionInput;
    try {
      input = parseNewMissionInput(envelopeJson);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Signed authorization JSON is invalid.');
      return;
    }
    setError(null);
    setIsLaunching(true);
    try {
      await onLaunch(input);
      setEnvelopeJson('');
      onClose();
    } catch {
      // Never print a server/body exception that might contain a signature,
      // bearer credential, trust key or signed policy contents.
      setError('Mission creation failed. Check your operator account, signed ROE trust, policy validity and scope.');
    } finally {
      setIsLaunching(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <div role="dialog" aria-modal="true" aria-labelledby="new-mission-title" className="bg-surface-container border border-primary-fixed/30 w-full max-w-xl max-h-[90vh] overflow-y-auto relative glow-cyan">
        <div className="absolute top-0 left-0 w-full h-1 bg-primary-fixed opacity-50" />
        <div className="p-6 border-b border-outline-variant flex justify-between items-center">
          <div className="flex items-center gap-3">
            <Rocket className="text-primary-fixed" size={20} />
            <span id="new-mission-title" className="font-label-caps text-primary-fixed tracking-widest">INITIALIZE SIGNED MISSION</span>
          </div>
          <button type="button" onClick={handleDismiss} disabled={isLaunching} aria-label="Close new mission" className="text-on-surface-variant hover:text-primary transition-colors disabled:opacity-50"><X size={20} /></button>
        </div>
        <form onSubmit={handleSubmit} className="p-7 space-y-5">
          <div className="space-y-2">
            <label htmlFor="mission-signed-roe" className="font-label-caps text-[10px] text-on-surface-variant flex items-center gap-2">
              <FileCheck2 size={13} /> EXTERNALLY SIGNED ED25519 ROE ENVELOPE (JSON)
            </label>
            <textarea id="mission-signed-roe" autoFocus required rows={8} maxLength={maxEnvelopeLength}
              spellCheck={false} autoComplete="off" value={envelopeJson}
              onChange={(event) => { setEnvelopeJson(event.target.value); setError(null); }}
              disabled={isLaunching} placeholder='{"version":1,"policy":{...},"signature":"..."}'
              className="w-full bg-black border border-outline-variant p-3 text-primary font-code-sm focus:border-primary-fixed/50 outline-none transition-all placeholder:opacity-40 disabled:opacity-50 resize-y"
            />
            <p className="text-[11px] text-on-surface-variant">
              Paste an envelope signed outside AI-OSOP. This browser does not sign or verify Ed25519 signatures;
              the backend checks trusted keys, operator ownership, revocation, version, scope and dates.
            </p>
          </div>

          {preview && (
            <section aria-label="Signed policy preview" className="bg-black/40 border border-outline-variant p-4 space-y-3">
              <div className="font-label-caps text-[10px] text-primary-fixed flex items-center gap-2">
                <Globe size={13} /> SIGNED POLICY PREVIEW — STRUCTURE ONLY, NOT VERIFIED
              </div>
              <dl className="text-[11px] font-code-sm text-on-surface-variant space-y-2 break-all">
                <div><dt className="inline text-primary-fixed">Engagement ID: </dt><dd className="inline">{preview.engagementId}</dd></div>
                <div><dt className="inline text-primary-fixed">Signed owner: </dt><dd className="inline">{preview.createdBy}</dd></div>
                <div><dt className="inline text-primary-fixed">Authorization ID: </dt><dd className="inline">{preview.authorizationId}</dd></div>
                <div><dt className="inline text-primary-fixed">Signing KID / version: </dt><dd className="inline">{preview.keyId} / {preview.version}</dd></div>
                <div><dt className="inline text-primary-fixed">Domains: </dt><dd className="inline">{preview.domains.length ? preview.domains.join(', ') : 'none'}</dd></div>
                <div><dt className="inline text-primary-fixed">IP ranges: </dt><dd className="inline">{preview.ips.length ? preview.ips.join(', ') : 'none'}</dd></div>
                <div><dt className="inline text-primary-fixed">Testing UTC window: </dt><dd className="inline">{preview.testingWindowStart} – {preview.testingWindowEnd}</dd></div>
                <div><dt className="inline text-primary-fixed">Model call budget: </dt><dd className="inline">{preview.llmCallBudgetTotal}</dd></div>
                <div><dt className="inline text-primary-fixed">USD cap: </dt><dd className="inline">{preview.llmCostBudgetUsd ?? 'Not specified'}</dd></div>
              </dl>
              <p className="text-[10px] text-on-surface-variant">
                All scope, restrictions, approvals and quotas come directly from the signed policy. They cannot be edited here.
              </p>
            </section>
          )}

          <div className="bg-primary-container/10 border border-primary-container/30 p-4 flex gap-4">
            <Shield className="text-primary-fixed shrink-0" size={20} />
            <p className="text-[11px] text-on-surface-variant leading-relaxed font-code-sm">
              A signature-shaped JSON string does not establish authorization. Only trusted backend verification can do that.
              No budget or testing permissions are added beyond the signed policy. Any signed USD cap is evaluated using
              provider-reported costs and may be exceeded by a request already accepted by the provider.
            </p>
          </div>

          {error && <p role="alert" className="text-[12px] text-error font-code-sm" aria-live="polite">{error}</p>}

          <div className="flex gap-4 pt-3">
            <button type="button" onClick={handleDismiss} disabled={isLaunching}
              className="flex-1 py-3 border border-outline text-on-surface font-label-caps text-[11px] hover:bg-surface-variant disabled:opacity-50">ABORT</button>
            <button type="submit" disabled={isLaunching || !preview}
              className="flex-1 py-3 bg-primary-fixed text-black font-label-caps text-[11px] glow-green hover:brightness-110 active:scale-95 disabled:opacity-50 disabled:grayscale disabled:cursor-not-allowed flex items-center justify-center gap-2">
              {isLaunching ? 'VERIFYING WITH SERVER...' : 'REQUEST MISSION'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

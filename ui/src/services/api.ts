/** Browser credentials live only in this tab's JavaScript memory. */
export const API_BASE = import.meta.env.VITE_API_BASE || 'http://127.0.0.1:8200';
export const WS_BASE = import.meta.env.VITE_WS_BASE || 'ws://127.0.0.1:8200';

export interface OperatorIdentity {
  sub: string;
  role: string;
  exp: number | null;
}

// Live export retained for existing display-only role hints. This value is
// *only* assigned after the server verifies /auth/me; never from Vite env.
export let AUTH_TOKEN = '';
let operator: OperatorIdentity | null = null;
let sessionEpoch = 0;
let expiryTimer: ReturnType<typeof setTimeout> | null = null;
const listeners = new Set<(identity: OperatorIdentity | null) => void>();

function isLoopback(hostname: string): boolean {
  return ['localhost', '127.0.0.1', '[::1]'].includes(hostname);
}

export function isSecureApiBase(base: string): boolean {
  try {
    const url = new URL(base);
    return !url.username && !url.password && !url.search && !url.hash && (
      url.protocol === 'https:' || (url.protocol === 'http:' && isLoopback(url.hostname))
    );
  } catch {
    return false;
  }
}

export function isSecureBrowserOrigin(): boolean {
  if (typeof window === 'undefined') return true; // SSR/test context only
  return window.location.protocol === 'https:' || (
    window.location.protocol === 'http:' && isLoopback(window.location.hostname)
  );
}

function notify(): void {
  for (const listener of listeners) listener(operator);
}

export function subscribeOperator(listener: (identity: OperatorIdentity | null) => void): () => void {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

export function signOut(): void {
  ++sessionEpoch; // Invalidate any in-flight sign-in response.
  AUTH_TOKEN = '';
  operator = null;
  if (expiryTimer) clearTimeout(expiryTimer);
  expiryTimer = null;
  notify();
}

/** Explicit sign-out attempts durable cross-replica token invalidation.
 * Local UI credentials are cleared synchronously before network access.
 * A failed/unsupported remote revocation is reported as unconfirmed; it must
 * never be presented as a provider/IdP session termination acknowledgement.
 */
export async function revokeAndSignOut(): Promise<boolean> {
  const previous = AUTH_TOKEN;
  signOut();
  if (!previous || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()) return false;
  try {
    const response = await fetch(`${API_BASE}/auth/logout`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${previous}`, Accept: 'application/json' },
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
    });
    if (!response.ok) return false;
    const body: unknown = await response.json();
    return body !== null && typeof body === 'object'
      && (body as { status?: unknown }).status === 'revoked';
  } catch {
    return false;
  }
}

export function currentOperator(): OperatorIdentity | null {
  if (operator && operator.exp !== null && operator.exp * 1000 <= Date.now()) {
    signOut();
  }
  return operator;
}

function scheduleExpiry(verifiedExpiry: number): void {
  if (operator?.exp !== verifiedExpiry) return;
  const remaining = verifiedExpiry * 1000 - Date.now();
  if (remaining <= 0) {
    signOut();
    return;
  }
  expiryTimer = setTimeout(() => scheduleExpiry(verifiedExpiry), Math.min(2147483647, remaining));
}

/** Never authorize a session from a locally decoded, unsigned JWT payload. */
export async function signIn(presented: string): Promise<OperatorIdentity> {
  // Remove any previous operator's credential before attempting a new login.
  signOut();
  const attempt = sessionEpoch;
  const token = presented.trim();
  if (!token || token.length > 4096) throw new Error('Provide a valid operator bearer token (maximum 4096 characters).');
  if (!isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()) {
    throw new Error('Sign-in requires HTTPS, or loopback HTTP during local development.');
  }
  let response: Response;
  try {
    response = await fetch(`${API_BASE}/auth/me`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
    });
  } catch {
    throw new Error('Cannot verify the operator token. Check the secure API connection.');
  }
  if (attempt !== sessionEpoch) throw new Error('Sign-in was cancelled.');
  if (!response.ok) throw new Error(
    response.status === 401 || response.status === 403
      ? 'Operator token rejected or expired. Provide a valid token and try again.'
      : `Operator verification unavailable (HTTP ${response.status}).`
  );
  let identity: unknown;
  try {
    identity = await response.json();
  } catch {
    throw new Error('Operator verification returned invalid data.');
  }
  if (attempt !== sessionEpoch) throw new Error('Sign-in was cancelled.');
  if (!identity || typeof identity !== 'object' || Array.isArray(identity)) {
    throw new Error('Operator identity could not be verified.');
  }
  const value = identity as Record<string, unknown>;
  if (typeof value.sub !== 'string' || !value.sub.trim() ||
      typeof value.role !== 'string' || !value.role.trim() ||
      !(value.exp === null || (typeof value.exp === 'number' &&
        Number.isSafeInteger(value.exp) && value.exp > Date.now() / 1000))) {
    throw new Error('Operator identity is incomplete or expired.');
  }
  AUTH_TOKEN = token;
  operator = { sub: value.sub, role: value.role, exp: value.exp as number | null };
  if (operator.exp !== null) scheduleExpiry(operator.exp);
  notify();
  return operator;
}

export function getRuntimeToken(): string {
  return currentOperator() && isSecureApiBase(API_BASE) && isSecureBrowserOrigin()
    ? AUTH_TOKEN : '';
}

/** Never pass supplied bearer credentials in a URL or implicit default. */
export function authHeaders(extra: Record<string, string> = {}): Record<string, string> {
  const bearer = getRuntimeToken();
  const { Authorization: _discarded, authorization: _lowerDiscarded, ...safeExtra } = extra;
  return { ...safeExtra, ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}) };
}

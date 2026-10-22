/** Senior-only host-owned disabled Turbo process status, NEVER tool execution. */
import {
  API_BASE, authHeaders, currentOperator, getRuntimeToken, isSecureApiBase, isSecureBrowserOrigin,
} from './api';

export interface PythonInertTurboStatus {
  service_id: 'turbo-intruder-mcp';
  lifecycle: 'host_unconfigured' | 'stopped' | 'running_disabled_unavailable';
  process_owned: boolean;
  listener_owned: boolean;
  health_unavailable: boolean;
  mcp_initialized: false;
  signed_action_verified: false;
  native_execution_enabled: false;
  independent_target_effect_verified: false;
  production_certified: false;
}

export async function readPythonInertTurboStatus(): Promise<PythonInertTurboStatus> {
  const principal = currentOperator();
  const token = getRuntimeToken();
  if (!principal || principal.role !== 'senior_operator' || !token || !isSecureApiBase(API_BASE)
      || !isSecureBrowserOrigin()) {
    throw new Error('Current signed senior operator over secure origin required.');
  }
  const response = await fetch(`${API_BASE}/system/python-inert-turbo/status`, {
    method: 'GET',
    headers: authHeaders({ Accept: 'application/json' }),
    credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
  });
  if (currentOperator()?.sub !== principal.sub || currentOperator()?.role !== principal.role
      || getRuntimeToken() !== token) {
    throw new Error('Signed senior operator changed while inspecting host process.');
  }
  if (!response.ok) throw new Error(`Host-owned disabled Turbo status unverified (HTTP ${response.status}).`);
  const stated = response.headers.get('content-length');
  if (stated && (!/^\d+$/.test(stated) || Number(stated) > 2048)) {
    throw new Error('Unbounded host process metadata rejected.');
  }
  if (!response.body) throw new Error('Missing bounded host process status.');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const item = await reader.read();
      if (item.done) break;
      size += item.value.byteLength;
      if (size > 2048) throw new Error('Unbounded host process metadata rejected.');
      chunks.push(item.value);
    }
  } catch (cause) {
    await reader.cancel().catch(() => undefined);
    throw cause;
  } finally {
    reader.releaseLock();
  }
  if (getRuntimeToken() !== token || currentOperator()?.sub !== principal.sub) {
    throw new Error('Host readback identity changed.');
  }
  const wire = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { wire.set(chunk, offset); offset += chunk.byteLength; }
  let decoded: unknown;
  try { decoded = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(wire)); }
  catch { throw new Error('Malformed host process readback.'); }
  if (!decoded || typeof decoded !== 'object' || Array.isArray(decoded)) {
    throw new Error('Invalid host process readback.');
  }
  const doc = decoded as Record<string, unknown>;
  const exact = new Set([
    'service_id', 'lifecycle', 'process_owned', 'listener_owned', 'health_unavailable',
    'mcp_initialized', 'signed_action_verified', 'native_execution_enabled',
    'independent_target_effect_verified', 'production_certified',
  ]);
  if (Object.keys(doc).length !== exact.size || Object.keys(doc).some(k => !exact.has(k))
      || doc.service_id !== 'turbo-intruder-mcp'
      || !['host_unconfigured', 'stopped', 'running_disabled_unavailable'].includes(String(doc.lifecycle))
      || typeof doc.process_owned !== 'boolean'
      || typeof doc.listener_owned !== 'boolean'
      || typeof doc.health_unavailable !== 'boolean'
      || doc.mcp_initialized !== false || doc.signed_action_verified !== false
      || doc.native_execution_enabled !== false || doc.independent_target_effect_verified !== false
      || doc.production_certified !== false
      || (doc.lifecycle === 'running_disabled_unavailable') !== doc.process_owned
      || doc.process_owned !== doc.listener_owned || doc.listener_owned !== doc.health_unavailable) {
    throw new Error('Process-only metadata falsely implies trusted target execution.');
  }
  return doc as unknown as PythonInertTurboStatus;
}

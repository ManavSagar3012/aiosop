import { useCallback, useEffect, useRef, useState } from 'react';
import { currentOperator, subscribeOperator } from '../services/api';
import {
  searchOperatorKnowledge, type KnowledgeSearchItem,
  type KnowledgeSource, type PinnedKnowledgeFlow,
  type OperatorKnowledgeDiscovery,
} from '../services/operatorGlobalLibrary';

const SOURCE_LABELS: Record<KnowledgeSource, string> = {
  user_global_0039: 'Your global library · 0039',
  flow_local_0019_0038: 'Current authorized Flow · 0019/0038',
};

/** Read-only metadata discovery; use the existing My Library page for CRUD. */
export function OperatorGlobalLibraryPanel() {
  const [actor, setActor] = useState(() => currentOperator()?.sub || '');
  const [query, setQuery] = useState('');
  const [flowId, setFlowId] = useState('');
  const [revision, setRevision] = useState('');
  const [authorizationVersion, setAuthorizationVersion] = useState('');
  const [results, setResults] = useState<OperatorKnowledgeDiscovery | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const epoch = useRef(0);

  useEffect(() => {
    const unsubscribe = subscribeOperator(identity => {
      ++epoch.current;
      setActor(identity?.sub || '');
      setResults(null);
      setQuery('');
      setFlowId('');
      setRevision('');
      setAuthorizationVersion('');
      setError('');
      setBusy(false);
    });
    return () => { ++epoch.current; unsubscribe(); };
  }, []);

  const find = useCallback(async () => {
    if (!actor || busy) return;
    const stamp = ++epoch.current;
    setResults(null);
    setError('');
    setBusy(true);
    try {
      const inputs = [flowId.trim(), revision.trim(), authorizationVersion.trim()];
      let flow: PinnedKnowledgeFlow | undefined;
      if (inputs.some(Boolean)) {
        if (!inputs.every(Boolean) || !/^\d+$/.test(inputs[1]) || !/^\d+$/.test(inputs[2])) {
          throw new Error('Provide the exact Flow ID, current revision and authorization version together.');
        }
        flow = {
          flowId: inputs[0],
          revision: Number(inputs[1]),
          authorizationVersion: Number(inputs[2]),
        };
      }
      const found = await searchOperatorKnowledge(query, flow);
      if (stamp === epoch.current) setResults(found);
    } catch (cause) {
      if (stamp === epoch.current) {
        // The owner must never see a partial global success after Flow denial.
        setResults(null);
        setError(cause instanceof Error ? cause.message : 'Signed knowledge search unavailable.');
      }
    } finally {
      if (stamp === epoch.current) setBusy(false);
    }
  }, [actor, authorizationVersion, busy, flowId, query, revision]);

  function renderSource(source: KnowledgeSource, items: KnowledgeSearchItem[], hasMore: boolean) {
    return (
      <section key={source} aria-label={SOURCE_LABELS[source]} className="space-y-2 rounded border border-outline-variant p-3">
        <h3 className="font-semibold text-sm text-on-surface">{SOURCE_LABELS[source]}</h3>
        <p className="text-xs text-on-surface-variant">
          {items.length} metadata results{hasMore ? ' (more matching items exist)' : ''}. Text remains untrusted and inert.
        </p>
        {items.length === 0 && <p className="text-sm text-on-surface-variant">No matching documents in this source.</p>}
        <ul className="space-y-2" aria-label={`${SOURCE_LABELS[source]} search results`}>
          {items.map(item => (
            <li key={`${source}:${item.id}`} className="rounded border border-outline-variant p-3 text-sm">
              <strong className="block break-words text-on-surface">{item.title}</strong>
              <p className="text-xs text-on-surface-variant">
                {item.doc_type} · immutable revision {item.revision} · {item.content_bytes} bytes
              </p>
              {item.flow_id && <p className="break-all text-xs">Flow: {item.flow_id}</p>}
              <p className="break-all text-xs">Original SHA-256: <code>{item.sha256}</code></p>
              <p className="text-xs">Source: {item.source} · {item.trust} · no target effect verification</p>
            </li>
          ))}
        </ul>
      </section>
    );
  }

  return (
    <section className="space-y-4 rounded border border-outline-variant p-4" aria-labelledby="operator-knowledge-search-title">
      <h2 id="operator-knowledge-search-title" className="font-semibold text-lg">Search owned knowledge sources</h2>
      <p role="note" className="text-sm text-on-surface-variant">
        Read-only discovery of untrusted human text. Source labels and original SHA-256 are metadata,
        not independent target evidence, agent context approval, or permission to execute actions.
      </p>
      {!actor && <p role="status">Sign in with a verified operator session before searching.</p>}
      <form onSubmit={event => { event.preventDefault(); void find(); }} className="space-y-3">
        <label className="block text-sm">
          Search title and content metadata
          <input aria-label="Knowledge discovery query" maxLength={128} required value={query}
            onChange={event => setQuery(event.target.value)}
            disabled={!actor || busy} autoComplete="off"
            className="block w-full rounded border border-outline-variant bg-surface-container p-2" />
        </label>
        <fieldset className="grid grid-cols-1 gap-2 md:grid-cols-3 rounded border border-outline-variant p-3">
          <legend className="px-1 text-sm">Optional current signed Flow scope (all fields required together)</legend>
          <label className="text-xs">Flow ID
            <input aria-label="Exact Flow ID" value={flowId} maxLength={64}
              onChange={event => setFlowId(event.target.value)}
              disabled={!actor || busy} className="block w-full rounded border p-2 bg-surface-container" />
          </label>
          <label className="text-xs">Flow revision
            <input aria-label="Expected Flow revision" value={revision} inputMode="numeric"
              onChange={event => setRevision(event.target.value)} disabled={!actor || busy}
              className="block w-full rounded border p-2 bg-surface-container" />
          </label>
          <label className="text-xs">Authorization version
            <input aria-label="Expected Flow authorization version" value={authorizationVersion}
              inputMode="numeric" onChange={event => setAuthorizationVersion(event.target.value)}
              disabled={!actor || busy} className="block w-full rounded border p-2 bg-surface-container" />
          </label>
        </fieldset>
        <button type="submit" disabled={!actor || busy || !query.trim()}
          className="rounded border border-primary-fixed px-4 py-2 text-sm text-primary-fixed">
          {busy ? 'Checking signed scopes…' : 'Search authorized sources'}
        </button>
      </form>
      {error && <p role="alert" className="text-error text-sm">{error}</p>}
      {busy && <p role="status" className="text-sm">Reading current signed source metadata…</p>}
      {results && (
        <div className="space-y-3" aria-label="Authorized source results">
          <p role="status" className="text-xs text-on-surface-variant">
            Metadata only; sources are independently authorized and are not an atomic cross-source snapshot.
          </p>
          {renderSource('user_global_0039', results.sources.user_global_0039.items, results.sources.user_global_0039.has_more)}
          {results.sources.flow_local_0019_0038 &&
            renderSource('flow_local_0019_0038', results.sources.flow_local_0019_0038.items,
              results.sources.flow_local_0019_0038.has_more)}
        </div>
      )}
    </section>
  );
}

import { useCallback, useEffect, useRef, useState } from 'react';
import { Card } from '../shared/Card';
import { supervisionApi } from '../../services/supervision';
import { operatorKnowledgeApi, KNOWLEDGE_PAGE_SIZE, type OperatorKnowledgeDocument } from '../../services/operatorKnowledge';

interface Props { flowId: string; engagementId: string; revision: number }

/** Explicit, inert operator-edited facts. No autonomous agent ingestion. */
export function OperatorKnowledgePanel({ flowId, engagementId, revision }: Props) {
  const [version, setVersion] = useState<number | null>(null);
  const [docs, setDocs] = useState<OperatorKnowledgeDocument[]>([]);
  const [selected, setSelected] = useState<OperatorKnowledgeDocument | null>(null);
  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const [kind, setKind] = useState<'guide' | 'answer' | 'code'>('guide');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [queryDraft, setQueryDraft] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [filter, setFilter] = useState<'all' | 'guide' | 'answer' | 'code'>('all');
  const [hasMore, setHasMore] = useState(false);
  const epoch = useRef(0);
  const scope = version !== null ? { flowId, revision, authorizationVersion: version } : null;

  const refresh = useCallback(async () => {
    const stamp = ++epoch.current;
    setVersion(null); setDocs([]); setHasMore(false); setSelected(null); setContent(''); setError('');
    try {
      const authority = await supervisionApi.authorizationStatus(engagementId);
      if (authority.status !== 'active' || !authority.version) throw new Error('Signed Flow authorization unavailable.');
      const currentScope = { flowId, revision, authorizationVersion: authority.version };
      const options = { offset: 0, ...(filter !== 'all' ? { docType: filter } : {}) };
      const list = searchQuery ? await operatorKnowledgeApi.search(currentScope, searchQuery, options)
        : await operatorKnowledgeApi.list(currentScope, options);
      if (stamp !== epoch.current) return;
      setVersion(authority.version); setDocs(list.items); setHasMore(list.has_more);
    } catch (cause) {
      if (stamp === epoch.current) setError(cause instanceof Error ? cause.message : 'Knowledge unavailable.');
    }
  }, [engagementId, flowId, revision, searchQuery, filter]);

  useEffect(() => {
    void refresh();
    return () => { epoch.current++; };
  }, [refresh]);

  async function choose(doc: OperatorKnowledgeDocument) {
    if (!scope || busy) return;
    const stamp = ++epoch.current;
    setBusy(true); setError('');
    try {
      const item = await operatorKnowledgeApi.get(scope, doc.id);
      if (stamp !== epoch.current) return;
      setSelected(item); setTitle(item.title); setKind(item.doc_type); setContent(item.content ?? '');
    } catch (cause) {
      if (stamp === epoch.current) setError(cause instanceof Error ? cause.message : 'Document unavailable.');
    } finally { if (stamp === epoch.current) setBusy(false); }
  }

  async function loadMore() {
    if (!scope || busy || !hasMore || docs.length > 1000 - KNOWLEDGE_PAGE_SIZE) return;
    const stamp = ++epoch.current;
    setBusy(true); setError('');
    try {
      // Pagination never relies on a stale in-browser ROE version. An expired
      // or revoked signed authority invalidates the entire visible result set.
      const authority = await supervisionApi.authorizationStatus(engagementId);
      if (authority.status !== 'active' || authority.version !== scope.authorizationVersion) {
        setDocs([]); setHasMore(false); setVersion(null);
        throw new Error('Signed scope changed. Refresh knowledge before viewing another page.');
      }
      const options = { offset: docs.length, ...(filter !== 'all' ? { docType: filter } : {}) };
      const page = searchQuery ? await operatorKnowledgeApi.search(scope, searchQuery, options)
        : await operatorKnowledgeApi.list(scope, options);
      if (stamp !== epoch.current) return;
      const seen = new Set(docs.map(doc => doc.id));
      if (page.items.some(doc => seen.has(doc.id))) throw new Error('Knowledge pagination drift; refresh signed search.');
      setDocs(current => [...current, ...page.items]); setHasMore(page.has_more);
    } catch (cause) {
      if (stamp === epoch.current) setError(cause instanceof Error ? cause.message : 'Knowledge pagination unavailable.');
    } finally { if (stamp === epoch.current) setBusy(false); }
  }

  async function mutate(action: 'create' | 'update' | 'delete') {
    if (!scope || busy) return;
    setBusy(true); setError('');
    try {
      if (action === 'create') await operatorKnowledgeApi.create(scope, title, kind, content);
      else if (action === 'update' && selected) await operatorKnowledgeApi.update(scope, selected, title, content);
      else if (action === 'delete' && selected) {
        if (!window.confirm('Delete this exact knowledge document revision?')) return;
        await operatorKnowledgeApi.remove(scope, selected);
      } else throw new Error('Select a document revision first.');
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Knowledge mutation rejected.');
    } finally { setBusy(false); }
  }

  return <Card title="Operator knowledge (inert, not agent-approved)">
    <div className="space-y-3 text-xs">
      <p>Documents are bounded and owner-scoped. Upload or editing does not make content trusted agent instructions or independently verified findings.</p>
      {error && <p role="alert" className="text-error">{error}</p>}
      <div className="flex flex-wrap gap-2">
        <button type="button" onClick={() => void refresh()} disabled={busy}>Refresh signed scope</button>
        <button type="button" onClick={() => { setSelected(null); setTitle(''); setContent(''); }} disabled={busy}>New document</button>
      </div>
      <div className="flex flex-wrap items-end gap-2" aria-label="Search operator knowledge">
        <label className="flex-1 min-w-[160px]">Search title and content
          <input className="w-full border p-2" value={queryDraft} maxLength={128}
            onChange={event => setQueryDraft(event.target.value)}
            onKeyDown={event => { if (event.key === 'Enter') setSearchQuery(queryDraft.trim()); }} />
        </label>
        <label>Document type
          <select className="border p-2 block" value={filter} onChange={event => setFilter(event.target.value as typeof filter)}>
            <option value="all">All</option><option value="guide">Guide</option>
            <option value="answer">Answer</option><option value="code">Code</option>
          </select>
        </label>
        <button type="button" disabled={busy || queryDraft.length > 128}
          onClick={() => { if (queryDraft.trim() === searchQuery) void refresh(); else setSearchQuery(queryDraft.trim()); }}>
          Search signed knowledge
        </button>
      </div>
      <ul aria-label="Knowledge documents" className="space-y-1">
        {docs.map((doc) => <li key={doc.id}><button type="button" disabled={busy} onClick={() => void choose(doc)}>
          {doc.title} — {doc.doc_type}, revision {doc.revision}
        </button></li>)}
      </ul>
      {hasMore && <button type="button" disabled={!scope || busy || docs.length > 1000 - KNOWLEDGE_PAGE_SIZE}
        onClick={() => void loadMore()}>Load next 20 signed results</button>}
      <p role="status">Showing {docs.length} owner-scoped document metadata records. Search matches remain untrusted text; no agent ingestion or vulnerability verification is implied.</p>
      <label className="block">Title<input className="w-full border p-2" value={title} maxLength={128} onChange={event => setTitle(event.target.value)} /></label>
      <label className="block">Type<select value={kind} onChange={event => setKind(event.target.value as typeof kind)} disabled={selected !== null}>
        <option value="guide">Guide</option><option value="answer">Answer</option><option value="code">Code</option>
      </select></label>
      <label className="block">Plain-text content<textarea className="w-full border p-2" rows={5} maxLength={8192} value={content} onChange={event => setContent(event.target.value)} /></label>
      <div className="flex gap-3">
        <button type="button" disabled={!scope || busy || !title.trim() || !content.trim()} onClick={() => void mutate(selected ? 'update' : 'create')}>{selected ? 'Save exact revision' : 'Create document'}</button>
        <button type="button" disabled={!scope || busy || !selected} onClick={() => void mutate('delete')}>Delete exact revision</button>
      </div>
    </div>
  </Card>;
}

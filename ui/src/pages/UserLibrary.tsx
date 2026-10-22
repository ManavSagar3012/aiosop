import { useCallback, useEffect, useRef, useState } from 'react';
import { BookOpen, Plus, RefreshCcw, Search, ShieldAlert, Trash2 } from 'lucide-react';
import { Card } from '../components/shared/Card';
import { OperatorGlobalLibraryPanel } from '../components/OperatorGlobalLibraryPanel';
import { currentOperator, subscribeOperator } from '../services/api';
import {
  GLOBAL_LIBRARY_PAGE_SIZE, userGlobalLibraryApi,
  type UserLibraryDocument, type UserLibraryKind,
} from '../services/userGlobalLibrary';

/** Human editable inert library shared across Flows by signed owner identity. */
export function UserLibrary() {
  const [docs, setDocs] = useState<UserLibraryDocument[]>([]);
  const [selected, setSelected] = useState<UserLibraryDocument | null>(null);
  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const [kind, setKind] = useState<UserLibraryKind>('guide');
  const [searchDraft, setSearchDraft] = useState('');
  const [searchTerm, setSearchTerm] = useState<string | undefined>(undefined);
  const [hasMore, setHasMore] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [actor, setActor] = useState(() => currentOperator()?.sub || '');
  const epoch = useRef(0);

  const clearEditor = useCallback(() => {
    setSelected(null);
    setTitle('');
    setContent('');
    setKind('guide');
  }, []);

  const refresh = useCallback(async () => {
    const stamp = ++epoch.current;
    setBusy(true);
    setDocs([]);
    setHasMore(false);
    clearEditor();
    setError('');
    try {
      const page = await userGlobalLibraryApi.list(0, searchTerm);
      if (stamp === epoch.current) {
        setDocs(page.items);
        setHasMore(page.has_more);
      }
    } catch (cause) {
      if (stamp === epoch.current) setError(cause instanceof Error ? cause.message : 'User library unavailable.');
    } finally {
      if (stamp === epoch.current) setBusy(false);
    }
  }, [clearEditor, searchTerm, actor]);

  useEffect(() => {
    const unsubscribe = subscribeOperator(identity => {
      ++epoch.current;
      setActor(identity?.sub || '');
      setDocs([]);
      setHasMore(false);
      clearEditor();
      setError('');
      setBusy(false);
    });
    return () => { ++epoch.current; unsubscribe(); };
  }, [clearEditor]);

  useEffect(() => {
    void refresh();
    return () => { ++epoch.current; };
  }, [refresh]);

  async function choose(document: UserLibraryDocument) {
    if (busy || !actor) return;
    const stamp = ++epoch.current;
    setBusy(true);
    setError('');
    clearEditor();
    try {
      const actual = await userGlobalLibraryApi.get(document.id);
      // Never edit after a mutation elsewhere changed the original revision.
      if (actual.revision !== document.revision || actual.sha256 !== document.sha256) {
        throw new Error('Library original revision changed. Refresh before editing.');
      }
      if (stamp === epoch.current) {
        setSelected(actual);
        setTitle(actual.title);
        setKind(actual.doc_type);
        setContent(actual.content ?? '');
      }
    } catch (cause) {
      if (stamp === epoch.current) setError(cause instanceof Error ? cause.message : 'Original library bytes unavailable.');
    } finally {
      if (stamp === epoch.current) setBusy(false);
    }
  }

  async function more() {
    if (busy || !actor || !hasMore || docs.length > 1000 - GLOBAL_LIBRARY_PAGE_SIZE) return;
    const stamp = ++epoch.current;
    setBusy(true);
    setError('');
    try {
      const page = await userGlobalLibraryApi.list(docs.length, searchTerm);
      if (stamp !== epoch.current) return;
      const seen = new Set(docs.map(doc => doc.id));
      if (page.items.some(doc => seen.has(doc.id))) throw new Error('Library result set shifted; refresh signed owner view.');
      setDocs(current => [...current, ...page.items]);
      setHasMore(page.has_more);
    } catch (cause) {
      if (stamp === epoch.current) setError(cause instanceof Error ? cause.message : 'Library pagination denied.');
    } finally {
      if (stamp === epoch.current) setBusy(false);
    }
  }

  async function mutate(action: 'save' | 'delete') {
    if (!actor || busy) return;
    if (action === 'delete') {
      if (!selected || !window.confirm('Permanently tombstone this exact original document revision? The history cannot be restored.')) return;
    }
    const stamp = ++epoch.current;
    setBusy(true);
    setError('');
    try {
      if (action === 'delete') {
        if (!selected) throw new Error('Choose a document before tombstoning.');
        await userGlobalLibraryApi.remove(selected);
      } else if (selected) {
        await userGlobalLibraryApi.update(selected, title, content);
      } else {
        await userGlobalLibraryApi.create(title, kind, content);
      }
      if (stamp === epoch.current) await refresh();
    } catch (cause) {
      if (stamp === epoch.current) {
        setError(cause instanceof Error ? cause.message : 'Original user library CAS rejected.');
        // Never offer a stale editor as if its revision still owned authority.
        clearEditor();
      }
    } finally {
      if (stamp === epoch.current) setBusy(false);
    }
  }

  return <div className="space-y-6 max-w-6xl mx-auto">
    <header className="flex flex-wrap gap-3 items-center justify-between">
      <div>
        <h1 className="font-display-lg text-2xl text-on-surface flex items-center gap-3">
          <BookOpen size={24} className="text-primary-fixed" /> User-owned Library
        </h1>
        <p className="text-on-surface-variant text-sm mt-2">
          Your guides, answers, and code notes across Flows. Only the current signed human owner can read or edit them.
        </p>
      </div>
      <button type="button" onClick={() => void refresh()} disabled={busy} className="flex gap-2 items-center border border-outline p-2 rounded">
        <RefreshCcw size={16} /> Refresh signed owner view
      </button>
    </header>

    <div role="note" className="border border-outline-variant bg-surface-container rounded p-4 flex gap-3 text-sm">
      <ShieldAlert size={20} className="text-primary-fixed shrink-0" />
      <p>All content is <strong>untrusted human-authored text</strong>. Saving a document does not approve it for agent context,
        authorize an MCP action, verify an exploit, establish target-owner evidence, or certify a release.</p>
    </div>
    {error && <p role="alert" className="p-3 border border-error text-error rounded">{error}</p>}
    {!actor && <p role="status" className="text-error">Sign in with a current verified human operator bearer to access the user library.</p>}

    <OperatorGlobalLibraryPanel />

    <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
      <Card title="Private library results">
        <div className="space-y-3">
          <div className="flex gap-2">
            <label className="flex-1 text-xs text-on-surface-variant">Search your own title and document text
              <input aria-label="Search your library" className="w-full p-2 rounded border border-outline-variant bg-surface-container"
                maxLength={128} value={searchDraft} onChange={event => setSearchDraft(event.target.value)}
                onKeyDown={event => { if (event.key === 'Enter') setSearchTerm(searchDraft.trim() || undefined); }} />
            </label>
            <button type="button" aria-label="Search signed user library" disabled={busy || !actor} onClick={() => setSearchTerm(searchDraft.trim() || undefined)}
              className="mt-auto p-2 border border-outline rounded"><Search size={18} /></button>
          </div>
          <ul aria-label="Global library documents" className="space-y-2 max-h-[460px] overflow-y-auto">
            {docs.map(doc => <li key={doc.id}>
              <button type="button" onClick={() => void choose(doc)} disabled={busy || !actor}
                className="w-full text-left p-3 rounded border border-outline-variant hover:border-primary-fixed text-xs">
                <strong className="block text-sm text-on-surface break-words">{doc.title}</strong>
                <span className="text-on-surface-variant">{doc.doc_type} · immutable revision {doc.revision} · SHA-256 {doc.sha256.slice(0, 12)}…</span>
              </button>
            </li>)}
          </ul>
          {hasMore && <button type="button" disabled={busy || docs.length > 1000 - GLOBAL_LIBRARY_PAGE_SIZE}
            onClick={() => void more()} className="border border-outline rounded p-2 text-xs">Next 20 owner-only results</button>}
          <p role="status" className="text-xs text-on-surface-variant">
            {docs.length} owner-scoped metadata results. Search never promotes these notes into trusted evidence.
          </p>
        </div>
      </Card>

      <Card title="Original document editor">
        <div className="space-y-3 text-xs">
          <button type="button" disabled={busy || !actor} onClick={clearEditor} className="border border-outline p-2 rounded flex items-center gap-2">
            <Plus size={16} /> New user-owned document
          </button>
          {selected && <p>Editing immutable original revision {selected.revision} ({selected.sha256.slice(0, 16)}…). Concurrent edits require an exact CAS.</p>}
          <label className="block">Title
            <input className="w-full border border-outline-variant bg-surface-container p-2 rounded" maxLength={128}
              value={title} onChange={event => setTitle(event.target.value)} disabled={busy || !actor} />
          </label>
          <label className="block">Kind
            <select className="w-full border border-outline-variant bg-surface-container p-2 rounded" value={kind}
              onChange={event => setKind(event.target.value as UserLibraryKind)} disabled={busy || !actor || !!selected}>
              <option value="guide">Guide</option><option value="answer">Answer</option><option value="code">Code</option>
            </select>
          </label>
          <label className="block">Plain-text content, maximum 8192 UTF-8 bytes
            <textarea className="w-full border border-outline-variant bg-surface-container p-2 rounded resize-y min-h-[200px]"
              value={content} onChange={event => setContent(event.target.value)} rows={10} maxLength={8192}
              disabled={busy || !actor} />
          </label>
          <div className="flex flex-wrap gap-2">
            <button type="button" disabled={busy || !actor || !title.trim() || !content.trim()}
              onClick={() => void mutate('save')} className="border border-primary-fixed text-primary-fixed p-2 rounded">
              {selected ? 'Save exact revision' : 'Create owned document'}
            </button>
            <button type="button" disabled={busy || !actor || !selected}
              onClick={() => void mutate('delete')} className="border border-error text-error p-2 rounded flex items-center gap-2">
              <Trash2 size={16} /> Tombstone original
            </button>
          </div>
        </div>
      </Card>
    </div>
  </div>;
}

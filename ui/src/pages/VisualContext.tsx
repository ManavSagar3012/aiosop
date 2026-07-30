import React, { useState, useMemo } from 'react';
import { API_BASE, authHeaders } from '../services/api';
import { Card } from '../components/shared/Card';
import { EmptyState } from '../components/shared/EmptyState';
import { Skeleton } from '../components/shared/Skeleton';
import { StatusBadge } from '../components/shared/StatusBadge';
import { useIntelligenceStore } from '../store/useIntelligenceStore';
import { useApiData } from '../hooks/useApiData';
import { useToast } from '../hooks/useToast';
import { Eye, Camera, GitCompare, Play, AlertTriangle, Crosshair, Loader2 } from 'lucide-react';

interface Trace {
  task_id: string;
  engagement_id?: string;
  elapsed_seconds?: number;
  stage_count?: number;
  is_complete?: boolean;
  failure?: { category?: string; reason?: string } | null;
  stages?: { stage?: string; [key: string]: any }[];
}

/**
 * Visual Context console.
 *
 * Drives the backend VisualContextAgent (multi-layer fusion: screenshot + DOM +
 * semantics + workflow) via the tasks API, and surfaces every agent_observation
 * the swarm emits over the live event feed. No hardcoded/mock data.
 */
export const VisualContext: React.FC = () => {
  const sessionId = useIntelligenceStore((s) => s.sessionId);
  const auditLog = useIntelligenceStore((s) => s.auditLog);
  const { addToast } = useToast();

  const [mode, setMode] = useState<'analyze' | 'compare'>('analyze');
  const [screenshotPath, setScreenshotPath] = useState('');
  const [screenshotPathB, setScreenshotPathB] = useState('');
  const [workflowState, setWorkflowState] = useState('');
  const [userRole, setUserRole] = useState('');
  const [identityA, setIdentityA] = useState('');
  const [identityB, setIdentityB] = useState('');
  const [submitting, setSubmitting] = useState(false);

  // Live task traces for this engagement (polls; traces include visual agent executions)
  const { data: tracesResp, loading: tracesLoading, refetch: refetchTraces } = useApiData<{ traces: Trace[] }>(
    sessionId ? `/engagements/${sessionId}/traces` : null,
    { pollInterval: 8000 }
  );
  const traces = tracesResp?.traces || [];

  // Visual observations from the live audit stream. The orchestrator normalizes
  // WS events into audit entries; visual agent results arrive as agent_observation /
  // hypothesis entries referencing screenshots.
  const visualObs = useMemo(
    () =>
      (auditLog || []).filter((e: any) => {
        const hay = JSON.stringify(e).toLowerCase();
        return hay.includes('visual') || hay.includes('screenshot') || hay.includes('view_comparison');
      }),
    [auditLog]
  );

  const canSubmit =
    !!sessionId &&
    !submitting &&
    (mode === 'analyze' ? !!screenshotPath : !!screenshotPath && !!screenshotPathB);

  const dispatch = async () => {
    if (!sessionId || !canSubmit) return;
    setSubmitting(true);
    try {
      const payload =
        mode === 'analyze'
          ? {
              task_type: 'analyze_screenshot',
              agent_type: 'visual',
              priority: 5,
              engagement_id: sessionId,
              payload: {
                screenshot_path: screenshotPath,
                workflow_state: workflowState || 'unknown',
                user_role: userRole || 'unknown',
              },
            }
          : {
              task_type: 'view_comparison',
              agent_type: 'visual',
              priority: 5,
              engagement_id: sessionId,
              payload: {
                screenshot_paths: [screenshotPath, screenshotPathB],
                identity_a: identityA || 'identity_a',
                identity_b: identityB || 'identity_b',
              },
            };

      const resp = await fetch(`${API_BASE}/tasks`, {
        method: 'POST',
        headers: authHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(payload),
      });

      if (resp.ok) {
        addToast(
          mode === 'analyze'
            ? 'Visual analysis task dispatched to swarm.'
            : 'Identity comparison task dispatched to swarm.',
          'success'
        );
        refetchTraces();
      } else {
        addToast(`Dispatch rejected by API (${resp.status}).`, 'error');
      }
    } catch (e) {
      addToast('Dispatch failed. Check API connectivity and retry.', 'error');
    } finally {
      setSubmitting(false);
    }
  };

  const inputCls =
    'w-full bg-surface-container-low border border-outline-variant px-3 py-2 font-code-sm text-[12px] text-on-surface focus:outline-none focus:border-secondary transition-colors placeholder:text-on-surface-variant/40';

  return (
    <div className="flex flex-col gap-6">
      {/* Header strip */}
      <div className="flex justify-between items-center bg-surface-container p-4 border border-outline-variant">
        <div className="flex items-center gap-3">
          <Eye className="text-secondary" size={20} />
          <div className="flex flex-col">
            <span className="font-label-caps text-label-xs text-on-surface-variant mb-1 uppercase">Fusion Engine</span>
            <span className="font-code-sm text-primary text-[14px]">
              SCREENSHOT + DOM + SEMANTICS + WORKFLOW
            </span>
          </div>
        </div>
        <div className="flex gap-4">
          <div className="bg-black/40 px-4 py-2 border border-outline-variant text-center">
            <div className="font-code-sm text-secondary text-[14px] font-bold">{visualObs.length}</div>
            <div className="font-label-caps text-on-surface-variant text-label-xs">OBSERVATIONS</div>
          </div>
          <div className="bg-black/40 px-4 py-2 border border-outline-variant text-center">
            <div className="font-code-sm text-primary text-[14px] font-bold">{traces.length}</div>
            <div className="font-label-caps text-on-surface-variant text-label-xs">TASK TRACES</div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Dispatch console */}
        <Card title="Dispatch Visual Agent" glow="cyan">
          {!sessionId ? (
            <EmptyState
              message="No active engagement."
              icon={<Crosshair size={32} />}
              hint="Start a mission to enable visual context operations."
            />
          ) : (
            <div className="space-y-4">
              {/* Mode toggle */}
              <div className="flex gap-2">
                <button
                  onClick={() => setMode('analyze')}
                  className={`flex-1 flex items-center justify-center gap-2 px-3 py-2 font-label-caps text-[10px] border transition-all ${
                    mode === 'analyze'
                      ? 'bg-secondary/10 border-secondary text-secondary glow-cyan'
                      : 'bg-surface-container-high border-outline-variant text-on-surface-variant hover:bg-surface-variant'
                  }`}
                >
                  <Camera size={13} /> ANALYZE SCREENSHOT
                </button>
                <button
                  onClick={() => setMode('compare')}
                  className={`flex-1 flex items-center justify-center gap-2 px-3 py-2 font-label-caps text-[10px] border transition-all ${
                    mode === 'compare'
                      ? 'bg-secondary/10 border-secondary text-secondary glow-cyan'
                      : 'bg-surface-container-high border-outline-variant text-on-surface-variant hover:bg-surface-variant'
                  }`}
                >
                  <GitCompare size={13} /> COMPARE IDENTITIES
                </button>
              </div>

              <div className="space-y-3">
                <div>
                  <label className="block font-label-caps text-label-xs text-on-surface-variant mb-1 uppercase">
                    {mode === 'analyze' ? 'Screenshot Path' : 'Baseline Screenshot (Identity A)'}
                  </label>
                  <input
                    className={inputCls}
                    placeholder="recon-screenshots/capture_a.png"
                    value={screenshotPath}
                    onChange={(e) => setScreenshotPath(e.target.value)}
                  />
                </div>

                {mode === 'analyze' ? (
                  <>
                    <div>
                      <label className="block font-label-caps text-label-xs text-on-surface-variant mb-1 uppercase">Workflow State</label>
                      <input
                        className={inputCls}
                        placeholder="e.g. post_login_dashboard"
                        value={workflowState}
                        onChange={(e) => setWorkflowState(e.target.value)}
                      />
                    </div>
                    <div>
                      <label className="block font-label-caps text-label-xs text-on-surface-variant mb-1 uppercase">Current Role</label>
                      <input
                        className={inputCls}
                        placeholder="e.g. user_standard"
                        value={userRole}
                        onChange={(e) => setUserRole(e.target.value)}
                      />
                    </div>
                  </>
                ) : (
                  <>
                    <div>
                      <label className="block font-label-caps text-label-xs text-on-surface-variant mb-1 uppercase">Test Screenshot (Identity B)</label>
                      <input
                        className={inputCls}
                        placeholder="recon-screenshots/capture_b.png"
                        value={screenshotPathB}
                        onChange={(e) => setScreenshotPathB(e.target.value)}
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="block font-label-caps text-label-xs text-on-surface-variant mb-1 uppercase">Identity A</label>
                        <input className={inputCls} placeholder="user_a" value={identityA} onChange={(e) => setIdentityA(e.target.value)} />
                      </div>
                      <div>
                        <label className="block font-label-caps text-label-xs text-on-surface-variant mb-1 uppercase">Identity B</label>
                        <input className={inputCls} placeholder="admin_b" value={identityB} onChange={(e) => setIdentityB(e.target.value)} />
                      </div>
                    </div>
                  </>
                )}

                <button
                  onClick={dispatch}
                  disabled={!canSubmit}
                  className="w-full flex items-center justify-center gap-2 bg-primary-container text-on-primary-fixed px-4 py-2.5 font-label-caps text-label-caps hover:brightness-110 transition-all active:scale-95 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  {submitting ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
                  {submitting ? 'DISPATCHING...' : 'DISPATCH TO SWARM'}
                </button>

                <p className="text-[10px] font-code-sm text-on-surface-variant/60 leading-relaxed">
                  {mode === 'analyze'
                    ? 'The VisualContextAgent fuses the screenshot with workflow + role context to identify critical operations and privilege boundaries.'
                    : 'Compares the same view across two identities to detect privilege-escalation UI differences (visual BFLA).'}
                </p>
              </div>
            </div>
          )}
        </Card>

        {/* Live observations */}
        <Card title="Live Visual Observations" glow="cyan" className="lg:col-span-2">
          <div className="space-y-3 max-h-[480px] overflow-y-auto custom-scrollbar pr-2">
            {visualObs.length === 0 ? (
              <EmptyState
                message="No visual observations yet."
                icon={<Eye size={28} />}
                hint="Dispatch a visual analysis or wait for the swarm to emit agent observations."
              />
            ) : (
              visualObs.slice(0, 30).map((obs: any, i: number) => (
                <div key={obs.id || i} className="bg-surface-container-high border border-outline-variant p-3">
                  <div className="flex justify-between items-center mb-1.5">
                    <span className="font-label-caps text-label-xs text-secondary uppercase">{obs.event_type?.replace(/_/g, ' ') || 'OBSERVATION'}</span>
                    <span className="font-code-sm text-[9px] text-on-surface-variant">{obs.timestamp ? new Date(obs.timestamp).toLocaleTimeString() : ''}</span>
                  </div>
                  <div className="font-code-sm text-[11px] text-on-surface leading-relaxed break-words">
                    {typeof obs.action === 'string' ? obs.action : JSON.stringify(obs.action ?? obs.details ?? obs.result ?? {}, null, 2)}
                  </div>
                  <div className="mt-1.5">
                    <StatusBadge value={obs.severity || 'info'} />
                  </div>
                </div>
              ))
            )}
          </div>
        </Card>
      </div>

      {/* Task traces */}
      <Card title="Recent Task Traces" className="col-span-full">
        {tracesLoading && !traces ? (
          <div className="space-y-2">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
          </div>
        ) : !traces || traces.length === 0 ? (
          <EmptyState
            message="No task traces recorded."
            icon={<AlertTriangle size={28} />}
            hint="Executed tasks (including visual agent runs) appear here with per-step status."
          />
        ) : (
          <div className="overflow-y-auto custom-scrollbar">
            <table className="w-full text-left font-code-sm text-code-sm">
              <thead className="sticky top-0 z-10">
                <tr className="text-on-surface-variant bg-surface-container-high">
                  <th className="px-3 py-2 font-label-caps text-label-xs uppercase">Task</th>
                  <th className="px-3 py-2 font-label-caps text-label-xs uppercase">Stages</th>
                  <th className="px-3 py-2 font-label-caps text-label-xs uppercase">Elapsed</th>
                  <th className="px-3 py-2 font-label-caps text-label-xs uppercase">Status</th>
                  <th className="px-3 py-2 font-label-caps text-label-xs uppercase">Outcome</th>
                </tr>
              </thead>
              <tbody>
                {traces.slice(0, 25).map((t) => (
                  <tr key={t.task_id} className="border-b border-outline-variant/30 hover:bg-surface-container-high/60 transition-colors">
                    <td className="px-3 py-2 text-on-surface truncate max-w-[200px]">{t.task_id}</td>
                    <td className="px-3 py-2 text-on-surface-variant text-[11px]">{t.stage_count ?? '—'}</td>
                    <td className="px-3 py-2 text-secondary text-[11px]">{t.elapsed_seconds != null ? `${t.elapsed_seconds}s` : '—'}</td>
                    <td className="px-3 py-2"><StatusBadge value={t.failure ? 'error' : t.is_complete ? 'completed' : 'running'} /></td>
                    <td className="px-3 py-2 text-on-surface-variant text-[11px] truncate max-w-[220px]">
                      {t.failure ? `${t.failure.category || ''}: ${t.failure.reason || ''}` : t.stages?.slice(-1)[0]?.stage || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
};

import React, { useState } from 'react';
import { Card } from '../components/shared/Card';
import { ErrorState } from '../components/shared/ErrorState';
import { Settings, Shield, Cpu } from 'lucide-react';
import { API_BASE, authHeaders } from '../services/api';

export const Administration: React.FC = () => {
  const [actionError, setActionError] = useState<{ message: string; retry: () => void } | null>(null);

  const haltEngagement = () => {
    const id = (document.getElementById('eng-id-input') as HTMLInputElement).value;
    fetch(`${API_BASE}/engagements/${id}/halt?reason=admin_action`, { method: 'POST', headers: authHeaders() })
      .then((res) => { if (!res.ok) throw new Error("Failed"); setActionError(null); })
      .catch(() => setActionError({ message: `Failed to halt engagement "${id}".`, retry: haltEngagement }));
  };

  const transitionPhase = () => {
    const id = (document.getElementById('eng-id-input') as HTMLInputElement).value;
    const phase = (document.getElementById('phase-input') as HTMLInputElement).value;
    fetch(`${API_BASE}/engagements/${id}/transition?new_phase=${phase}`, {
      method: 'POST',
      headers: authHeaders(),
    })
      .then((res) => { if (!res.ok) throw new Error("Failed"); setActionError(null); })
      .catch(() => setActionError({
        message: `Failed to transition engagement "${id}" to phase "${phase}".`,
        retry: transitionPhase,
      }));
  };

  return (
    <div className="flex flex-col" style={{ gap: 16 }}>
      {actionError && (
        <ErrorState message={actionError.message} onRetry={actionError.retry} />
      )}

      <div className="grid grid-cols-3" style={{ gap: 16 }}>
        <Card title="Swarm Configuration">
          <div className="flex flex-col" style={{ gap: 16 }}>
            {[
              { icon: <Cpu size={16} style={{ color: 'var(--accent)' }} />, label: 'Max Parallel Agents', control: (
                <input type="number" defaultValue={5} className="input" style={{ width: 64, textAlign: 'center' }} />
              )},
              { icon: <Settings size={16} style={{ color: 'var(--danger)' }} />, label: 'Evidence Integrity Mode', control: (
                <select className="select" style={{ fontSize: 11 }}>
                  <option>STRICT (100% LIVE)</option>
                  <option>BALANCED (ALLOW DERIVED)</option>
                  <option>DEV (ALLOW MOCKS)</option>
                </select>
              )},
              { icon: <Shield size={16} style={{ color: 'var(--accent)' }} />, label: 'Verification Strictness', control: (
                <select className="select" style={{ fontSize: 11 }}>
                  <option>Loose (1 Source)</option>
                  <option selected>Balanced (2 Sources)</option>
                  <option>Strict (3+ Sources)</option>
                </select>
              )},
            ].map(({ icon, label, control }) => (
              <div key={label} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: 'var(--text-primary)' }}>
                  {icon}
                  {label}
                </div>
                {control}
              </div>
            ))}
          </div>
        </Card>

        <Card title="Budget & Limits">
          <div className="flex flex-col" style={{ gap: 16 }}>
            <div>
              <label style={{ display: 'block', fontFamily: "'JetBrains Mono', monospace", fontSize: 9, fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--text-tertiary)', marginBottom: 6 }}>
                MAX ENGAGEMENT BUDGET (USD)
              </label>
              <input type="text" defaultValue="500.00" className="input" style={{ color: 'var(--interactive)' }} />
            </div>
            <div>
              <label style={{ display: 'block', fontFamily: "'JetBrains Mono', monospace", fontSize: 9, fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--text-tertiary)', marginBottom: 6 }}>
                S2 ESCALATION THRESHOLD (EV)
              </label>
              <input type="text" defaultValue="7.5" className="input" style={{ color: 'var(--interactive)' }} />
            </div>
            <button className="btn btn-primary" style={{ width: '100%', justifyContent: 'center' }}>
              SAVE GLOBAL POLICIES
            </button>
          </div>
        </Card>

        <Card title="Provider API Keys">
          <div className="flex flex-col" style={{ gap: 10 }}>
            {[
              { name: 'OPENAI_GPT4O', masked: '••••••••sk-4a', active: true },
              { name: 'ANTHROPIC_CLAUDE3', masked: '••••••••key-f2', active: true },
              { name: 'SHODAN_API_KEY', masked: 'NOT CONFIGURED', active: false },
            ].map(({ name, masked, active }) => (
              <div
                key={name}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '8px 0',
                  borderBottom: '1px solid var(--border-subtle)',
                  opacity: active ? 1 : 0.5,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div
                    style={{
                      width: 6,
                      height: 6,
                      borderRadius: '50%',
                      background: active ? 'var(--accent)' : 'var(--text-disabled)',
                    }}
                  />
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: 'var(--text-primary)' }}>
                    {name}
                  </span>
                </div>
                <span
                  style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: 10,
                    color: active ? 'var(--text-tertiary)' : 'var(--danger)',
                  }}
                >
                  {masked}
                </span>
              </div>
            ))}
            <button className="btn btn-ghost" style={{ width: '100%', justifyContent: 'center', marginTop: 8 }}>
              CONFIGURE VAULT
            </button>
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-2" style={{ gap: 16 }}>
        <Card title="Operational Stress Testing">
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: 16,
              background: 'var(--surface-2)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius-md)',
            }}
          >
            <div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: 'var(--accent)' }}>
                Simulation: High-Velocity Swarm
              </div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: 'var(--text-tertiary)', marginTop: 4, letterSpacing: '0.05em', textTransform: 'uppercase' }}>
                Target: 1,000 Events / Second
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button
                onClick={() => {
                  import('../services/load_test').then(m => m.loadTester.start(1000));
                }}
                className="btn btn-danger btn-sm"
              >
                START STRESS TEST
              </button>
              <button
                onClick={() => {
                  import('../services/load_test').then(m => m.loadTester.stop());
                }}
                className="btn btn-ghost btn-sm"
              >
                HALT
              </button>
            </div>
          </div>
        </Card>

        <Card title="Historical Learning Policy">
          <div className="grid grid-cols-2" style={{ gap: 24 }}>
            <div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: 'var(--text-tertiary)', lineHeight: 1.6 }}>
                The Swarm is currently configured to share{' '}
                <span style={{ color: 'var(--accent)', fontWeight: 700, textDecoration: 'underline' }}>SEMANTIC MEMORY</span>{' '}
                across all engagements. This means patterns learned in Target A will inform prioritization in Target B.
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 16 }}>
                <input
                  type="checkbox"
                  defaultChecked
                  style={{ accentColor: 'var(--accent)' }}
                />
                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: 'var(--text-primary)' }}>
                  Enable Cross-Engagement Pattern Learning
                </span>
              </div>
            </div>
            <div
              style={{
                padding: 16,
                background: 'var(--surface-2)',
                border: '1px dashed var(--border)',
                borderRadius: 'var(--radius-md)',
              }}
            >
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: 'var(--text-disabled)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 8 }}>
                Active Knowledge Base Statistics
              </div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: 'var(--text-tertiary)', opacity: 0.6 }}>
                No live knowledge-base metrics available yet.
              </div>
            </div>
          </div>
        </Card>

        <Card title="Dead Letter Queue">
          <div className="flex flex-col" style={{ gap: 8 }}>
            <button className="btn btn-ghost" style={{ width: '100%', justifyContent: 'center' }}>VIEW DLQ ENTRIES</button>
            <button className="btn btn-ghost" style={{ width: '100%', justifyContent: 'center' }}>REQUEUE ALL PENDING</button>
          </div>
        </Card>

        <Card title="Engagement Control Panel">
          <div className="flex flex-col" style={{ gap: 10 }}>
            <input type="text" placeholder="Engagement ID" className="input" id="eng-id-input" />
            <button className="btn btn-danger" style={{ width: '100%', justifyContent: 'center' }} onClick={haltEngagement}>
              HALT ENGAGEMENT
            </button>
            <input type="text" placeholder="Phase (e.g., exploitation)" className="input" id="phase-input" />
            <button className="btn btn-ghost" style={{ width: '100%', justifyContent: 'center' }} onClick={transitionPhase}>
              TRANSITION PHASE
            </button>
          </div>
        </Card>
      </div>
    </div>
  );
};

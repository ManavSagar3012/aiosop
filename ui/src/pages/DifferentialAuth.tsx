import React, { useState } from 'react';
import { API_BASE, authHeaders } from '../services/api';
import { Card } from '../components/shared/Card';
import { EmptyState } from '../components/shared/EmptyState';
import { ErrorState } from '../components/shared/ErrorState';
import { Shield, Lock, Eye } from 'lucide-react';
import { useIntelligenceStore } from '../store/useIntelligenceStore';

export const DifferentialAuth: React.FC = () => {
  const { diffAuthFindings, sessionId } = useIntelligenceStore();
  const [activeFindingIdx, setActiveFindingIdx] = useState(0);
  const [activeIdentity, setActiveIdentity] = useState<'user_a' | 'user_b' | 'admin'>('user_b');
  const [validateError, setValidateError] = useState<string | null>(null);

  const currentFinding = diffAuthFindings[activeFindingIdx];

  const handleValidate = async () => {
    if (!currentFinding || !sessionId) return;
    setValidateError(null);
    try {
      await fetch(`${API_BASE}/engagements/${sessionId}/findings/${currentFinding.id}/replay`, {
        method: 'POST',
        headers: authHeaders()
      });
      alert("Exploit validation task queued.");
    } catch (e) {
      setValidateError('Failed to queue exploit validation task.');
    }
  };

  const identities = ['user_a', 'user_b', 'admin'] as const;

  return (
    <div className="flex flex-col" style={{ gap: 16, height: '100%' }}>
      {/* Header bar */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '16px 20px',
          background: 'var(--surface-1)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-lg)',
        }}
      >
        <div>
          <div
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 9,
              fontWeight: 700,
              letterSpacing: '0.1em',
              textTransform: 'uppercase',
              color: 'var(--text-tertiary)',
              marginBottom: 4,
            }}
          >
            Target Resource
          </div>
          <div
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 13,
              color: 'var(--accent)',
            }}
          >
            {currentFinding?.resource_id || "AWAITING ANOMALY..."} // {currentFinding?.category?.toUpperCase()}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {diffAuthFindings.length > 1 && (
            <div style={{ display: 'flex', gap: 4, marginRight: 8 }}>
              {diffAuthFindings.map((_, i) => (
                <button
                  key={i}
                  onClick={() => setActiveFindingIdx(i)}
                  aria-label={`Show finding ${i + 1}`}
                  style={{
                    width: 8,
                    height: 8,
                    borderRadius: '50%',
                    background: activeFindingIdx === i ? 'var(--accent)' : 'var(--surface-3)',
                    border: 'none',
                    cursor: 'pointer',
                  }}
                />
              ))}
            </div>
          )}
          {identities.map(id => (
            <button
              key={id}
              onClick={() => setActiveIdentity(id)}
              className={activeIdentity === id ? 'btn btn-primary btn-sm' : 'btn btn-ghost btn-sm'}
            >
              {id.replace('_', ' ').toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {diffAuthFindings.length === 0 ? (
        <div style={{ flex: 1 }}>
          <EmptyState
            message="No differential authorization findings recorded yet"
            icon={<Shield size={32} />}
            hint="Awaiting anomaly detection from the active engagement"
          />
        </div>
      ) : (
        <div className="grid grid-cols-2" style={{ gap: 16, flex: 1, minHeight: 0 }}>
          {/* Baseline */}
          <Card title="Baseline Observation (Expected Identity)">
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 12,
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 11,
                maxHeight: 500,
                overflowY: 'auto',
              }}
              className="custom-scrollbar"
            >
              <div
                style={{
                  padding: 12,
                  background: 'var(--surface-2)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-md)',
                }}
              >
                <div
                  style={{
                    color: 'var(--accent)',
                    fontWeight: 700,
                    letterSpacing: '0.1em',
                    textTransform: 'uppercase',
                    fontSize: 9,
                    marginBottom: 8,
                  }}
                >
                  HTTP Response
                </div>
                <div style={{ color: 'var(--text-primary)', marginBottom: 4 }}>HTTP/1.1 200 OK</div>
                <div style={{ color: 'var(--text-tertiary)' }}>Content-Type: application/json</div>
                <div style={{ color: 'var(--text-primary)', marginTop: 8 }}>
                  {`{ "id": "${currentFinding?.resource_id || 'res-123'}", "status": "active" }`}
                </div>
              </div>

              <div
                style={{
                  padding: 12,
                  background: 'var(--surface-2)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-md)',
                }}
              >
                <div
                  style={{
                    color: 'var(--accent)',
                    fontWeight: 700,
                    letterSpacing: '0.1em',
                    textTransform: 'uppercase',
                    fontSize: 9,
                    marginBottom: 8,
                  }}
                >
                  DOM Semantics
                </div>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <span className="badge badge-success">BUTTON: DELETE</span>
                  <span className="badge badge-success">BUTTON: EDIT</span>
                </div>
              </div>

              <div
                style={{
                  height: 200,
                  background: 'var(--surface-2)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-md)',
                  position: 'relative',
                }}
              >
                <Eye size={48} style={{ color: 'var(--text-disabled)' }} />
                <span
                  style={{
                    position: 'absolute',
                    bottom: 8,
                    right: 8,
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: 9,
                    color: 'var(--text-disabled)',
                  }}
                >
                  SCREENSHOT: BASELINE_VIEW.PNG
                </span>
              </div>
            </div>
          </Card>

          {/* Comparison */}
          <Card
            title={`Test Observation (${activeIdentity.replace('_', ' ').toUpperCase()})`}
            accent={activeIdentity === 'user_b' ? 'danger' : 'none'}
          >
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 12,
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 11,
                maxHeight: 500,
                overflowY: 'auto',
              }}
              className="custom-scrollbar"
            >
              <div
                style={{
                  padding: 12,
                  background: activeIdentity === 'user_b' && currentFinding ? 'var(--danger-bg)' : 'var(--surface-2)',
                  border: `1px solid ${activeIdentity === 'user_b' && currentFinding ? 'var(--danger-border)' : 'var(--border)'}`,
                  borderRadius: 'var(--radius-md)',
                }}
              >
                <div
                  style={{
                    color: activeIdentity === 'user_b' && currentFinding ? 'var(--danger)' : 'var(--accent)',
                    fontWeight: 700,
                    letterSpacing: '0.1em',
                    textTransform: 'uppercase',
                    fontSize: 9,
                    marginBottom: 8,
                  }}
                >
                  HTTP Response
                </div>
                <div style={{ color: 'var(--text-primary)', marginBottom: 4 }}>
                  {activeIdentity === 'user_b' && currentFinding
                    ? `HTTP/1.1 ${currentFinding.observed_result}`
                    : 'HTTP/1.1 200 OK'}
                </div>
                <div style={{ color: 'var(--text-tertiary)', fontStyle: 'italic' }}>
                  Expected: {currentFinding?.expected_result || '200 OK'}
                </div>
                <div style={{ color: 'var(--text-primary)', marginTop: 8 }}>
                  {`{ "id": "${currentFinding?.resource_id || 'res-123'}", "data": "..." }`}
                </div>
              </div>

              <div
                style={{
                  padding: 12,
                  background: 'var(--surface-2)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-md)',
                }}
              >
                <div
                  style={{
                    color: 'var(--accent)',
                    fontWeight: 700,
                    letterSpacing: '0.1em',
                    textTransform: 'uppercase',
                    fontSize: 9,
                    marginBottom: 8,
                  }}
                >
                  DOM Semantics (Diff Detected)
                </div>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  {currentFinding ? (
                    <span className="badge badge-danger">UNAUTHORIZED VISIBILITY DETECTED</span>
                  ) : (
                    <span className="badge badge-neutral">NO DIFF RECORDED</span>
                  )}
                </div>
              </div>

              <div
                style={{
                  height: 200,
                  background: 'var(--surface-2)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-md)',
                }}
              >
                {currentFinding ? (
                  <div style={{ textAlign: 'center' }}>
                    <Shield size={48} style={{ color: 'var(--danger)', margin: '0 auto 8px' }} />
                    <span className="badge badge-danger">{currentFinding.category.toUpperCase()}</span>
                  </div>
                ) : (
                  <span style={{ color: 'var(--text-disabled)', fontStyle: 'italic' }}>
                    Awaiting findings...
                  </span>
                )}
              </div>
            </div>
          </Card>
        </div>
      )}

      {validateError && (
        <ErrorState message={validateError} onRetry={handleValidate} />
      )}

      {/* Verdict footer */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '16px 20px',
          background: 'var(--surface-1)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-lg)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <div
            style={{
              width: 48,
              height: 48,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              borderRadius: 'var(--radius-md)',
              background: currentFinding ? 'var(--danger-bg)' : 'var(--surface-2)',
              color: currentFinding ? 'var(--danger)' : 'var(--text-tertiary)',
              border: `1px solid ${currentFinding ? 'var(--danger-border)' : 'var(--border)'}`,
            }}
          >
            <Lock size={20} />
          </div>
          <div>
            <div
              style={{
                fontFamily: "'Space Grotesk', sans-serif",
                fontSize: 16,
                fontWeight: 700,
                color: currentFinding ? 'var(--danger)' : 'var(--text-secondary)',
              }}
            >
              Differential Verdict: {currentFinding ? 'CRITICAL ANOMALY' : 'NO ANOMALIES DETECTED'}
            </div>
            <div
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 11,
                color: 'var(--text-tertiary)',
                marginTop: 4,
              }}
            >
              {currentFinding
                ? `Confidence: ${(currentFinding.confidence * 100).toFixed(1)}% // ${currentFinding.test_identity_id} accessed restricted resource.`
                : 'All observed identities respect baseline authorization boundaries.'}
              {currentFinding && (
                <span
                  onClick={handleValidate}
                  style={{ color: 'var(--accent)', textDecoration: 'underline', cursor: 'pointer', marginLeft: 8 }}
                >
                  PROVE EXPLOITABILITY
                </span>
              )}
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            disabled={!currentFinding}
            className="btn btn-danger btn-sm"
            onClick={handleValidate}
          >
            VALIDATE HYPOTHESIS
          </button>
          <button disabled={!currentFinding} className="btn btn-ghost btn-sm">
            SAVE EVIDENCE
          </button>
        </div>
      </div>
    </div>
  );
};

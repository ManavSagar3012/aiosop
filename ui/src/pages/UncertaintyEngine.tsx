import React, { useState } from 'react';
import { API_BASE, authHeaders } from '../services/api';
import { Card } from '../components/shared/Card';
import { EmptyState } from '../components/shared/EmptyState';
import { ErrorState } from '../components/shared/ErrorState';
import { useIntelligenceStore } from '../store/useIntelligenceStore';
import { AlertOctagon, Lightbulb, Search, ArrowRight } from 'lucide-react';

export const UncertaintyEngine: React.FC = () => {
  const { uncertainties, sessionId } = useIntelligenceStore();
  const [launchError, setLaunchError] = useState<string | null>(null);

  const handleLaunchSwarm = async () => {
    if (!sessionId) return;
    setLaunchError(null);
    try {
      await fetch(`${API_BASE}/engagements/${sessionId}/discovery/trigger`, {
        method: 'POST',
        headers: authHeaders()
      });
      alert("Discovery swarm successfully deployed to target asset.");
    } catch (e) {
      console.error("Discovery trigger failed", e);
      setLaunchError("Failed to deploy discovery swarm. Check target connectivity and retry.");
    }
  };

  const blockedPathsCount = uncertainties.reduce((acc, curr) => acc + (curr.blockedPaths?.length || 0), 0);

  return (
    <div className="flex flex-col" style={{ gap: 16, height: '100%' }}>
      {/* Header */}
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
            Reasoning Mode
          </div>
          <div
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 13,
              color: 'var(--accent)',
            }}
          >
            SKEPTICAL_OPTIMISM (FORMAL TRACKING OF UNKNOWNS)
          </div>
        </div>
        <div style={{ display: 'flex', gap: 12 }}>
          <div
            style={{
              padding: '8px 16px',
              background: 'var(--surface-2)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius-md)',
              textAlign: 'center',
            }}
          >
            <div
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 16,
                fontWeight: 700,
                color: 'var(--interactive)',
                fontVariantNumeric: 'tabular-nums',
              }}
            >
              {uncertainties?.length || 0}
            </div>
            <div
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 9,
                color: 'var(--text-tertiary)',
                letterSpacing: '0.1em',
                textTransform: 'uppercase',
              }}
            >
              TOTAL UNKNOWNS
            </div>
          </div>
          <div
            style={{
              padding: '8px 16px',
              background: 'var(--surface-2)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius-md)',
              textAlign: 'center',
            }}
          >
            <div
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 16,
                fontWeight: 700,
                color: 'var(--danger)',
                fontVariantNumeric: 'tabular-nums',
              }}
            >
              {blockedPathsCount}
            </div>
            <div
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 9,
                color: 'var(--text-tertiary)',
                letterSpacing: '0.1em',
                textTransform: 'uppercase',
              }}
            >
              BLOCKED PATHS
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2" style={{ gap: 16, flex: 1, minHeight: 0 }}>
        {/* Knowledge Boundaries */}
        <Card title="Knowledge Boundaries (What the AI is Missing)">
          <div
            style={{
              maxHeight: 600,
              overflowY: 'auto',
              display: 'flex',
              flexDirection: 'column',
              gap: 16,
            }}
            className="custom-scrollbar"
          >
            {launchError && (
              <ErrorState message={launchError} onRetry={handleLaunchSwarm} />
            )}
            {uncertainties.length > 0 ? uncertainties.map(unc => (
              <div
                key={unc.id}
                style={{
                  padding: 20,
                  background: 'var(--surface-2)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-md)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
                  <AlertOctagon size={20} style={{ color: 'var(--interactive)' }} />
                  <div
                    style={{
                      fontFamily: "'Space Grotesk', sans-serif",
                      fontSize: 16,
                      fontWeight: 600,
                      color: 'var(--text-primary)',
                    }}
                  >
                    {unc.target}
                  </div>
                </div>

                <div className="grid grid-cols-2" style={{ gap: 24 }}>
                  <div>
                    <div
                      style={{
                        fontFamily: "'JetBrains Mono', monospace",
                        fontSize: 9,
                        fontWeight: 700,
                        letterSpacing: '0.1em',
                        textTransform: 'uppercase',
                        color: 'var(--text-tertiary)',
                        marginBottom: 10,
                      }}
                    >
                      Formal Unknowns
                    </div>
                    <div className="flex flex-col" style={{ gap: 8 }}>
                      {(unc.unknowns || []).map(u => (
                        <div
                          key={u}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: 8,
                            fontFamily: "'JetBrains Mono', monospace",
                            fontSize: 11,
                            color: 'var(--text-primary)',
                          }}
                        >
                          <div style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--interactive)', flexShrink: 0 }} />
                          {u}
                        </div>
                      ))}
                    </div>
                  </div>
                  <div>
                    <div
                      style={{
                        fontFamily: "'JetBrains Mono', monospace",
                        fontSize: 9,
                        fontWeight: 700,
                        letterSpacing: '0.1em',
                        textTransform: 'uppercase',
                        color: 'var(--text-tertiary)',
                        marginBottom: 10,
                      }}
                    >
                      Blocked Discovery Paths
                    </div>
                    <div className="flex flex-col" style={{ gap: 8 }}>
                      {(unc.blockedPaths || []).map(p => (
                        <div
                          key={p}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: 8,
                            fontFamily: "'JetBrains Mono', monospace",
                            fontSize: 11,
                            color: 'var(--danger)',
                          }}
                        >
                          <div style={{ width: 6, height: 6, background: 'var(--danger)', flexShrink: 0 }} />
                          {p}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                <div
                  style={{
                    marginTop: 20,
                    paddingTop: 12,
                    borderTop: '1px solid var(--border)',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 8,
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: 10,
                      color: 'var(--text-tertiary)',
                      fontStyle: 'italic',
                    }}
                  >
                    <Lightbulb size={14} style={{ color: 'var(--accent)' }} />
                    Recommended Action: Manual session injection or high-depth crawling.
                  </div>
                  <button
                    onClick={handleLaunchSwarm}
                    className="btn btn-secondary btn-sm"
                  >
                    <ArrowRight size={12} />
                    LAUNCH DISCOVERY SWARM
                  </button>
                </div>
              </div>
            )) : (
              <EmptyState message="No knowledge boundaries identified yet" icon={<Search size={48} />} />
            )}
          </div>
        </Card>

        {/* Reasoning Transparency */}
        <Card title="Reasoning Transparency (Brain Dump)">
          <div
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 11,
              color: 'var(--text-tertiary)',
              lineHeight: 1.7,
              display: 'flex',
              flexDirection: 'column',
              gap: 16,
            }}
          >
            <div
              style={{
                padding: 16,
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
                  fontSize: 10,
                  marginBottom: 8,
                }}
              >
                SWARM_GOVERNOR // RATIONALE:
              </div>
              <div style={{ color: 'var(--text-primary)', lineHeight: 1.7 }}>
                {uncertainties.length > 0 ? (
                  <>
                    "The current uncertainty regarding{' '}
                    <span style={{ color: 'var(--interactive)', textDecoration: 'underline', fontStyle: 'italic' }}>
                      {uncertainties[0].unknowns?.[0] || 'Target Context'}
                    </span>{' '}
                    has halted exploitation attempts. We lack confirmation of the state transition for{' '}
                    <span style={{ fontStyle: 'italic' }}>{uncertainties[0].target}</span>.
                    Escalating to{' '}
                    <span style={{ color: 'var(--accent)', fontStyle: 'italic', fontWeight: 700 }}>VisualContextAgent</span>{' '}
                    to identify hidden iframe triggers."
                  </>
                ) : (
                  <>
                    "Swarm reasoning is currently deterministic. No high-uncertainty state transitions detected in the last cycle.
                    Continuing{' '}
                    <span style={{ color: 'var(--interactive)' }}>Mission Discovery</span>{' '}
                    phase."
                  </>
                )}
              </div>
            </div>

            <div className="grid grid-cols-2" style={{ gap: 12 }}>
              <div
                style={{
                  padding: 12,
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-md)',
                }}
              >
                <div
                  style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: 9,
                    fontWeight: 700,
                    letterSpacing: '0.1em',
                    textTransform: 'uppercase',
                    color: 'var(--accent)',
                    marginBottom: 6,
                  }}
                >
                  MOST UNCERTAIN STACK
                </div>
                <div style={{ color: 'var(--text-primary)', fontSize: 12 }}>
                  Cloudflare Turnstile + Custom WebGL
                </div>
              </div>
              <div
                style={{
                  padding: 12,
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-md)',
                }}
              >
                <div
                  style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: 9,
                    fontWeight: 700,
                    letterSpacing: '0.1em',
                    textTransform: 'uppercase',
                    color: 'var(--accent)',
                    marginBottom: 6,
                  }}
                >
                  HIGHEST DATA GAP
                </div>
                <div style={{ color: 'var(--text-primary)', fontSize: 12 }}>
                  Organization Admin Credentials
                </div>
              </div>
            </div>

            <div style={{ textAlign: 'center', paddingTop: 32, opacity: 0.3 }}>
              <Search size={40} style={{ margin: '0 auto 8px', color: 'var(--text-tertiary)' }} />
              <p style={{ fontStyle: 'italic', color: 'var(--text-tertiary)' }}>
                Scanning for latent knowledge boundaries...
              </p>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
};

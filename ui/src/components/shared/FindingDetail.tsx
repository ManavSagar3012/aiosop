import React, { useState } from 'react';
import { Finding } from '../../store/useIntelligenceStore';
import { StatusBadge } from './StatusBadge';
import {
  Copy, Check, X,
  ChevronDown, ChevronUp, Users, FlaskConical
} from 'lucide-react';

interface FindingDetailProps {
  finding: Finding;
  onApprove?: (id: string) => void;
  onReject?: (id: string) => void;
}

const SEVERITY_CONFIG: Record<string, { border: string; bg: string }> = {
  critical: { border: 'var(--danger-border)', bg: 'var(--danger-bg)' },
  high:     { border: 'var(--warning-border)', bg: 'var(--warning-bg)' },
  medium:   { border: 'var(--interactive-border)', bg: 'var(--interactive-bg)' },
  low:      { border: 'var(--border)', bg: 'var(--surface-2)' },
  info:     { border: 'var(--border)', bg: 'var(--surface-2)' },
};

export const FindingDetail: React.FC<FindingDetailProps> = ({
  finding,
  onApprove,
  onReject,
}) => {
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);

  const severity = SEVERITY_CONFIG[finding.severity] || SEVERITY_CONFIG.info;

  const handleCopyEvidence = () => {
    const evidenceStr = JSON.stringify(finding, null, 2);
    navigator.clipboard.writeText(evidenceStr);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      style={{
        border: '1px solid var(--border)',
        borderLeft: `3px solid ${severity.border}`,
        borderRadius: 'var(--radius-md)',
        background: 'var(--surface-1)',
        overflow: 'hidden',
        transition: 'border-color var(--duration-fast)',
      }}
    >
      {/* Header */}
      <div className="flex items-center justify-between" style={{ padding: '12px 16px' }}>
        <div className="flex items-center gap-3 min-w-0 flex-1">
          <StatusBadge value={finding.severity} kind="severity" />
          <span
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 10,
              color: 'var(--text-tertiary)',
              letterSpacing: '0.05em',
            }}
          >
            {finding.category?.replace(/_/g, ' ')}
          </span>
          <span className="truncate" style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 12,
            fontWeight: 600,
            color: 'var(--text-primary)',
          }}>
            {finding.title}
          </span>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {finding.evScore !== undefined && (
            <span
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 10,
                color: 'var(--accent)',
                padding: '2px 8px',
                background: 'var(--accent-bg)',
                border: '1px solid var(--accent-border)',
                borderRadius: 'var(--radius-full)',
              }}
            >
              EV: {finding.evScore.toFixed(0)}
            </span>
          )}
          <StatusBadge value={finding.status} />

          <div className="flex items-center gap-0.5" style={{ marginLeft: 4 }}>
            {onApprove && (
              <button
                onClick={() => onApprove(finding.id)}
                className="btn btn-icon btn-ghost"
                style={{ width: 26, height: 26, color: 'var(--accent)' }}
                title="Approve"
              >
                <Check size={13} />
              </button>
            )}
            {onReject && (
              <button
                onClick={() => onReject(finding.id)}
                className="btn btn-icon btn-ghost"
                style={{ width: 26, height: 26, color: 'var(--danger)' }}
                title="Reject"
              >
                <X size={13} />
              </button>
            )}
            <button
              onClick={handleCopyEvidence}
              className="btn btn-icon btn-ghost"
              style={{ width: 26, height: 26 }}
              title="Copy evidence"
            >
              {copied ? <Check size={13} style={{ color: 'var(--accent)' }} /> : <Copy size={13} />}
            </button>
            <button
              onClick={() => setExpanded(!expanded)}
              className="btn btn-icon btn-ghost"
              style={{ width: 26, height: 26 }}
            >
              {expanded ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
            </button>
          </div>
        </div>
      </div>

      {/* Metrics bar */}
      <div
        className="flex items-center gap-4"
        style={{
          padding: '6px 16px',
          background: 'var(--surface-2)',
          borderTop: '1px solid var(--border-subtle)',
          borderBottom: expanded ? '1px solid var(--border-subtle)' : 'none',
        }}
      >
        <div className="flex items-center gap-1.5" style={{ color: 'var(--text-tertiary)', fontFamily: "'JetBrains Mono', monospace", fontSize: 10 }}>
          <FlaskConical size={11} />
          EVIDENCE: {finding.evidenceCount}
        </div>
        <div className="flex items-center gap-1.5" style={{ color: 'var(--text-tertiary)', fontFamily: "'JetBrains Mono', monospace", fontSize: 10 }}>
          <Users size={11} />
          CONSENSUS: {finding.agentConsensus?.length || 0} AGENTS
        </div>
        {finding.provenance && (
          <span
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 9,
              fontWeight: 600,
              letterSpacing: '0.08em',
              textTransform: 'uppercase',
              color: finding.provenance === 'live' ? 'var(--accent)' : 'var(--text-secondary)',
              padding: '1px 6px',
              background: finding.provenance === 'live' ? 'var(--accent-bg)' : 'var(--surface-3)',
              border: `1px solid ${finding.provenance === 'live' ? 'var(--accent-border)' : 'var(--border)'}`,
              borderRadius: 'var(--radius-full)',
            }}
          >
            {finding.provenance}
          </span>
        )}
      </div>

      {/* Expanded evidence */}
      {expanded && (
        <div style={{ padding: '12px 16px' }}>
          {finding.evidence && finding.evidence.length > 0 && (
            <div>
              <div
                style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 10,
                  fontWeight: 700,
                  letterSpacing: '0.1em',
                  textTransform: 'uppercase',
                  color: 'var(--text-tertiary)',
                  marginBottom: 8,
                }}
              >
                EVIDENCE
              </div>
              <div
                style={{
                  background: 'var(--surface-2)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-md)',
                  padding: 12,
                  maxHeight: 200,
                  overflowY: 'auto',
                }}
                className="custom-scrollbar"
              >
                {finding.evidence.map((ev: string | Record<string, unknown>, i: number) => (
                  <pre
                    key={i}
                    style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: 11,
                      color: 'var(--text-secondary)',
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-all',
                      margin: 0,
                      lineHeight: 1.6,
                    }}
                  >
                    {typeof ev === 'string' ? ev : JSON.stringify(ev, null, 2)}
                  </pre>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

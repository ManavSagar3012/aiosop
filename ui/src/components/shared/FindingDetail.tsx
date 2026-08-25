import React, { useState } from 'react';
import { Finding } from '../../store/useIntelligenceStore';
import { API_BASE, authHeaders } from '../../services/api';
import {
  Shield, ExternalLink, Copy, Check, X, Eye,
  AlertTriangle, FileText, ChevronDown, ChevronUp
} from 'lucide-react';

interface FindingDetailProps {
  finding: Finding;
  onApprove?: (id: string) => void;
  onReject?: (id: string) => void;
}

export const FindingDetail: React.FC<FindingDetailProps> = ({
  finding,
  onApprove,
  onReject,
}) => {
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);
  const [replaying, setReplaying] = useState(false);

  const severityColor = {
    critical: 'text-error border-error/30 bg-error/5',
    high: 'text-warning border-warning/30 bg-warning/5',
    medium: 'text-secondary border-secondary/30 bg-secondary/5',
    low: 'text-on-surface-variant border-outline-variant',
    info: 'text-on-surface-variant border-outline-variant',
  }[finding.severity] || 'text-on-surface-variant';

  const handleCopyEvidence = () => {
    const evidenceStr = JSON.stringify(finding, null, 2);
    navigator.clipboard.writeText(evidenceStr);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleReplay = async () => {
    setReplaying(true);
    try {
      const res = await fetch(`${API_BASE}/engagements/${finding.engagement_id}/findings/${finding.id}/replay`, {
        method: 'POST',
        headers: authHeaders(),
      });
      if (res.ok) {
        const data = await res.json();
        alert(`Replay result: ${data.status || 'completed'}`);
      }
    } catch (e) {
      console.error('Replay failed', e);
    }
    setReplaying(false);
  };

  return (
    <div className={`border ${severityColor} p-4 space-y-3`}>
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1">
            <span className="font-label-caps text-[9px] uppercase tracking-wider px-1.5 py-0.5 border border-current opacity-70">
              {finding.severity}
            </span>
            <span className="font-code-sm text-[10px] opacity-50">
              {finding.category?.replace(/_/g, ' ')}
            </span>
            {finding.evScore !== undefined && (
              <span className="font-code-sm text-[10px] text-primary">
                EV: {finding.evScore.toFixed(0)}
              </span>
            )}
          </div>
          <h4 className="font-label-caps text-label-caps text-on-surface">
            {finding.title}
          </h4>
        </div>

        <div className="flex items-center gap-1">
          {onApprove && (
            <button
              onClick={() => onApprove(finding.id)}
              className="p-1.5 text-success hover:bg-success/10 transition-colors"
              title="Approve"
            >
              <Check size={14} />
            </button>
          )}
          {onReject && (
            <button
              onClick={() => onReject(finding.id)}
              className="p-1.5 text-error hover:bg-error/10 transition-colors"
              title="Reject"
            >
              <X size={14} />
            </button>
          )}
          <button
            onClick={handleCopyEvidence}
            className="p-1.5 text-on-surface-variant hover:bg-surface-container-high transition-colors"
            title="Copy evidence"
          >
            {copied ? <Check size={14} className="text-success" /> : <Copy size={14} />}
          </button>
          <button
            onClick={() => setExpanded(!expanded)}
            className="p-1.5 text-on-surface-variant hover:bg-surface-container-high transition-colors"
          >
            {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </button>
        </div>
      </div>

      {/* Target */}
      {finding.target && (
        <div className="flex items-center gap-2 font-code-sm text-[11px] text-on-surface-variant">
          <ExternalLink size={12} />
          <span className="truncate">{finding.target}</span>
        </div>
      )}

      {/* Description */}
      {finding.description && (
        <p className="font-body-sm text-body-sm text-on-surface-variant leading-relaxed">
          {finding.description}
        </p>
      )}

      {/* Expanded evidence */}
      {expanded && (
        <div className="space-y-2 border-t border-outline-variant pt-3">
          {/* Status */}
          <div className="flex items-center gap-2">
            <span className="font-code-sm text-[10px] text-on-surface-variant">STATUS:</span>
            <span className="font-code-sm text-[10px] uppercase">{finding.status}</span>
          </div>

          {/* Evidence blocks */}
          {finding.evidence && finding.evidence.length > 0 && (
            <div>
              <div className="font-code-sm text-[10px] text-on-surface-variant mb-1">EVIDENCE:</div>
              <div className="bg-black/40 border border-outline-variant p-3 max-h-60 overflow-y-auto custom-scrollbar">
                {finding.evidence.map((ev, i) => (
                  <pre key={i} className="font-code-sm text-[10px] text-on-surface whitespace-pre-wrap break-all">
                    {typeof ev === 'string' ? ev : JSON.stringify(ev, null, 2)}
                  </pre>
                ))}
              </div>
            </div>
          )}

          {/* Replay button */}
          <button
            onClick={handleReplay}
            disabled={replaying}
            className="flex items-center gap-2 px-3 py-1.5 border border-outline-variant font-label-caps text-[10px] hover:bg-surface-container-high transition-colors disabled:opacity-50"
          >
            <Eye size={12} />
            {replaying ? 'REPLAYING...' : 'REPLAY VERIFICATION'}
          </button>
        </div>
      )}
    </div>
  );
};

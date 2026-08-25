import React from 'react';
import { useSwarmStore } from '../../store/useSwarmStore';
import { useIntelligenceStore } from '../../store/useIntelligenceStore';
import {
  AlertTriangle, CheckCircle, Clock, Target,
} from 'lucide-react';

export const MissionBriefing: React.FC = () => {
  const { agents, currentPhase } = useSwarmStore();
  const { findings, verifications, sessionId } = useIntelligenceStore();

  const verified = (findings || []).filter(f => f.status === 'verified');
  const pending = (verifications || []).length;
  const critical = (findings || []).filter(f => f.severity === 'critical');
  const total = (findings || []).length;

  const activeAgents = (agents || []).filter(a => a.status === 'running').length;
  const conversionRate = total > 0 ? ((verified.length / total) * 100).toFixed(0) : '0';

  const buildNarrative = () => {
    if (!sessionId) {
      return {
        icon: <Clock size={18} style={{ color: 'var(--text-tertiary)' }} />,
        title: 'Standing By',
        description: 'No active engagement. Start a mission to begin automated penetration testing.',
        accent: 'var(--text-tertiary)',
      };
    }
    if (critical.length > 0 && pending > 0) {
      return {
        icon: <AlertTriangle size={18} style={{ color: 'var(--danger)' }} />,
        title: 'Critical Findings Need Attention',
        description: `${critical.length} critical finding${critical.length > 1 ? 's' : ''} confirmed. ${pending} approval${pending > 1 ? 's' : ''} awaiting your decision.`,
        accent: 'var(--danger)',
      };
    }
    if (verified.length > 0) {
      return {
        icon: <CheckCircle size={18} style={{ color: 'var(--accent)' }} />,
        title: 'Mission Progressing',
        description: `${verified.length} verified finding${verified.length > 1 ? 's' : ''} (${conversionRate}% conversion). ${activeAgents} agent${activeAgents !== 1 ? 's' : ''} actively scanning.`,
        accent: 'var(--accent)',
      };
    }
    return {
      icon: <Target size={18} style={{ color: 'var(--interactive)' }} />,
      title: 'Scanning Attack Surface',
      description: `${total} candidate${total !== 1 ? 's' : ''} discovered. ${activeAgents} agent${activeAgents !== 1 ? 's' : ''} working. Phase: ${currentPhase.replace(/_/g, ' ').toUpperCase()}.`,
      accent: 'var(--interactive)',
    };
  };

  const narrative = buildNarrative();

  return (
    <div
      className="card reveal-up"
      style={{
        padding: '20px 24px',
        borderTop: `2px solid ${narrative.accent}`,
      }}
    >
      <div className="flex items-center gap-5">
        {/* Icon */}
        <div
          className="flex items-center justify-center shrink-0"
          style={{
            width: 40,
            height: 40,
            borderRadius: 'var(--radius-lg)',
            background: 'var(--surface-2)',
            border: '1px solid var(--border)',
          }}
        >
          {narrative.icon}
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 10,
              fontWeight: 700,
              letterSpacing: '0.1em',
              textTransform: 'uppercase',
              color: 'var(--text-disabled)',
              marginBottom: 4,
            }}
          >
            MISSION BRIEFING
          </div>
          <div
            style={{
              fontFamily: "'Space Grotesk', sans-serif",
              fontSize: 18,
              fontWeight: 700,
              color: 'var(--text-primary)',
              marginBottom: 4,
            }}
          >
            {narrative.title}
          </div>
          <div
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 12,
              color: 'var(--text-secondary)',
              lineHeight: 1.5,
            }}
          >
            {narrative.description}
          </div>
        </div>

        {/* Quick stats */}
        <div className="flex items-center gap-6 shrink-0">
          <div className="text-center">
            <div
              style={{
                fontFamily: "'Space Grotesk', sans-serif",
                fontSize: 28,
                fontWeight: 800,
                lineHeight: 1,
                color: 'var(--accent)',
                fontVariantNumeric: 'tabular-nums',
              }}
            >
              {verified.length}
            </div>
            <div
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 9,
                fontWeight: 700,
                letterSpacing: '0.1em',
                textTransform: 'uppercase',
                color: 'var(--text-disabled)',
                marginTop: 4,
              }}
            >
              VERIFIED
            </div>
          </div>
          <div className="text-center">
            <div
              style={{
                fontFamily: "'Space Grotesk', sans-serif",
                fontSize: 28,
                fontWeight: 800,
                lineHeight: 1,
                color: 'var(--danger)',
                fontVariantNumeric: 'tabular-nums',
              }}
            >
              {critical.length}
            </div>
            <div
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 9,
                fontWeight: 700,
                letterSpacing: '0.1em',
                textTransform: 'uppercase',
                color: 'var(--text-disabled)',
                marginTop: 4,
              }}
            >
              CRITICAL
            </div>
          </div>
          <div className="text-center">
            <div
              style={{
                fontFamily: "'Space Grotesk', sans-serif",
                fontSize: 28,
                fontWeight: 800,
                lineHeight: 1,
                color: 'var(--warning)',
                fontVariantNumeric: 'tabular-nums',
              }}
            >
              {pending}
            </div>
            <div
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 9,
                fontWeight: 700,
                letterSpacing: '0.1em',
                textTransform: 'uppercase',
                color: 'var(--text-disabled)',
                marginTop: 4,
              }}
            >
              PENDING
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

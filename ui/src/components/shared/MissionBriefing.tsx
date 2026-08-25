import React from 'react';
import { useSwarmStore } from '../../store/useSwarmStore';
import { useIntelligenceStore } from '../../store/useIntelligenceStore';
import {
  AlertTriangle, CheckCircle, Clock, Shield, Target,
  TrendingUp, AlertCircle, Crosshair
} from 'lucide-react';

export const MissionBriefing: React.FC = () => {
  const { agents, budget, currentPhase, currentObjective } = useSwarmStore();
  const { findings, verifications, sessionId } = useIntelligenceStore();

  const verified = (findings || []).filter(f => f.status === 'verified');
  const pending = (verifications || []).length;
  const critical = (findings || []).filter(f => f.severity === 'critical');
  const rejected = (findings || []).filter(f => f.status === 'rejected');
  const total = (findings || []).length;

  const spent = (budget?.spent || 0) + (agents || []).reduce((acc, a) => acc + (a.cost_incurred || 0), 0);
  const activeAgents = (agents || []).filter(a => a.status === 'running').length;
  const conversionRate = total > 0 ? ((verified.length / total) * 100).toFixed(0) : '0';

  // Build narrative
  const buildNarrative = () => {
    if (!sessionId) {
      return {
        status: 'standby',
        icon: <Clock size={20} className="text-on-surface-variant" />,
        title: 'Standing By',
        lines: ['No active engagement. Start a mission to begin.'],
      };
    }

    if (critical.length > 0 && pending > 0) {
      return {
        status: 'critical',
        icon: <AlertTriangle size={20} className="text-error" />,
        title: 'Critical Findings Need Attention',
        lines: [
          `${critical.length} critical finding${critical.length > 1 ? 's' : ''} confirmed`,
          `${pending} approval${pending > 1 ? 's' : ''} awaiting your decision`,
          `Phase: ${currentPhase.replace(/_/g, ' ').toUpperCase()}`,
        ],
      };
    }

    if (verified.length > 0) {
      return {
        status: 'progress',
        icon: <CheckCircle size={20} className="text-primary-fixed" />,
        title: 'Mission Progressing',
        lines: [
          `${verified.length} verified finding${verified.length > 1 ? 's' : ''} (${conversionRate}% conversion)`,
          `${activeAgents} agent${activeAgents !== 1 ? 's' : ''} actively scanning`,
          `$${spent.toFixed(2)} operational spend`,
        ],
      };
    }

    return {
      status: 'scanning',
      icon: <Target size={20} className="text-secondary" />,
      title: 'Scanning Attack Surface',
      lines: [
        `${total} candidate${total !== 1 ? 's' : ''} discovered`,
        `${activeAgents} agent${activeAgents !== 1 ? 's' : ''} working`,
        `Phase: ${currentPhase.replace(/_/g, ' ').toUpperCase()}`,
      ],
    };
  };

  const narrative = buildNarrative();

  return (
    <div className="bg-surface-container-low border border-outline-variant p-5 relative overflow-hidden">
      {/* Ambient sweep */}
      <div className="absolute top-0 left-0 h-px w-1/3 bg-gradient-to-r from-transparent via-primary-fixed to-transparent sweep-line pointer-events-none" />

      <div className="flex items-start gap-4">
        <div className="p-2.5 bg-surface-container border border-outline-variant">
          {narrative.icon}
        </div>
        <div className="flex-1">
          <h3 className="font-label-caps text-label-caps text-on-surface mb-1">
            MISSION BRIEFING
          </h3>
          <div className="font-display-lg text-display-lg text-on-surface mb-2">
            {narrative.title}
          </div>
          <div className="space-y-1">
            {narrative.lines.map((line, i) => (
              <div key={i} className="flex items-center gap-2 font-code-sm text-[11px] text-on-surface-variant">
                <span className="w-1 h-1 rounded-full bg-primary-fixed opacity-60" />
                {line}
              </div>
            ))}
          </div>
        </div>

        {/* Quick stats */}
        <div className="flex gap-4 shrink-0">
          <div className="text-center">
            <div className="font-display-lg text-display-lg text-primary-fixed leading-none">
              {verified.length}
            </div>
            <div className="font-code-sm text-[9px] text-on-surface-variant mt-1">VERIFIED</div>
          </div>
          <div className="text-center">
            <div className="font-display-lg text-display-lg text-error leading-none">
              {critical.length}
            </div>
            <div className="font-code-sm text-[9px] text-on-surface-variant mt-1">CRITICAL</div>
          </div>
          <div className="text-center">
            <div className="font-display-lg text-display-lg text-secondary leading-none">
              {pending}
            </div>
            <div className="font-code-sm text-[9px] text-on-surface-variant mt-1">PENDING</div>
          </div>
        </div>
      </div>
    </div>
  );
};

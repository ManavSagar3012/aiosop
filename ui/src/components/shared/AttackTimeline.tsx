import React from 'react';
import { useIntelligenceStore } from '../../store/useIntelligenceStore';
import { useSwarmStore } from '../../store/useSwarmStore';
import {
  Shield, AlertTriangle, CheckCircle, Clock, Target,
  Zap, ArrowRight, Crosshair
} from 'lucide-react';

interface TimelineEvent {
  id: string;
  timestamp: string;
  type: 'phase' | 'finding' | 'agent' | 'approval';
  title: string;
  description?: string;
  severity?: string;
  status?: string;
}

export const AttackTimeline: React.FC = () => {
  const { currentPhase } = useSwarmStore();
  const { findings, auditLog } = useIntelligenceStore();

  // Build timeline events from audit log and findings
  const buildTimeline = (): TimelineEvent[] => {
    const events: TimelineEvent[] = [];

    // Add phase events from audit log
    (auditLog || []).forEach((entry: any) => {
      if (entry.event_type === 'phase_transition' || entry.event_type === 'auto_transition') {
        events.push({
          id: entry.id,
          timestamp: entry.timestamp,
          type: 'phase',
          title: `Phase: ${entry.action?.phase || entry.action?.new_phase || 'unknown'}`,
          description: typeof entry.action === 'string' ? entry.action : JSON.stringify(entry.action),
        });
      }
      if (entry.event_type === 'finding_update' || entry.event_type === 'vulnerability_confirmed') {
        events.push({
          id: entry.id,
          timestamp: entry.timestamp,
          type: 'finding',
          title: typeof entry.action === 'string' ? entry.action : (entry.action?.title || 'Finding detected'),
          severity: entry.severity,
          status: entry.action?.status,
        });
      }
      if (entry.event_type === 'task_completed' || entry.event_type === 'task_failed') {
        events.push({
          id: entry.id,
          timestamp: entry.timestamp,
          type: 'agent',
          title: typeof entry.action === 'string' ? entry.action : `Task ${entry.action?.task_type || 'completed'}`,
          status: entry.event_type === 'task_completed' ? 'success' : 'failed',
        });
      }
      if (entry.event_type === 'approval' || entry.event_type === 'approval_resolved') {
        events.push({
          id: entry.id,
          timestamp: entry.timestamp,
          type: 'approval',
          title: typeof entry.action === 'string' ? entry.action : `Approval: ${entry.action?.decision || 'pending'}`,
          status: entry.action?.decision,
        });
      }
    });

    // Add findings as events
    (findings || []).forEach((f: any) => {
      events.push({
        id: f.id,
        timestamp: f.created_at || f.timestamp || new Date().toISOString(),
        type: 'finding',
        title: f.title,
        severity: f.severity,
        status: f.status,
        description: f.category,
      });
    });

    // Sort by timestamp
    events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

    // Deduplicate by id
    const seen = new Set<string>();
    return events.filter(e => {
      if (seen.has(e.id)) return false;
      seen.add(e.id);
      return true;
    });
  };

  const timeline = buildTimeline();

  const getEventIcon = (event: TimelineEvent) => {
    switch (event.type) {
      case 'phase':
        return <ArrowRight size={14} className="text-primary-fixed" />;
      case 'finding':
        if (event.severity === 'critical') return <AlertTriangle size={14} className="text-error" />;
        if (event.severity === 'high') return <Shield size={14} className="text-warning" />;
        return <Crosshair size={14} className="text-secondary" />;
      case 'agent':
        return event.status === 'success'
          ? <CheckCircle size={14} className="text-success" />
          : <Zap size={14} className="text-error" />;
      case 'approval':
        return <Target size={14} className="text-primary" />;
      default:
        return <Clock size={14} className="text-on-surface-variant" />;
    }
  };

  return (
    <div className="bg-surface-container-low border border-outline-variant p-5">
      <div className="font-label-caps text-label-caps text-on-surface-variant mb-4">
        ATTACK TIMELINE
      </div>

      {timeline.length === 0 ? (
        <div className="text-center py-8 text-on-surface-variant/50">
          <Clock size={24} className="mx-auto mb-2 opacity-30" />
          <p className="font-code-sm text-[11px]">No events yet — waiting for activity</p>
        </div>
      ) : (
        <div className="relative">
          {/* Vertical line */}
          <div className="absolute left-[11px] top-0 bottom-0 w-px bg-outline-variant" />

          <div className="space-y-3">
            {timeline.slice(-20).reverse().map((event) => (
              <div key={event.id} className="flex items-start gap-3 relative">
                {/* Icon */}
                <div className="relative z-10 w-6 h-6 flex items-center justify-center bg-background border border-outline-variant shrink-0">
                  {getEventIcon(event)}
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-code-sm text-[10px] text-on-surface-variant">
                      {new Date(event.timestamp).toLocaleTimeString()}
                    </span>
                    {event.type === 'phase' && (
                      <span className="font-label-caps text-[8px] text-primary-fixed border border-primary-fixed/30 px-1">
                        PHASE
                      </span>
                    )}
                    {event.severity && (
                      <span className={`font-label-caps text-[8px] ${
                        event.severity === 'critical' ? 'text-error' :
                        event.severity === 'high' ? 'text-warning' : 'text-secondary'
                      }`}>
                        {event.severity.toUpperCase()}
                      </span>
                    )}
                  </div>
                  <div className="font-label-sm text-label-sm text-on-surface truncate">
                    {event.title}
                  </div>
                  {event.description && (
                    <div className="font-code-sm text-[10px] text-on-surface-variant/60 truncate">
                      {event.description}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

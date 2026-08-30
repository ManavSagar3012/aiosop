import React from 'react';
import { useIntelligenceStore } from '../../store/useIntelligenceStore';
import { Card } from './Card';
import { Clock } from 'lucide-react';

interface TimelineEvent {
  id: string;
  timestamp: string;
  type: 'phase' | 'finding' | 'agent' | 'approval';
  title: string;
  description?: string;
  severity?: string;
  status?: string;
}

const EVENT_COLORS: Record<string, string> = {
  phase: 'var(--accent)',
  finding: 'var(--interactive)',
  agent: 'var(--info)',
  approval: 'var(--warning)',
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'var(--danger)',
  high: 'var(--warning)',
  medium: 'var(--interactive)',
  low: 'var(--text-tertiary)',
};

export const AttackTimeline: React.FC = () => {
  const { findings, auditLog } = useIntelligenceStore();

  const buildTimeline = (): TimelineEvent[] => {
    const events: TimelineEvent[] = [];

    (auditLog || []).forEach((entry: any) => {
      if (entry.event_type === 'phase_transition' || entry.event_type === 'auto_transition') {
        events.push({
          id: entry.id,
          timestamp: entry.timestamp,
          type: 'phase',
          // FIX (timeline-phase-shape-2026-08-30): audit phase_transition events
          // carry {to_phase, from_phase} while WS events carry {new_phase}/{phase};
          // read all three so the timeline stops rendering "Phase: unknown".
          title: `Phase: ${entry.action?.phase || entry.action?.new_phase || entry.action?.to_phase || 'unknown'}`,
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

    events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

    const seen = new Set<string>();
    return events.filter(e => {
      if (seen.has(e.id)) return false;
      seen.add(e.id);
      return true;
    });
  };

  const timeline = buildTimeline();

  return (
    <Card title="Attack Timeline" subtitle={`${timeline.length} events tracked`}>
      {timeline.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-12 text-center">
          <div
            className="flex items-center justify-center mb-3"
            style={{
              width: 40,
              height: 40,
              borderRadius: 'var(--radius-lg)',
              background: 'var(--surface-2)',
              border: '1px solid var(--border)',
              color: 'var(--text-tertiary)',
            }}
          >
            <Clock size={18} />
          </div>
          <div
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 12,
              color: 'var(--text-tertiary)',
            }}
          >
            No events yet — waiting for activity
          </div>
        </div>
      ) : (
        <div style={{ maxHeight: 360, overflowY: 'auto' }} className="custom-scrollbar">
          <div className="flex flex-col" style={{ gap: 2 }}>
            {timeline.slice(-15).reverse().map((event) => (
              <div
                key={event.id}
                className="flex items-start gap-3"
                style={{
                  padding: '8px 12px',
                  borderRadius: 'var(--radius-md)',
                  transition: 'background var(--duration-fast)',
                }}
                onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--surface-hover)')}
                onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
              >
                {/* Dot */}
                <div className="flex items-center justify-center shrink-0" style={{ marginTop: 4 }}>
                  <div
                    style={{
                      width: 8,
                      height: 8,
                      borderRadius: '50%',
                      background: SEVERITY_COLORS[event.severity || ''] || EVENT_COLORS[event.type],
                      boxShadow: event.severity === 'critical' ? 'var(--shadow-glow-red)' : 'none',
                    }}
                  />
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span
                      style={{
                        fontFamily: "'JetBrains Mono', monospace",
                        fontSize: 10,
                        color: 'var(--text-disabled)',
                      }}
                    >
                      {new Date(event.timestamp).toLocaleTimeString()}
                    </span>
                    <span
                      style={{
                        fontFamily: "'JetBrains Mono', monospace",
                        fontSize: 9,
                        fontWeight: 600,
                        letterSpacing: '0.08em',
                        textTransform: 'uppercase',
                        color: EVENT_COLORS[event.type],
                        padding: '1px 6px',
                        background: 'var(--surface-2)',
                        border: '1px solid var(--border)',
                        borderRadius: 'var(--radius-full)',
                      }}
                    >
                      {event.type}
                    </span>
                    {event.severity && (
                      <span
                        style={{
                          fontFamily: "'JetBrains Mono', monospace",
                          fontSize: 9,
                          fontWeight: 600,
                          color: SEVERITY_COLORS[event.severity] || 'var(--text-tertiary)',
                        }}
                      >
                        {event.severity.toUpperCase()}
                      </span>
                    )}
                  </div>
                  <div
                    className="truncate"
                    style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: 12,
                      color: 'var(--text-primary)',
                      marginTop: 2,
                    }}
                  >
                    {event.title}
                  </div>
                  {event.description && (
                    <div
                      className="truncate"
                      style={{
                        fontFamily: "'JetBrains Mono', monospace",
                        fontSize: 10,
                        color: 'var(--text-tertiary)',
                        marginTop: 1,
                      }}
                    >
                      {event.description}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </Card>
  );
};

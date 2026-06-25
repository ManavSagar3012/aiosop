import re
filepath = "src/ai_osop/reliability/agent_reaper.py"
with open(filepath, "r") as f:
    content = f.read()

# Add context={} to AuditEvent
content = content.replace("write_audit_event(AuditEvent(event_type='task_recovered', severity='INFO', actor_type='system', actor_id='reaper', action={'task_id': task.id}, result={'status': 'requeued'}, engagement_id=task.engagement_id))",
                          "write_audit_event(AuditEvent(event_type='task_recovered', severity='INFO', actor_type='system', actor_id='reaper', action={'task_id': task.id}, result={'status': 'requeued'}, context={}, engagement_id=task.engagement_id))")

with open(filepath, "w") as f:
    f.write(content)

import os
import re
from sqlalchemy import create_engine, text
import json

# Setup
DB_URI = "postgresql://osop:osop@localhost:5432/osop" # Standard config assumed

def run_audit():
    # 1. Latest Engagement
    engine = create_engine(DB_URI)
    with engine.connect() as conn:
        res = conn.execute(text("SELECT engagement_id FROM audit_logs ORDER BY timestamp DESC LIMIT 1"))
        eng_id = res.scalar()
        print(f"--- LATEST ENGAGEMENT: {eng_id} ---")
        
        # 2. Tasks for this engagement
        tasks = conn.execute(text("SELECT event_type, action, result FROM audit_logs WHERE engagement_id=:eid"), {"eid": eng_id})
        task_data = tasks.fetchall()
        print(f"Total tasks in DB: {len(task_data)}")
        
    # 3. Evidence Files
    print("\n--- EVIDENCE VAULT SCAN ---")
    vault_files = []
    for root, _, files in os.walk('evidence_vault'):
        for f in files:
            path = os.path.join(root, f)
            stats = os.stat(path)
            vault_files.append({
                "path": path,
                "size": stats.st_size,
                "created": stats.st_ctime
            })
    print(json.dumps(vault_files, indent=2))
    
    # 4. Log Analysis
    print("\n--- LOG ANALYSIS ---")
    patterns = ['Page.goto', 'page.screenshot', 'browser.newContext', 'context.tracing.start', 'context.close']
    try:
        with open('api.log', 'r') as f:
            content = f.read()
            for p in patterns:
                count = len(re.findall(p, content))
                print(f"Pattern '{p}' count: {count}")
    except FileNotFoundError:
        print("api.log not found")

if __name__ == "__main__":
    run_audit()

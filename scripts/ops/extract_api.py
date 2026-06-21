import httpx
import time
import sys

API_BASE = 'http://localhost:8200'
HEADERS = {'Authorization': 'Bearer dev-token'}

r = httpx.post(f'{API_BASE}/tasks', json={
    'task_type': 'extract_har_api_inventory',
    'priority': 5,
    'agent_type': 'workflow',
    'payload': {'workflow_id': 'wf-038b2bed07ec'},
    'engagement_id': 'eng-20260616111630-ai-osop-full-mission-2'
}, headers=HEADERS)

print(r.status_code, r.text)
task_id = r.json()['id']

while True:
    r = httpx.get(f'{API_BASE}/tasks/{task_id}', headers=HEADERS)
    st = r.json()['status']
    print(f'{task_id}: {st}')
    if st in ('completed', 'failed', 'cancelled'):
        break
    time.sleep(3)

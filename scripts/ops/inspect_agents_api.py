import http.client
import json

from jose import jwt
from ai_osop.core.config import settings

secret = settings.jwt_secret or "dev-jwt-secret"
token = jwt.encode(
    {"role": "senior_operator", "username": "inspect-tool", "sub": "inspect-tool"},
    secret,
    algorithm="HS256",
)
conn = http.client.HTTPConnection("127.0.0.1", 8200)
try:
    conn.request("GET", "/agents", headers={"Authorization": f"Bearer {token}"})
    resp = conn.getresponse()
    print(f"Status: {resp.status}")
    data = json.loads(resp.read().decode())
    print(f"Total agents registered in Orchestrator: {len(data)}")
    for agent in sorted(data, key=lambda x: x.get("agent_id", "")):
        print(f"Agent: {agent.get('agent_id')}")
        print(f"  Type: {agent.get('agent_type')}")
        print(f"  Status: {agent.get('status')}")
        print(f"  Current Task: {agent.get('current_task')}")
        print("-" * 50)
except Exception as e:
    print(f"Error: {e}")
finally:
    conn.close()

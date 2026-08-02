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
    tid = "task-f788995fde18"
    conn.request("GET", f"/tasks/{tid}", headers={"Authorization": f"Bearer {token}"})
    resp = conn.getresponse()
    print(f"Status: {resp.status}")
    if resp.status == 200:
        data = json.loads(resp.read().decode())
        print(f"In-Memory Task {tid}:")
        print(f"  Type: {data.get('type')}")
        print(f"  Status: {data.get('status')}")
        print(f"  Assigned Agent: {data.get('assigned_agent_id')}")
        print(f"  Created At: {data.get('created_at')}")
        print(f"  Started At: {data.get('started_at')}")
        print(f"  Completed At: {data.get('completed_at')}")
        print(f"  Payload: {data.get('payload')}")
        print(f"  Result: {data.get('result')}")
    else:
        print(f"Failed to fetch task: {resp.read().decode()}")
except Exception as e:
    print(f"Error: {e}")
finally:
    conn.close()

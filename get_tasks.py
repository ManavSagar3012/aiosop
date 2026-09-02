import os
from datetime import datetime, timedelta
from jose import jwt
from dotenv import load_dotenv
import urllib.request
import json

load_dotenv()
secret = os.getenv("OSOP_JWT_SECRET")

to_encode = {
    "sub": "senior_admin",
    "role": "senior_operator",
    "exp": datetime.utcnow() + timedelta(days=1)
}
encoded_jwt = jwt.encode(to_encode, secret, algorithm="HS256")
headers = {"Authorization": f"Bearer {encoded_jwt}", "Content-Type": "application/json"}

# Halt the old engagement
try:
    req = urllib.request.Request(
        "http://localhost:8201/engagements/eng-20260826162304-eng-qwen-v10/halt",
        headers=headers,
        method="POST",
        data=json.dumps({"reason": "Free up agents"}).encode()
    )
    with urllib.request.urlopen(req) as response:
        print("Halted old engagement:", json.loads(response.read().decode()))
except Exception as e:
    print("Halt error:", e)

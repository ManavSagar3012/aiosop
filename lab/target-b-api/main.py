from fastapi import FastAPI, HTTPException, Header
from typing import Optional

app = FastAPI()

# Mock database
users = {
    1: {"name": "Admin Alice", "role": "admin", "secret": "super_secret_key_123"},
    2: {"name": "User Bob", "role": "user", "secret": "bob_secret"}
}

tokens = {
    "token_alice": 1,
    "token_bob": 2
}

@app.get("/")
def read_root():
    return {"status": "api_online", "version": "1.0"}

@app.get("/api/v1/profile")
def get_profile(user_id: int, authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    token = authorization.replace("Bearer ", "")
    if token not in tokens:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # IDOR vulnerability: We check authentication, but NOT authorization for the specific user_id
    # A real app would check if tokens[token] == user_id (unless admin)
    
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
        
    return users[user_id]

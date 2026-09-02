import sqlite3
from typing import Optional
from fastapi import FastAPI, Header, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI(title="OSOP Ground Truth Benchmark Target")

# --- Setup in-memory DB for SQLi ---
conn = sqlite3.connect(":memory:", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, secret TEXT)")
cursor.execute("INSERT INTO users (username, secret) VALUES ('admin', 'flag{sqli_success}')")
cursor.execute("INSERT INTO users (username, secret) VALUES ('guest', 'guest_secret')")
conn.commit()

# --- True Positive: SQL Injection ---
@app.get("/api/v1/users")
def get_user(username: str):
    # Intentional SQLi vulnerability
    query = f"SELECT id, username, secret FROM users WHERE username = '{username}'"
    try:
        cursor.execute(query)
        res = cursor.fetchall()
        return {"data": res}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# --- True Positive: Reflected XSS ---
@app.get("/profile", response_class=HTMLResponse)
def get_profile(name: str = Query(default="Guest")):
    # Intentional XSS
    return f"<html><body><h1>Welcome, {name}</h1></body></html>"

# --- False Positive Trap: Looks like SQLi but is parameterized ---
@app.get("/api/v1/search")
def search_items(q: str):
    # Uses parameterized query - safe!
    # But might trigger generic scanners if they see syntax
    query = "SELECT id, username, secret FROM users WHERE username LIKE ?"
    cursor.execute(query, (f"%{q}%",))
    res = cursor.fetchall()
    return {"results": res, "query_debug": "SELECT * FROM items WHERE name LIKE '%" + q.replace("'", "''") + "%'"}

# --- Attack Chain: Broken Auth -> IDOR -> Data Exfiltration ---
# Step 1: Obtain a 'token' via broken auth (predictable or missing password check)
class LoginReq(BaseModel):
    username: str

@app.post("/api/v1/auth/login")
def login(req: LoginReq):
    # Intentional broken auth: no password required, token is just username
    return {"token": f"token_for_{req.username}"}

# Step 2: IDOR using the token
db_docs = {
    1: {"owner": "guest", "content": "public doc"},
    2: {"owner": "admin", "content": "flag{idor_success_admin_doc}"}
}

@app.get("/api/v1/docs/{doc_id}")
def get_doc(doc_id: int, authorization: Optional[str] = Header(None)):
    if not authorization:
        return JSONResponse(status_code=401, content={"error": "Missing token"})
    
    doc = db_docs.get(doc_id)
    if not doc:
        return JSONResponse(status_code=404, content={"error": "Not found"})
    
    # Intentional IDOR: we check if user has A token, but not the RIGHT token for the doc
    user = authorization.replace("Bearer token_for_", "")
    if user:  # Any valid-looking user token can read any doc
        return {"doc": doc}
    
    return JSONResponse(status_code=403, content={"error": "Invalid token"})


from fastapi import FastAPI
import uvicorn
app = FastAPI()
@app.get("/health")
async def health():
    return {"server_id": "burp-mcp", "status": "ready"}
@app.get("/mcp/initialize")
async def initialize():
    return {"server_id": "burp-mcp", "status": "ready", "capabilities": ["proxy"], "tools": []}
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8081)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port)

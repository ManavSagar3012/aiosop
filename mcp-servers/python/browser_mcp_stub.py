from fastapi import FastAPI
import uvicorn
app = FastAPI()
@app.get("/health")
async def health(): return {"status": "ready"}
@app.post("/mcp/initialize")
async def initialize(request: dict):
    return {
        "server_id": "browser-mcp",
        "status": "ready",
        "capabilities": ["browser"],
        "tools": []
    }
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8091)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port)

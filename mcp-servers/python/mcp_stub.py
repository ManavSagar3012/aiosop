from fastapi import FastAPI
import uvicorn, argparse
app = FastAPI()
@app.get("/health")
async def health(): return {"status": "ready"}
@app.post("/mcp/initialize")
async def initialize(request: dict): return {"server_id": "stub", "status": "ready", "capabilities": ["tool"], "tools": []}
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port)

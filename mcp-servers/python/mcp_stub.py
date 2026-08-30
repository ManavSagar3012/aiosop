from fastapi import FastAPI
import uvicorn, argparse

app = FastAPI()

server_id = "stub"

@app.get("/health")
async def health():
    return {"status": "ready"}

@app.post("/mcp/initialize")
async def initialize(request: dict):
    return {"server_id": server_id, "status": "ready", "capabilities": ["tool"], "tools": []}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int)
    parser.add_argument("--server-id", type=str)
    args = parser.parse_args()
    server_id = args.server_id
    uvicorn.run(app, host="127.0.0.1", port=args.port)

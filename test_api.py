from fastapi import FastAPI
app = FastAPI()
@app.get("/ready")
async def ready():
    return {"status": "ready"}

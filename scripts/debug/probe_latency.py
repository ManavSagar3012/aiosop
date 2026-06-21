import asyncio
import time
import requests

async def check_loop():
    while True:
        start = time.perf_counter()
        await asyncio.sleep(0)
        end = time.perf_counter()
        lag = (end - start) * 1000
        if lag > 10:
            print(f"CRITICAL LOOP LAG: {lag:.2f}ms")
        await asyncio.sleep(1)

if __name__ == "__main__":
    # This won't work unless I inject it into the running app.
    # Instead, I'll probe the API /health 5 times and check variance.
    headers = {'Authorization': 'Bearer dev-token'}
    for i in range(5):
        start = time.time()
        try:
            requests.get('http://localhost:8200/health', timeout=5)
            print(f"Probe {i}: {(time.time() - start)*1000:.2f}ms")
        except:
            print(f"Probe {i}: FAILED")

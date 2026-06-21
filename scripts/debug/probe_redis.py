import redis
import time

def probe_redis():
    start = time.time()
    try:
        r = redis.from_url("redis://localhost:6379/0")
        ping = r.ping()
        print(f"Redis Ping: {ping} (Latency: {(time.time() - start)*1000:.2f}ms)")
        r.close()
    except Exception as e:
        print(f"Redis Probing FAILED: {e}")

if __name__ == "__main__":
    probe_redis()

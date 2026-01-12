import os, json
from flask import Flask, request
from redis import Redis
from redis.exceptions import ConnectionError, TimeoutError

PORT = int(os.environ.get("PORT", "1814"))
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
stream = os.environ.get("STREAM", "syslog:raw")

app = Flask(__name__)

# Initialize Redis connection
try:
    r = Redis.from_url(REDIS_URL, decode_responses=False, socket_connect_timeout=5, socket_timeout=5)
    r.ping()  # Test connection
    print(f"[redis-writer] Connected to Redis at {REDIS_URL}")
except Exception as e:
    print(f"[redis-writer] ERROR: Failed to connect to Redis: {e}")
    raise

@app.post("/ingest")
def ingest():
    try:
        data = request.get_json(silent=True) or {
            "raw": request.data.decode("utf-8", errors="replace")
        }
        r.xadd(stream, {"event": json.dumps(data, ensure_ascii=False)})
        return "OK", 200
    except (ConnectionError, TimeoutError) as e:
        print(f"[redis-writer] Redis connection error: {e}")
        return "Redis connection error", 503
    except Exception as e:
        print(f"[redis-writer] Error ingesting data: {e}")
        return "Internal error", 500

@app.get("/health")
def health():
    try:
        r.ping()
        return "OK", 200
    except Exception as e:
        return f"Redis error: {str(e)}", 503

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False)

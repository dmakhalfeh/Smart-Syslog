import os, json
from flask import Flask, request
from redis import Redis

PORT = int(os.environ.get("PORT", "1814"))
r = Redis.from_url(os.environ["REDIS_URL"])
stream = os.environ.get("STREAM", "syslog:raw")

app = Flask(__name__)

@app.post("/ingest")
def ingest():
    data = request.get_json(silent=True) or {
        "raw": request.data.decode("utf-8", errors="replace")
    }
    r.xadd(stream, {"event": json.dumps(data, ensure_ascii=False)})
    return "OK"

@app.get("/health")
def health():
    r.ping()
    return "OK"

app.run(host="0.0.0.0", port=PORT)

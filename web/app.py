from flask import Flask, jsonify
import redis
import os

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = 6379

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
app = Flask(__name__)

@app.route("/")
def index():
    return """
    <h1>Blocked IPs</h1>
    <div id="data"></div>
    <script>
      fetch('/api/blocked')
        .then(r => r.json())
        .then(d => {
          let html = '<table border=1><tr><th>IP</th><th>Score</th><th>Reason</th><th>Last Seen</th></tr>';
          d.forEach(ip => {
            html += `<tr>
              <td>${ip.ip}</td>
              <td>${ip.score}</td>
              <td>${ip.reason}</td>
              <td>${ip.last_seen}</td>
            </tr>`;
          });
          html += '</table>';
          document.getElementById('data').innerHTML = html;
        });
    </script>
    """

@app.route("/api/blocked")
def blocked():
    stream = os.getenv("BLOCKLIST_STREAM", "syslog:blocklist")

    items = r.xrevrange(stream, max="+", min="-", count=200)  # latest 200
    out = []
    for entry_id, fields in items:
        out.append({
            "id": entry_id,
            "ip": fields.get("ip", fields.get("src_ip", "")),
            "score": fields.get("score", ""),
            "reason": fields.get("reason", fields.get("rule", "")),
            "ts": fields.get("ts", fields.get("time", fields.get("@timestamp", ""))),
        })
    return jsonify(out)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

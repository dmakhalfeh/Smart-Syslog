from flask import Flask, jsonify, render_template_string, request
import redis
import os
import re
import json
from datetime import datetime
from typing import Dict, List, Any, Set

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = 6379
BLOCKLIST_STREAM = os.getenv("BLOCKLIST_STREAM", "syslog:blocklist")
PARSED_STREAM = os.getenv("PARSED_STREAM", "syslog:parsed")
SCORE_ZSET = os.getenv("SCORE_ZSET", "ip:score")
SCORE_HASH = os.getenv("SCORE_HASH", "ip:score:meta")
SCORE_BLOCK_THRESHOLD = int(os.getenv("SCORE_BLOCK_THRESHOLD", "15"))
BLOCK_KEY_PREFIX = os.getenv("BLOCK_KEY_PREFIX", "ip:blocked")

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
app = Flask(__name__)


def format_timestamp(ts: str) -> str:
    """Convert Unix timestamp to human-readable format"""
    try:
        ts_float = float(ts)
        dt = datetime.fromtimestamp(ts_float)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return ts or "N/A"


def format_relative_time(ts: str) -> str:
    """Convert timestamp to relative time (e.g., '2 minutes ago')"""
    try:
        ts_float = float(ts)
        now = datetime.now().timestamp()
        diff = now - ts_float
        
        if diff < 60:
            return f"{int(diff)}s ago"
        elif diff < 3600:
            return f"{int(diff/60)}m ago"
        elif diff < 86400:
            return f"{int(diff/3600)}h ago"
        else:
            return f"{int(diff/86400)}d ago"
    except (ValueError, TypeError):
        return "N/A"


def extract_ports_from_logs(ip: str) -> Set[str]:
    """Extract unique ports from logs for a given IP"""
    ports = set()
    if not ip or ip == "N/A":
        return ports
    
    try:
        ip_clean = ip.strip()
        # Get logs from parsed stream
        items = r.xrevrange(PARSED_STREAM, max="+", min="-", count=500)
        
        # Simple pattern: match dst_port=80, src_port=443, etc.
        # Case insensitive, handles spaces: dst_port=80, dst_port = 80, DST_PORT=443
        port_pattern = re.compile(r'(dst_port|src_port|dport|sport|port)\s*=\s*(\d{1,5})', re.IGNORECASE)
        
        for entry_id, fields in items:
            log_ip = str(fields.get("ip", "")).strip()
            
            # Only process logs for this specific IP
            if log_ip != ip_clean:
                continue
            
            # Check message text for dst_port= pattern
            message = str(fields.get("message", ""))
            if message:
                # Find all matches: returns list of tuples like [('dst_port', '80'), ('src_port', '443')]
                matches = port_pattern.findall(message)
                for field_name, port_str in matches:
                    try:
                        port_num = int(port_str)
                        if 1 <= port_num <= 65535:
                            ports.add(str(port_num))
                    except ValueError:
                        continue
            
            # Also check raw JSON fields
            raw_json = fields.get("raw", "")
            if raw_json:
                try:
                    raw_data = json.loads(raw_json)
                    # Check common port field names in raw JSON
                    for field_name in ["dst_port", "src_port", "dport", "sport", "port", 
                                      "DST_PORT", "SRC_PORT", "DPORT", "SPORT", "PORT",
                                      "destination_port", "source_port"]:
                        port_value = raw_data.get(field_name)
                        if port_value:
                            try:
                                port_num = int(port_value)
                                if 1 <= port_num <= 65535:
                                    ports.add(str(port_num))
                            except (ValueError, TypeError):
                                pass
                except (json.JSONDecodeError, TypeError):
                    pass
        
        return ports
    except Exception as e:
        import sys
        print(f"DEBUG: Error extracting ports for {ip}: {e}", file=sys.stderr, flush=True)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return set()


def get_ports_for_ip(ip: str) -> str:
    """Get ports associated with an IP, formatted as comma-separated string"""
    if not ip or ip == "N/A":
        return "N/A"
    
    try:
        ports = extract_ports_from_logs(ip)
        if ports:
            # Sort ports numerically
            sorted_ports = sorted([int(p) for p in ports if p.isdigit() and p])
            if sorted_ports:
                return ", ".join([str(p) for p in sorted_ports])
    except Exception as e:
        print(f"Error getting ports for {ip}: {e}", flush=True)
    
    return "N/A"


def block_key(ip: str) -> str:
    return f"{BLOCK_KEY_PREFIX}:{ip}"


def is_blocked_ip(ip: str) -> bool:
    try:
        return bool(ip) and r.exists(block_key(ip)) == 1
    except Exception:
        return False


def ttl_seconds_for_ip(ip: str, fallback: str) -> str:
    if not ip:
        return fallback
    try:
        ttl = r.ttl(block_key(ip))
        if ttl is None or ttl < 0:
            return fallback
        return str(ttl)
    except Exception:
        return fallback


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE, SCORE_BLOCK_THRESHOLD=SCORE_BLOCK_THRESHOLD)


@app.route("/api/blocked")
def blocked():
    """Get blocked IPs from the blocklist stream"""
    try:
        items = r.xrevrange(BLOCKLIST_STREAM, max="+", min="-", count=200)
        out = []
        for entry_id, fields in items:
            ts = fields.get("ts", fields.get("time", fields.get("@timestamp", "")))
            ip = fields.get("ip", fields.get("src_ip", ""))
            if not is_blocked_ip(ip):
                continue
            ports = get_ports_for_ip(ip)
            out.append({
                "id": entry_id,
                "ip": ip,
                "score": fields.get("score", "0"),
                "reason": fields.get("reason", fields.get("rule", "score_threshold")),
                "ts": ts,
                "formatted_ts": format_timestamp(ts),
                "relative_ts": format_relative_time(ts),
                "ttl_seconds": ttl_seconds_for_ip(ip, fields.get("ttl_seconds", "3600")),
                "action": fields.get("action", "block"),
                "ports": ports,
            })
        return jsonify(out)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scores")
def scores():
    """Get top IP scores from sorted set"""
    try:
        top_ips = r.zrevrange(SCORE_ZSET, 0, 99, withscores=True)  # Top 100
        out = []
        for ip, score in top_ips:
            # Get metadata
            last_seen = r.hget(SCORE_HASH, f"{ip}:last_seen")
            last_inc = r.hget(SCORE_HASH, f"{ip}:last_inc")
            blocked = is_blocked_ip(ip)
            blocked_at = r.hget(SCORE_HASH, f"{ip}:blocked_at") if blocked else None
            
            ports = get_ports_for_ip(ip)
            out.append({
                "ip": ip,
                "score": float(score),
                "last_seen": format_timestamp(last_seen) if last_seen else "N/A",
                "relative_last_seen": format_relative_time(last_seen) if last_seen else "N/A",
                "last_inc": last_inc or "0",
                "is_blocked": blocked,
                "blocked_at": format_timestamp(blocked_at) if blocked_at else None,
                "status": "blocked" if blocked else ("warning" if float(score) >= SCORE_BLOCK_THRESHOLD * 0.7 else "monitoring"),
                "ports": ports,
            })
        return jsonify(out)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/logs")
def logs():
    """Get logs from parsed stream, optionally filtered by IP"""
    try:
        ip_filter = request.args.get("ip", "").strip()
        count = int(request.args.get("count", "500"))
        
        # Get recent logs from parsed stream
        items = r.xrevrange(PARSED_STREAM, max="+", min="-", count=count)
        out = []
        
        for entry_id, fields in items:
            log_ip = fields.get("ip", "")
            
            # Filter by IP if specified
            if ip_filter and ip_filter.lower() not in log_ip.lower():
                continue
            
            out.append({
                "id": entry_id,
                "timestamp": fields.get("ts", ""),
                "host": fields.get("host", "N/A"),
                "program": fields.get("program", "N/A"),
                "message": fields.get("message", ""),
                "ip": log_ip or "N/A",
                "ip_role": fields.get("ip_role", "none"),
                "ip_method": fields.get("ip_method", "none"),
                "ignored_ip": fields.get("ignored_ip", "0") == "1",
                "formatted_ts": format_timestamp(fields.get("ts", "")),
                "relative_ts": format_relative_time(fields.get("ts", "")),
            })
        
        return jsonify(out)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/debug/ports/<ip>")
def debug_ports(ip: str):
    """Debug endpoint to test port extraction for a specific IP"""
    try:
        ports = extract_ports_from_logs(ip)
        # Also get sample logs for this IP
        items = r.xrevrange(PARSED_STREAM, max="+", min="-", count=10)
        sample_logs = []
        for entry_id, fields in items:
            if str(fields.get("ip", "")).strip() == ip.strip():
                sample_logs.append({
                    "message": fields.get("message", ""),
                    "raw": fields.get("raw", "")[:200] if fields.get("raw") else ""
                })
        
        return jsonify({
            "ip": ip,
            "ports_found": list(ports),
            "ports_formatted": get_ports_for_ip(ip),
            "sample_logs": sample_logs[:3]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/stats")
def stats():
    """Get overall statistics"""
    try:
        blocked_count = sum(1 for _ in r.scan_iter(match=f"{BLOCK_KEY_PREFIX}:*"))
        tracked_ips = r.zcard(SCORE_ZSET)
        top_score = 0
        if tracked_ips > 0:
            top_result = r.zrevrange(SCORE_ZSET, 0, 0, withscores=True)
            if top_result:
                top_score = float(top_result[0][1])
        
        # Count IPs above threshold
        high_score_ips = r.zcount(SCORE_ZSET, SCORE_BLOCK_THRESHOLD, "+inf")
        warning_ips = r.zcount(SCORE_ZSET, int(SCORE_BLOCK_THRESHOLD * 0.7), SCORE_BLOCK_THRESHOLD - 1)
        
        return jsonify({
            "blocked_ips": blocked_count,
            "tracked_ips": tracked_ips,
            "top_score": top_score,
            "high_score_ips": high_score_ips,
            "warning_ips": warning_ips,
            "block_threshold": SCORE_BLOCK_THRESHOLD,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Smart Syslog - IP Blocklist Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
            color: #333;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
        }

        header {
            background: white;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        h1 {
            color: #2d3748;
            margin-bottom: 10px;
            font-size: 2rem;
        }

        .subtitle {
            color: #718096;
            font-size: 0.95rem;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }

        .stat-card {
            background: white;
            border-radius: 12px;
            padding: 25px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            transition: transform 0.2s;
        }

        .stat-card:hover {
            transform: translateY(-2px);
        }

        .stat-value {
            font-size: 2.5rem;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 5px;
        }

        .stat-label {
            color: #718096;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            background: white;
            padding: 10px;
            border-radius: 12px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        .tab {
            padding: 12px 24px;
            background: transparent;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1rem;
            font-weight: 500;
            color: #718096;
            transition: all 0.2s;
        }

        .tab:hover {
            background: #f7fafc;
        }

        .tab.active {
            background: #667eea;
            color: white;
        }

        .content-panel {
            background: white;
            border-radius: 12px;
            padding: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            min-height: 400px;
        }

        .toolbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 15px;
        }

        .search-box {
            flex: 1;
            min-width: 200px;
            padding: 12px 20px;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.2s;
        }

        .search-box:focus {
            outline: none;
            border-color: #667eea;
        }

        .auto-refresh {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .switch {
            position: relative;
            display: inline-block;
            width: 50px;
            height: 24px;
        }

        .switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }

        .slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: #cbd5e0;
            transition: .4s;
            border-radius: 24px;
        }

        .slider:before {
            position: absolute;
            content: "";
            height: 18px;
            width: 18px;
            left: 3px;
            bottom: 3px;
            background-color: white;
            transition: .4s;
            border-radius: 50%;
        }

        input:checked + .slider {
            background-color: #667eea;
        }

        input:checked + .slider:before {
            transform: translateX(26px);
        }

        .table-wrapper {
            overflow-x: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        thead {
            background: #f7fafc;
        }

        th {
            padding: 15px;
            text-align: left;
            font-weight: 600;
            color: #2d3748;
            border-bottom: 2px solid #e2e8f0;
            cursor: pointer;
            user-select: none;
        }

        th:hover {
            background: #edf2f7;
        }

        td {
            padding: 15px;
            border-bottom: 1px solid #e2e8f0;
        }

        tbody tr {
            transition: background 0.2s;
        }

        tbody tr:hover {
            background: #f7fafc;
        }

        .ip-badge {
            font-family: 'Courier New', monospace;
            font-weight: bold;
            color: #2d3748;
            background: #edf2f7;
            padding: 4px 8px;
            border-radius: 4px;
        }

        .score-badge {
            display: inline-block;
            padding: 6px 12px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 0.9rem;
        }

        .score-high {
            background: #fed7d7;
            color: #c53030;
        }

        .score-warning {
            background: #feebc8;
            color: #c05621;
        }

        .score-normal {
            background: #c6f6d5;
            color: #22543d;
        }

        .badge-blocked {
            background: #fc8181;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85rem;
            font-weight: 600;
        }

        .badge-monitoring {
            background: #90cdf4;
            color: #2c5282;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85rem;
            font-weight: 600;
        }

        .badge-warning {
            background: #fbd38d;
            color: #744210;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85rem;
            font-weight: 600;
        }

        .loading {
            text-align: center;
            padding: 40px;
            color: #718096;
        }

        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #718096;
        }

        .empty-state svg {
            width: 80px;
            height: 80px;
            margin-bottom: 20px;
            opacity: 0.5;
        }

        .refresh-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #48bb78;
            margin-left: 8px;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .hidden {
            display: none;
        }

        @media (max-width: 768px) {
            .toolbar {
                flex-direction: column;
            }

            .search-box {
                width: 100%;
            }

            .tabs {
                flex-wrap: wrap;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Smart Syslog Dashboard <span class="refresh-indicator" id="refreshIndicator"></span></h1>
            <p class="subtitle">Real-time IP blocklist and threat monitoring</p>
        </header>

        <div class="stats-grid" id="statsGrid">
            <div class="stat-card">
                <div class="stat-value" id="statBlocked">-</div>
                <div class="stat-label">Blocked IPs</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="statTracked">-</div>
                <div class="stat-label">Tracked IPs</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="statHighScore">-</div>
                <div class="stat-label">High Score IPs</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="statTopScore">-</div>
                <div class="stat-label">Top Score</div>
            </div>
        </div>

        <div class="tabs">
            <button class="tab active" data-tab="blocked" onclick="switchTab('blocked', this)">Blocked IPs</button>
            <button class="tab" data-tab="scores" onclick="switchTab('scores', this)">IP Scores</button>
            <button class="tab" data-tab="logs" onclick="switchTab('logs', this)">Logs</button>
        </div>

        <div class="content-panel">
            <div class="toolbar">
                <input type="text" class="search-box" id="searchBox" placeholder="Search IP addresses..." onkeypress="if(event.key==='Enter' && currentTab==='logs') fetchLogs();">
                <div class="auto-refresh">
                    <label>Auto-refresh:</label>
                    <label class="switch">
                        <input type="checkbox" id="autoRefresh" checked>
                        <span class="slider"></span>
                    </label>
                    <span id="refreshStatus">On (5s)</span>
                </div>
            </div>

            <div id="blockedPanel">
                <div class="table-wrapper">
                    <table id="blockedTable">
                        <thead>
                            <tr>
                                <th onclick="sortTable('blocked', 'ip')">IP Address</th>
                                <th onclick="sortTable('blocked', 'score')">Score</th>
                                <th onclick="sortTable('blocked', 'reason')">Reason</th>
                                <th onclick="sortTable('blocked', 'ts')">Blocked At</th>
                                <th>Ports</th>
                                <th>TTL</th>
                            </tr>
                        </thead>
                        <tbody id="blockedTableBody">
                            <tr><td colspan="6" class="loading">Loading blocked IPs...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <div id="scoresPanel" class="hidden">
                <div class="table-wrapper">
                    <table id="scoresTable">
                        <thead>
                            <tr>
                                <th onclick="sortTable('scores', 'ip')">IP Address</th>
                                <th onclick="sortTable('scores', 'score')">Score</th>
                                <th>Status</th>
                                <th onclick="sortTable('scores', 'last_seen')">Last Seen</th>
                                <th>Ports</th>
                                <th>Last Increment</th>
                            </tr>
                        </thead>
                        <tbody id="scoresTableBody">
                            <tr><td colspan="6" class="loading">Loading IP scores...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <div id="logsPanel" class="hidden">
                <div class="table-wrapper">
                    <table id="logsTable">
                        <thead>
                            <tr>
                                <th onclick="sortTable('logs', 'ip')">IP Address</th>
                                <th onclick="sortTable('logs', 'host')">Host</th>
                                <th>Message</th>
                            </tr>
                        </thead>
                        <tbody id="logsTableBody">
                            <tr><td colspan="3" class="loading">Loading logs...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentTab = 'blocked';
        let blockedData = [];
        let scoresData = [];
        let logsData = [];
        let sortConfig = { field: null, direction: 'desc' };
        let refreshInterval = null;
        let autoRefreshEnabled = true;

        function getScoreClass(score, threshold = {{SCORE_BLOCK_THRESHOLD}}) {
            score = parseFloat(score);
            if (score >= threshold) return 'score-high';
            if (score >= threshold * 0.7) return 'score-warning';
            return 'score-normal';
        }

        function getStatusBadge(status) {
            if (status === 'blocked') return '<span class="badge-blocked">BLOCKED</span>';
            if (status === 'warning') return '<span class="badge-warning">WARNING</span>';
            return '<span class="badge-monitoring">MONITORING</span>';
        }

        async function fetchStats() {
            try {
                const res = await fetch('/api/stats');
                const data = await res.json();
                
                document.getElementById('statBlocked').textContent = data.blocked_ips || 0;
                document.getElementById('statTracked').textContent = data.tracked_ips || 0;
                document.getElementById('statHighScore').textContent = data.high_score_ips || 0;
                document.getElementById('statTopScore').textContent = Math.round(data.top_score || 0);
            } catch (error) {
                console.error('Error fetching stats:', error);
            }
        }

        async function fetchBlocked() {
            try {
                const res = await fetch('/api/blocked');
                blockedData = await res.json();
                renderBlocked();
            } catch (error) {
                console.error('Error fetching blocked IPs:', error);
                document.getElementById('blockedTableBody').innerHTML = 
                    '<tr><td colspan="6" class="empty-state">Error loading data</td></tr>';
            }
        }

        async function fetchScores() {
            try {
                const res = await fetch('/api/scores');
                scoresData = await res.json();
                renderScores();
            } catch (error) {
                console.error('Error fetching scores:', error);
                document.getElementById('scoresTableBody').innerHTML = 
                    '<tr><td colspan="5" class="empty-state">Error loading data</td></tr>';
            }
        }

        async function fetchLogs() {
            try {
                const search = document.getElementById('searchBox').value.trim();
                const url = search ? `/api/logs?ip=${encodeURIComponent(search)}` : '/api/logs';
                const res = await fetch(url);
                logsData = await res.json();
                renderLogs();
            } catch (error) {
                console.error('Error fetching logs:', error);
                document.getElementById('logsTableBody').innerHTML = 
                    '<tr><td colspan="3" class="empty-state">Error loading data</td></tr>';
            }
        }

        function renderLogs() {
            const tbody = document.getElementById('logsTableBody');
            const search = document.getElementById('searchBox').value.toLowerCase();
            
            let filtered = logsData.filter(item => {
                if (!search) return true;
                const searchLower = search.toLowerCase();
                return (
                    item.ip.toLowerCase().includes(searchLower) ||
                    item.host.toLowerCase().includes(searchLower) ||
                    item.program.toLowerCase().includes(searchLower) ||
                    item.message.toLowerCase().includes(searchLower)
                );
            });

            if (filtered.length === 0) {
                tbody.innerHTML = '<tr><td colspan="3" class="empty-state">No logs found</td></tr>';
                return;
            }

            if (sortConfig.field) {
                filtered.sort((a, b) => {
                    let aVal = a[sortConfig.field];
                    let bVal = b[sortConfig.field];
                    
                    if (sortConfig.field === 'timestamp') {
                        aVal = parseFloat(aVal) || 0;
                        bVal = parseFloat(bVal) || 0;
                    } else {
                        aVal = String(aVal || '').toLowerCase();
                        bVal = String(bVal || '').toLowerCase();
                    }
                    
                    if (sortConfig.direction === 'asc') {
                        return aVal > bVal ? 1 : -1;
                    } else {
                        return aVal < bVal ? 1 : -1;
                    }
                });
            }

            tbody.innerHTML = filtered.map(item => `
                <tr>
                    <td>${item.ip !== 'N/A' ? `<span class="ip-badge">${item.ip}</span>` : '<span style="color: #718096;">N/A</span>'}</td>
                    <td>${item.host || 'N/A'}</td>
                    <td style="white-space: pre-wrap; word-wrap: break-word; max-width: 600px;">${item.message || 'N/A'}</td>
                </tr>
            `).join('');
        }

        function renderBlocked() {
            const tbody = document.getElementById('blockedTableBody');
            const search = document.getElementById('searchBox').value.toLowerCase();
            
            let filtered = blockedData.filter(item => 
                !search || item.ip.toLowerCase().includes(search)
            );

            if (filtered.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No blocked IPs found</td></tr>';
                return;
            }

            if (sortConfig.field) {
                filtered.sort((a, b) => {
                    let aVal = a[sortConfig.field];
                    let bVal = b[sortConfig.field];
                    
                    if (sortConfig.field === 'score') {
                        aVal = parseFloat(aVal);
                        bVal = parseFloat(bVal);
                    }
                    
                    if (sortConfig.direction === 'asc') {
                        return aVal > bVal ? 1 : -1;
                    } else {
                        return aVal < bVal ? 1 : -1;
                    }
                });
            }

            tbody.innerHTML = filtered.map(item => `
                <tr>
                    <td><span class="ip-badge">${item.ip}</span></td>
                    <td><span class="score-badge ${getScoreClass(item.score)}">${item.score}</span></td>
                    <td>${item.reason || 'score_threshold'}</td>
                    <td>
                        <div>${item.formatted_ts}</div>
                        <small style="color: #718096;">${item.relative_ts}</small>
                    </td>
                    <td><span style="font-family: monospace; color: #667eea;">${item.ports || 'N/A'}</span></td>
                    <td>${Math.round(item.ttl_seconds / 60)} min</td>
                </tr>
            `).join('');
        }

        function renderScores() {
            const tbody = document.getElementById('scoresTableBody');
            const search = document.getElementById('searchBox').value.toLowerCase();
            
            let filtered = scoresData.filter(item => 
                !search || item.ip.toLowerCase().includes(search)
            );

            if (filtered.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No tracked IPs found</td></tr>';
                return;
            }

            if (sortConfig.field) {
                filtered.sort((a, b) => {
                    let aVal = a[sortConfig.field];
                    let bVal = b[sortConfig.field];
                    
                    if (sortConfig.field === 'score') {
                        aVal = a.score;
                        bVal = b.score;
                    }
                    
                    if (sortConfig.direction === 'asc') {
                        return aVal > bVal ? 1 : -1;
                    } else {
                        return aVal < bVal ? 1 : -1;
                    }
                });
            }

            tbody.innerHTML = filtered.map(item => `
                <tr>
                    <td><span class="ip-badge">${item.ip}</span></td>
                    <td><span class="score-badge ${getScoreClass(item.score)}">${Math.round(item.score)}</span></td>
                    <td>${getStatusBadge(item.status)}</td>
                    <td>
                        <div>${item.last_seen}</div>
                        <small style="color: #718096;">${item.relative_last_seen}</small>
                    </td>
                    <td><span style="font-family: monospace; color: #667eea;">${item.ports || 'N/A'}</span></td>
                    <td>+${item.last_inc}</td>
                </tr>
            `).join('');
        }

        function switchTab(tab, buttonElement) {
            currentTab = tab;
            
            // Update tab buttons
            document.querySelectorAll('.tab').forEach(btn => {
                btn.classList.remove('active');
            });
            if (buttonElement) {
                buttonElement.classList.add('active');
            } else {
                // Fallback: find button by data-tab attribute
                const btn = document.querySelector(`.tab[data-tab="${tab}"]`);
                if (btn) btn.classList.add('active');
            }
            
            // Show/hide panels
            document.getElementById('blockedPanel').classList.toggle('hidden', tab !== 'blocked');
            document.getElementById('scoresPanel').classList.toggle('hidden', tab !== 'scores');
            document.getElementById('logsPanel').classList.toggle('hidden', tab !== 'logs');
            
            // Update search placeholder
            const searchBox = document.getElementById('searchBox');
            if (tab === 'logs') {
                searchBox.placeholder = 'Search IP addresses, hosts, programs, or messages...';
            } else {
                searchBox.placeholder = 'Search IP addresses...';
            }
            
            // Load data for active tab
            if (tab === 'blocked') {
                fetchBlocked();
            } else if (tab === 'scores') {
                fetchScores();
            } else if (tab === 'logs') {
                fetchLogs();
            }
        }

        function sortTable(tab, field) {
            if (currentTab !== tab) return;
            
            if (sortConfig.field === field) {
                sortConfig.direction = sortConfig.direction === 'asc' ? 'desc' : 'asc';
            } else {
                sortConfig.field = field;
                sortConfig.direction = 'desc';
            }
            
            if (tab === 'blocked') {
                renderBlocked();
            } else if (tab === 'scores') {
                renderScores();
            } else if (tab === 'logs') {
                renderLogs();
            }
        }

        function refreshData() {
            fetchStats();
            if (currentTab === 'blocked') {
                fetchBlocked();
            } else if (currentTab === 'scores') {
                fetchScores();
            } else if (currentTab === 'logs') {
                fetchLogs();
            }
        }

        function setupAutoRefresh() {
            const checkbox = document.getElementById('autoRefresh');
            checkbox.addEventListener('change', (e) => {
                autoRefreshEnabled = e.target.checked;
                document.getElementById('refreshStatus').textContent = 
                    autoRefreshEnabled ? 'On (5s)' : 'Off';
                
                if (autoRefreshEnabled) {
                    startRefresh();
                } else {
                    stopRefresh();
                }
            });
        }

        function startRefresh() {
            if (refreshInterval) clearInterval(refreshInterval);
            refreshInterval = setInterval(() => {
                if (autoRefreshEnabled) {
                    refreshData();
                }
            }, 5000);
        }

        function stopRefresh() {
            if (refreshInterval) {
                clearInterval(refreshInterval);
                refreshInterval = null;
            }
        }

        // Search box
        document.getElementById('searchBox').addEventListener('input', () => {
            if (currentTab === 'blocked') {
                renderBlocked();
            } else if (currentTab === 'scores') {
                renderScores();
            } else if (currentTab === 'logs') {
                // For logs, re-fetch from API if IP search is used
                const search = document.getElementById('searchBox').value.trim();
                if (search && /^\d+\.\d+\.\d+\.\d+/.test(search)) {
                    // If it looks like an IP, fetch from API
                    fetchLogs();
                } else {
                    // Otherwise filter client-side
                    renderLogs();
                }
            }
        });

        // Initialize
        setupAutoRefresh();
        refreshData();
        startRefresh();
    </script>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)

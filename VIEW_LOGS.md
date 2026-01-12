# Viewing Syslog Messages and Logs

## Quick Reference

### View syslog-ng logs (received messages)

**Real-time logs (recommended):**
```bash
ssh root@10.0.0.61
docker compose logs -f syslog-ng
```

**View log file:**
```bash
docker compose exec syslog-ng tail -f /var/log/syslog-ng/received.log
```

**Last 100 lines:**
```bash
docker compose exec syslog-ng tail -n 100 /var/log/syslog-ng/received.log
```

---

## All Log Locations

### 1. Syslog-ng (Syslog Receiver)

Shows all received syslog messages:

```bash
# Console logs (stdout) - real-time
docker compose logs -f syslog-ng

# Log file - persisted
docker compose exec syslog-ng tail -f /var/log/syslog-ng/received.log

# Search for specific IP or message
docker compose exec syslog-ng grep "203.0.113.100" /var/log/syslog-ng/received.log
```

**Log format:**
```
2025-01-11T12:00:00+00:00 hostname program: message content
```

---

### 2. Redis-Writer

Shows HTTP requests from syslog-ng:

```bash
docker compose logs -f redis-writer
```

**What you'll see:**
- Connection status
- HTTP requests received
- Redis connection errors (if any)

---

### 3. Worker

Shows message processing and scoring:

```bash
docker compose logs -f worker
```

**What you'll see:**
- Messages being processed
- IP scoring activities
- Block events
- Errors

---

### 4. Web Dashboard

Shows Flask app logs:

```bash
docker compose logs -f web
```

**What you'll see:**
- Flask startup messages
- API requests
- Redis connection status
- Errors

---

### 5. Redis

View Redis data directly:

```bash
# Connect to Redis CLI
docker compose exec redis redis-cli

# View raw stream messages
XREAD COUNT 10 STREAMS syslog:raw 0

# View blocked IPs stream
XREAD COUNT 10 STREAMS syslog:blocklist 0

# View IP scores
ZRANGE ip:score 0 -1 WITHSCORES

# View score metadata
HGETALL ip:score:meta

# Count items
XLEN syslog:raw
ZCARD ip:score
XLEN syslog:blocklist
```

---

## View All Logs Together

```bash
# All services at once
docker compose logs -f

# Filter by service name
docker compose logs -f syslog-ng worker redis-writer
```

---

## Search Logs

```bash
# Search all logs for an IP address
docker compose logs | grep "203.0.113.100"

# Search for errors
docker compose logs | grep -i error

# Search syslog-ng log file
docker compose exec syslog-ng grep "keyword" /var/log/syslog-ng/received.log

# Search with context (5 lines before/after)
docker compose logs | grep -A 5 -B 5 "error"
```

---

## Log Retention

- **Console logs (docker logs):** Managed by Docker (default: rotate)
- **File logs (`/var/log/syslog-ng/received.log`):** Persisted in Docker volume `syslog_logs`

To clear logs:
```bash
# Clear console logs (rotate)
docker compose logs --tail=0 syslog-ng

# Clear log file
docker compose exec syslog-ng truncate -s 0 /var/log/syslog-ng/received.log
```

---

## Monitoring in Real-Time

**Watch all services:**
```bash
watch -n 2 'docker compose ps'
```

**Follow multiple logs:**
```bash
docker compose logs -f syslog-ng worker web
```

**Monitor with timestamps:**
```bash
docker compose logs -f -t syslog-ng
```

---

## Example Log Output

### Syslog-ng (received message):
```
2025-01-11T12:00:00+00:00 test-host myapp: srcip=203.0.113.100 Connection blocked
```

### Worker (processing):
```
[worker] consuming stream=syslog:raw group=syslog-workers consumer=worker-1
```

### Redis-writer (received HTTP):
```
[redis-writer] Connected to Redis at redis://redis:6379/0
127.0.0.1 - - [11/Jan/2025 12:00:00] "POST /ingest HTTP/1.1" 200 -
```

---

## Troubleshooting with Logs

1. **No messages appearing in dashboard?**
   ```bash
   # Check if syslog-ng is receiving messages
   docker compose logs -f syslog-ng
   
   # Check if redis-writer is getting HTTP requests
   docker compose logs -f redis-writer
   
   # Check if worker is processing
   docker compose logs -f worker
   ```

2. **Messages received but not scored?**
   ```bash
   # Check worker logs for errors
   docker compose logs worker | grep -i error
   
   # Check Redis data
   docker compose exec redis redis-cli ZRANGE ip:score 0 -1 WITHSCORES
   ```

3. **Connection issues?**
   ```bash
   # Check all services for connection errors
   docker compose logs | grep -i "connection\|connect\|error"
   ```

# Troubleshooting Guide

## Web Container Exited with Error - FIXED ✅

The web container was missing the Flask server startup code. This has been fixed.

### To apply the fix on your server:

**Option 1: Rebuild and restart (recommended)**
```bash
ssh root@10.0.0.61
cd /opt/smart-syslog
docker compose up -d --build web
docker compose logs -f web
```

**Option 2: If files are already synced, just rebuild:**
```bash
ssh root@10.0.0.61
cd /opt/smart-syslog
docker compose build web
docker compose up -d web
```

---

## Common Commands for Debugging

### Check container status
```bash
docker compose ps
```

### View logs for a specific service
```bash
# Web service logs
docker compose logs -f web

# Syslog-ng logs (shows received syslog messages in real-time)
docker compose logs -f syslog-ng

# View syslog-ng log file directly
docker compose exec syslog-ng tail -f /var/log/syslog-ng/received.log

# Worker logs
docker compose logs -f worker

# Redis-writer logs
docker compose logs -f redis-writer

# All services
docker compose logs -f

# Last 100 lines
docker compose logs --tail=100 web

# Errors only
docker compose logs web 2>&1 | grep -i error
```

### Restart a specific service
```bash
docker compose restart web
# or
docker compose up -d --force-recreate web
```

### Rebuild and restart
```bash
docker compose up -d --build web
```

### Check if container is running
```bash
docker ps | grep web
# or
docker compose ps web
```

### Access container shell (if running)
```bash
docker compose exec web sh
```

### Check if port is in use
```bash
netstat -tlnp | grep 8111
# or
ss -tlnp | grep 8111
```

---

## Common Issues

### 1. Container exits immediately

**Check logs:**
```bash
docker compose logs web
```

**Common causes:**
- Missing code (like missing `app.run()` - now fixed)
- Python syntax errors
- Missing dependencies
- Port already in use

### 2. Port already in use

**Find what's using the port:**
```bash
lsof -i :8111
# or
netstat -tlnp | grep 8111
```

**Kill the process or change the port in docker-compose.yml**

### 3. Cannot connect to Redis

**Check Redis is running:**
```bash
docker compose ps redis
docker compose logs redis
```

**Test Redis connection:**
```bash
docker compose exec redis redis-cli ping
# Should return: PONG
```

### 4. Service won't start

**Check all dependencies:**
```bash
docker compose ps
```

All services should be running:
- redis
- worker
- redis-writer
- syslog-ng
- web

**Check Docker daemon:**
```bash
systemctl status docker
```

### 5. Permission errors

**If you see permission errors:**
```bash
# Make sure you're in the project directory
cd /opt/smart-syslog

# Check file permissions
ls -la

# If needed, fix permissions
chmod -R 755 .
```

---

## Testing the Web Service

### 1. Check if it's running
```bash
curl http://localhost:8111
# or from another machine:
curl http://10.0.0.61:8111
```

### 2. Test API endpoints
```bash
# Stats
curl http://10.0.0.61:8111/api/stats

# Blocked IPs
curl http://10.0.0.61:8111/api/blocked

# IP Scores
curl http://10.0.0.61:8111/api/scores
```

### 3. Access in browser
Open: `http://10.0.0.61:8111`

---

## Full Service Restart

If everything is broken, restart all services:

```bash
cd /opt/smart-syslog

# Stop everything
docker compose down

# Remove volumes (⚠️ deletes data)
# docker compose down -v

# Rebuild and start
docker compose up -d --build

# Check status
docker compose ps

# Watch logs
docker compose logs -f
```

---

## Updating Code After Changes

If you've made code changes and need to deploy:

1. **Transfer files to server:**
   ```bash
   # From your local machine
   rsync -avz --exclude='.git' --exclude='.DS_Store' ./ root@10.0.0.61:/opt/smart-syslog/
   ```

2. **Rebuild and restart:**
   ```bash
   # On server
   ssh root@10.0.0.61
   cd /opt/smart-syslog
   docker compose up -d --build
   ```

Or use the deploy script:
```bash
./deploy.sh
```

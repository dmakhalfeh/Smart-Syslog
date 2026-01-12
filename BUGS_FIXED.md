# Bugs Found and Fixed

## Summary
Reviewed all project files and fixed 4 critical bugs that could cause the application to fail.

---

## Bugs Fixed

### 1. ✅ JavaScript Bug in `web/app.py` - `event.target` Not Defined
**Severity:** High  
**Impact:** Tab switching would fail with JavaScript error

**Problem:**
- The `switchTab()` function used `event.target` but `event` was not passed as a parameter
- This would cause a `ReferenceError: event is not defined` when clicking tabs

**Fix:**
- Updated `switchTab()` to accept `buttonElement` parameter
- Updated button onclick handlers to pass `this` as second argument
- Added fallback logic to find button by data-tab attribute

**Files Changed:**
- `web/app.py` (lines ~494-495, ~700-719)

---

### 2. ✅ Missing Restart Policy in `docker-compose.yml`
**Severity:** Medium  
**Impact:** Web service wouldn't automatically restart on failure

**Problem:**
- The `web` service was missing `restart: unless-stopped` policy
- Other services had it, causing inconsistency
- If the web container crashed, it wouldn't restart automatically

**Fix:**
- Added `restart: unless-stopped` to web service configuration

**Files Changed:**
- `docker-compose.yml` (line ~73)

---

### 3. ✅ Missing Error Handling in `redis-writer/app.py`
**Severity:** High  
**Impact:** Service would crash on Redis connection failures

**Problem:**
- No error handling for Redis connection failures
- No error handling in `/ingest` endpoint
- Service would crash if Redis was unavailable
- No connection timeout configuration

**Fix:**
- Added Redis connection error handling with try/except
- Added error handling to `/ingest` endpoint
- Added connection timeout configuration
- Added proper error responses (503 for connection errors, 500 for other errors)
- Added connection test on startup
- Wrapped `app.run()` in `if __name__ == "__main__"` guard

**Files Changed:**
- `redis-writer/app.py` (entire file refactored)

---

### 4. ✅ Missing Error Handling in `web/app.py` API Endpoints
**Severity:** Medium  
**Impact:** API endpoints would return 500 errors without proper error messages

**Problem:**
- `/api/blocked`, `/api/scores`, and `/api/stats` endpoints had no error handling
- If Redis connection failed or any error occurred, the app would crash
- No graceful error responses

**Fix:**
- Wrapped all Redis operations in try/except blocks
- Added proper error responses (500 status code with error message)
- Errors are now caught and returned as JSON responses instead of crashing

**Files Changed:**
- `web/app.py` (lines ~52-119)

---

## Files Reviewed

✅ `docker-compose.yml` - Fixed  
✅ `web/app.py` - Fixed (JavaScript bug + error handling)  
✅ `worker/worker.py` - No bugs found (already has good error handling)  
✅ `redis-writer/app.py` - Fixed  
✅ `web/Dockerfile` - OK  
✅ `worker/Dockerfile` - OK  
✅ `redis-writer/Dockerfile` - OK  
✅ `syslog-ng/syslog-ng.conf` - OK  

---

## Testing Recommendations

After deploying these fixes, test:

1. **Tab Switching:**
   - Open dashboard at http://10.0.0.61:8111
   - Click between "Blocked IPs" and "IP Scores" tabs
   - Verify tabs switch correctly without JavaScript errors

2. **Redis Connection Failures:**
   - Stop Redis container: `docker compose stop redis`
   - Verify web dashboard shows error messages instead of crashing
   - Verify redis-writer logs errors but doesn't crash
   - Restart Redis: `docker compose start redis`
   - Verify services recover

3. **Container Restart:**
   - Stop web container: `docker compose stop web`
   - Verify it restarts automatically (check after a few seconds)
   - Check logs: `docker compose logs web`

4. **Error Handling:**
   - Check browser console for JavaScript errors
   - Test API endpoints directly: `curl http://10.0.0.61:8111/api/stats`
   - Verify error responses are JSON format

---

## Deployment

To apply these fixes to your server:

```bash
# Option 1: Use deploy script
./deploy.sh

# Option 2: Manual deployment
rsync -avz --exclude='.git' --exclude='.DS_Store' ./ root@10.0.0.61:/opt/smart-syslog/
ssh root@10.0.0.61 "cd /opt/smart-syslog && docker compose up -d --build"
```

---

## Additional Notes

- All fixes maintain backward compatibility
- No breaking changes to API or configuration
- Error messages are now more descriptive
- Services are more resilient to failures

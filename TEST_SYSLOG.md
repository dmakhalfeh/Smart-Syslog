# Testing Guide - Sending Test Syslog Messages

Your syslog server listens on **port 1514/udp**.

## Quick Test (Simplest)

### From the server itself (10.0.0.61):

```bash
# SSH into your server
ssh root@10.0.0.61

# Send a test message
echo "test message" | nc -u localhost 1514

# Or using logger (if available)
logger -n localhost -P 1514 "Test syslog message from $(hostname)"
```

### From your local machine (Mac):

```bash
# Using netcat (nc)
echo "test message" | nc -u 10.0.0.61 1514

# Using logger (if available)
logger -n 10.0.0.61 -P 1514 "Test syslog message from Mac"
```

---

## Method 1: Using `logger` Command (Recommended)

**On Mac:**
```bash
logger -n 10.0.0.61 -P 1514 -p local0.info "Test message"
```

**On Linux/Server:**
```bash
logger -n 10.0.0.61 -P 1514 -p local0.info "Test message"
# Or to localhost if you're on the server:
logger -n localhost -P 1514 -p local0.info "Test message"
```

**Send a message with an IP address (for testing scoring):**
```bash
logger -n 10.0.0.61 -P 1514 "srcip=192.168.1.100 Connection blocked"
```

---

## Method 2: Using `nc` (netcat)

**Single message:**
```bash
echo "Test syslog message" | nc -u 10.0.0.61 1514
```

**Multiple messages:**
```bash
for i in {1..5}; do
  echo "Test message $i" | nc -u 10.0.0.61 1514
  sleep 1
done
```

**Send with IP address:**
```bash
echo '{"srcip":"203.0.113.10","message":"Failed login attempt"}' | nc -u 10.0.0.61 1514
```

---

## Method 3: Using Python Script

Create and run this script:

```python
#!/usr/bin/env python3
import socket
import json
import time

def send_syslog(host, port, message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(message.encode('utf-8'), (host, port))
        print(f"Sent: {message}")
    finally:
        sock.close()

# Test messages
send_syslog('10.0.0.61', 1514, 'Test message 1')
time.sleep(1)
send_syslog('10.0.0.61', 1514, '{"srcip":"203.0.113.50","message":"Attack detected"}')
```

---

## Method 4: Using `socat` (if installed)

```bash
echo "Test message" | socat - UDP-DATAGRAM:10.0.0.61:1514
```

---

## Method 5: Testing with Real IP Addresses (for Scoring)

To test the IP scoring and blocking system, send messages with IP addresses:

```bash
# Send multiple messages from the same IP (will increase score)
for i in {1..20}; do
  echo "srcip=203.0.113.100 Message $i" | nc -u 10.0.0.61 1514
  sleep 0.5
done
```

This will:
1. Score the IP address (203.0.113.100)
2. After 15 messages (SCORE_BLOCK_THRESHOLD=15), it should be blocked
3. Check the dashboard at http://10.0.0.61:8111

---

## Test Script

I've created a test script for you (see `test_syslog.sh`). Run it with:

```bash
chmod +x test_syslog.sh
./test_syslog.sh
```

---

## Verify Messages Were Received

### Check syslog-ng logs:
```bash
ssh root@10.0.0.61

# View real-time logs from console (stdout)
docker compose logs -f syslog-ng

# View log file directly
docker compose exec syslog-ng tail -f /var/log/syslog-ng/received.log

# View last 100 lines
docker compose exec syslog-ng tail -n 100 /var/log/syslog-ng/received.log
```

### Check redis-writer logs:
```bash
docker compose logs -f redis-writer
```

### Check worker logs:
```bash
docker compose logs -f worker
```

### Check Redis data:
```bash
docker compose exec redis redis-cli
> XREAD COUNT 10 STREAMS syslog:raw 0
> ZRANGE ip:score 0 -1 WITHSCORES
> XLEN syslog:blocklist
```

### Check the web dashboard:
Open http://10.0.0.61:8111 in your browser

---

## Testing Different Scenarios

### Test 1: Simple Message
```bash
echo "Simple test message" | nc -u 10.0.0.61 1514
```

### Test 2: Message with Source IP
```bash
echo '{"srcip":"203.0.113.1","event":"login_failed"}' | nc -u 10.0.0.61 1514
```

### Test 3: Multiple IPs to Test Scoring
```bash
# Send 20 messages from IP 203.0.113.100 (should trigger block after 15)
for i in {1..20}; do
  echo "srcip=203.0.113.100 Failed attempt $i" | nc -u 10.0.0.61 1514
  sleep 0.3
done
```

### Test 4: Different IP Addresses
```bash
for ip in 203.0.113.10 203.0.113.20 203.0.113.30; do
  for i in {1..5}; do
    echo "srcip=$ip Test message $i" | nc -u 10.0.0.61 1514
  done
done
```

### Test 5: Attack-like Messages (should score higher)
```bash
echo '{"srcip":"203.0.113.200","message":"Connection blocked due to brute force attack"}' | nc -u 10.0.0.61 1514
echo '{"srcip":"203.0.113.200","message":"Port scan detected"}' | nc -u 10.0.0.61 1514
echo '{"srcip":"203.0.113.200","message":"Intrusion attempt blocked"}' | nc -u 10.0.0.61 1514
```

---

## Troubleshooting

### If messages aren't being received:

1. **Check if syslog-ng is running:**
   ```bash
   docker compose ps syslog-ng
   ```

2. **Check if port 1514 is listening:**

   **On Linux server:**
   ```bash
   # Using netstat (shows UDP listeners)
   netstat -ulnp | grep 1514
   
   # Using ss (modern alternative)
   ss -ulnp | grep 1514
   
   # Using lsof
   lsof -i :1514
   
   # Check if Docker container is exposing the port
   docker compose ps syslog-ng
   docker port $(docker compose ps -q syslog-ng) 1514/udp
   ```

   **On macOS (your local machine):**
   ```bash
   # Using lsof (works on macOS)
   lsof -i :1514 -i UDP
   
   # Using netstat (different syntax on macOS)
   netstat -an | grep 1514 | grep UDP
   
   # Check Docker container
   docker compose ps syslog-ng
   ```

   **Expected output (if listening):**
   ```
   udp6       0      0 :::1514                 :::*                    12345/docker-proxy
   udp        0      0 0.0.0.0:1514             0.0.0.0:*               12345/docker-proxy
   ```

   **If you see output, port 1514 is listening!** If you don't see anything, the service might not be running.

3. **Check firewall:**
   ```bash
   # Allow UDP port 1514
   ufw allow 1514/udp
   # or iptables
   iptables -A INPUT -p udp --dport 1514 -j ACCEPT
   ```

4. **Test connectivity:**
   ```bash
   # From your Mac
   nc -u -v 10.0.0.61 1514
   # Type a message and press Enter
   ```

5. **Check syslog-ng configuration:**
   ```bash
   docker compose exec syslog-ng syslog-ng -F -f /etc/syslog-ng/syslog-ng.conf --validate
   ```

---

## Standard Syslog Format

If you want to send properly formatted syslog messages:

```
<PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
```

Example:
```
<134>Jan 11 12:00:00 test-host myapp: Test message
```

Using logger (which formats it automatically):
```bash
logger -n 10.0.0.61 -P 1514 -t myapp -p local0.info "Test message"
```

---

## Quick Test Checklist

- [ ] Send a test message
- [ ] Check syslog-ng logs (should see message received)
- [ ] Check redis-writer logs (should see HTTP request)
- [ ] Check worker logs (should see message processed)
- [ ] Check Redis stream: `docker compose exec redis redis-cli XREAD COUNT 1 STREAMS syslog:raw 0`
- [ ] Check web dashboard: http://10.0.0.61:8111
- [ ] Send multiple messages with same IP (test scoring)
- [ ] Verify IP appears in dashboard after scoring

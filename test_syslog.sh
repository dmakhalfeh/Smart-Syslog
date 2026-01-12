#!/bin/bash

# Test script for sending syslog messages to Smart Syslog server
# Usage: ./test_syslog.sh [server_ip]

SERVER_IP="${1:-10.0.0.61}"
PORT=1514

echo "🧪 Testing Smart Syslog Server at ${SERVER_IP}:${PORT}"
echo ""

# Check if nc (netcat) is available
if ! command -v nc &> /dev/null; then
    echo "❌ Error: 'nc' (netcat) is not installed."
    echo "   Install it with: brew install netcat (Mac) or apt-get install netcat (Linux)"
    exit 1
fi

# Test 1: Simple message
echo "📤 Test 1: Sending simple test message..."
echo "Test message $(date)" | nc -u -w1 ${SERVER_IP} ${PORT}
sleep 1

# Test 2: Message with source IP
echo "📤 Test 2: Sending message with source IP..."
echo '{"srcip":"203.0.113.10","message":"Test connection","timestamp":"'$(date +%s)'"}' | nc -u -w1 ${SERVER_IP} ${PORT}
sleep 1

# Test 3: Multiple messages from same IP (for scoring)
echo "📤 Test 3: Sending 5 messages from same IP (203.0.113.100)..."
for i in {1..5}; do
  echo "srcip=203.0.113.100 Test message $i at $(date +%H:%M:%S)" | nc -u -w1 ${SERVER_IP} ${PORT}
  sleep 0.5
done
sleep 1

# Test 4: Attack-like messages (should score higher)
echo "📤 Test 4: Sending attack-like messages (203.0.113.200)..."
echo '{"srcip":"203.0.113.200","message":"Connection blocked due to brute force"}' | nc -u -w1 ${SERVER_IP} ${PORT}
sleep 0.5
echo '{"srcip":"203.0.113.200","message":"Port scan detected"}' | nc -u -w1 ${SERVER_IP} ${PORT}
sleep 0.5
echo '{"srcip":"203.0.113.200","message":"Intrusion attempt blocked"}' | nc -u -w1 ${SERVER_IP} ${PORT}
sleep 1

echo ""
echo "✅ Test messages sent!"
echo ""
echo "📊 Next steps:"
echo "   1. Check logs: ssh root@${SERVER_IP} 'docker compose logs -f worker'"
echo "   2. View dashboard: http://${SERVER_IP}:8111"
echo "   3. Check Redis: ssh root@${SERVER_IP} 'docker compose exec redis redis-cli ZRANGE ip:score 0 -1 WITHSCORES'"
echo ""
echo "💡 To send more messages to trigger blocking (need 15+ messages from same IP):"
echo "   for i in {1..20}; do echo \"srcip=203.0.113.100 Message \$i\" | nc -u -w1 ${SERVER_IP} ${PORT}; sleep 0.3; done"

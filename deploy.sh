#!/bin/bash

# Deployment script for Smart Syslog to Debian server
# Server IP: 10.0.0.61

SERVER_IP="10.0.0.61"
SERVER_USER="${SERVER_USER:-root}"  # Change this to your SSH user if not root
DEPLOY_PATH="/opt/smart-syslog"      # Change this if you want a different path

echo "🚀 Deploying Smart Syslog to ${SERVER_USER}@${SERVER_IP}..."
echo "📁 Deployment path: ${DEPLOY_PATH}"
echo ""

# Step 1: Create deployment directory on server
echo "📦 Step 1: Creating directory on server..."
ssh ${SERVER_USER}@${SERVER_IP} "mkdir -p ${DEPLOY_PATH}"

# Step 2: Transfer production files only (exclude docs, backups, etc.)
echo "📤 Step 2: Transferring production files to server..."
rsync -avz \
  --exclude='.git' \
  --exclude='.DS_Store' \
  --exclude='*.pyc' \
  --exclude='__pycache__' \
  --exclude='*.md' \
  --exclude='*.sh' \
  --exclude='BUGS_FIXED.md' \
  --exclude='DEPLOYMENT.md' \
  --exclude='DEPLOY_QUICK.md' \
  --exclude='DEPLOY_SSH.md' \
  --exclude='TEST_SYSLOG.md' \
  --exclude='TROUBLESHOOTING.md' \
  --exclude='VIEW_LOGS.md' \
  --exclude='deploy.sh' \
  --exclude='test_syslog.sh' \
  ./ ${SERVER_USER}@${SERVER_IP}:${DEPLOY_PATH}/

# Step 3: Verify Docker is available
echo "🐳 Step 3: Verifying Docker..."
ssh ${SERVER_USER}@${SERVER_IP} "docker --version && docker compose version"

# Step 4: Build and start services
echo "🏗️  Step 4: Building and starting services..."
ssh ${SERVER_USER}@${SERVER_IP} "cd ${DEPLOY_PATH} && docker compose up -d --build"

# Step 5: Show status
echo "📊 Step 5: Service status..."
ssh ${SERVER_USER}@${SERVER_IP} "cd ${DEPLOY_PATH} && docker compose ps"

echo ""
echo "✅ Deployment complete!"
echo ""
echo "📝 Next steps:"
echo "   • View logs: ssh ${SERVER_USER}@${SERVER_IP} 'cd ${DEPLOY_PATH} && docker compose logs -f'"
echo "   • Access dashboard: http://${SERVER_IP}:8111"
echo "   • Syslog endpoint: ${SERVER_IP}:1514/udp"
echo "   • Check status: ssh ${SERVER_USER}@${SERVER_IP} 'cd ${DEPLOY_PATH} && docker compose ps'"

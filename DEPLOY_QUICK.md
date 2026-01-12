# Quick Deployment Guide - Debian Server (10.0.0.61)

## Option 1: Automated Deployment Script

1. **Make the script executable:**
   ```bash
   chmod +x deploy.sh
   ```

2. **Edit the script if needed** (change `SERVER_USER` or `DEPLOY_PATH`):
   ```bash
   nano deploy.sh
   ```

3. **Run the deployment:**
   ```bash
   ./deploy.sh
   ```

   Or specify a different user:
   ```bash
   SERVER_USER=yourusername ./deploy.sh
   ```

---

## Option 2: Manual Step-by-Step Deployment

### Step 1: Install Docker on your Debian server (if not already installed)

**SSH into your server:**
```bash
ssh root@10.0.0.61
# or: ssh yourusername@10.0.0.61
```

**On the server, install Docker:**
```bash
# Update package index
apt-get update

# Install prerequisites
apt-get install -y ca-certificates curl gnupg lsb-release

# Add Docker's official GPG key
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

# Set up repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
  $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Start and enable Docker
systemctl start docker
systemctl enable docker

# Verify installation
docker --version
docker compose version
```

### Step 2: Transfer files from your Mac to the server

**On your Mac (in the "Smart Syslog" directory), use one of these methods:**

**Using rsync (recommended):**
```bash
rsync -avz --exclude='.git' --exclude='.DS_Store' \
  ./ root@10.0.0.61:/opt/smart-syslog/
```

**Using tar + scp:**
```bash
# Create archive
tar -czf smart-syslog.tar.gz \
  --exclude='.git' \
  --exclude='.DS_Store' \
  --exclude='*.pyc' \
  --exclude='__pycache__' \
  .

# Transfer
scp smart-syslog.tar.gz root@10.0.0.61:/tmp/

# On server, extract:
ssh root@10.0.0.61 "mkdir -p /opt/smart-syslog && cd /opt/smart-syslog && tar -xzf /tmp/smart-syslog.tar.gz"
```

**Using SCP directly:**
```bash
scp -r docker-compose.yml worker redis-writer web syslog-ng root@10.0.0.61:/opt/smart-syslog/
```

### Step 3: Deploy on the server

**SSH into your server:**
```bash
ssh root@10.0.0.61
```

**Navigate to the project directory:**
```bash
cd /opt/smart-syslog
```

**Start the services:**
```bash
docker compose up -d
```

The `-d` flag runs in detached mode (background).

### Step 4: Verify deployment

**Check if all services are running:**
```bash
docker compose ps
```

You should see:
- redis
- worker
- redis-writer
- syslog-ng
- web (blocked-ip-dashboard)

**View logs:**
```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f web
docker compose logs -f worker
```

**Check if ports are listening:**
```bash
netstat -tlnp | grep -E '1514|8111'
# or
ss -tlnp | grep -E '1514|8111'
```

### Step 5: Access your services

- **Web Dashboard:** http://10.0.0.61:8111
- **Syslog Input:** 10.0.0.61:1514/udp

---

## Common Commands

### On the server:

**Start services:**
```bash
cd /opt/smart-syslog
docker compose up -d
```

**Stop services:**
```bash
docker compose down
```

**Restart services:**
```bash
docker compose restart
```

**Rebuild after code changes:**
```bash
docker compose up -d --build
```

**View logs:**
```bash
docker compose logs -f [service-name]
```

**Check status:**
```bash
docker compose ps
```

**Access container shell:**
```bash
docker compose exec web sh
docker compose exec redis redis-cli
```

---

## Firewall Configuration (if needed)

If you have a firewall enabled, allow the ports:

```bash
# UFW (if installed)
ufw allow 1514/udp
ufw allow 8111/tcp

# iptables
iptables -A INPUT -p udp --dport 1514 -j ACCEPT
iptables -A INPUT -p tcp --dport 8111 -j ACCEPT
```

---

## Troubleshooting

**If Docker commands fail with permission errors:**
```bash
# Add your user to docker group (replace 'yourusername')
usermod -aG docker yourusername
# Then log out and log back in
```

**If services fail to start:**
```bash
# Check logs
docker compose logs

# Check Docker daemon
systemctl status docker

# Verify Docker can run containers
docker run hello-world
```

**If port is already in use:**
```bash
# Find what's using the port
lsof -i :8111
# or
netstat -tlnp | grep 8111
```

---

## Notes

- Default SSH user is `root`. Change to your actual username if different.
- Default deployment path is `/opt/smart-syslog`. You can change this.
- Make sure you can SSH into the server without password (use SSH keys) or be ready to enter password.
- The deployment script will install Docker automatically if it's not present.

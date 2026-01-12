# Deployment Guide - Smart Syslog

## Prerequisites

### 1. Install Docker on your server

**Ubuntu/Debian:**
```bash
# Update package index
sudo apt-get update

# Install required packages
sudo apt-get install -y ca-certificates curl gnupg lsb-release

# Add Docker's official GPG key
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Set up repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine and Docker Compose
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

**CentOS/RHEL:**
```bash
# Install Docker
sudo yum install -y docker docker-compose-plugin
sudo systemctl start docker
sudo systemctl enable docker
```

### 2. Verify Installation
```bash
docker --version
docker compose version
```

## Deployment Steps

### Option 1: Using Git (Recommended)

1. **Push your code to a Git repository** (GitHub, GitLab, etc.)

2. **On your server, clone the repository:**
   ```bash
   git clone <your-repository-url>
   cd "Smart Syslog"
   ```

3. **Build and start services:**
   ```bash
   docker compose up -d
   ```
   
   The `-d` flag runs containers in detached mode (background).

### Option 2: Using SCP/SFTP

1. **Compress your project directory:**
   ```bash
   # On your local machine
   tar -czf smart-syslog.tar.gz "Smart Syslog"
   ```

2. **Transfer to server:**
   ```bash
   scp smart-syslog.tar.gz user@your-server:/path/to/destination/
   ```

3. **On your server:**
   ```bash
   # Extract
   tar -xzf smart-syslog.tar.gz
   cd "Smart Syslog"
   
   # Start services
   docker compose up -d
   ```

### Option 3: Direct File Transfer

1. **Use rsync to sync files:**
   ```bash
   rsync -avz "Smart Syslog/" user@your-server:/path/to/destination/
   ```

2. **On your server:**
   ```bash
   cd /path/to/destination
   docker compose up -d
   ```

## Running the Services

### Start all services:
```bash
docker compose up -d
```

### View running services:
```bash
docker compose ps
```

### View logs:
```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f web
docker compose logs -f worker
```

### Stop services:
```bash
docker compose down
```

### Stop and remove volumes (⚠️ deletes data):
```bash
docker compose down -v
```

### Rebuild after code changes:
```bash
docker compose up -d --build
```

## Production Considerations

### 1. Environment Variables

Create a `.env` file for sensitive configuration:
```bash
# .env file
REDIS_PASSWORD=your-secure-password
# Add other sensitive variables here
```

Update `docker-compose.yml` to use these variables if needed.

### 2. Firewall Configuration

Ensure these ports are open:
- **1514/udp**: Syslog input
- **8111/tcp**: Web dashboard

```bash
# Ubuntu/Debian (ufw)
sudo ufw allow 1514/udp
sudo ufw allow 8111/tcp

# Or iptables
sudo iptables -A INPUT -p udp --dport 1514 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8111 -j ACCEPT
```

### 3. Running as a Service (Optional)

Create a systemd service for auto-start:

```bash
sudo nano /etc/systemd/system/smart-syslog.service
```

Add:
```ini
[Unit]
Description=Smart Syslog Docker Compose
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/path/to/Smart Syslog
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable smart-syslog.service
sudo systemctl start smart-syslog.service
```

### 4. Resource Limits (Optional)

Add resource limits to `docker-compose.yml`:
```yaml
services:
  worker:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G
```

### 5. Health Checks

Add health checks to critical services:
```yaml
services:
  redis:
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3
```

## Troubleshooting

### Check container status:
```bash
docker compose ps
```

### View detailed logs:
```bash
docker compose logs --tail=100 -f
```

### Access container shell:
```bash
docker compose exec web sh
docker compose exec redis redis-cli
```

### Check resource usage:
```bash
docker stats
```

### Rebuild specific service:
```bash
docker compose build worker
docker compose up -d worker
```

## Security Best Practices

1. **Use Docker secrets** for sensitive data in production
2. **Keep Docker and images updated**: `docker compose pull && docker compose up -d`
3. **Use specific image tags** (you're already doing this with `redis:8.2.2-alpine`)
4. **Run containers as non-root** when possible
5. **Use reverse proxy** (nginx/traefik) in front of the web service
6. **Enable firewall** and only expose necessary ports

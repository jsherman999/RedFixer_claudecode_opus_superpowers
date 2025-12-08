# RedFixer Deployment Guide

This guide covers deploying RedFixer using Podman containers on RHEL 9 systems.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start with Podman Compose](#quick-start-with-podman-compose)
- [Production Deployment with Systemd](#production-deployment-with-systemd)
- [Manual Container Deployment](#manual-container-deployment)
- [Configuration](#configuration)
- [Monitoring and Maintenance](#monitoring-and-maintenance)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

- RHEL 9.x or compatible distribution
- Podman 4.x or later
- Python 3.11+ (for development/testing)
- Node.js 20+ (for frontend development)
- At least 2GB RAM
- 10GB disk space

### Install Podman

```bash
# RHEL 9
sudo dnf install -y podman podman-compose

# Verify installation
podman --version
```

## Quick Start with Podman Compose

The fastest way to deploy RedFixer for development or testing.

### 1. Clone the Repository

```bash
git clone https://github.com/jsherman999/RedFixer_claudecode_opus_superpowers.git
cd RedFixer_claudecode_opus_superpowers
```

### 2. Create Configuration File

```bash
cat > config.yaml <<EOF
api:
  host: "0.0.0.0"
  port: 8000
  api_key: "$(openssl rand -hex 32)"
  debug: false

database:
  db_path: "/app/data/redfixer.db"

scanner:
  nmap:
    enabled: true
    binary_path: "/usr/bin/nmap"
  nuclei:
    enabled: true
    binary_path: "/usr/bin/nuclei"
  openvas:
    enabled: false
EOF
```

### 3. Build Images

```bash
# Build backend
podman build -t redfixer-backend:latest -f backend/Containerfile backend/

# Build frontend
podman build -t redfixer-frontend:latest -f frontend/Containerfile frontend/
```

### 4. Deploy with Podman Compose

```bash
podman-compose up -d
```

### 5. Verify Deployment

```bash
# Check containers
podman ps

# Check backend health
curl http://localhost:8000/api/v1/health

# Access frontend
# Open browser to http://localhost:8080
```

## Production Deployment with Systemd

For production environments, use systemd services for automatic startup and management.

### Option 1: Podman Pod Service (Recommended)

This approach manages both containers as a single pod.

#### 1. Build and Tag Images

```bash
cd /opt/redfixer
podman build -t localhost/redfixer-backend:latest -f backend/Containerfile backend/
podman build -t localhost/redfixer-frontend:latest -f frontend/Containerfile frontend/
```

#### 2. Create Configuration

```bash
sudo mkdir -p /etc/redfixer
sudo cp config.yaml /etc/redfixer/config.yaml
sudo chown root:root /etc/redfixer/config.yaml
sudo chmod 640 /etc/redfixer/config.yaml
```

#### 3. Install Systemd Service

```bash
sudo cp deployment/systemd/redfixer-pod.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable redfixer-pod.service
sudo systemctl start redfixer-pod.service
```

#### 4. Verify Service

```bash
sudo systemctl status redfixer-pod.service
podman pod ps
podman ps
```

### Option 2: Standalone Services

Deploy backend and frontend as separate systemd services (without containers).

#### 1. Create User and Directories

```bash
sudo useradd -r -s /bin/false redfixer
sudo mkdir -p /opt/redfixer/{backend,data}
sudo mkdir -p /etc/redfixer
sudo chown -R redfixer:redfixer /opt/redfixer
```

#### 2. Install Backend

```bash
cd /opt/redfixer/backend
sudo -u redfixer python3.11 -m venv .venv
sudo -u redfixer .venv/bin/pip install -e /path/to/redfixer/backend
```

#### 3. Install Configuration

```bash
sudo cp config.yaml /etc/redfixer/config.yaml
sudo chown root:redfixer /etc/redfixer/config.yaml
sudo chmod 640 /etc/redfixer/config.yaml
```

#### 4. Install and Start Service

```bash
sudo cp deployment/systemd/redfixer-backend.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable redfixer-backend.service
sudo systemctl start redfixer-backend.service
```

#### 5. Verify Service

```bash
sudo systemctl status redfixer-backend.service
sudo journalctl -u redfixer-backend.service -f
curl http://localhost:8000/api/v1/health
```

## Manual Container Deployment

For advanced use cases or custom deployments.

### Create Persistent Volume

```bash
podman volume create redfixer-data
```

### Run Backend Container

```bash
podman run -d \
  --name redfixer-backend \
  --publish 8000:8000 \
  --volume redfixer-data:/app/data:Z \
  --volume ./config.yaml:/app/config.yaml:ro,Z \
  --env REDFIXER_CONFIG=/app/config.yaml \
  --restart unless-stopped \
  localhost/redfixer-backend:latest
```

### Run Frontend Container

```bash
podman run -d \
  --name redfixer-frontend \
  --publish 8080:8080 \
  --env VITE_API_URL=http://localhost:8000/api/v1 \
  --restart unless-stopped \
  localhost/redfixer-frontend:latest
```

## Configuration

### Environment Variables

#### Backend

- `REDFIXER_CONFIG`: Path to config.yaml file
- `REDFIXER_DATABASE__DB_PATH`: Override database path
- `REDFIXER_API__API_KEY`: Override API key
- `REDFIXER_API__HOST`: API bind address (default: 0.0.0.0)
- `REDFIXER_API__PORT`: API port (default: 8000)

#### Frontend

- `VITE_API_URL`: Backend API URL (default: http://localhost:8000/api/v1)
- `VITE_API_KEY`: API key for backend authentication

### Configuration File

The `config.yaml` file controls all backend settings. Example:

```yaml
api:
  host: "0.0.0.0"
  port: 8000
  api_key: "your-secure-api-key-here"
  debug: false

database:
  db_path: "/app/data/redfixer.db"

scanner:
  nmap:
    enabled: true
    binary_path: "/usr/bin/nmap"
  nuclei:
    enabled: true
    binary_path: "/usr/bin/nuclei"
    template_path: "/opt/nuclei-templates"
  openvas:
    enabled: false
```

## Monitoring and Maintenance

### Health Checks

```bash
# Backend health
curl http://localhost:8000/api/v1/health

# Frontend health
curl http://localhost:8080/health
```

### Logs

```bash
# Podman compose logs
podman-compose logs -f

# Individual container logs
podman logs -f redfixer-backend
podman logs -f redfixer-frontend

# Systemd service logs
sudo journalctl -u redfixer-pod.service -f
sudo journalctl -u redfixer-backend.service -f
```

### Database Backup

```bash
# Using podman volume
podman run --rm \
  --volume redfixer-data:/data:ro \
  --volume $(pwd):/backup \
  registry.access.redhat.com/ubi9/ubi-minimal:latest \
  tar czf /backup/redfixer-backup-$(date +%Y%m%d).tar.gz /data

# Or copy from host
sudo cp /var/lib/containers/storage/volumes/redfixer-data/_data/redfixer.db \
  /backup/redfixer-$(date +%Y%m%d).db
```

### Update Containers

```bash
# Pull latest code
git pull

# Rebuild images
podman build -t localhost/redfixer-backend:latest -f backend/Containerfile backend/
podman build -t localhost/redfixer-frontend:latest -f frontend/Containerfile frontend/

# Restart services
sudo systemctl restart redfixer-pod.service
# OR
podman-compose down && podman-compose up -d
```

## Troubleshooting

### Container Won't Start

```bash
# Check logs
podman logs redfixer-backend

# Verify image exists
podman images | grep redfixer

# Check port availability
sudo ss -tlnp | grep 8000
```

### Permission Issues

```bash
# SELinux context for volumes
podman run --volume ./config.yaml:/app/config.yaml:ro,Z ...

# Check SELinux denials
sudo ausearch -m avc -ts recent | grep podman
```

### Database Connection Errors

```bash
# Verify volume exists
podman volume inspect redfixer-data

# Check database file permissions
podman exec redfixer-backend ls -la /app/data/
```

### Network Issues

```bash
# Verify port bindings
podman port redfixer-backend
podman port redfixer-frontend

# Check firewall
sudo firewall-cmd --list-all
sudo firewall-cmd --add-port=8000/tcp --permanent
sudo firewall-cmd --add-port=8080/tcp --permanent
sudo firewall-cmd --reload
```

### Frontend Can't Connect to Backend

1. Verify backend is running: `curl http://localhost:8000/api/v1/health`
2. Check CORS configuration in backend config.yaml
3. Verify frontend environment variables are set correctly
4. Check browser console for CORS errors

### Service Won't Start with Systemd

```bash
# Check service status
sudo systemctl status redfixer-pod.service

# View detailed logs
sudo journalctl -u redfixer-pod.service -n 100 --no-pager

# Verify systemd unit file syntax
systemd-analyze verify /etc/systemd/system/redfixer-pod.service
```

## Security Considerations

### Production Checklist

- [ ] Change default API key in config.yaml
- [ ] Use HTTPS with reverse proxy (nginx/Apache)
- [ ] Enable firewall rules for ports 8000 and 8080
- [ ] Regular security updates for container images
- [ ] Implement backup strategy for database
- [ ] Monitor logs for suspicious activity
- [ ] Use non-root containers (already configured)
- [ ] Enable SELinux (enabled by default on RHEL 9)

### Reverse Proxy Example (Nginx)

```nginx
server {
    listen 443 ssl http2;
    server_name redfixer.example.com;

    ssl_certificate /etc/ssl/certs/redfixer.crt;
    ssl_certificate_key /etc/ssl/private/redfixer.key;

    location /api/ {
        proxy_pass http://localhost:8000/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location / {
        proxy_pass http://localhost:8080/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Support

For issues and questions:
- GitHub Issues: https://github.com/jsherman999/RedFixer_claudecode_opus_superpowers/issues
- Documentation: See README.md in project root

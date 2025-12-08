#!/usr/bin/env bash
# RedFixer Podman Deployment Script
# Automates configuration setup and container deployment

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running from project root
if [[ ! -f "podman-compose.yml" ]]; then
    error "Must be run from the project root directory containing podman-compose.yml"
    exit 1
fi

info "Starting RedFixer deployment..."

# Step 3: Create configuration file
info "Step 1/4: Setting up configuration..."
if [[ -f "config.yaml" ]]; then
    warn "config.yaml already exists. Backing up to config.yaml.bak"
    cp config.yaml config.yaml.bak
fi

cp config.example.yaml config.yaml
success "Created config.yaml from config.example.yaml"

# Generate secure API key
API_KEY=$(openssl rand -hex 32)
info "Generated secure API key: ${API_KEY}"

# Replace the API key in config.yaml (macOS-compatible sed)
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    sed -i '' "s/change-me-in-production/${API_KEY}/" config.yaml
else
    # Linux
    sed -i "s/change-me-in-production/${API_KEY}/" config.yaml
fi

success "Updated config.yaml with secure API key"

# Display the API key for user reference
echo ""
info "=========================================="
info "Your API Key: ${API_KEY}"
info "Save this key - you'll need it for API calls"
info "=========================================="
echo ""

# Step 4: Check if podman-compose is installed
info "Step 2/4: Checking dependencies..."
if ! command -v podman-compose &> /dev/null; then
    error "podman-compose is not installed"
    info "Install with: pip install podman-compose"
    exit 1
fi

if ! command -v podman &> /dev/null; then
    error "podman is not installed"
    info "Install with: brew install podman (macOS) or dnf install podman (RHEL/Fedora)"
    exit 1
fi

success "podman and podman-compose are installed"

# Step 5: Build containers
info "Step 3/4: Building containers (this may take a few minutes)..."
podman-compose build

success "Containers built successfully"

# Step 6: Start containers
info "Step 4/4: Starting containers..."
podman-compose up -d

success "Containers started successfully"

# Verify deployment
echo ""
info "Verifying deployment..."
sleep 3  # Give containers time to start

# Check if containers are running
if podman ps --format "{{.Names}}" | grep -q "redfixer-backend"; then
    success "Backend container is running"
else
    error "Backend container is not running"
    info "Check logs with: podman-compose logs backend"
fi

if podman ps --format "{{.Names}}" | grep -q "redfixer-frontend"; then
    success "Frontend container is running"
else
    error "Frontend container is not running"
    info "Check logs with: podman-compose logs frontend"
fi

# Test backend health endpoint
echo ""
info "Testing backend health endpoint..."
if curl -s -f http://localhost:8000/api/v1/health > /dev/null 2>&1; then
    success "Backend API is responding at http://localhost:8000"
else
    warn "Backend API health check failed (container may still be starting)"
    info "Wait a moment and try: curl http://localhost:8000/api/v1/health"
fi

# Final instructions
echo ""
success "=========================================="
success "RedFixer deployment complete!"
success "=========================================="
echo ""
info "Access the application:"
info "  - Frontend UI:  http://localhost:8080"
info "  - Backend API:  http://localhost:8000"
info "  - API Docs:     http://localhost:8000/docs"
echo ""
info "Useful commands:"
info "  - View logs:       podman-compose logs -f"
info "  - Stop containers: podman-compose down"
info "  - Restart:         podman-compose restart"
info "  - Check status:    podman ps"
echo ""
info "Configuration saved to: config.yaml"
info "API Key: ${API_KEY}"
echo ""

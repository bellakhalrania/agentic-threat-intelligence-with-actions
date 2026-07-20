#!/bin/bash
# ============================================================
# deploy.sh — Production deployment script
# Agentic Threat Intelligence Platform
#
# Usage:
#   ./deploy.sh                    # Full deploy (build + start)
#   ./deploy.sh --no-cache         # Full deploy without cache
#   ./deploy.sh --update           # Pull latest + rebuild + restart
#   ./deploy.sh --rollback         # Rollback to previous version
#   ./deploy.sh --status           # Check deployment status
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

COMPOSE_FILES="-f docker-compose.yml -f docker-compose.prod.yml"
BACKUP_DIR="${SCRIPT_DIR}/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ---- Pre-flight checks ----

preflight_checks() {
    log_info "Running pre-flight checks..."

    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi

    # Check Docker Compose
    if ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not available."
        exit 1
    fi

    # Check .env file
    if [ ! -f .env ]; then
        log_error ".env file not found. Copy .env.example to .env and fill in the values."
        exit 1
    fi

    # Check required API keys
    if grep -q "your_groq_api_key_here" .env 2>/dev/null; then
        log_error "GROQ_API_KEY is not set in .env. Please configure it first."
        exit 1
    fi

    # Check nginx SSL certificates
    if [ ! -f nginx/ssl/cert.pem ] || [ ! -f nginx/ssl/key.pem ]; then
        log_warn "SSL certificates not found. Generating self-signed certificates..."
        mkdir -p nginx/ssl
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout nginx/ssl/key.pem \
            -out nginx/ssl/cert.pem \
            -subj "/C=TN/ST=Tunisia/L=Tunis/O=ThreatIntel/CN=localhost" 2>/dev/null
        log_info "Self-signed certificates generated."
        log_warn "Replace with Let's Encrypt certificates for production use."
    fi

    log_info "Pre-flight checks passed."
}

# ---- Backup current data ----

backup_current() {
    log_info "Creating backup of current data..."
    mkdir -p "$BACKUP_DIR"

    # Backup threat_intel_data volume
    if docker volume inspect threat_intel_data &> /dev/null; then
        docker run --rm -v threat_intel_data:/data -v "$BACKUP_DIR":/backup \
            alpine tar czf "/backup/threat_intel_data_${TIMESTAMP}.tar.gz" \
            -C /data . 2>/dev/null || true
        log_info "Backed up threat_intel_data"
    fi

    # Backup neo4j_data volume
    if docker volume inspect neo4j_data &> /dev/null; then
        docker run --rm -v neo4j_data:/data -v "$BACKUP_DIR":/backup \
            alpine tar czf "/backup/neo4j_data_${TIMESTAMP}.tar.gz" \
            -C /data . 2>/dev/null || true
        log_info "Backed up neo4j_data"
    fi

    log_info "Backup complete: ${BACKUP_DIR}/"
}

# ---- Deploy ----

deploy() {
    local cache_flag="$1"

    preflight_checks
    backup_current

    log_info "Building Docker images..."
    if [ "$cache_flag" = "--no-cache" ]; then
        docker compose $COMPOSE_FILES build --no-cache
    else
        docker compose $COMPOSE_FILES build
    fi

    log_info "Stopping existing services..."
    docker compose $COMPOSE_FILES down --remove-orphans 2>/dev/null || true

    log_info "Starting services..."
    docker compose $COMPOSE_FILES up -d

    log_info "Waiting for services to be healthy..."
    sleep 10

    # Check health
    if curl -sf http://localhost:8000/health > /dev/null 2>&1; then
        log_info "API is healthy!"
    else
        log_warn "API health check failed. Check logs with: make logs"
    fi

    log_info "============================================"
    log_info "  Deployment complete!"
    log_info "  API: https://localhost"
    log_info "  Docs: https://localhost/docs"
    log_info "  Neo4j: http://localhost:7474"
    log_info "============================================"
}

# ---- Update (pull latest code + redeploy) ----

update() {
    log_info "Pulling latest code from repository..."
    git pull

    log_info "Rebuilding and restarting..."
    deploy "--no-cache"
}

# ---- Rollback ----

rollback() {
    log_info "Rolling back to previous version..."

    # Find the most recent backup
    local latest_backup=$(ls -t "$BACKUP_DIR"/*.tar.gz 2>/dev/null | head -1)
    if [ -z "$latest_backup" ]; then
        log_error "No backups found to rollback to."
        exit 1
    fi

    log_info "Found backup: $latest_backup"

    # Restore from backup
    local backup_name=$(basename "$latest_backup")
    if echo "$backup_name" | grep -q "neo4j"; then
        docker run --rm -v neo4j_data:/data -v "$BACKUP_DIR":/backup \
            alpine tar xzf "/backup/$backup_name" -C /data
    elif echo "$backup_name" | grep -q "threat_intel_data"; then
        docker run --rm -v threat_intel_data:/data -v "$BACKUP_DIR":/backup \
            alpine tar xzf "/backup/$backup_name" -C /data
    fi

    # Restart with previous Docker image
    log_info "Restarting services..."
    docker compose $COMPOSE_FILES up -d

    log_info "Rollback complete."
}

# ---- Status ----

status() {
    echo ""
    echo "=== Service Status ==="
    docker compose $COMPOSE_FILES ps

    echo ""
    echo "=== Resource Usage ==="
    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" \
        $(docker compose $COMPOSE_FILES ps -q) 2>/dev/null || true

    echo ""
    echo "=== API Health ==="
    curl -s http://localhost:8000/health | python3 -m json.tool 2>/dev/null || echo "API not reachable"

    echo ""
    echo "=== Volume Sizes ==="
    for vol in threat_intel_data neo4j_data; do
        if docker volume inspect "$vol" &> /dev/null; then
            local size=$(docker run --rm -v "$vol":/data alpine du -sh /data 2>/dev/null | cut -f1)
            echo "  $vol: $size"
        fi
    done
}

# ---- Main ----

main() {
    case "${1:-deploy}" in
        deploy)
            deploy "${2:-}"
            ;;
        --no-cache)
            deploy "--no-cache"
            ;;
        --update)
            update
            ;;
        --rollback)
            rollback
            ;;
        --status)
            status
            ;;
        --help|-h)
            echo "Usage: $0 [OPTION]"
            echo ""
            echo "Options:"
            echo "  deploy        Full deployment (build + start) [default]"
            echo "  --no-cache    Full deployment without cache"
            echo "  --update      Pull latest code + rebuild + restart"
            echo "  --rollback    Rollback to previous version"
            echo "  --status      Check deployment status"
            echo "  --help        Show this help"
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Usage: $0 [deploy|--no-cache|--update|--rollback|--status|--help]"
            exit 1
            ;;
    esac
}

main "$@"
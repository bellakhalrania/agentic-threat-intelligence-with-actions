#!/usr/bin/env bash
set -euo pipefail

# Pull Wazuh alerts from manager container into local project file,
# then trigger investigation through app.py API.

PROJECT_DIR="/home/rania/Documents/agentic-threat-intelligence-with-actions"
ALERTS_DST="$PROJECT_DIR/data/wazuh_logs/alerts.json"
WAZUH_CONTAINER="single-node_wazuh.manager_1"
WAZUH_SRC="/var/ossec/logs/alerts/alerts.json"
INVESTIGATE_URL="http://127.0.0.1:8000/investigate/connector/wazuh"
OWNER_USER="rania"
OWNER_GROUP="rania"

LOG_PREFIX="[pull_wazuh_and_investigate]"

echo "$LOG_PREFIX $(date -u +%Y-%m-%dT%H:%M:%SZ) starting"

cd "$PROJECT_DIR"
mkdir -p "$PROJECT_DIR/data/wazuh_logs"

# 1) Pull current alerts.json from Wazuh manager container
docker cp "$WAZUH_CONTAINER:$WAZUH_SRC" "$ALERTS_DST"
chown "$OWNER_USER:$OWNER_GROUP" "$ALERTS_DST"
chmod 644 "$ALERTS_DST"

# 2) Trigger investigate connector endpoint
response=$(curl -sS -X POST "$INVESTIGATE_URL" -H "Content-Type: application/json")
echo "$LOG_PREFIX investigate response: $response"

echo "$LOG_PREFIX $(date -u +%Y-%m-%dT%H:%M:%SZ) completed"
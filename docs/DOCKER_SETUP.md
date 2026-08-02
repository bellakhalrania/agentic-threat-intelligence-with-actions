# Docker Integration with Wazuh

This guide explains how to integrate the Agentic Threat Intelligence Platform with your existing Wazuh Docker setup using shared volumes.

## Architecture

```
┌────────────────────────────────────────－－－－─────────┐
│                    Docker Network                        │
├────────────────────────────────────────－－－－─────────┤
│                                                           │
│  ┌──────────────────┐         ┌──────────────────────┐ │
│  │   Wazuh Manager  │         │ Threat Intel Platform │ │
│  │                  │         │                      │ │
│  │  /var/ossec/logs/│────────▶│  /app/data/wazuh_logs/ │ │
│  │  alerts/         │  Shared │  (read-only)         │ │
│  │  alerts.json     │  Volume │                      │ │
│  └──────────────────┘         └──────────────────────┘ │
│                                                           │
└────────────────────────────────────────－－－－－－－－─┘
```

## Step 1: Update Your Wazuh Docker Compose

Add the shared volume to your existing Wazuh docker-compose.yml:

```yaml
# In your Wazuh docker-compose.yml
services:
  wazuh.manager:
    # ... existing configuration ...
    volumes:
      - wazuh_logs:/var/ossec/logs/alerts  # Add this line

volumes:
  wazuh_logs:
    external: true  # Important: make it external so it can be shared
```

**Important**: Set `external: true` so the volume can be shared between compose files.

## Step 2: Create the External Volume

If the volume doesn't exist yet, create it:

```bash
docker volume create wazuh_logs
```

## Step 3: Restart Wazuh with New Configuration

```bash
cd ~/wazuh-docker/wazuh-docker/single-node
docker-compose down
docker-compose up -d
```

Verify the volume is mounted:

```bash
docker exec -it single-node-wazuh.manager-1 ls -l /var/ossec/logs/alerts
```

## Step 4: Configure Threat Intelligence Platform

Navigate to the threat intelligence project:

```bash
cd ~/Documents/agentic-threat-intelligence-with-actions
```

Update `.env` file:

```bash
# Copy example
cp .env.example .env

# Edit .env with your API keys
nano .env
```

Required environment variables:
```bash
GROQ_API_KEY=your_groq_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
OTX_API_KEY=your_otx_api_key
NEO4J_URI=bolt://neo4j:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=changeme
WAZUH_ALERTS_PATH=/app/data/wazuh_logs/alerts.json
```

## Step 5: Start Threat Intelligence Platform

```bash
# Build and start the services
docker-compose up -d

# View logs
docker-compose logs -f threat-intel
```

## Step 6: Verify Integration

Check that the Wazuh logs are accessible:

```bash
# Inside the threat-intel container
docker exec -it threat-intel-platform ls -la /app/data/wazuh_logs/

# Should show alerts.json from Wazuh
```

Test the connector:

```bash
# Run a single investigation
docker exec -it threat-intel-platform python main.py --source wazuh
```

## Step 7: Enable Continuous Monitoring

For continuous monitoring, use the monitor script:

```bash
# Update docker-compose.yml command or run manually
docker exec -it threat-intel-platform python monitor.py --source wazuh --interval 30
```

Or update the docker-compose.yml to run monitor by default:

```yaml
services:
  threat-intel:
    # ... existing config ...
    command: ["python", "monitor.py", "--source", "wazuh", "--interval", "30"]
```

## Troubleshooting

### Issue: Volume not accessible

**Check if volume exists:**
```bash
docker volume ls | grep wazuh_logs
```

**Create if missing:**
```bash
docker volume create wazuh_logs
```

### Issue: Permission denied on alerts.json

The volume is mounted read-only in the threat-intel container. If you get permission errors, check that the Wazuh container has proper permissions:

```bash
docker exec -it single-node-wazuh.manager-1 ls -l /var/ossec/logs/alerts/alerts.json
```

### Issue: No alerts found

Check that alerts.json has content:

```bash
docker exec -it threat-intel-platform cat /app/data/wazuh_logs/alerts.json | head -n 5
```

### Issue: Container can't connect to Neo4j

Ensure both containers are on the same network:

```bash
docker network inspect threat-intel-network
```

Both containers should be listed in the network.

## Alternative: Manual Volume Creation

If you prefer not to use external volumes, you can modify the docker-compose.yml to create the volume:

```yaml
# In threat-intel docker-compose.yml
volumes:
  wazuh_logs:  # Remove external: true
  neo4j_data:
```

And in your Wazuh docker-compose.yml:

```yaml
volumes:
  wazuh_logs:  # Remove external: true
```

Then start Wazuh first to create the volume, then start threat-intel.

## Network Configuration

Both containers should be on the same Docker network. The docker-compose.yml creates a network called `threat-intel-network`.

If your Wazuh is on a different network, you can either:

1. **Add Wazuh to the threat-intel network:**
   ```yaml
   # In Wazuh docker-compose.yml
   services:
     wazuh.manager:
       networks:
         - threat-intel-network
   
   networks:
     threat-intel-network:
       external: true
   ```

2. **Use host networking for threat-intel:**
   ```yaml
   services:
     threat-intel:
       network_mode: host
   ```

## Verification Commands

```bash
# Check volume is mounted in Wazuh
docker exec -it single-node-wazuh.manager-1 df -h | grep alerts

# Check volume is mounted in threat-intel
docker exec -it threat-intel-platform df -h | grep wazuh_logs

# Check alerts.json is accessible
docker exec -it threat-intel-platform wc -l /app/data/wazuh_logs/alerts.json

# Test connector
docker exec -it threat-intel-platform python -c "
from connectors.wazuh_connector import WazuhConnector
c = WazuhConnector()
events = c.fetch_events()
print(f'Fetched {len(events)} events')
"
```

## Summary

With this setup:
1. Wazuh writes alerts to `/var/ossec/logs/alerts/alerts.json`
2. The `wazuh_logs` volume is shared between containers
3. Threat Intel Platform reads from `/app/data/wazuh_logs/alerts.json` (read-only)
4. No file copying or API calls needed
5. Real-time access to Wazuh alerts
6. Clean separation of concerns

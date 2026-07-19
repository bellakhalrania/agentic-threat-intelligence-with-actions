# FastAPI Documentation

## Overview

The Agentic Threat Intelligence Platform now includes a REST API built with FastAPI. This API provides programmatic access to the threat intelligence investigation pipeline, including Wazuh connector integration.

## Installation

The API dependencies are already included in `requirements.txt`:

```txt
fastapi>=0.109.0
uvicorn>=0.27.0
```

## Running the API

### Development Mode

```bash
uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

### Production Mode

```bash
uvicorn app:app --host 0.0.0.0 --port 8000 --workers 4
```

## API Documentation

Once the server is running, access the interactive API documentation:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## Endpoints

### Health Check

#### GET `/health`

Check if the API is running.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2026-07-18T12:04:43.123456",
  "version": "1.0.0"
}
```

### Investigate Events

#### POST `/investigate`

Investigate security events with flexible input options.

**Request Body:**
```json
{
  "events": [
    {
      "timestamp": "2026-07-18T10:15:00Z",
      "source": "wazuh",
      "rule_description": "PowerShell execution"
    }
  ],
  "source": {
    "type": "file",
    "path": "./data/events.json"
  }
}
```

**Response:**
```json
{
  "success": true,
  "report": "# Threat Intelligence Report...",
  "response_actions": [...],
  "campaign_id": "123e4567-...",
  "events_processed": 3
}
```

### Investigate from File

#### POST `/investigate/file/{file_path}`

Investigate events from a JSON file.

**Example:**
```bash
curl -X POST "http://localhost:8000/investigate/file/./data/test_wazuh_alerts_realistic.json"
```

### Investigate from Connector

#### POST `/investigate/connector/{connector_name}`

Investigate events from a connector (e.g., Wazuh).

**Query Parameters:**
- `test_data` (optional): Path to test data file

**Example:**
```bash
curl -X POST "http://localhost:8000/investigate/connector/wazuh?test_data=./data/test_wazuh_alerts_realistic.json"
```

### List Connectors

#### GET `/connectors`

List available connectors.

**Response:**
```json
{
  "connectors": [
    {
      "name": "wazuh",
      "description": "Wazuh security alerts",
      "modes": ["file", "api"]
    }
  ]
}
```

### Get Configuration

#### GET `/config`

Get current configuration (sensitive values masked).

**Response:**
```json
{
  "wazuh": {
    "api_url": "https://localhost:55000",
    "api_user": "wazuh-wui",
    "alerts_path": "/app/data/wazuh_logs/alerts.json",
    "poll_interval": 30,
    "verify_ssl": false
  },
  "threat_intel": {
    "abuseipdb_configured": true,
    "otx_configured": true,
    "groq_configured": true
  }
}
```

## Usage Examples

### Example 1: Investigate Wazuh Alerts

```bash
curl -X POST "http://localhost:8000/investigate/connector/wazuh?test_data=./data/test_wazuh_alerts_realistic.json"
```

### Example 2: Investigate from File

```bash
curl -X POST "http://localhost:8000/investigate/file/./data/raw_logs/4_wazuh_insider_exfil.json"
```

### Example 3: Direct Event Submission

```bash
curl -X POST "http://localhost:8000/investigate" \
  -H "Content-Type: application/json" \
  -d '{
    "events": [
      {
        "timestamp": "2026-07-18T10:15:00Z",
        "source": "wazuh",
        "rule_description": "PowerShell execution"
      }
    ]
  }'
```

### Example 4: Using Python Requests

```python
import requests

# Investigate Wazuh alerts
response = requests.post(
    "http://localhost:8000/investigate/connector/wazuh",
    params={"test_data": "./data/test_wazuh_alerts_realistic.json"}
)

result = response.json()
print(result["report"])
```

## Error Handling

The API returns appropriate HTTP status codes:

- `200 OK`: Successful request
- `400 Bad Request`: Invalid request parameters
- `404 Not Found`: File or resource not found
- `500 Internal Server Error`: Server error during investigation

**Error Response Example:**
```json
{
  "detail": "File not found: ./data/missing.json"
}
```

## Integration with Wazuh

The API integrates with the Wazuh connector to fetch and investigate alerts:

1. **File Mode**: Reads from Wazuh alerts.json file
2. **API Mode**: Fetches from Wazuh REST API
3. **Test Mode**: Uses sample data for testing

## Docker Integration

To run the API in Docker, update the docker-compose.yml:

```yaml
services:
  threat-intel:
    # ... existing config ...
    command: ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
    ports:
      - "8000:8000"
```

## Security Considerations

1. **Authentication**: Currently no authentication - add API keys or OAuth for production
2. **Rate Limiting**: Implement rate limiting for production use
3. **HTTPS**: Use HTTPS in production environments
4. **Input Validation**: FastAPI provides automatic validation via Pydantic
5. **Sensitive Data**: Configuration endpoint masks sensitive values

## Performance

- FastAPI provides async support for better performance
- Consider using background tasks for long-running investigations
- Implement caching for repeated investigations
- Use connection pooling for database/API calls

## Monitoring

Add monitoring endpoints for production:

```python
@app.get("/metrics")
async def metrics():
    # Return application metrics
    pass
```

## Testing

Test the API endpoints:

```bash
# Health check
curl http://localhost:8000/health

# List connectors
curl http://localhost:8000/connectors

# Get config
curl http://localhost:8000/config

# Investigate test data
curl -X POST "http://localhost:8000/investigate/connector/wazuh?test_data=./data/test_wazuh_alerts_realistic.json"
```

## Future Enhancements

- Add WebSocket support for real-time updates
- Implement background task queue for async investigations
- Add authentication/authorization
- Implement rate limiting
- Add comprehensive logging and monitoring
- Support for additional connectors (Sysmon, Suricata, etc.)
- Batch investigation endpoint
- Investigation history and retrieval

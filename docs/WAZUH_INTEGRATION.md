# Wazuh Integration Documentation

## Overview

This document describes the Wazuh connector integration for the Agentic Threat Intelligence Platform. The connector enables real-time ingestion of Wazuh security alerts into the investigation pipeline while maintaining compatibility with the existing offline workflow.

## Architecture

### New Workflow

```
Wazuh (alerts.json or REST API)
    ↓
WazuhConnector (connectors/wazuh_connector.py)
    ↓
CollectionAgent (normalization)
    ↓
IOC Extraction
    ↓
IOC Enrichment (Threat Intel Providers)
    ↓
ATT&CK Mapping (Deterministic Rules)
    ↓
Correlation (Evidence-based Summary)
    ↓
Prediction
    ↓
Reporting
    ↓
Response Actions
```

### Key Design Decisions

#### 1. **Connector Interface Pattern**
- **Decision**: Created abstract `BaseConnector` interface with `fetch_events()` method
- **Rationale**: Enables pluggable architecture for future connectors (Sysmon, Suricata, Zeek, Microsoft Defender, CrowdStrike)
- **Benefit**: Each connector implements the same interface, ensuring downstream agents receive consistent data regardless of source

#### 2. **Dual-Mode Operation**
- **Decision**: WazuhConnector supports both file-based and API-based ingestion
- **Rationale**: File mode for testing/development, API mode for production
- **Benefit**: Easy testing without requiring live Wazuh deployment

#### 3. **State Tracking for Deduplication**
- **Decision**: Connector tracks `_last_timestamp` and `_processed_ids` to avoid duplicate processing
- **Rationale**: Wazuh alerts are persistent; re-reading the same file should not reprocess old alerts
- **Benefit**: Enables continuous monitoring without duplicate investigations

#### 4. **Preservation of Original Events**
- **Decision**: CollectionAgent preserves original event data in `raw` field
- **Rationale**: Traceability and debugging require access to source-specific data
- **Benefit**: Analysts can always trace back to the original Wazuh alert

#### 5. **No Downstream Modifications**
- **Decision**: All downstream agents (IOC extraction, ATT&CK mapping, reporting) remain unchanged
- **Rationale**: CollectionAgent already handles Wazuh normalization via `_normalize_wazuh()`
- **Benefit**: Minimal risk, existing functionality preserved

## File Structure

```
connectors/
├── __init__.py           # Package initialization
├── base.py               # BaseConnector abstract interface
└── wazuh_connector.py    # Wazuh implementation

data/
└── sample_wazuh_alerts.json  # Sample data for testing

config.py                 # Added Wazuh configuration variables
main.py                   # Modified for dual source support
monitor.py                # New continuous monitoring script
```

## Configuration

### Environment Variables

Add to `.env` file:

```bash
# Wazuh Connector Configuration
WAZUH_API_URL=https://localhost:55000
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASSWORD=your_password_here
WAZUH_ALERTS_PATH=/var/ossec/logs/alerts/alerts.json
WAZUH_POLL_INTERVAL=30
```

### Configuration Classes

Updated `config.py` with:

```python
WAZUH_API_URL = os.getenv("WAZUH_API_URL", "https://localhost:55000")
WAZUH_API_USER = os.getenv("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASSWORD = os.getenv("WAZUH_API_PASSWORD", "")
WAZUH_ALERTS_PATH = os.getenv("WAZUH_ALERTS_PATH", "/var/ossec/logs/alerts/alerts.json")
WAZUH_POLL_INTERVAL = int(os.getenv("WAZUH_POLL_INTERVAL", "30"))
```

## Usage

### Offline Mode (Original)

```bash
python main.py --events data/sample_events/sample_events.json
```

### Live Mode with Wazuh (File-based)

```bash
python main.py --source wazuh
```

### Live Mode with Wazuh (API-based)

```bash
python main.py --source wazuh --use-api
```

### Testing with Sample Data

```bash
python main.py --source wazuh --test-data data/sample_wazuh_alerts.json
```

### Continuous Monitoring

```bash
python monitor.py --source wazuh --interval 30
```

## Connector Implementation

### BaseConnector Interface

```python
class BaseConnector(ABC):
    @abstractmethod
    def fetch_events(self) -> List[Dict]:
        """Fetch new events from the data source."""
        pass
    
    @abstractmethod
    def get_last_event_timestamp(self) -> Optional[str]:
        """Get the timestamp of the last processed event."""
        pass
    
    def reset_state(self) -> None:
        """Reset internal state for reprocessing."""
        pass
```

### WazuhConnector Features

1. **Dual Format Support**
   - Line-by-line JSON (standard Wazuh format)
   - JSON array (for testing)

2. **Deduplication**
   - Tracks processed alert IDs
   - Tracks last processed timestamp
   - Only returns new alerts on each call

3. **API Integration**
   - Supports Wazuh REST API
   - Query alerts since last timestamp
   - Basic authentication

4. **Error Handling**
   - Graceful degradation on file read errors
   - API timeout handling
   - JSON parsing error recovery

## Normalization Flow

### Wazuh Alert Structure

```json
{
  "version": 1,
  "timestamp": "2026-06-20T10:15:00Z",
  "rule": {
    "level": 6,
    "description": "PowerShell command execution",
    "groups": ["windows", "powershell"]
  },
  "agent": {
    "id": "001",
    "name": "WORKSTATION-07"
  },
  "id": "15750000-0000-0000-0000-000000000001",
  "full_log": "powershell.exe -enc JABzAD0AT..."
}
```

### Normalized Event (CollectionAgent)

```python
{
  "event_id": "generated-or-preserved",
  "source": "wazuh",
  "event_type": "wazuh_alert",
  "timestamp": "2026-06-20T10:15:00Z",
  "host": "WORKSTATION-07",
  "rule_description": "PowerShell command execution",
  "rule_level": 6,
  "rule_groups": ["windows", "powershell"],
  "severity": 6,
  "raw": {...}  # Original Wazuh alert preserved
}
```

## Example: Normalized Wazuh Alert Flow

### Input (Wazuh Alert)

```json
{
  "version": 1,
  "timestamp": "2026-06-20T10:15:00Z",
  "rule": {
    "level": 6,
    "description": "PowerShell command execution",
    "groups": ["windows", "powershell"]
  },
  "agent": {
    "id": "001",
    "name": "WORKSTATION-07"
  },
  "id": "15750000-0000-0000-0000-000000000001",
  "full_log": "powershell.exe -enc JABzAD0AT..."
}
```

### After CollectionAgent Normalization

```python
{
  "event_id": "15750000-0000-0000-0000-000000000001",
  "source": "wazuh",
  "event_type": "wazuh_alert",
  "timestamp": "2026-06-20T10:15:00Z",
  "host": "WORKSTATION-07",
  "rule_description": "PowerShell command execution",
  "rule_level": 6,
  "rule_groups": ["windows", "powershell"],
  "severity": 6,
  "raw": {
    "version": 1,
    "timestamp": "2026-06-20T10:15:00Z",
    "rule": {...},
    "agent": {...},
    "id": "15750000-0000-0000-0000-000000000001",
    "full_log": "powershell.exe -enc JABzAD0AT..."
  }
}
```

### After IOC Extraction

```python
[
  {
    "type": "process",
    "value": "powershell.exe",
    "source_event_id": "15750000-0000-0000-0000-000000000001",
    "confidence": 1.0
  }
]
```

### After IOC Enrichment

```python
{
  "value": "powershell.exe",
  "ioc_type": "process",
  "reputation": "unknown",
  "confidence": 0.0,
  "source": "",
  "raw": {...}
}
```

### After ATT&CK Mapping

```python
{
  "attack_id": "T1059.001",
  "technique_name": "PowerShell",
  "confidence": 1.0,
  "rule_name": "powershell_execution",
  "matched_on": "process_name == 'powershell.exe'",
  "evidence_event_id": "15750000-0000-0000-0000-000000000001",
  "mapping_source": "deterministic_rule",
  "known_groups": ["APT28", "Lazarus", "APT42"],
  "known_software": [],
  "recommended_mitigations": ["Disable PowerShell", "Enforce execution policies"]
}
```

## Future Connectors

To add a new connector (e.g., Sysmon, Suricata, Zeek):

1. Create `connectors/<connector>_connector.py`
2. Implement `BaseConnector` interface
3. Add connector choice to `main.py` argument parser
4. Add configuration variables to `config.py`
5. Update documentation

Example:

```python
# connectors/sysmon_connector.py
from connectors.base import BaseConnector

class SysmonConnector(BaseConnector):
    def fetch_events(self) -> List[Dict]:
        # Implement Sysmon event fetching
        pass
    
    def get_last_event_timestamp(self) -> Optional[str]:
        # Return last processed timestamp
        pass
```

## Testing

### Unit Tests

```python
# tests/test_wazuh_connector.py
def test_wazuh_connector_fetch_events():
    connector = WazuhConnector(test_data_path="data/sample_wazuh_alerts.json")
    events = connector.fetch_events()
    assert len(events) == 3
    assert events[0]["rule"]["description"] == "PowerShell command execution"

def test_wazuh_connector_deduplication():
    connector = WazuhConnector(test_data_path="data/sample_wazuh_alerts.json")
    events1 = connector.fetch_events()
    events2 = connector.fetch_events()
    assert len(events1) == 3
    assert len(events2) == 0  # No new events
```

### Integration Tests

```bash
# Test with sample data
python main.py --source wazuh --test-data data/sample_wazuh_alerts.json

# Test continuous monitoring (short interval)
python monitor.py --source wazuh --interval 5
```

## Troubleshooting

### Issue: No events fetched

**Check**:
- Wazuh alerts file path is correct
- File exists and is readable
- File format is valid JSON (line-by-line or array)

**Solution**:
```bash
# Verify file exists
ls -la /var/ossec/logs/alerts/alerts.json

# Check file format
head -n 5 /var/ossec/logs/alerts/alerts.json
```

### Issue: API connection fails

**Check**:
- Wazuh API URL is correct
- Credentials are valid
- SSL certificate is trusted (or disable verification for testing)

**Solution**:
```bash
# Test API connection
curl -k -u wazuh-wui:password https://localhost:55000/
```

### Issue: Duplicate events processed

**Check**:
- Connector state is being reset
- Timestamps are not monotonic

**Solution**:
- Ensure connector instance is persistent
- Check timestamp format consistency

## Performance Considerations

1. **File Polling**: Reading entire file on each poll can be expensive for large alert files
   - **Mitigation**: Consider file position tracking for large deployments

2. **API Rate Limits**: Wazuh API may have rate limits
   - **Mitigation**: Implement exponential backoff in API mode

3. **Memory Usage**: Tracking all processed IDs can consume memory
   - **Mitigation**: Implement periodic cleanup of old IDs

## Security Considerations

1. **API Credentials**: Store in environment variables, never in code
2. **SSL Verification**: Disable only for testing; enable in production
3. **File Permissions**: Ensure alerts file has appropriate permissions
4. **Network Security**: Use VPN/firewall rules to restrict API access

## Summary

The Wazuh connector integration provides:

- **Modular architecture** via BaseConnector interface
- **Dual-mode operation** (file/API) for flexibility
- **Deduplication** to prevent reprocessing
- **Traceability** via preserved original events
- **Zero downstream changes** to existing agents
- **Easy extensibility** for future connectors

The integration maintains backward compatibility while enabling real-time threat intelligence processing from Wazuh security alerts.

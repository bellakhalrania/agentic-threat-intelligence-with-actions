"""
connectors/wazuh_connector.py
Wazuh connector for ingesting security alerts from Wazuh.

Supports two modes:
1. File-based: Reads from Wazuh alerts.json file (default for testing)
2. API-based: Fetches alerts via Wazuh REST API (for production)

The connector tracks the last processed timestamp to avoid duplicate
processing and returns only new alerts on each fetch_events() call.
"""

import json
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional

import requests
from requests.auth import HTTPBasicAuth

from config import config
from connectors.base import BaseConnector

logger = logging.getLogger(__name__)


class WazuhConnector(BaseConnector):
    """Connector for Wazuh security alerts.
    
    This connector can operate in two modes:
    - File mode: Reads from Wazuh's alerts.json file (default)
    - API mode: Fetches alerts via Wazuh REST API
    
    The connector tracks the last processed timestamp to ensure
    only new alerts are returned on each call to fetch_events().
    """

    def __init__(
        self,
        use_api: bool = False,
        alerts_path: Optional[str] = None,
        api_url: Optional[str] = None,
        api_user: Optional[str] = None,
        api_password: Optional[str] = None,
        test_data_path: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
    ):
        """Initialize the Wazuh connector.
        
        Args:
            use_api: If True, use Wazuh REST API. If False, read from alerts.json file.
            alerts_path: Path to Wazuh alerts.json file. Defaults to config.WAZUH_ALERTS_PATH.
            api_url: Wazuh API URL. Defaults to config.WAZUH_API_URL.
            api_user: Wazuh API username. Defaults to config.WAZUH_API_USER.
            api_password: Wazuh API password. Defaults to config.WAZUH_API_PASSWORD.
            test_data_path: Path to sample JSON file for testing (overrides alerts_path).
            verify_ssl: Whether to verify SSL certificates. Defaults to config.WAZUH_VERIFY_SSL.
        """
        self.use_api = use_api
        self.alerts_path = test_data_path or alerts_path or config.WAZUH_ALERTS_PATH
        self.api_url = api_url or config.WAZUH_API_URL
        self.api_user = api_user or config.WAZUH_API_USER
        self.api_password = api_password or config.WAZUH_API_PASSWORD
        self.verify_ssl = verify_ssl if verify_ssl is not None else config.WAZUH_VERIFY_SSL
        
        # Track last processed timestamp to avoid duplicates
        self._last_timestamp: Optional[str] = None
        self._processed_ids: set = set()
        
        # For testing: allow overriding with sample data
        self._test_mode = test_data_path is not None

    def fetch_events(self) -> List[Dict]:
        """Fetch new alerts from Wazuh.
        
        Returns:
            List of raw Wazuh alert dicts. Each dict contains the
            original Wazuh alert structure. The CollectionAgent will
            normalize these to the common schema.
        """
        if self.use_api:
            return self._fetch_from_api()
        else:
            return self._fetch_from_file()

    def _fetch_from_file(self) -> List[Dict]:
        """Fetch alerts from Wazuh alerts.json file.
        
        Supports two formats:
        1. Line-by-line JSON (standard Wazuh format)
        2. JSON array (for testing/sample data)
        
        We read the file, filter for new alerts based on timestamp,
        and return them.
        """
        if not os.path.exists(self.alerts_path):
            logger.warning(f"Wazuh alerts file not found: {self.alerts_path}")
            return []

        new_alerts = []
        
        try:
            with open(self.alerts_path, 'r') as f:
                content = f.read().strip()
                
                if not content:
                    return []
                
                # Try to parse as JSON array first (test mode)
                if content.startswith('['):
                    try:
                        alerts = json.loads(content)
                        if isinstance(alerts, list):
                            for alert in alerts:
                                if self._is_new_alert(alert):
                                    new_alerts.append(alert)
                    except json.JSONDecodeError:
                        logger.warning("Failed to parse as JSON array, trying line-by-line")
                        # Fall through to line-by-line parsing
                else:
                    # Line-by-line parsing (standard Wazuh format)
                    for line in content.split('\n'):
                        line = line.strip()
                        if not line:
                            continue
                        
                        try:
                            alert = json.loads(line)
                            if self._is_new_alert(alert):
                                new_alerts.append(alert)
                        except json.JSONDecodeError:
                            logger.warning(f"Failed to parse alert line: {line[:100]}...")
                            continue
                            
        except IOError as e:
            logger.error(f"Error reading Wazuh alerts file: {e}")
            return []

        logger.info(f"Fetched {len(new_alerts)} new alerts from Wazuh file")
        return new_alerts

    def _is_new_alert(self, alert: Dict) -> bool:
        """Check if an alert is new (not processed yet)."""
        alert_timestamp = alert.get("timestamp")
        alert_id = alert.get("id")
        
        if alert_id in self._processed_ids:
            return False
        
        if self._last_timestamp and alert_timestamp:
            if alert_timestamp <= self._last_timestamp:
                return False
        
        # Mark as processed
        self._processed_ids.add(alert_id)
        
        # Update last timestamp
        if alert_timestamp:
            if self._last_timestamp is None or alert_timestamp > self._last_timestamp:
                self._last_timestamp = alert_timestamp
        
        return True

    def _fetch_from_api(self) -> List[Dict]:
        """Fetch alerts from Wazuh REST API.
        
        Uses the Wazuh API to query alerts since the last processed timestamp.
        """
        if not self.api_password:
            logger.warning("Wazuh API password not configured, cannot fetch from API")
            return []

        try:
            # Build query parameters
            params = {}
            if self._last_timestamp:
                params["q"] = f"timestamp>{self._last_timestamp}"
            
            # Make API request - correct Wazuh API endpoint
            url = f"{self.api_url}/api/alerts"
            auth = HTTPBasicAuth(self.api_user, self.api_password)
            
            # Use configured SSL verification setting
            response = requests.get(
                url,
                auth=auth,
                params=params,
                verify=self.verify_ssl,
                timeout=30
            )
            
            response.raise_for_status()
            data = response.json()
            
            # Extract alerts from response - Wazuh API returns data in different format
            alerts = data.get("data", [])
            if isinstance(alerts, dict):
                alerts = alerts.get("items", alerts)
            
            if not isinstance(alerts, list):
                logger.warning(f"Unexpected API response format: {type(alerts)}")
                return []
            
            # Filter for new alerts
            new_alerts = []
            for alert in alerts:
                alert_id = alert.get("id")
                alert_timestamp = alert.get("timestamp")
                
                if alert_id in self._processed_ids:
                    continue
                
                new_alerts.append(alert)
                self._processed_ids.add(alert_id)
                
                # Update last timestamp
                if alert_timestamp:
                    if self._last_timestamp is None or alert_timestamp > self._last_timestamp:
                        self._last_timestamp = alert_timestamp
            
            logger.info(f"Fetched {len(new_alerts)} new alerts from Wazuh API")
            return new_alerts
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching alerts from Wazuh API: {e}")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing Wazuh API response: {e}")
            return []

    def get_last_event_timestamp(self) -> Optional[str]:
        """Get the timestamp of the last processed event."""
        return self._last_timestamp

    def reset_state(self) -> None:
        """Reset internal state for reprocessing."""
        self._last_timestamp = None
        self._processed_ids.clear()
        logger.info("Wazuh connector state reset")

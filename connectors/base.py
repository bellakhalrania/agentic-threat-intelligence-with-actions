"""
connectors/base.py
Abstract base class for all telemetry connectors.

All connectors must implement the BaseConnector interface to ensure
compatibility with the investigation pipeline. This architecture allows
easy addition of new data sources (Sysmon, Suricata, Zeek, Microsoft Defender,
CrowdStrike, etc.) without modifying downstream agents.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Optional


class BaseConnector(ABC):
    """Abstract base class for telemetry connectors.
    
    Each connector is responsible for:
    - Fetching raw events from its source (API, file, database, etc.)
    - Tracking which events have been processed to avoid duplicates
    - Returning raw events in the format expected by CollectionAgent
    - Preserving original event data for traceability
    
    The CollectionAgent handles normalization to the common schema, so
    connectors should return raw source-specific events.
    """

    @abstractmethod
    def fetch_events(self) -> List[Dict]:
        """Fetch new events from the data source.
        
        Returns:
            List of raw event dicts from the source. Each dict should
            contain source-specific fields. The CollectionAgent will
            normalize these to the common schema.
            
        Note:
            Implementations should track which events have been processed
            to avoid returning duplicates on subsequent calls.
        """
        pass

    @abstractmethod
    def get_last_event_timestamp(self) -> Optional[str]:
        """Get the timestamp of the last processed event.
        
        Returns:
            ISO 8601 timestamp string of the last processed event,
            or None if no events have been processed yet.
            
        Note:
            This is used for checkpointing and resuming from the
            last processed position.
        """
        pass

    def reset_state(self) -> None:
        """Reset internal state (e.g., for testing or reprocessing).
        
        Default implementation does nothing. Override if your connector
        maintains persistent state that needs to be reset.
        """
        pass

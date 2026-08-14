"""
connectors/
Modular connector interface for ingesting security telemetry from various sources.
"""

from connectors.agent_connector import AgentConnector
from connectors.base import BaseConnector

__all__ = ["BaseConnector", "AgentConnector"]

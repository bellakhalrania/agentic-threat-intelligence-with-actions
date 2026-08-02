"""
intelligence/threat_intel/models.py
Data models for threat intelligence enrichment results.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class EnrichmentEvidence(BaseModel):
    """Raw evidence returned by a single threat intelligence provider.

    This is stored verbatim so analysts can audit the source data.
    """

    provider: str
    raw_response: Dict[str, Any]
    queried_at: datetime = Field(default_factory=datetime.utcnow)


class EnrichmentResult(BaseModel):
    """Merged enrichment result for a single IOC value.

    Attributes:
        value: The IOC string (e.g. "198.51.100.23", "evil.com").
        ioc_type: Normalized type — one of "ip", "domain", "url", "hash", "email".
        reputation: One of "benign", "suspicious", "malicious", "unknown".
            Never invented — always derived from provider data.
        confidence: Float 0.0–1.0 representing confidence in the reputation.
        tags: List of descriptive tags from providers (e.g. "tor", "malware", "phishing").
        first_seen: Earliest timestamp this IOC was observed by any provider, if available.
        last_seen: Most recent timestamp this IOC was observed by any provider, if available.
        source: Human-readable name of the provider(s) that contributed data.
        evidence: List of raw evidence blobs from each provider.
        raw: The original IOCModel fields preserved for downstream use.
    """

    value: str
    ioc_type: str
    reputation: str = "unknown"
    confidence: float = 0.0
    tags: List[str] = Field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    source: str = ""
    evidence: List[EnrichmentEvidence] = Field(default_factory=list)
    raw: Dict[str, Any] = Field(default_factory=dict)
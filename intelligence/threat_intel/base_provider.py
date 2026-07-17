"""
intelligence/threat_intel/base_provider.py
Abstract base class for all threat intelligence providers.

Each provider subclass must implement ``enrich`` which returns an
``EnrichmentResult`` for a single IOC value, or ``None`` if the provider
cannot handle that IOC type.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Set

from intelligence.threat_intel.models import EnrichmentEvidence, EnrichmentResult


class ThreatIntelProvider(ABC):
    """Base class for pluggable threat intelligence providers.

    Providers self-declare which IOC types they support via ``supported_types``.
    The registry uses this to dispatch IOCs to the right providers.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable provider name (e.g. "AbuseIPDB")."""
        ...

    @property
    @abstractmethod
    def supported_types(self) -> Set[str]:
        """Set of IOC types this provider can enrich.

        Values are the normalized types used in IOCModel: ipv4, ipv6, domain,
        url, email, md5, sha1, sha256.
        """
        ...

    @abstractmethod
    def enrich(self, ioc_type: str, value: str) -> Optional[EnrichmentResult]:
        """Enrich a single IOC.

        Args:
            ioc_type: Normalized IOC type (e.g. "ipv4", "domain", "md5").
            value: The IOC string to look up.

        Returns:
            An ``EnrichmentResult`` if the provider has data, or ``None``
            if the IOC was not found / not applicable.
        """
        ...

    def _normalize_ioc_type(self, ioc_type: str) -> str:
        """Map IOCModel types to enrichment types.

        Returns one of: ip, domain, url, hash, email.
        """
        mapping: Dict[str, str] = {
            "ipv4": "ip",
            "ipv6": "ip",
            "domain": "domain",
            "url": "url",
            "email": "email",
            "md5": "hash",
            "sha1": "hash",
            "sha256": "hash",
        }
        return mapping.get(ioc_type, "unknown")

    def _build_evidence(self, raw_response: dict) -> EnrichmentEvidence:
        return EnrichmentEvidence(
            provider=self.name,
            raw_response=raw_response,
        )
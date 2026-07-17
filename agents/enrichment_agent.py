"""
agents/enrichment_agent.py
Extracts indicators of compromise from normalized events and enriches each
using pluggable threat intelligence providers (no LLM calls).

Each IOC is looked up against every registered provider that supports its
type. Results are merged into a single EnrichmentResult per IOC with
reputation, confidence, tags, timestamps, source attribution, and raw
evidence from every provider.
"""

from typing import Dict, List

from intelligence.ioc_extractor import extract_iocs
from intelligence.threat_intel.models import EnrichmentResult
from intelligence.threat_intel.registry import ProviderRegistry


class EnrichmentAgent:
    """Enriches IOCs using external threat intelligence providers.

    Providers are registered at construction time. By default the registry
    is empty — call ``register_provider`` or pass a pre-configured registry
    to wire in real services.
    """

    def __init__(self, registry: ProviderRegistry | None = None) -> None:
        self._registry = registry or ProviderRegistry()

    @property
    def registry(self) -> ProviderRegistry:
        return self._registry

    def register_provider(self, provider) -> None:
        """Register an additional threat intelligence provider."""
        self._registry.register(provider)

    def run(self, events: List[Dict]) -> List[Dict]:
        """Extract IOCs from events and enrich them via all registered providers.

        Args:
            events: List of normalized event dicts.

        Returns:
            List of enriched IOC dicts (serialized EnrichmentResult).
            Each dict includes: value, ioc_type, reputation, confidence,
            tags, first_seen, last_seen, source, evidence, and raw.
            Never invents reputation values — always derived from provider data.
        """
        iocs = extract_iocs(events)
        if not iocs:
            return []

        # Convert IOCModel instances to dicts for the registry
        ioc_dicts = [ioc.model_dump() for ioc in iocs]

        # Enrich via all registered providers
        enriched: List[EnrichmentResult] = self._registry.enrich_all(ioc_dicts)

        # Serialize to dicts for downstream pipeline compatibility
        return [result.model_dump() for result in enriched]
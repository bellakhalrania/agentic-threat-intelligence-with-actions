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

from config import config, is_protected_target
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

        Protected targets (management IPs and protected target hosts — see
        MANAGEMENT_SOURCE_IP / PROTECTED_MANAGEMENT_IPS / PROTECTED_TARGET_HOSTS)
        are never sent to external providers. They are kept in the output but
        marked ``benign`` / confidence 1.0 with a ``protected_management`` tag so
        they can never be scored malicious or trigger downstream auto-blocking.

        Args:
            events: List of normalized event dicts.

        Returns:
            List of enriched IOC dicts (serialized EnrichmentResult).
            Each dict includes: value, ioc_type, reputation, confidence,
            tags, first_seen, last_seen, source, evidence, and raw.
            Never invents reputation values — always derived from provider data.
        """
        iocs = extract_iocs(events)
        
        print("\n========== ENRICHMENT AGENT ==========\n")
        for ioc in iocs:
            print(ioc)

        if not iocs:
            return []

        # Convert IOCModel instances to dicts for the registry
        ioc_dicts = [ioc.model_dump() for ioc in iocs]

        # Enrich via all registered providers, protecting local/management IOCs
        enriched: List[EnrichmentResult] = self._enrich_ioc_dicts(ioc_dicts)

        # Serialize to dicts for downstream pipeline compatibility
        return [result.model_dump() for result in enriched]

    def _enrich_ioc_dicts(self, ioc_dicts: List[Dict]) -> List[EnrichmentResult]:
        """Enrich IOC dicts, short-circuiting protected targets as trusted/benign.

        Protected IOCs (matching protected management IPs or protected target
        hosts) are converted to a trusted result without any provider query.
        All remaining IOCs are enriched normally via the registry.
        """
        trusted: List[EnrichmentResult] = []
        to_enrich: List[Dict] = []
        for ioc in ioc_dicts:
            value = (ioc.get("value") or "").strip()
            if value and is_protected_target(value):
                trusted.append(self._build_trusted_result(ioc))
            else:
                to_enrich.append(ioc)

        enriched = self._registry.enrich_all(to_enrich) if to_enrich else []
        return trusted + enriched

    def _build_trusted_result(self, ioc: Dict) -> EnrichmentResult:
        """Build a benign EnrichmentResult for a protected management/target IOC.

        No provider is queried. The result is explicitly marked benign with
        confidence 1.0 and tagged so it can never be scored malicious and can
        never trigger automated blocking downstream.
        """
        value = ioc.get("value", "")
        ioc_type = ioc.get("type", "")
        return EnrichmentResult(
            value=value,
            ioc_type=ProviderRegistry._normalize_type(ioc_type),
            reputation="benign",
            confidence=1.0,
            tags=["protected_management", "trusted"],
            source="local-policy",
            raw=ioc,
        )
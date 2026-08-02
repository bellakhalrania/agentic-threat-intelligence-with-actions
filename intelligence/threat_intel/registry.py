"""
intelligence/threat_intel/registry.py
Provider registry that discovers, dispatches, and merges results from
multiple threat intelligence providers.

Usage::

    registry = ProviderRegistry()
    registry.register(AbuseIPDBProvider())
    registry.register(OTXProvider())

    results = registry.enrich_all(iocs)  # List[EnrichmentResult]
"""

from typing import Dict, List, Optional

from intelligence.threat_intel.base_provider import ThreatIntelProvider
from intelligence.threat_intel.models import EnrichmentResult


class ProviderRegistry:
    """Registry of threat intelligence providers.

    Providers are registered by name (unique). When enriching IOCs, the
    registry dispatches each IOC to every provider that supports its type,
    then merges the results into a single ``EnrichmentResult`` per IOC.
    """

    def __init__(self) -> None:
        self._providers: Dict[str, ThreatIntelProvider] = {}

    def register(self, provider: ThreatIntelProvider) -> None:
        """Register a provider. Replaces any existing provider with the same name."""
        self._providers[provider.name] = provider

    @property
    def providers(self) -> List[ThreatIntelProvider]:
        return list(self._providers.values())

    def enrich(self, ioc_type: str, value: str) -> Optional[EnrichmentResult]:
        """Enrich a single IOC across all applicable providers.

        Args:
            ioc_type: IOC type (e.g. "ipv4", "domain", "md5").
            value: The IOC value.

        Returns:
            A merged ``EnrichmentResult``, or ``None`` if no provider returned data.
        """
        results: List[EnrichmentResult] = []
        for provider in self._providers.values():
            if ioc_type not in provider.supported_types:
                continue
            try:
                result = provider.enrich(ioc_type, value)
                if result is not None:
                    results.append(result)
            except Exception:
                # Provider failure should not break the pipeline
                continue

        if not results:
            return None

        return self._merge_results(results)

    def enrich_all(
        self, iocs: List[Dict]
    ) -> List[EnrichmentResult]:
        """Enrich a list of IOC dicts (as produced by IOCModel.model_dump()).

        Args:
            iocs: List of dicts with at least ``type`` and ``value`` keys.

        Returns:
            List of merged ``EnrichmentResult`` objects. IOCs with no provider
            data are returned with reputation "unknown" and confidence 0.0.
        """
        enriched: List[EnrichmentResult] = []
        for ioc in iocs:
            ioc_type = ioc.get("type", "")
            value = ioc.get("value", "")
            if not value:
                continue

            result = self.enrich(ioc_type, value)
            if result is None:
                # Return a minimal result so the IOC is not dropped
                result = EnrichmentResult(
                    value=value,
                    ioc_type=self._normalize_type(ioc_type),
                    reputation="unknown",
                    confidence=0.0,
                    source="",
                    raw=ioc,
                )
            else:
                # Preserve original IOCModel fields
                result.raw = ioc

            enriched.append(result)

        return enriched

    @staticmethod
    def _merge_results(results: List[EnrichmentResult]) -> EnrichmentResult:
        """Merge multiple EnrichmentResults for the same IOC into one.

        Merging rules:
        - reputation: Most severe wins (malicious > suspicious > unknown > benign)
        - confidence: Average of all provider confidences
        - tags: Union of all tags
        - first_seen: Earliest timestamp
        - last_seen: Most recent timestamp
        - source: Comma-separated list of provider names
        - evidence: All evidence blobs collected
        """
        if not results:
            raise ValueError("Cannot merge empty list of results")

        base = results[0]

        # Reputation severity ordering
        severity = {"benign": 0, "unknown": 1, "suspicious": 2, "malicious": 3}
        worst_reputation = base.reputation
        worst_severity = severity.get(base.reputation, 0)

        all_tags: set = set(base.tags)
        all_evidence = list(base.evidence)
        sources = {base.source} if base.source else set()
        first_seen = base.first_seen
        last_seen = base.last_seen
        confidence_sum = base.confidence
        count = 1

        for r in results[1:]:
            sev = severity.get(r.reputation, 0)
            if sev > worst_severity:
                worst_severity = sev
                worst_reputation = r.reputation

            all_tags.update(r.tags)
            all_evidence.extend(r.evidence)
            if r.source:
                sources.add(r.source)
            confidence_sum += r.confidence
            count += 1

            # Track earliest first_seen
            if r.first_seen and (first_seen is None or r.first_seen < first_seen):
                first_seen = r.first_seen
            # Track latest last_seen
            if r.last_seen and (last_seen is None or r.last_seen > last_seen):
                last_seen = r.last_seen

        return EnrichmentResult(
            value=base.value,
            ioc_type=base.ioc_type,
            reputation=worst_reputation,
            confidence=round(confidence_sum / count, 4),
            tags=sorted(all_tags),
            first_seen=first_seen,
            last_seen=last_seen,
            source=", ".join(sorted(sources)),
            evidence=all_evidence,
            raw=base.raw,
        )

    @staticmethod
    def _normalize_type(ioc_type: str) -> str:
        mapping = {
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
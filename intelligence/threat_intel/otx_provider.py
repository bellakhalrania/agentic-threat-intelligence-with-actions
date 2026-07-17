"""
intelligence/threat_intel/otx_provider.py
Threat intelligence provider using AlienVault OTX (Open Threat Exchange).

Supports: ipv4, ipv6, domain, hostname, url, md5, sha1, sha256
Uses the OTXv2 Python library.
"""

from typing import Optional, Set

from OTXv2 import OTXv2
from OTXv2.exceptions import BadRequest, NotKey

from config import config
from intelligence.threat_intel.base_provider import ThreatIntelProvider
from intelligence.threat_intel.models import EnrichmentResult


class OTXProvider(ThreatIntelProvider):
    """Enrich IOCs using AlienVault OTX."""

    @property
    def name(self) -> str:
        return "AlienVault OTX"

    @property
    def supported_types(self) -> Set[str]:
        return {"ipv4", "ipv6", "domain", "hostname", "url", "md5", "sha1", "sha256"}

    def enrich(self, ioc_type: str, value: str) -> Optional[EnrichmentResult]:
        api_key = config.OTX_API_KEY
        if not api_key:
            return None

        # Map IOC type to OTX indicator type
        otx_type = self._to_otx_type(ioc_type)
        if otx_type is None:
            return None

        try:
            otx = OTXv2(api_key)
            result = otx.get_indicator_details_full(otx_type, value)
        except (BadRequest, NotKey, Exception):
            return None

        if not result or not result.get("general"):
            return None

        general = result.get("general", {})
        pulse_info = general.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])
        validation = general.get("validation", 0)
        false_positive = general.get("false_positive", [])
        is_false_positive = any(
            fp.get("assessment", "") == "false-positive" for fp in false_positive
        )

        # Count total pulses and references
        total_pulses = len(pulses)
        malicious_pulses = sum(
            1 for p in pulses if p.get("TLP", "") == "red"
        )

        # Determine reputation
        if is_false_positive:
            reputation = "benign"
        elif total_pulses >= 5 and malicious_pulses >= 2:
            reputation = "malicious"
        elif total_pulses >= 1:
            reputation = "suspicious"
        else:
            reputation = "unknown"

        # Confidence based on pulse count and validation
        confidence = min(total_pulses / 20.0, 1.0)
        if validation > 0:
            confidence = min(confidence + 0.2, 1.0)

        # Collect tags from pulses
        tags = set()
        for pulse in pulses:
            for tag in pulse.get("tags", []):
                tags.add(tag.lower().replace(" ", "_"))
            # Add adversary and malware from pulse
            adversary = pulse.get("adversary", "")
            if adversary:
                tags.add(f"adversary:{adversary.lower().replace(' ', '_')}")
            malware = pulse.get("malware_families", [])
            for m in malware:
                tags.add(f"malware:{m.lower().replace(' ', '_')}")

        # Extract timestamps
        first_seen = None
        last_seen = None
        if pulses:
            created_dates = [
                p.get("created") for p in pulses if p.get("created")
            ]
            modified_dates = [
                p.get("modified") for p in pulses if p.get("modified")
            ]
            if created_dates:
                first_seen = min(created_dates)
            if modified_dates:
                last_seen = max(modified_dates)

        return EnrichmentResult(
            value=value,
            ioc_type=self._normalize_ioc_type(ioc_type),
            reputation=reputation,
            confidence=confidence,
            tags=sorted(tags),
            first_seen=first_seen,
            last_seen=last_seen,
            source=self.name,
            evidence=[self._build_evidence(result)],
        )

    @staticmethod
    def _to_otx_type(ioc_type: str) -> Optional[str]:
        """Map IOCModel type to OTX indicator type."""
        mapping = {
            "ipv4": "IPv4",
            "ipv6": "IPv6",
            "domain": "domain",
            "hostname": "hostname",
            "url": "url",
            "md5": "file",
            "sha1": "file",
            "sha256": "file",
        }
        return mapping.get(ioc_type)
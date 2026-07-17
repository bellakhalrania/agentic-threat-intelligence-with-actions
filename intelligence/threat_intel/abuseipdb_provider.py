"""
intelligence/threat_intel/abuseipdb_provider.py
Threat intelligence provider using AbuseIPDB API (https://www.abuseipdb.com/).

Supports: ipv4
Returns reputation based on abuseConfidenceScore.
"""

from typing import Optional, Set

import requests

from config import config
from intelligence.threat_intel.base_provider import ThreatIntelProvider
from intelligence.threat_intel.models import EnrichmentResult


class AbuseIPDBProvider(ThreatIntelProvider):
    """Enrich IPv4 addresses using AbuseIPDB."""

    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    @property
    def name(self) -> str:
        return "AbuseIPDB"

    @property
    def supported_types(self) -> Set[str]:
        return {"ipv4"}

    def enrich(self, ioc_type: str, value: str) -> Optional[EnrichmentResult]:
        if ioc_type not in self.supported_types:
            return None

        api_key = config.ABUSEIPDB_API_KEY
        if not api_key:
            return None

        try:
            response = requests.get(
                self.BASE_URL,
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": value, "maxAgeInDays": "90", "verbose": ""},
                timeout=10,
            )
            response.raise_for_status()
            data = response.json().get("data", {})
        except requests.RequestException:
            return None

        if not data:
            return None

        abuse_score = data.get("abuseConfidenceScore", 0)
        is_public = data.get("isPublic", True)
        total_reports = data.get("totalReports", 0)
        domain = data.get("domain", "")
        country = data.get("countryCode", "")
        usage_type = data.get("usageType", "")
        isp = data.get("isp", "")
        last_reported = data.get("lastReportedAt")
        confidence = min(abuse_score / 100.0, 1.0)

        # Map abuseConfidenceScore to reputation
        if abuse_score >= 50:
            reputation = "malicious"
        elif abuse_score >= 10:
            reputation = "suspicious"
        elif total_reports > 0:
            reputation = "suspicious"
        else:
            reputation = "benign"

        tags = []
        if usage_type:
            tags.append(usage_type.lower().replace(" ", "_"))
        if country:
            tags.append(f"country:{country}")
        if isp:
            tags.append(f"isp:{isp}")
        if domain:
            tags.append(f"domain:{domain}")
        if not is_public:
            tags.append("non_public")

        return EnrichmentResult(
            value=value,
            ioc_type=self._normalize_ioc_type(ioc_type),
            reputation=reputation,
            confidence=confidence,
            tags=tags,
            first_seen=None,
            last_seen=last_reported,
            source=self.name,
            evidence=[self._build_evidence(data)],
        )
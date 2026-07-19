"""
intelligence/campaign_builder.py
Helper functions for building a human-readable attack storyline (ordered
chain of tactics/techniques) from a campaign's related techniques -
used by the Reporting Agent and graph_queries.py.
"""

from typing import List, Dict

# Canonical ATT&CK tactic ordering (kill-chain order), used to sort techniques
# into a coherent storyline even if events arrived out of order.
TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]


def calculate_confidence(events: List[Dict], iocs: List[Dict], techniques: List[Dict]) -> float:
    """Calculate campaign confidence deterministically from evidence strength.
    
    Weights are heuristic starting points, not statistically calibrated.
    
    Args:
        events: Normalized security events
        iocs: Enriched indicators of compromise
        techniques: Mapped ATT&CK techniques with confidence scores
        
    Returns:
        Confidence score between 0.0 and 1.0
    """
    if not events:
        return 0.0
    
    # Technique score: sum of technique confidences, capped at 0.5
    technique_score = min(sum(t.get("confidence", 0.0) for t in techniques) * 0.15, 0.5)
    
    # IOC score: count of malicious IOCs from real threat intel sources
    malicious_iocs = sum(1 for ioc in iocs if ioc.get("reputation") == "malicious" and ioc.get("source"))
    ioc_score = min(malicious_iocs * 0.15, 0.3)
    
    # Event score: number of events, capped at 0.2
    event_score = min(len(events) * 0.05, 0.2)
    
    return round(min(technique_score + ioc_score + event_score, 1.0), 2)


def build_storyline(techniques: List[Dict]) -> List[Dict]:
    from intelligence.mitre_mapper import get_tactic

    def sort_key(t):
        tactic = (get_tactic(t.get("technique_id", "")) or "").split(",")[0].strip()
        return TACTIC_ORDER.index(tactic) if tactic in TACTIC_ORDER else len(TACTIC_ORDER)

    return sorted(techniques, key=sort_key)

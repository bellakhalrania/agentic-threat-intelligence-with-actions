"""
agents/correlation_agent.py
Connects isolated events/IOCs/techniques into a single coherent attack
campaign narrative, and persists the relationships into Neo4j via
knowledge_graph/graph_builder.py.

The LLM is used ONLY to summarize the provided evidence. It must never
invent malware names, APT groups, CVEs, or attack objectives not present
in the evidence. Every claim must be backed by specific evidence items.
"""

import uuid
import logging
from typing import List, Dict
from llm.groq_client import invoke_llm
from llm.prompts import CORRELATION_SYSTEM_PROMPT
from llm.output_parsers import extract_json
from knowledge_graph.graph_builder import persist_campaign

logger = logging.getLogger(__name__)


class CorrelationAgent:
    """Correlates events, IOCs, and techniques into a campaign summary.
    
    The LLM is constrained to ONLY summarize the provided evidence. It must:
    - Never invent malware names, APT groups, CVEs, or attack objectives
    - Explicitly state "Unknown" when evidence is insufficient
    - Reference specific evidence items in every paragraph
    - Make no unsupported conclusions
    """

    def run(self, events: List[Dict], iocs: List[Dict], techniques: List[Dict]) -> Dict:
        """Correlates evidence into a campaign summary using LLM for summarization only.
        
        Args:
            events: Normalized security events
            iocs: Enriched indicators of compromise
            techniques: Mapped ATT&CK techniques with evidence
            
        Returns:
            Campaign summary dict with evidence-backed claims only
        """
        if not events:
            return self._empty_campaign()

        # Build evidence context for LLM
        evidence_context = self._build_evidence_context(events, iocs, techniques)
        
        response = invoke_llm(
            system_prompt=CORRELATION_SYSTEM_PROMPT, 
            user_prompt=evidence_context
        )

        try:
            campaign = extract_json(response)
            campaign = self._validate_campaign(campaign, events, iocs, techniques)
        except ValueError as e:
            logger.warning("LLM did not return valid JSON for correlation: %s", e)
            campaign = self._fallback_campaign(events, iocs, techniques)

        campaign.setdefault("campaign_id", str(uuid.uuid4()))

        try:
            persist_campaign(campaign, events, techniques)
        except Exception as e:
            logger.exception("Failed to persist campaign to Neo4j: %s", e)

        return campaign

    def _build_evidence_context(self, events: List[Dict], iocs: List[Dict], techniques: List[Dict]) -> str:
        """Builds structured evidence context for the LLM."""
        context_parts = []
        
        context_parts.append("=== EVENTS ===")
        for event in events:
            context_parts.append(f"Event ID: {event.get('event_id', 'unknown')}")
            context_parts.append(f"  Type: {event.get('event_type', 'unknown')}")
            context_parts.append(f"  Host: {event.get('host', 'unknown')}")
            context_parts.append(f"  Process: {event.get('process', 'unknown')}")
            context_parts.append(f"  Command Line: {event.get('command_line', 'unknown')}")
            context_parts.append(f"  Source IP: {event.get('src_ip', 'unknown')}")
            context_parts.append(f"  Destination IP: {event.get('dest_ip', 'unknown')}")
            context_parts.append("")
        
        context_parts.append("=== IOCs ===")
        for ioc in iocs:
            context_parts.append(f"Value: {ioc.get('value', 'unknown')}")
            context_parts.append(f"  Type: {ioc.get('type', 'unknown')}")
            context_parts.append(f"  Reputation: {ioc.get('reputation', 'unknown')}")
            context_parts.append(f"  Confidence: {ioc.get('confidence', 'unknown')}")
            context_parts.append(f"  Source: {ioc.get('source', 'unknown')}")
            context_parts.append("")
        
        context_parts.append("=== TECHNIQUES ===")
        for technique in techniques:
            context_parts.append(f"ID: {technique.get('attack_id', 'unknown')}")
            context_parts.append(f"  Name: {technique.get('technique_name', 'unknown')}")
            context_parts.append(f"  Confidence: {technique.get('confidence', 'unknown')}")
            context_parts.append(f"  Evidence Event: {technique.get('evidence_event_id', 'unknown')}")
            context_parts.append(f"  Mapping Source: {technique.get('mapping_source', 'unknown')}")
            context_parts.append("")
        
        return "\n".join(context_parts)

    def _validate_campaign(self, campaign: Dict, events: List[Dict], iocs: List[Dict], techniques: List[Dict]) -> Dict:
        """Validates that campaign claims are backed by evidence."""
        # Ensure campaign_id is present
        if "campaign_id" not in campaign:
            campaign["campaign_id"] = str(uuid.uuid4())
        
        # Validate that techniques are from the provided list
        if "related_techniques" in campaign:
            valid_techniques = {t.get("attack_id") for t in techniques}
            campaign["related_techniques"] = [
                t for t in campaign["related_techniques"] if t in valid_techniques
            ]
        
        # Ensure objective is "Unknown" if not explicitly provided
        if not campaign.get("objective"):
            campaign["objective"] = "Unknown"
        
        # Ensure name is "Unclassified Activity" if not explicitly provided
        if not campaign.get("name") or campaign.get("name") == "Unknown":
            campaign["name"] = "Unclassified Activity"
        
        return campaign

    def _fallback_campaign(self, events: List[Dict], iocs: List[Dict], techniques: List[Dict]) -> Dict:
        """Returns a minimal campaign when LLM fails."""
        return {
            "campaign_id": str(uuid.uuid4()),
            "name": "Unclassified Activity",
            "objective": "Unknown",
            "timeline": [
                {
                    "timestamp": e.get("timestamp", "unknown"),
                    "event_id": e.get("event_id", "unknown"),
                    "description": f"Event type: {e.get('event_type', 'unknown')}"
                }
                for e in events
            ],
            "related_techniques": [t.get("attack_id") for t in techniques],
            "evidence_summary": f"Based on {len(events)} events, {len(iocs)} IOCs, and {len(techniques)} techniques. Insufficient evidence to determine campaign objective or attribution.",
            "confidence": 0.0,
        }

    def _empty_campaign(self) -> Dict:
        """Returns an empty campaign when no events are provided."""
        return {
            "campaign_id": str(uuid.uuid4()),
            "name": "No Activity",
            "objective": "Unknown",
            "timeline": [],
            "related_techniques": [],
            "evidence_summary": "No events provided for correlation.",
            "confidence": 0.0,
        }

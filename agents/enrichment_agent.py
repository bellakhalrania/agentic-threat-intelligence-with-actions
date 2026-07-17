"""
agents/enrichment_agent.py
Extracts indicators of compromise from normalized events and enriches each
with a verdict, category, and justification.
"""

from typing import List, Dict
from intelligence.ioc_extractor import extract_iocs
from llm.groq_client import invoke_llm
from llm.prompts import ENRICHMENT_SYSTEM_PROMPT
from llm.output_parsers import extract_json


class EnrichmentAgent:
    def run(self, events: List[Dict]) -> List[Dict]:
        iocs = extract_iocs(events)
        if not iocs:
            return []

        # Convert IOCModel instances to dicts for LLM processing
        ioc_dicts = [ioc.model_dump() for ioc in iocs]
        
        response = invoke_llm(
            system_prompt=ENRICHMENT_SYSTEM_PROMPT,
            user_prompt=str(ioc_dicts),
        )
        try:
            enriched = extract_json(response)
        except ValueError:
            # Fall back to unenriched IOCs rather than dropping them
            enriched = [{**ioc_dict, "verdict": "unknown"} for ioc_dict in ioc_dicts]

        return enriched

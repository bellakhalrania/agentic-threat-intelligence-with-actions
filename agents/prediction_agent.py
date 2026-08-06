"""
agents/prediction_agent.py
Predicts the attacker's likely next technique(s) given the techniques
observed so far, combining RAG-retrieved related techniques with LLM
reasoning about common ATT&CK attack-chain progressions.

Hallucination prevention:
- The LLM is given an explicit candidate set of technique IDs from the RAG
  context so it cannot invent IDs from training data.
- Every predicted ID is validated against the MITRE ATT&CK knowledge layer
  (same guard used by AttackMappingAgent). Deprecated or unknown IDs are
  discarded rather than passed downstream.
"""

import logging
import re
from typing import List, Dict, Optional

from rag.attack_chain_retriever import retrieve_likely_next_techniques_with_ids
from llm.groq_client import invoke_llm
from llm.prompts import PREDICTION_SYSTEM_PROMPT
from llm.output_parsers import extract_json

logger = logging.getLogger(__name__)


class PredictionAgent:
    def run(self, techniques: List[Dict], campaign: Dict) -> Dict:
        print("\n========== PREDICTION AGENT ==========\n")
        
        if not techniques:
            logger.info("PREDICTION_AGENT: No techniques observed - skipping prediction")
            print("No techniques observed - skipping prediction")
            return {"likely_next_techniques": [], "rationale": "No techniques observed yet."}

        technique_names = [t.get("technique_name") or t.get("name", "") for t in techniques if t.get("technique_name") or t.get("name")]

        print(f"Observed Techniques: {technique_names}")
        logger.info("PREDICTION_AGENT: Observed techniques: %s", technique_names)

        # Retrieve RAG context and extract the valid candidate IDs from it
        related_context, candidate_ids = retrieve_likely_next_techniques_with_ids(technique_names)

        print(f"RAG Context Length: {len(related_context)} characters")
        print(f"Candidate IDs from RAG: {sorted(candidate_ids)}")
        logger.info("PREDICTION_AGENT: RAG context length: %d characters", len(related_context))
        logger.info("PREDICTION_AGENT: Candidate IDs from RAG: %s", sorted(candidate_ids))

        # If RAG returned nothing, skip prediction rather than risk hallucination
        if not candidate_ids:
            logger.warning(
                "PREDICTION_AGENT: no RAG context returned — skipping LLM call to avoid hallucination"
            )
            print("No RAG context - skipping prediction to avoid hallucination")
            return {
                "likely_next_techniques": [],
                "rationale": "Prediction skipped: No suitable follow-on techniques were found in the knowledge base.",
            }

        prompt = (
            f"Observed techniques so far:\n{technique_names}\n\n"
            f"Campaign context:\n{campaign}\n\n"
            f"Related ATT&CK techniques (RAG context — ONLY use IDs from this list):\n{related_context}\n\n"
            f"Valid technique IDs you may predict: {sorted(candidate_ids)}"
        )
        
        print("Invoking LLM for prediction...")
        logger.info("PREDICTION_AGENT: Invoking LLM with prompt (first 200 chars): %s...", prompt[:200])
        response = invoke_llm(system_prompt=PREDICTION_SYSTEM_PROMPT, user_prompt=prompt)
        
        print(f"LLM Response (first 200 chars): {response[:200]}...")
        logger.info("PREDICTION_AGENT: LLM response (first 200 chars): %s...", response[:200])

        try:
            result = extract_json(response)
            logger.info("PREDICTION_AGENT: Parsed LLM result: %s", result)
        except ValueError as e:
            logger.warning("PREDICTION_AGENT: Failed to parse LLM response as JSON: %s", e)
            print(f" Failed to parse LLM response: {e}")
            return {
                "likely_next_techniques": [],
                "rationale": "Prediction could not be parsed from model output.",
            }

        # --- Hallucination guard: validate every predicted technique ID ---
        predicted_before = result.get("likely_next_techniques", [])
        print(f"Predicted Techniques (before validation): {predicted_before}")
        logger.info("PREDICTION_AGENT: Techniques predicted by LLM (before validation): %s", predicted_before)
        
        result["likely_next_techniques"] = self._validate_predicted_techniques(
            result.get("likely_next_techniques", []),
            candidate_ids,
        )
        
        print(f"Predicted Techniques (after validation): {result['likely_next_techniques']}")
        print(f"Rationale: {result.get('rationale', 'N/A')}")
        logger.info("PREDICTION_AGENT: Techniques after validation: %s", result["likely_next_techniques"])
        print("===========================\n")

        return result

    @staticmethod
    def _validate_predicted_techniques(
        predicted: List, candidate_ids: set
    ) -> List:
        """
        Validates each predicted technique against two layers:
        1. Candidate-set constraint: ID must be in the RAG-returned set.
        2. Knowledge-layer lookup: ID must resolve in the MITRE knowledge base
           (catches deprecated IDs like T1060 that exist in training data but
           not in the current ATT&CK version).

        Returns a filtered list with only valid, current techniques.
        """
        # Import here to avoid circular imports at module level
        from knowledge.attack.config import AttackConfig
        from knowledge.attack.service import AttackService
        from knowledge.base.exceptions import RecordNotFoundError, KnowledgeLayerError

        try:
            attack_service = AttackService.create(AttackConfig())
        except Exception as exc:
            logger.error("PredictionAgent: could not initialise AttackService for validation: %s", exc)
            return []  # Fail closed — return nothing rather than unvalidated IDs

        validated = []
        tech_id_pattern = re.compile(r'T\d{4}(?:\.\d{3})?', re.IGNORECASE)

        for item in predicted:
            # Items may be dicts or bare strings
            if isinstance(item, dict):
                raw_id = item.get("technique_id") or item.get("attack_id") or ""
            elif isinstance(item, str):
                raw_id = item
            else:
                logger.warning("PredictionAgent: unexpected item type in prediction: %r", item)
                continue

            # Extract the technique ID (handles "T1059.001 (PowerShell)" style strings)
            match = tech_id_pattern.search(raw_id)
            if not match:
                logger.warning("PredictionAgent: cannot extract technique ID from %r — discarding", raw_id)
                continue

            tech_id = match.group(0).upper()

            # Layer 1: Candidate-set constraint
            if tech_id not in candidate_ids:
                logger.warning(
                    "PredictionAgent: predicted ID %r not in RAG candidate set — discarding (hallucination risk)",
                    tech_id,
                )
                continue

            # Layer 2: Knowledge-layer existence check (catches deprecated IDs)
            try:
                attack_service.get_technique(tech_id)
            except RecordNotFoundError:
                logger.warning(
                    "PredictionAgent: predicted ID %r not found in knowledge layer "
                    "(may be deprecated or invented) — discarding",
                    tech_id,
                )
                continue
            except KnowledgeLayerError as exc:
                logger.error("PredictionAgent: knowledge layer error for %r: %s — discarding", tech_id, exc)
                continue

            validated.append(item)
            logger.debug("PredictionAgent: validated predicted technique %r", tech_id)

        attack_service.close()
        logger.info(
            "PredictionAgent: %d/%d predicted techniques passed validation",
            len(validated),
            len(predicted),
        )
        return validated

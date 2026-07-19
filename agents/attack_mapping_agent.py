"""
agents/attack_mapping_agent.py

Maps each normalized event to a MITRE ATT&CK technique.

This version replaces the ChromaDB/RAG retriever with the deterministic
MITRE ATT&CK Knowledge Layer (``knowledge.attack``) built earlier:

1. **Deterministic fast path** — every event is first run through
   ``AttackService.match_event()`` (rule-based, no LLM call at all).
   If a rule fires, that result is returned directly: it's cheaper,
   faster, and fully auditable.
2. **LLM fallback, grounded in the knowledge layer instead of a vector
   store** — for events the rules don't cover, real technique/tactic/
   group/mitigation text is pulled from the SQLite-backed knowledge
   layer via ``AttackService.search()`` and used as the LLM's context,
   in place of ``retrieve_attack_context`` from ChromaDB.
3. **Verification, not trust** — the LLM is never allowed to invent an
   ATT&CK ID. Whatever ``attack_id`` it proposes is looked up in the
   knowledge layer; if it doesn't resolve to a real technique, the
   mapping is discarded rather than passed downstream.
4. **Enrichment** — every accepted mapping (deterministic or LLM) is
   enriched with known groups, software, and mitigations pulled from
   the knowledge layer, so downstream agents get that context for free.

The knowledge layer itself still contains no LLM logic, no LangGraph
logic, and no RAG — all of that lives here, in the agent layer, exactly
as it should.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from knowledge.attack.config import AttackConfig
from knowledge.attack.matcher import MatchResult, TelemetryEvent
from knowledge.attack.models import SearchResult
from knowledge.attack.service import AttackService
from knowledge.base.exceptions import KnowledgeLayerError, RecordNotFoundError

from llm.groq_client import invoke_llm
from llm.output_parsers import extract_json
from llm.prompts import ATTACK_MAPPING_SYSTEM_PROMPT

logger = logging.getLogger(__name__)

# Minimum confidence threshold for LLM-based technique mappings
LLM_MIN_CONFIDENCE = 0.4


class AttackMappingAgent:
    """Maps normalized telemetry events to MITRE ATT&CK techniques.

    Attributes:
        attack_service: The facade over the deterministic ATT&CK
            knowledge layer, used both for the rule-based fast path and
            for grounding/verifying the LLM fallback.
        context_limit: Maximum number of knowledge-layer search results
            included as LLM context per event.
    """

    def __init__(self, attack_service: Optional[AttackService] = None, context_limit: int = 5) -> None:
        """Initializes the agent.

        Args:
            attack_service: An already-constructed
                :class:`~knowledge.attack.service.AttackService`. If
                omitted, a default one is built from
                :class:`~knowledge.attack.config.AttackConfig`
                (dependency injection is preferred for testing).
            context_limit: How many knowledge-layer search results to
                surface to the LLM as grounding context.
        """
        self.attack_service = attack_service or AttackService.create(AttackConfig())
        self.context_limit = context_limit

    def close(self) -> None:
        """Closes the underlying knowledge-layer database connection."""
        self.attack_service.close()

    def run(self, events: List[Dict]) -> List[Dict]:
        """Maps a batch of normalized events to ATT&CK techniques.

        Args:
            events: Normalized event dicts (e.g. ``event_type``,
                ``process``, ``command_line``, ``user``, ``src_ip``,
                ``dest_ip``, ``event_id``).

        Returns:
            A list of mapping dicts, one per event that could be
            confidently mapped. Events that neither a deterministic
            rule nor a verified LLM call could map are skipped.
        """
        mapped_techniques: List[Dict] = []
        for event in events:
            mapped = self._map_event(event)
            if mapped is not None:
                mapped_techniques.append(mapped)
        return mapped_techniques

    # ------------------------------------------------------------------
    # Per-event mapping
    # ------------------------------------------------------------------

    def _map_event(self, event: Dict) -> Optional[Dict]:
        """Maps a single event, trying the deterministic path first.

        Args:
            event: A single normalized event dict.

        Returns:
            A mapping dict, or ``None`` if no confident mapping could
            be produced.
        """
        deterministic = self._try_deterministic_match(event)
        if deterministic is not None:
            return deterministic
        return self._try_llm_match(event)

    def _try_deterministic_match(self, event: Dict) -> Optional[Dict]:
        """Attempts to map an event using the rule-based ATT&CK matcher.

        Args:
            event: A single normalized event dict.

        Returns:
            A mapping dict built from the highest-confidence rule
            match, or ``None`` if no rule fired (or the event carried
            no usable telemetry fields).
        """
        try:
            telemetry_event = TelemetryEvent(
                process_name=event.get("process"),
                command_line=event.get("command_line"),
                parent_process_name=event.get("parent_process"),
                file_name=event.get("file_name"),
                network_destination=event.get("dest_ip"),
                raw=event,
            )
        except KnowledgeLayerError:
            # Event had nothing the deterministic matcher can use;
            # fall through to the LLM path, which has richer context
            # (e.g. free-text descriptions) to work with.
            return None

        try:
            matches = self.attack_service.match_event(telemetry_event)
        except KnowledgeLayerError:
            logger.exception("Deterministic matcher failed for event %s", event.get("event_id"))
            return None

        if not matches:
            return None

        best: MatchResult = max(matches, key=lambda match: match.confidence)
        try:
            technique = self.attack_service.get_technique(best.technique_attack_id)
        except RecordNotFoundError:
            logger.warning(
                "Deterministic rule %s referenced unknown technique %s",
                best.rule_name,
                best.technique_attack_id,
            )
            return None

        mapped = {
            "attack_id": technique.attack_id,
            "technique_name": technique.name,
            "confidence": best.confidence,
            "rule_name": best.rule_name,
            "matched_on": best.matched_on,
            "evidence_event_id": event.get("event_id"),
            "mapping_source": "deterministic_rule",
        }
        self._enrich(mapped, technique.attack_id)
        return mapped

    def _try_llm_match(self, event: Dict) -> Optional[Dict]:
        """Attempts to map an event via the LLM, grounded and verified.

        Args:
            event: A single normalized event dict.

        Returns:
            A mapping dict if the LLM proposed a valid, verifiable
            ATT&CK ID, otherwise ``None``.
        """
        description = self._event_to_text(event)
        context_results = self._gather_context(event, description)
        
        # Skip LLM fallback if no grounding context is available to avoid hallucination risk.
        if not context_results:
            logger.debug(
                "No grounding context available for event %s; skipping LLM fallback to avoid ungrounded hallucination risk",
                event.get("event_id"),
            )
            return None
        
        context_text = self._format_context(context_results)

        prompt = f"Event:\n{description}\n\nRetrieved ATT&CK context:\n{context_text}"
        response = invoke_llm(system_prompt=ATTACK_MAPPING_SYSTEM_PROMPT, user_prompt=prompt)

        try:
            mapped = extract_json(response)
        except ValueError:
            logger.debug("LLM did not return parseable JSON for event %s", event.get("event_id"))
            return None

        attack_id = mapped.get("attack_id") or mapped.get("technique_id")
        if not attack_id:
            logger.debug("LLM response had no attack_id for event %s", event.get("event_id"))
            return None

        # Ground truth check: never forward an ATT&CK ID the LLM
        # invented. If it doesn't resolve in the knowledge layer, the
        # mapping is dropped rather than passed downstream.
        try:
            technique = self.attack_service.get_technique(str(attack_id).strip())
        except RecordNotFoundError:
            logger.warning(
                "LLM proposed unknown ATT&CK ID %r for event %s; discarding",
                attack_id,
                event.get("event_id"),
            )
            return None
        except KnowledgeLayerError:
            logger.exception("Knowledge layer error validating attack_id %r", attack_id)
            return None

        # Candidate-set constraint: verify the LLM selected an attack_id
        # that was present in the retrieved context.
        context_attack_ids = {result.attack_id for result in context_results}
        if context_attack_ids and str(attack_id).strip() not in context_attack_ids:
            logger.warning(
                "LLM selected attack_id %r not present in retrieved context for event %s; discarding",
                attack_id,
                event.get("event_id"),
            )
            return None

        # Confidence validation: ensure confidence is a valid float between 0 and 1.
        confidence = mapped.get("confidence")
        if confidence is None:
            confidence = 0.5
        elif isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not (0.0 <= confidence <= 1.0):
            logger.warning(
                "LLM returned invalid confidence %r for event %s",
                confidence,
                event.get("event_id"),
            )
            return None
        else:
            confidence = float(confidence)

        # Minimum confidence threshold check.
        if confidence < LLM_MIN_CONFIDENCE:
            logger.debug(
                "LLM mapping for event %s below confidence threshold (%.2f); discarding",
                event.get("event_id"),
                LLM_MIN_CONFIDENCE,
            )
            return None

        mapped["attack_id"] = technique.attack_id
        mapped["technique_name"] = technique.name
        mapped["evidence_event_id"] = event.get("event_id")
        mapped["mapping_source"] = "llm"
        mapped["confidence"] = confidence

        self._enrich(mapped, technique.attack_id)
        return mapped

    # ------------------------------------------------------------------
    # Context gathering (replaces the old ChromaDB retriever)
    # ------------------------------------------------------------------

    def _gather_context(self, event: Dict, description: str) -> List[SearchResult]:
        """Pulls grounding context for the LLM from the knowledge layer.

        Args:
            event: The original normalized event dict.
            description: The flattened text form of the event.

        Returns:
            A list of :class:`~knowledge.attack.models.SearchResult`
            objects to present to the LLM as context. Falls back to
            per-field searches (process name, then command line) if a
            whole-description search returns nothing.
        """
        try:
            results = self.attack_service.search(description, limit=self.context_limit)
        except KnowledgeLayerError:
            results = []

        if results:
            return results

        for field in ("process", "command_line"):
            value = event.get(field)
            if not value:
                continue
            try:
                results = self.attack_service.search(str(value), limit=self.context_limit)
            except KnowledgeLayerError:
                continue
            if results:
                return results

        return []

    @staticmethod
    def _format_context(results: List[SearchResult]) -> str:
        """Formats knowledge-layer search results as LLM-ready context text.

        Args:
            results: Search results to format.

        Returns:
            A newline-delimited string, one line per result, or a
            explicit "no context" note if ``results`` is empty (so the
            LLM knows not to assume unstated details).
        """
        if not results:
            return "No matching ATT&CK objects were found in the knowledge base for this event."
        lines = []
        for result in results:
            snippet = (result.description or "").strip()
            if len(snippet) > 400:
                snippet = snippet[:400] + "..."
            lines.append(f"[{result.object_type.value}] {result.attack_id} - {result.name}: {snippet}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Enrichment
    # ------------------------------------------------------------------

    def _enrich(self, mapped: Dict, attack_id: str) -> None:
        """Adds known groups/software/mitigations to a mapping in place.

        Args:
            mapped: The mapping dict to enrich (mutated in place).
            attack_id: The verified ATT&CK technique ID to enrich for.
        """
        try:
            groups = self.attack_service.get_groups(attack_id)
            software = self.attack_service.get_software(attack_id)
            mitigations = self.attack_service.get_mitigations(attack_id)
        except KnowledgeLayerError:
            logger.exception("Failed to enrich mapping for %s", attack_id)
            return
        mapped["known_groups"] = [group.name for group in groups]
        mapped["known_software"] = [software_item.name for software_item in software]
        mapped["recommended_mitigations"] = [mitigation.name for mitigation in mitigations]

    # ------------------------------------------------------------------
    # Event formatting
    # ------------------------------------------------------------------

    @staticmethod
    def _event_to_text(event: Dict) -> str:
        """Flattens a normalized event dict into a single text description.

        Args:
            event: A single normalized event dict.

        Returns:
            A comma-separated ``key=value`` description, omitting any
            field whose value is missing (``None``).
        """
        parts = [
            f"event_type={event.get('event_type')}",
            f"process={event.get('process')}",
            f"command_line={event.get('command_line')}",
            f"user={event.get('user')}",
            f"src_ip={event.get('src_ip')}",
            f"dest_ip={event.get('dest_ip')}",
        ]
        return ", ".join(p for p in parts if "None" not in p)
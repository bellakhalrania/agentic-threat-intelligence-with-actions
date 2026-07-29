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
            A list of mapping dicts, potentially multiple per event
            if multiple techniques match. Events that neither a 
            deterministic rule nor a verified LLM call could map are 
            skipped.
        """
        mapped_techniques: List[Dict] = []
        print("\n========== MAPPING AGENT ==========\n")
        print(f"Processing {len(events)} events...\n")

        for i, event in enumerate(events, 1):
            print(f"--- Event {i} ---")
            print(f"Event ID: {event.get('event_id', 'unknown')}")
            print(f"Event Type: {event.get('event_type', 'unknown')}")
            print(f"Process: {event.get('process', 'N/A')}")
            print(f"Command Line: {event.get('command_line', 'N/A')[:100]}..." if event.get('command_line') and len(event.get('command_line', '')) > 100 else f"Command Line: {event.get('command_line', 'N/A')}")
            
            event_techniques = self._map_event(event)
            
            if event_techniques:
                print(f"\n✅ Mapped to {len(event_techniques)} technique(s):")
                for tech in event_techniques:
                    print(f"   - {tech.get('attack_id')}: {tech.get('technique_name')}")
                    print(f"     Confidence: {tech.get('confidence', 'N/A')}")
                    print(f"     Source: {tech.get('mapping_source', 'N/A')}")
                    if tech.get('rule_name'):
                        print(f"     Rule: {tech.get('rule_name')}")
                mapped_techniques.extend(event_techniques)
            else:
                print("\n❌ No techniques mapped for this event")
            print()
        
        print(f"--- Summary ---")
        print(f"Total events processed: {len(events)}")
        print(f"Total techniques mapped: {len(mapped_techniques)}")
        print("========================\n")
        
        # Detect SSH brute-force patterns and boost confidence
        mapped_techniques = self._detect_ssh_brute_force(events, mapped_techniques)
        
        return mapped_techniques

    # ------------------------------------------------------------------
    # Per-event mapping
    # ------------------------------------------------------------------

    def _map_event(self, event: Dict) -> List[Dict]:
        """Maps a single event, trying pre-existing metadata first, then deterministic rules.

        Args:
            event: A single normalized event dict.

        Returns:
            A list of mapping dicts for all matched techniques,
            or an empty list if no confident mapping could be produced.
        """
        # 1. Check for pre-existing MITRE metadata (e.g. from Wazuh)
        metadata_mappings = self._try_metadata_match(event)
        if metadata_mappings:
            return metadata_mappings

        # 2. Try deterministic rules
        deterministic = self._try_deterministic_match(event)
        if deterministic:
            return deterministic

        # 3. Fall back to LLM
        llm_result = self._try_llm_match(event)
        return [llm_result] if llm_result else []

    def _try_metadata_match(self, event: Dict) -> List[Dict]:
        """Checks if the event already has MITRE IDs (e.g. from Wazuh rules)."""
        mitre_ids = event.get("rule_mitre")
        if not mitre_ids:
            return []

        if isinstance(mitre_ids, str):
            mitre_ids = [mitre_ids]

        mappings = []
        for attack_id in mitre_ids:
            try:
                technique = self._resolve_technique(str(attack_id))
                mapped = {
                    "attack_id": technique.attack_id,
                    "technique_name": technique.name,
                    "confidence": 1.0,
                    "mapping_source": "event_metadata",
                    "evidence_event_id": event.get("event_id"),
                }
                self._enrich(mapped, technique.attack_id)
                mappings.append(mapped)
            except (RecordNotFoundError, KnowledgeLayerError):
                continue
        return mappings

    def _try_deterministic_match(self, event: Dict) -> List[Dict]:
        """Attempts to map an event using the rule-based ATT&CK matcher.

        Args:
            event: A single normalized event dict.

        Returns:
            A list of mapping dicts for ALL matching rules,
            or an empty list if no rule fired.
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
            return []

        try:
            matches = self.attack_service.match_event(telemetry_event)
        except KnowledgeLayerError:
            logger.exception("Deterministic matcher failed for event %s", event.get("event_id"))
            return []

        if not matches:
            return []

        # Return ALL matching techniques, not just the best one
        mapped_techniques = []
        for match in matches:
            try:
                technique = self.attack_service.get_technique(match.technique_attack_id)
                mapped = {
                    "attack_id": technique.attack_id,
                    "technique_name": technique.name,
                    "confidence": match.confidence,
                    "rule_name": match.rule_name,
                    "matched_on": match.matched_on,
                    "evidence_event_id": event.get("event_id"),
                    "mapping_source": "deterministic_rule",
                }
                self._enrich(mapped, technique.attack_id)
                mapped_techniques.append(mapped)
            except RecordNotFoundError:
                logger.warning(
                    "Deterministic rule %s referenced unknown technique %s",
                    match.rule_name,
                    match.technique_attack_id,
                )
                continue

        return mapped_techniques

    def _try_llm_match(self, event: Dict) -> Optional[Dict]:
        """Attempts to map an event via the LLM, grounded and verified.

        Args:
            event: A single normalized event dict.

        Returns:
            A mapping dict if the LLM proposed a valid, verifiable
            ATT&CK ID, otherwise ``None``.
        """
        description = self._event_to_text(event)
        
        # DEBUG: Log input to MITRE analysis
        logger.info(f"MITRE INPUT: {description}")
        
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

        # DEBUG: Log raw LLM response
        logger.info(f"MITRE RAW RESPONSE: {response}")

        try:
            parsed = extract_json(response)
        except ValueError:
            logger.debug("LLM did not return parseable JSON for event %s", event.get("event_id"))
            return None

        # Handle both array and single object responses
        if isinstance(parsed, list):
            mappings = parsed
        elif isinstance(parsed, dict):
            mappings = [parsed]
        else:
            logger.debug("LLM response was not a JSON array or object for event %s", event.get("event_id"))
            return None

        if not mappings:
            logger.debug("LLM returned empty mappings for event %s", event.get("event_id"))
            return None

        # Use the first mapping with highest confidence
        best_mapping = None
        best_confidence = 0.0
        for mapped in mappings:
            attack_id = mapped.get("attack_id") or mapped.get("technique_id")
            confidence = mapped.get("confidence", 0.0)
            if attack_id and confidence > best_confidence:
                best_mapping = mapped
                best_confidence = confidence

        if not best_mapping:
            logger.debug("LLM response had no valid attack_id for event %s", event.get("event_id"))
            return None

        attack_id = best_mapping.get("attack_id") or best_mapping.get("technique_id")

        # Ground truth check: never forward an ATT&CK ID the LLM
        # invented. If it doesn't resolve in the knowledge layer, the
        # mapping is dropped rather than passed downstream.
        try:
            technique = self._resolve_technique(str(attack_id).strip())
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
        normalized_attack_id = technique.attack_id
        if context_attack_ids and normalized_attack_id not in context_attack_ids and str(attack_id).strip() not in context_attack_ids:
            logger.warning(
                "LLM selected attack_id %r (normalized=%r) not present in retrieved context for event %s; discarding",
                attack_id,
                normalized_attack_id,
                event.get("event_id"),
            )
            return None

        # Confidence validation: ensure confidence is a valid float between 0 and 1.
        confidence = best_mapping.get("confidence")
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

        # DEBUG: Log successful MITRE mapping
        logger.info(f"MITRE OUTPUT: {attack_id} - {technique.name} (confidence: {confidence})")

        mapped = {
            "attack_id": technique.attack_id,
            "technique_name": technique.name,
            "evidence_event_id": event.get("event_id"),
            "mapping_source": "llm",
            "confidence": confidence,
        }

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

        # Fallback to ChromaDB semantic search if knowledge layer search returns nothing
        try:
            from rag.vector_store import query_similar
            chroma_results = query_similar(description, n_results=self.context_limit)
            documents = chroma_results.get("documents", [[]])[0]
            metadatas = chroma_results.get("metadatas", [[]])[0]
            
            if documents:
                # Convert ChromaDB results to SearchResult format
                from knowledge.attack.models import SearchResult, ObjectType
                chroma_search_results = []
                for doc, meta in zip(documents, metadatas):
                    tech_id = (meta.get("technique_id") or "").upper().strip()
                    name = meta.get("name", "")
                    if tech_id:
                        chroma_search_results.append(
                            SearchResult(
                                attack_id=tech_id,
                                name=name,
                                description=doc,
                                object_type=ObjectType.TECHNIQUE
                            )
                        )
                # Log candidate IDs for debugging
                candidate_ids = [r.attack_id for r in chroma_search_results]
                logger.info("ATTACK_MAPPING: Using ChromaDB semantic search fallback (%d results)", len(chroma_search_results))
                logger.info("ATTACK_MAPPING: ChromaDB candidate IDs: %s", candidate_ids)
                logger.info("ATTACK_MAPPING: ChromaDB contains T1041? %s", "T1041" in candidate_ids)
                logger.info("ATTACK_MAPPING: ChromaDB contains T1567? %s", "T1567" in candidate_ids)
                
                # Keyword-based augmentation for exfiltration-related queries
                # If semantic search misses known exfiltration techniques, add them explicitly
                exfiltration_keywords = ["exfiltration", "outbound", "data transfer", "exfil"]
                if any(keyword in description.lower() for keyword in exfiltration_keywords):
                    exfil_ids = {"T1041", "T1567", "T1020", "T1011", "T1052"}
                    missing_exfil = exfil_ids - set(candidate_ids)
                    if missing_exfil:
                        logger.info("ATTACK_MAPPING: Adding missing exfiltration techniques from keyword match: %s", missing_exfil)
                        # Try to fetch these techniques from ChromaDB by ID
                        try:
                            import chromadb
                            from config import config
                            client = chromadb.PersistentClient(path=config.CHROMA_PERSIST_DIR)
                            collection = client.get_collection(name=config.CHROMA_COLLECTION_ATTACK)
                            for tech_id in missing_exfil:
                                tech_results = collection.get(where={"technique_id": tech_id})
                                if tech_results['ids']:
                                    chroma_search_results.append(
                                        SearchResult(
                                            attack_id=tech_id,
                                            name=tech_results['metadatas'][0].get('name', ''),
                                            description=tech_results['documents'][0] if tech_results['documents'] else '',
                                            object_type=ObjectType.TECHNIQUE
                                        )
                                    )
                        except Exception as e:
                            logger.debug("ATTACK_MAPPING: Failed to augment with exfiltration techniques: %s", e)
                
                return chroma_search_results
        except Exception as e:
            logger.debug("ChromaDB fallback failed: %s", e)

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

    def _resolve_technique(self, attack_id: str):
        """Resolve ATT&CK ID; fall back from sub-technique (e.g. T1562.001) to parent (T1562)."""
        cleaned = str(attack_id or "").strip().upper()
        candidates = [cleaned]
        if "." in cleaned:
            candidates.append(cleaned.split(".", 1)[0])

        last_error = None
        for candidate in candidates:
            try:
                return self.attack_service.get_technique(candidate)
            except RecordNotFoundError as exc:
                last_error = exc
                continue

        if last_error:
            raise last_error
        raise RecordNotFoundError(f"Technique not found: {attack_id}")

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

    def _detect_ssh_brute_force(self, events: List[Dict], mapped_techniques: List[Dict]) -> List[Dict]:
        """Detects SSH brute-force patterns and boosts confidence for T1110.
        
        If 3+ failed SSH logins from the same source IP occur within a short time
        window followed by a successful login, this increases the confidence for
        T1110 (Brute Force) mappings and adds a brute-force indicator.
        
        Args:
            events: The original normalized events.
            mapped_techniques: The current technique mappings.
            
        Returns:
            Updated technique mappings with boosted confidence for brute-force patterns.
        """
        from datetime import datetime
        from collections import defaultdict
        
        # Group SSH authentication events by source IP
        ssh_events_by_ip = defaultdict(list)
        for event in events:
            if event.get("service") == "ssh" and event.get("event_type") in ("authentication_failed", "authentication_success"):
                src_ip = event.get("src_ip")
                if src_ip:
                    ssh_events_by_ip[src_ip].append(event)
        
        # Check each IP for brute-force pattern
        for src_ip, ip_events in ssh_events_by_ip.items():
            # Sort by timestamp
            ip_events.sort(key=lambda e: e.get("timestamp", ""))
            
            # Count failures before each success
            failures = 0
            for event in ip_events:
                if event.get("event_type") == "authentication_failed":
                    failures += 1
                elif event.get("event_type") == "authentication_success" and failures >= 3:
                    # Brute-force pattern detected: 3+ failures followed by success
                    print(f"\n🔍 SSH Brute-Force Pattern Detected:")
                    print(f"   Source IP: {src_ip}")
                    print(f"   Failed attempts: {failures}")
                    print(f"   Successful login detected")
                    
                    # Boost confidence for T1110 mappings from this IP
                    for tech in mapped_techniques:
                        if tech.get("attack_id") == "T1110":
                            # Check if this technique came from an event with this src_ip
                            evidence_event_id = tech.get("evidence_event_id")
                            evidence_event = next((e for e in events if e.get("event_id") == evidence_event_id), None)
                            if evidence_event and evidence_event.get("src_ip") == src_ip:
                                old_confidence = tech.get("confidence", 0.7)
                                tech["confidence"] = min(old_confidence + 0.2, 1.0)  # Boost by 0.2, max 1.0
                                tech["ssh_brute_force_detected"] = True
                                tech["ssh_brute_force_failures"] = failures
                                print(f"   ✅ Boosted T1110 confidence from {old_confidence} to {tech['confidence']}")
                    
                    failures = 0  # Reset for next success
        
        return mapped_techniques

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
            f"rule_description={event.get('rule_description')}",
            f"rule_level={event.get('rule_level')}",
            f"rule_groups={event.get('rule_groups')}",
        ]
        
        # Include full_log if present in raw event
        raw = event.get("raw", {})
        if isinstance(raw, dict) and raw.get("full_log"):
            parts.append(f"full_log={raw.get('full_log')}")
        
        return ", ".join(p for p in parts if "None" not in p)

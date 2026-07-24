# Agent Architecture — Communication & Data Flow

## 1. Collection Agent (`agents/collection_agent.py`)
- **Input:** `raw_events` (raw telemetry from Wazuh, Sysmon, Suricata, Zeek, Windows Event Logs)
- **Output:** Writes `events` (normalized event dicts) to state
- **Communication mechanism:** Pure rule-based normalization (no LLM). Detects source heuristically, dispatches to source-specific normalizer, preserves original data under a `raw` key.
- **Downstream consumers:** Enrichment Agent, Attack Mapping Agent, Correlation Agent

## 2. Enrichment Agent (`agents/enrichment_agent.py`)
- **Input:** `events` (from Collection Agent)
- **Output:** Writes `iocs` (enriched IOC dicts) to state
- **Communication mechanism:**
  - Extracts IOCs from events via `intelligence/ioc_extractor.py`
  - Enriches each IOC through the `ProviderRegistry` (`intelligence/threat_intel/registry.py`), which dispatches to registered providers (AbuseIPDB, OTX)
  - Merges multi-provider results into a single `EnrichmentResult` per IOC
- **Downstream consumers:** Correlation Agent, Response Agent, Reporting Agent

## 3. Attack Mapping Agent (`agents/attack_mapping_agent.py`)
- **Input:** `events` (from Collection Agent)
- **Output:** Writes `techniques` (ATT&CK technique mappings) to state
- **Communication mechanism:** Two-tier approach:
  - **Deterministic fast path:** Rule-based matching via `AttackService.match_event()` (knowledge layer)
  - **LLM fallback:** Grounded in the knowledge layer (`AttackService.search()`), verified against real ATT&CK IDs, with ChromaDB semantic search as a last resort
  - Enriches each mapping with known groups, software, and mitigations
- **Downstream consumers:** Correlation Agent, Prediction Agent, Response Agent, Reporting Agent

## 4. Correlation Agent (`agents/correlation_agent.py`)
- **Input:** `events`, `iocs`, `techniques` (from Collection, Enrichment, and Mapping agents)
- **Output:** Writes `campaign` (campaign summary dict) to state
- **Communication mechanism:**
  - Builds structured evidence context from all three inputs
  - Uses LLM only for summarization (constrained to never invent malware names, APT groups, CVEs, or objectives)
  - Overwrites LLM confidence with deterministic calculation (`calculate_confidence()`)
  - Persists to Neo4j via `knowledge_graph/graph_builder.py` (`persist_campaign()`) — writes `Campaign`, `Event`, `Host`, and `Technique` nodes with relationships
- **Downstream consumers:** Prediction Agent, Response Agent, Reporting Agent

## 5. Prediction Agent (`agents/prediction_agent.py`)
- **Input:** `techniques`, `campaign` (from Mapping and Correlation agents)
- **Output:** Writes `prediction` (likely next techniques + rationale) to state
- **Communication mechanism:**
  - Retrieves attack-chain progression context from ChromaDB via `rag/attack_chain_retriever.py` (`retrieve_likely_next_techniques_with_ids()`)
  - Uses the RAG-returned candidate IDs as a constraint set — the LLM can only predict IDs from this set
  - Two-layer hallucination guard: (1) candidate-set constraint, (2) knowledge-layer existence check (catches deprecated/invented IDs)
- **Downstream consumers:** Reporting Agent

## 6. Response Agent (`agents/response_agent.py`)
- **Input:** `campaign`, `techniques`, `iocs` (from Correlation, Mapping, and Enrichment agents)
- **Output:** Writes `actions_taken` (list of `ActionResult` dicts) to state
- **Communication mechanism:**
  - Deterministic pre-check: auto-proposes `block_ip` for high-confidence malicious IOCs (confidence ≥ 0.8) before LLM call
  - LLM proposes structured action objects (`block_ip`, `isolate_host`, `disable_account`, etc.)
  - Policy layer (`actions/policy.py`) — deterministic, non-LLM safety gate that decides: `auto_execute` / `pending_approval` / `denied` based on kill switch, protected targets, severity thresholds, confidence thresholds, and rate limiting
  - Action connectors (`actions/connectors.py`) — dispatches approved actions to simulated firewall/EDR/IAM APIs via `ACTION_DISPATCH` dict
  - Audit log (`actions/audit_log.py`) — append-only JSONL log recording every action regardless of outcome
- **Downstream consumers:** Reporting Agent

## 7. Reporting Agent (`agents/reporting_agent.py`)
- **Input:** The entire `InvestigationState` (all fields: `events`, `iocs`, `techniques`, `campaign`, `prediction`, `actions_taken`)
- **Output:** Writes `report` (final markdown) to state
- **Communication mechanism:**
  - Passes the full state as an LLM prompt with `REPORTING_SYSTEM_PROMPT`
  - Report Validator (`agents/report_validator.py`) — cross-checks every report claim against actual evidence: validates IP addresses, timestamps, threat intel values, ATT&CK technique IDs, response action statuses, geographic claims, APT attributions, and recommendation technique IDs
  - Saves report to `reports/generated_reports/` via `reports/report_generator.py`
- **Downstream consumers:** None (terminal node — output is the final report)

#
---

## Cross-Cutting Communication Summary

| Component | Communicates With | Via |
|---|---|---|
| Enrichment Agent → Threat Intel Providers | AbuseIPDB, OTX | `ProviderRegistry.enrich_all()` |
| Correlation Agent → Neo4j | Graph database | `graph_builder.persist_campaign()` |
| Prediction Agent → RAG | ChromaDB (attack chain collection) | `retrieve_likely_next_techniques_with_ids()` |
| Response Agent → Policy | Safety gate | `policy.evaluate()` |
| Response Agent → Connectors | Firewall, EDR, IAM (simulated) | `ACTION_DISPATCH` dict |
| Response Agent → Audit Log | Append-only JSONL | `audit_log.record()` |
| Reporting Agent → Validator | Hallucination checker | `validate_report()` |
| `main.py` → Investigation Memory | Persistence | `investigation_memory.save()` |

---

## Key Design Principle

The architecture follows a **shared state + linear flow** model:

- The `InvestigationState` is the single communication bus.
- Each agent is a pure function that reads from it and writes back partial updates.
- `graph/nodes.py` wrapper functions handle the state read/write.
- `graph/workflow.py` defines the linear edge connections between agents.
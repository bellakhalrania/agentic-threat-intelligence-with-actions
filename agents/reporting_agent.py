"""
agents/reporting_agent.py
Generates the final markdown intelligence report from a compact investigation
summary, using the LLM for prose and validating the result against evidence.

The agent intentionally does not send full raw events to the LLM. Wazuh alerts
can contain large nested `raw` payloads, which easily exceed Groq on-demand TPM
limits. Instead, it sends bounded evidence summaries that preserve the important
facts needed for a concise report.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

from graph.state import InvestigationState
from llm.groq_client import invoke_llm
from llm.prompts import REPORTING_SYSTEM_PROMPT
from reports.report_generator import save_report
from agents.report_validator import validate_report

logger = logging.getLogger(__name__)


class ReportingAgent:
    MAX_EVENTS = 12
    MAX_IOCS = 20
    MAX_TECHNIQUES = 20
    MAX_ACTIONS = 12
    MAX_TEXT_CHARS = 300

    def run(self, state: InvestigationState) -> str:
        prompt = self._build_compact_prompt(state)

        try:
            report_markdown = invoke_llm(
                system_prompt=REPORTING_SYSTEM_PROMPT,
                user_prompt=prompt,
            )
        except Exception as exc:
            logger.exception("Reporting LLM failed; generating deterministic fallback report: %s", exc)
            report_markdown = self._fallback_report(state, error=str(exc))

        # Validate report against evidence before saving (for logging only)
        validation_result = validate_report(report_markdown, state)

        if not validation_result['valid']:
            logger.error(
                f"Report validation failed for campaign {state.get('campaign', {}).get('campaign_id', 'unknown')}. "
                f"Issues: {len(validation_result['issues'])}"
            )
            logger.warning("Saving report despite validation failures - requires human review")

        if validation_result['warnings']:
            logger.warning(
                f"Report validation produced {len(validation_result['warnings'])} warnings "
                f"for campaign {state.get('campaign', {}).get('campaign_id', 'unknown')}"
            )

        save_report(
            report_markdown,
            campaign=state.get("campaign", {})
        )
        return report_markdown

    def _build_compact_prompt(self, state: InvestigationState) -> str:
        evidence = {
            "summary_counts": {
                "events": len(state.get("events", [])),
                "iocs": len(state.get("iocs", [])),
                "techniques": len(state.get("techniques", [])),
                "actions_taken": len(state.get("actions_taken", [])),
            },
            "events": self._summarize_events(state.get("events", [])),
            "iocs": self._summarize_iocs(state.get("iocs", [])),
            "attack_techniques": self._summarize_techniques(state.get("techniques", [])),
            "campaign": self._summarize_campaign(state.get("campaign", {})),
            "prediction": self._summarize_prediction(state.get("prediction", {})),
            "response_actions_taken": self._summarize_actions(state.get("actions_taken", [])),
            "reporting_instruction": (
                "Write the report only from this compact evidence. Mention that counts may exceed "
                "listed samples when summary_counts are larger than the arrays. Do not invent raw event details."
            ),
        }
        return json.dumps(evidence, indent=2, sort_keys=True, default=str)

    def _summarize_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        summarized = []
        for event in events[: self.MAX_EVENTS]:
            summarized.append({
                "event_id": event.get("event_id"),
                "source": event.get("source"),
                "event_type": event.get("event_type"),
                "timestamp": event.get("timestamp"),
                "host": event.get("host"),
                "user": event.get("user"),
                "username": event.get("username"),
                "process": event.get("process"),
                "command_line": self._shorten(event.get("command_line")),
                "src_ip": event.get("src_ip"),
                "dest_ip": event.get("dest_ip"),
                "service": event.get("service"),
                "rule_description": self._shorten(event.get("rule_description")),
                "rule_level": event.get("rule_level"),
                "rule_groups": event.get("rule_groups"),
                "rule_mitre": event.get("rule_mitre"),
            })
        return summarized

    def _summarize_iocs(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        summarized = []
        for ioc in iocs[: self.MAX_IOCS]:
            summarized.append({
                "value": ioc.get("value"),
                "ioc_type": ioc.get("ioc_type") or ioc.get("type"),
                "reputation": ioc.get("reputation"),
                "confidence": ioc.get("confidence"),
                "source": ioc.get("source"),
                "tags": ioc.get("tags"),
                "source_event_id": ioc.get("source_event_id"),
            })
        return summarized

    def _summarize_techniques(self, techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        summarized = []
        seen = set()
        for technique in techniques:
            key = (
                technique.get("attack_id") or technique.get("technique_id"),
                technique.get("evidence_event_id"),
            )
            if key in seen:
                continue
            seen.add(key)
            summarized.append({
                "attack_id": technique.get("attack_id") or technique.get("technique_id"),
                "technique_name": technique.get("technique_name") or technique.get("name"),
                "confidence": technique.get("confidence"),
                "evidence_event_id": technique.get("evidence_event_id"),
                "mapping_source": technique.get("mapping_source"),
                "rule_name": technique.get("rule_name"),
            })
            if len(summarized) >= self.MAX_TECHNIQUES:
                break
        return summarized

    def _summarize_campaign(self, campaign: Dict[str, Any]) -> Dict[str, Any]:
        timeline = campaign.get("timeline") or []
        return {
            "campaign_id": campaign.get("campaign_id"),
            "name": campaign.get("name"),
            "objective": campaign.get("objective"),
            "confidence": campaign.get("confidence"),
            "related_techniques": campaign.get("related_techniques"),
            "evidence_summary": self._shorten(campaign.get("evidence_summary"), 800),
            "timeline": [
                {
                    "timestamp": item.get("timestamp"),
                    "event_id": item.get("event_id"),
                    "description": self._shorten(item.get("description")),
                }
                for item in timeline[: self.MAX_EVENTS]
            ],
        }

    def _summarize_prediction(self, prediction: Dict[str, Any]) -> Dict[str, Any]:
        likely = prediction.get("likely_next_techniques") or []
        return {
            "likely_next_techniques": likely[:10],
            "rationale": self._shorten(prediction.get("rationale"), 800),
        }

    def _summarize_actions(self, actions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        summarized = []
        for action_result in actions[: self.MAX_ACTIONS]:
            action = action_result.get("action", action_result)
            summarized.append({
                "action_type": action.get("action_type"),
                "target": action.get("target"),
                "severity": action.get("severity"),
                "status": action_result.get("status"),
                "technique_id": action.get("technique_id"),
                "confidence": action.get("confidence"),
                "rationale": self._shorten(action.get("rationale")),
                "detail": self._shorten(action_result.get("detail")),
                "dry_run": action_result.get("dry_run"),
            })
        return summarized

    def _fallback_report(self, state: InvestigationState, error: str = "") -> str:
        campaign = state.get("campaign", {})
        techniques = self._summarize_techniques(state.get("techniques", []))
        iocs = self._summarize_iocs(state.get("iocs", []))
        actions = self._summarize_actions(state.get("actions_taken", []))
        prediction = self._summarize_prediction(state.get("prediction", {}))

        lines = [
            "# Threat Intelligence Report",
            "",
            "## Executive Summary",
            f"Campaign: {campaign.get('name', 'Unclassified Activity')}.",
            f"Objective: {campaign.get('objective', 'Unknown')}.",
            f"Confidence: {campaign.get('confidence', 'Unknown')}.",
            "",
            "## Campaign Assessment",
            self._shorten(campaign.get("evidence_summary"), 1200) or "No campaign summary available.",
            "",
            "## ATT&CK Techniques",
        ]

        if techniques:
            lines.extend(["| Technique ID | Name | Confidence | Evidence Event |", "|---|---|---:|---|"])
            for tech in techniques:
                lines.append(
                    f"| {tech.get('attack_id') or ''} | {tech.get('technique_name') or ''} | "
                    f"{tech.get('confidence') or ''} | {tech.get('evidence_event_id') or ''} |"
                )
        else:
            lines.append("No confirmed ATT&CK techniques were mapped.")

        lines.extend(["", "## IOCs"])
        if iocs:
            lines.extend(["| Value | Type | Reputation | Confidence | Source |", "|---|---|---|---:|---|"])
            for ioc in iocs:
                lines.append(
                    f"| {ioc.get('value') or ''} | {ioc.get('ioc_type') or ''} | "
                    f"{ioc.get('reputation') or ''} | {ioc.get('confidence') or ''} | {ioc.get('source') or ''} |"
                )
        else:
            lines.append("No IOCs were extracted.")

        lines.extend(["", "## Predicted Next Steps"])
        if prediction.get("likely_next_techniques"):
            for item in prediction["likely_next_techniques"]:
                if isinstance(item, dict):
                    lines.append(f"- {item.get('technique_id')}: {item.get('technique_name')} — {item.get('rationale')}")
                else:
                    lines.append(f"- {item}")
            if prediction.get("rationale"):
                lines.append(f"\nRationale: {prediction['rationale']}")
        else:
            lines.append(prediction.get("rationale") or "No predicted next steps available.")

        lines.extend(["", "## Response Actions"])
        if actions:
            lines.extend(["| Action | Target | Status | Severity | Rationale |", "|---|---|---|---|---|"])
            for action in actions:
                lines.append(
                    f"| {action.get('action_type') or ''} | {action.get('target') or ''} | "
                    f"{action.get('status') or ''} | {action.get('severity') or ''} | {action.get('rationale') or ''} |"
                )
        else:
            lines.append("No response actions were proposed.")

        if error:
            lines.extend([
                "",
                "## Generation Note",
                "The LLM report generation failed, so this deterministic fallback report was generated from the investigation state.",
                f"Error: `{self._shorten(error, 500)}`",
            ])

        return "\n".join(lines)

    @classmethod
    def _shorten(cls, value: Any, max_chars: int | None = None) -> Any:
        if value is None:
            return None
        text = str(value)
        limit = max_chars or cls.MAX_TEXT_CHARS
        if len(text) <= limit:
            return text
        return text[: limit - 3] + "..."

"""
agents/reporting_agent.py
Generates the final markdown intelligence report from the full
investigation state, using the LLM for prose plus a Jinja2 template for
structure (reports/markdown_templates.py) for consistent formatting.

Includes validation to prevent hallucinations by cross-checking report
claims against actual evidence.
"""

import logging
from graph.state import InvestigationState
from llm.groq_client import invoke_llm
from llm.prompts import REPORTING_SYSTEM_PROMPT
from reports.report_generator import save_report
from agents.report_validator import validate_report

logger = logging.getLogger(__name__)


class ReportingAgent:
    def run(self, state: InvestigationState) -> str:
        prompt = (
            f"Events:\n{state.get('events')}\n\n"
            f"IOCs:\n{state.get('iocs')}\n\n"
            f"ATT&CK Techniques:\n{state.get('techniques')}\n\n"
            f"Campaign:\n{state.get('campaign')}\n\n"
            f"Prediction:\n{state.get('prediction')}\n\n"
            f"Response Actions Taken:\n{state.get('actions_taken')}"
        )
        report_markdown = invoke_llm(system_prompt=REPORTING_SYSTEM_PROMPT, user_prompt=prompt)

        # Validate report against evidence before saving
        validation_result = validate_report(report_markdown, state)

        if not validation_result['valid']:
            logger.error(
                f"Report validation failed for campaign {state.get('campaign', {}).get('campaign_id', 'unknown')}. "
                f"Issues: {len(validation_result['issues'])}"
            )
            # In production, you might want to:
            # 1. Reject the report entirely
            # 2. Flag for human review
            # 3. Regenerate with stricter constraints
            # For now, we log the error but still save (with validation metadata)
            logger.warning("Saving report despite validation failures - requires human review")

        if validation_result['warnings']:
            logger.warning(
                f"Report validation produced {len(validation_result['warnings'])} warnings "
                f"for campaign {state.get('campaign', {}).get('campaign_id', 'unknown')}"
            )

        # Pass validation results to report generator
        validation_status = "Passed" if validation_result['valid'] else "Failed"
        save_report(
            report_markdown,
            campaign=state.get("campaign", {}),
            validation_status=validation_status,
            validation_issues=validation_result['issues']
        )
        return report_markdown

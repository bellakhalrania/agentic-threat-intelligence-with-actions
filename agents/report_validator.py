"""
agents/report_validator.py
Validates threat intelligence reports against actual evidence to prevent hallucinations.

Cross-checks report claims against:
- Original Wazuh events
- Threat intelligence API responses (AbuseIPDB, OTX)
- Mapped ATT&CK techniques
- Response action audit logs
"""

import logging
import re
from typing import Dict, List, Set
from graph.state import InvestigationState

logger = logging.getLogger(__name__)


class ReportValidator:
    """Validates report claims against investigation evidence."""

    def __init__(self):
        self.issues = []
        self.warnings = []

    def validate(self, report_markdown: str, state: InvestigationState) -> Dict:
        """
        Validates report claims against actual evidence.

        Args:
            report_markdown: The generated markdown report
            state: The investigation state with actual evidence

        Returns:
            Dict with 'valid' (bool), 'issues' (list), 'warnings' (list)
        """
        self.issues = []
        self.warnings = []

        # Extract evidence from state
        events = state.get('events', [])
        iocs = state.get('iocs', [])
        techniques = state.get('techniques', [])
        actions_taken = state.get('actions_taken', [])

        # Validate IP addresses
        self._validate_ips(report_markdown, iocs, events)

        # Validate timestamps and timeline
        self._validate_timeline(report_markdown, events)

        # Validate threat intelligence claims
        self._validate_threat_intel(report_markdown, iocs)

        # Validate ATT&CK techniques
        self._validate_techniques(report_markdown, techniques)

        # Validate response actions
        self._validate_response_actions(report_markdown, actions_taken)

        # Validate geographic and targeting claims
        self._validate_geographic_claims(report_markdown)

        # Validate campaign/actor attributions
        self._validate_attribution_claims(report_markdown, state.get('campaign', {}), techniques)

        # Validate that recommendations do not cite uninvestigated (hallucinated) technique IDs
        self._validate_recommendations(report_markdown, techniques)

        return {
            'valid': len(self.issues) == 0,
            'issues': self.issues,
            'warnings': self.warnings
        }

    def _validate_ips(self, report_markdown: str, iocs: List[Dict], events: List[Dict]) -> None:
        """Validates that all IPs in report exist in evidence (IOCs or original events)."""
        # Extract IPv4 addresses from report
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        report_ips = set(re.findall(ip_pattern, report_markdown))

        # Extract IPs from evidence (both IOCs and original events)
        evidence_ips = set()
        
        # From IOCs
        for ioc in iocs:
            value = ioc.get('value', '')
            if re.match(ip_pattern, value):
                evidence_ips.add(value)
        
        # From original events (src_ip, dest_ip fields)
        for event in events:
            for field in ['src_ip', 'dest_ip', 'source_ip', 'destination_ip']:
                ip = event.get(field)
                if ip and re.match(ip_pattern, ip):
                    evidence_ips.add(ip)

        # Check for invented IPs
        for ip in report_ips:
            if ip not in evidence_ips:
                self.issues.append(
                    f"IP hallucination: Report mentions IP {ip} not found in evidence (IOCs or events)"
                )

    def _validate_timeline(self, report_markdown: str, events: List[Dict]) -> None:
        """Validates timeline entries against actual events."""
        # Extract timestamps from report (ISO format), but exclude report metadata
        # Report metadata typically appears in header like "**Generated:** 2026-07-21T..."
        # We'll only validate timestamps that appear in the Timeline section
        lines = report_markdown.split('\n')
        in_timeline_section = False
        timeline_timestamps = set()

        for line in lines:
            if '## Timeline' in line or 'Timeline' in line:
                in_timeline_section = True
            elif line.startswith('##') and in_timeline_section:
                in_timeline_section = False
            elif in_timeline_section:
                timestamp_pattern = r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}'
                matches = re.findall(timestamp_pattern, line)
                timeline_timestamps.update(matches)

        # Extract timestamps from evidence
        evidence_timestamps = set()
        for event in events:
            ts = event.get('timestamp')
            if ts:
                evidence_timestamps.add(ts[:19])  # Normalize to same format

        # Check for invented timestamps in timeline section only
        for ts in timeline_timestamps:
            if ts not in evidence_timestamps:
                self.issues.append(
                    f"Timeline hallucination: Report timeline contains timestamp {ts} not in evidence events"
                )

    def _validate_threat_intel(self, report_markdown: str, iocs: List[Dict]) -> None:
        """Validates threat intelligence claims against API responses.

        Checks both structural claims (AbuseIPDB as source) AND that numeric
        values reported (e.g. totalReports, confidence score) match the actual
        API values stored in the evidence, not just any number the LLM may have
        invented.
        """
        # Skip validation in Recommendations section - mentioning threat intel sources
        # as recommendations (e.g., "share with OTX") is acceptable
        lines = report_markdown.split('\n')
        in_recommendations_section = False
        non_recommendation_text = []

        for line in lines:
            if '## Recommendations' in line:
                in_recommendations_section = True
            elif line.startswith('##') and in_recommendations_section:
                in_recommendations_section = False
            elif not in_recommendations_section:
                non_recommendation_text.append(line)

        non_recommendation_markdown = '\n'.join(non_recommendation_text)

        # Check for AbuseIPDB-specific claims (outside recommendations)
        abuseipdb_keywords = [
            r'(\d+)\s+reports',
            r'(\d+)\s+distinct\s+users',
            r'abuse\s+confidence\s+score',
            r'tor\s+exit\s+node',
        ]

        for pattern in abuseipdb_keywords:
            matches = re.findall(pattern, non_recommendation_markdown, re.IGNORECASE)
            if matches:
                # Check if these values are in the actual IOC data
                found_in_evidence = False
                for ioc in iocs:
                    if 'AbuseIPDB' in str(ioc.get('source', '')):
                        found_in_evidence = True
                        break

                if not found_in_evidence:
                    self.issues.append(
                        f"Threat intel hallucination: Report contains AbuseIPDB-specific data "
                        f"('{pattern}') but no AbuseIPDB source in evidence"
                    )

        # --- Numeric value accuracy check ---
        # Verify that specific numeric values the report claims (e.g. "120 reports") match
        # the actual values returned by the API and stored in the evidence, not just any
        # arbitrary number the LLM might generate.
        for ioc in iocs:
            for evidence_item in ioc.get('evidence', []):
                raw_resp = {}
                if hasattr(evidence_item, 'raw_response'):
                    raw_resp = evidence_item.raw_response  # Pydantic model
                elif isinstance(evidence_item, dict):
                    raw_resp = evidence_item.get('raw_response', {})

                total_reports = raw_resp.get('totalReports')
                abuse_score = raw_resp.get('abuseConfidenceScore')

                if total_reports is not None:
                    # Check that the exact number appears in the report
                    if not re.search(rf'\b{re.escape(str(total_reports))}\b', non_recommendation_markdown):
                        # Allow "120 reports" even if report says "over 100 reports" — only flag
                        # when a DIFFERENT specific number is given
                        different_number = re.search(
                            r'(\b\d+\b)\s+(?:total\s+)?reports',
                            non_recommendation_markdown,
                            re.IGNORECASE,
                        )
                        if different_number and different_number.group(1) != str(total_reports):
                            self.issues.append(
                                f"Threat intel value mismatch: Report states "
                                f"'{different_number.group(1)} reports' for {ioc.get('value')} "
                                f"but AbuseIPDB evidence shows {total_reports} total reports"
                            )

                if abuse_score is not None:
                    # Confidence in report is stored as float (0-1); score is 0-100
                    expected_confidence = round(min(abuse_score / 100.0, 1.0), 2)
                    # Accept either form: 0.98 or 98%
                    if not (
                        re.search(rf'\b{re.escape(str(expected_confidence))}\b', non_recommendation_markdown)
                        or re.search(rf'\b{re.escape(str(abuse_score))}\s*%?\b', non_recommendation_markdown)
                    ):
                        self.warnings.append(
                            f"Threat intel value check: confidence for {ioc.get('value')} "
                            f"expected {expected_confidence} (from score {abuse_score}) "
                            f"— verify the report states the correct value"
                        )

        # Check for OTX-specific claims (outside recommendations)
        # Only flag if it appears to be claiming OTX was used as a source, not just mentioning it
        # Examples of claims: "OTX reported", "according to OTX", "OTX pulse detected"
        # Examples of acceptable mentions: "share with OTX", "via OTX", "OTX community"
        otx_claim_patterns = [
            r'OTX\s+(?:reported|detected|indicated|showed|confirmed)',
            r'according\s+to\s+OTX',
            r'OTX\s+pulse\s+(?:detected|found|observed)',
            r'AlienVault\s+(?:reported|detected|indicated)',
        ]

        for pattern in otx_claim_patterns:
            if re.search(pattern, non_recommendation_markdown, re.IGNORECASE):
                found_in_evidence = False
                for ioc in iocs:
                    if 'OTX' in str(ioc.get('source', '')) or 'AlienVault' in str(ioc.get('source', '')):
                        found_in_evidence = True
                        break

                if not found_in_evidence:
                    self.issues.append(
                        f"Threat intel hallucination: Report claims OTX/AlienVault as source "
                        f"but no OTX source in evidence"
                    )

    def _validate_techniques(self, report_markdown: str, techniques: List[Dict]) -> None:
        """Validates ATT&CK technique IDs against mapped techniques."""
        # Extract technique IDs from report (T#### or T####.###)
        # But exclude techniques in "Predicted Next Steps" section as these are reasonable inferences
        lines = report_markdown.split('\n')
        in_prediction_section = False
        prediction_techniques = set()
        other_techniques = set()

        for line in lines:
            if 'Predicted Next Steps' in line or 'Prediction' in line:
                in_prediction_section = True
            elif line.startswith('##') and in_prediction_section:
                in_prediction_section = False
            elif in_prediction_section:
                technique_pattern = r'T\d{4}(?:\.\d{3})?'
                matches = re.findall(technique_pattern, line)
                prediction_techniques.update(matches)
            else:
                technique_pattern = r'T\d{4}(?:\.\d{3})?'
                matches = re.findall(technique_pattern, line)
                other_techniques.update(matches)

        # Extract technique IDs from evidence
        evidence_techniques = set()
        for tech in techniques:
            tech_id = tech.get('attack_id') or tech.get('technique_id')
            if tech_id:
                evidence_techniques.add(tech_id.upper())

        # Only flag techniques NOT in prediction section
        for tech_id in other_techniques:
            if tech_id not in evidence_techniques:
                self.issues.append(
                    f"MITRE hallucination: Report mentions technique {tech_id} not in mapped techniques"
                )

    def _validate_response_actions(self, report_markdown: str, actions_taken: List[Dict]) -> None:
        """Validates response action statuses against audit log.
        
        Response Agent uses status values: 'executed', 'pending_approval', 'denied', 'failed'
        """
        # Look for "Executed" or "Completed" status in report (both terms may be used)
        executed_pattern = r'\|\s*(?:Executed|Completed)\s*\|'
        if re.search(executed_pattern, report_markdown):
            # Check if any actions in evidence are actually executed
            has_executed = any(
                action.get('status', '').lower() == 'executed'
                for action in actions_taken
            )

            if not has_executed:
                self.issues.append(
                    "Response action hallucination: Report marks actions as 'Executed/Completed' "
                    "but no executed actions in evidence audit log"
                )

        # Check for specific action types that might be fabricated
        action_types_in_report = set()
        action_pattern = r'\|\s*([a-z_]+)\s*\|'  # Match action_type in table
        for match in re.finditer(action_pattern, report_markdown, re.IGNORECASE):
            action_type = match.group(1)
            if action_type in ['block_ip', 'isolate_host', 'kill_process', 'disable_account',
                             'quarantine_file', 'firewall_block', 'notify_analyst']:
                action_types_in_report.add(action_type)

        # Verify these action types exist in evidence
        evidence_action_types = set()
        for action in actions_taken:
            # Handle both dict and ActionResult object formats
            if isinstance(action, dict):
                action_type = action.get('action_type', '').lower()
            else:
                # ActionResult object - access via action.action.action_type
                action_type = getattr(action, 'action', None)
                if action_type:
                    action_type = getattr(action_type, 'action_type', '').lower()
                else:
                    action_type = ''
            if action_type:
                evidence_action_types.add(action_type)

        for action_type in action_types_in_report:
            if action_type not in evidence_action_types:
                self.issues.append(
                    f"Response action hallucination: Report mentions action type '{action_type}' "
                    f"not found in evidence"
                )

    def _validate_geographic_claims(self, report_markdown: str) -> None:
        """Validates that no geographic claims are made without evidence."""
        # Common country names and geographic terms
        geo_keywords = [
            r'\b(Germany|US|USA|United States|Sweden|Russia|China|North Korea|Iran)\b',
            r'\b(Europe|Asia|North America|South America)\b',
            r'\b(Berlin|Washington|Moscow|Beijing|Tehran)\b',
        ]

        for pattern in geo_keywords:
            if re.search(pattern, report_markdown, re.IGNORECASE):
                self.warnings.append(
                    f"Geographic claim detected: Report contains geographic reference "
                    f"('{pattern}') - ensure this is backed by evidence"
                )

    def _validate_attribution_claims(self, report_markdown: str, campaign: Dict, techniques: List[Dict]) -> None:
        """Validates campaign/actor attributions against evidence."""
        campaign_name = campaign.get('name', '')

        # Extract known groups from techniques (MITRE enrichment)
        known_groups = set()
        for tech in techniques:
            if 'known_groups' in tech:
                known_groups.update(tech['known_groups'])

        # Check for APT group mentions
        apt_pattern = r'\bAPT[-\d]?\w*\b'
        apt_mentions = set(re.findall(apt_pattern, report_markdown, re.IGNORECASE))

        # Only allow APT mentions if they're in the known_groups from techniques
        # or if the campaign name itself contains an APT reference
        allowed_apts = set()
        if 'APT' in campaign_name.upper():
            allowed_apts.update(apt_mentions)  # Allow if campaign name has APT

        # Also allow APTs that are in the known_groups from MITRE enrichment
        for group in known_groups:
            if 'APT' in group.upper():
                allowed_apts.add(group)

        # Check for invented APT attributions
        for apt in apt_mentions:
            if apt.upper() not in {a.upper() for a in allowed_apts}:
                self.issues.append(
                    f"Attribution hallucination: Report mentions APT group '{apt}' "
                    f"without evidence backing"
                )

        # Check for campaign name fabrication
        if campaign_name == 'Unclassified Activity':
            # Report should not assign a different campaign name
            campaign_name_pattern = r'Campaign:\s*\*\*([^*]+)\*\*'
            matches = re.findall(campaign_name_pattern, report_markdown)
            for match in matches:
                if match != 'Unclassified Activity' and match != 'Unclassified Activity':
                    self.warnings.append(
                        f"Campaign name assignment: Report assigns campaign name '{match}' "
                        f"but evidence shows 'Unclassified Activity'"
                    )

    def _validate_recommendations(self, report_markdown: str, techniques: List[Dict]) -> None:
        """Validates that the Recommendations section does not cite technique IDs
        that are not in the confirmed mapped techniques.

        This catches second-order hallucinations where predicted technique IDs
        (themselves potentially hallucinated by the PredictionAgent) bleed into
        recommendations, making the analyst act on fabricated threat intelligence.
        """
        lines = report_markdown.split('\n')
        in_rec_section = False
        rec_techniques: Set[str] = set()

        for line in lines:
            if '## Recommendations' in line:
                in_rec_section = True
            elif line.startswith('##') and in_rec_section:
                in_rec_section = False
            elif in_rec_section:
                matches = re.findall(r'T\d{4}(?:\.\d{3})?', line)
                rec_techniques.update(m.upper() for m in matches)

        evidence_techniques: Set[str] = {
            (t.get('attack_id') or t.get('technique_id') or '').upper()
            for t in techniques
        }
        # Remove empty strings from set
        evidence_techniques.discard('')

        for tech_id in rec_techniques:
            if tech_id not in evidence_techniques:
                self.issues.append(
                    f"Recommendation hallucination: Recommendations section cites "
                    f"technique {tech_id} which is not in the confirmed mapped techniques. "
                    f"This may be a predicted (unconfirmed) or invented technique ID."
                )


def validate_report(report_markdown: str, state: InvestigationState) -> Dict:
    """
    Convenience function to validate a report.

    Args:
        report_markdown: The generated markdown report
        state: The investigation state with actual evidence

    Returns:
        Dict with 'valid' (bool), 'issues' (list), 'warnings' (list)
    """
    validator = ReportValidator()
    result = validator.validate(report_markdown, state)

    if not result['valid']:
        logger.error(f"Report validation failed with {len(result['issues'])} issues")
        for issue in result['issues']:
            logger.error(f"  - {issue}")

    if result['warnings']:
        logger.warning(f"Report validation produced {len(result['warnings'])} warnings")
        for warning in result['warnings']:
            logger.warning(f"  - {warning}")

    return result

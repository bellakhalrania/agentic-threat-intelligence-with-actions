"""
agents/response_agent.py
Seventh pipeline stage (optional - wire into graph/workflow.py to enable).

Takes the campaign + techniques + prediction and proposes concrete response
actions. Critically: the LLM only ever PROPOSES a structured action. Every
proposal is passed through actions/policy.py (deterministic, non-LLM logic)
before anything is allowed to actually execute, and every outcome - executed,
pending, or denied - is written to the audit log.
"""

import json
from typing import Any, List, Dict, Set
from llm.groq_client import invoke_llm
from llm.output_parsers import extract_json
from actions.action_models import ProposedAction, ActionResult
from actions.connectors import ACTION_DISPATCH
from actions.risk_scoring import calculate_risk_score
from actions import policy, audit_log
from config import config, is_protected_target

RESPONSE_SYSTEM_PROMPT = """You are an incident response analyst. Given a
compact threat summary with mapped ATT&CK techniques and predictions, propose
concrete response actions. For each action, output:
{"action_type": "block_ip|isolate_host|disable_account|kill_process|quarantine_file|notify_analyst",
 "target": "...", "severity": "low|medium|high", "rationale": "...",
 "technique_id": "...", "confidence": 0.0}
Respond ONLY with a JSON array of action objects. Be conservative: only
propose disruptive actions (isolate_host, disable_account) when evidence is
strong. Thresholds:
- block_ip: only when a source IP is an explicit valid action target and the
  summary indicates strong evidence
- isolate_host: only when a victim isolation target is explicitly listed and
  multiple high-confidence techniques or high severity are observed
- notify_analyst: ALWAYS include at least one notify_analyst action summarizing the situation."""


class ResponseAgent:
    def run(self, threat_summary: Dict[str, Any], iocs: List[Dict]) -> List[ActionResult]:
        """Propose actions from bounded threat context, never raw events.

        IOC enrichment remains available for deterministic auto-blocking and
        action auditing. It is intentionally excluded from the LLM prompt;
        the prompt is the supplied deterministic threat summary only.
        """
        print("\n========== RESPONSE AGENT ==========\n")
        threat_summary = threat_summary or {}
        campaign = threat_summary.get("campaign") or {}
        techniques = threat_summary.get("top_mitre_techniques") or []
        risk = calculate_risk_score(threat_summary, iocs)
        print(f"Risk Score: {risk.score}/100 (version {risk.version})")
        print(f"Risk Factors: {', '.join(risk.factors)}")

        # --- Extract valid targets to prevent LLM hallucination ---
        valid_targets = self._extract_valid_targets(threat_summary, iocs)
        victim_isolation_targets = self._extract_victim_isolation_targets(threat_summary)
        attacker_source_ips = self._extract_attacker_source_ips(threat_summary)
        print(f"Valid Targets for Actions: {', '.join(valid_targets) if valid_targets else 'None detected'}")
        
        print(f"Input Context:")
        print(f"  Campaign: {campaign.get('name', 'unknown')} (ID: {campaign.get('campaign_id', 'unknown')[:8]}...)")
        print(f"  Techniques: {len(techniques)}")
        print(f"  IOCs: {len(iocs)}")
        print()
        
        # --- Deterministic pre-check: auto-propose block_ip for high-confidence malicious IOCs ---
        # This ensures critical threats are never missed because the LLM was overly conservative.
        pre_proposals = self._auto_propose_high_confidence_actions(iocs)
        
        if pre_proposals:
            print(f"--- Auto-Proposed Actions (Deterministic) ---")
            for i, proposal in enumerate(pre_proposals, 1):
                print(f"  {i}. {proposal.get('action_type')} on {proposal.get('target')}")
                print(f"     Severity: {proposal.get('severity')}")
                print(f"     Rationale: {proposal.get('rationale')}")
                print(f"     Confidence: {proposal.get('confidence')}")
            print()
        else:
            print("--- Auto-Proposed Actions: None ---")
            print()

        # The response LLM receives exactly one bounded, deterministic object.
        prompt = json.dumps(threat_summary, sort_keys=True, separators=(",", ":"))
        print("Invoking LLM for action proposals...")
        response = invoke_llm(system_prompt=RESPONSE_SYSTEM_PROMPT, user_prompt=prompt)

        try:
            llm_proposals = extract_json(response)
            llm_proposals = self._sanitize_llm_proposals(
                llm_proposals,
                valid_targets,
                victim_isolation_targets,
                attacker_source_ips,
            )
            print(f"LLM proposed {len(llm_proposals)} action(s)")
        except ValueError:
            llm_proposals = []
            print("LLM failed to return valid JSON")

        llm_proposals = self._ensure_analyst_notification(llm_proposals, campaign)

        if llm_proposals:
            print(f"\n--- LLM-Proposed Actions ---")
            for i, proposal in enumerate(llm_proposals, 1):
                print(f"  {i}. {proposal.get('action_type')} on {proposal.get('target')}")
                print(f"     Severity: {proposal.get('severity')}")
                print(f"     Rationale: {proposal.get('rationale')}")
                print(f"     Technique ID: {proposal.get('technique_id', 'N/A')}")
                print(f"     Confidence: {proposal.get('confidence')}")
            print()

        # Merge: pre_proposals first so deterministic actions take priority
        # De-duplicate: skip LLM proposals that duplicate an auto-proposed action
        all_proposals = list(pre_proposals)
        auto_targets = {p["target"] + p["action_type"] for p in pre_proposals}
        for raw in llm_proposals:
            dedup_key = raw.get("target", "") + raw.get("action_type", "")
            if dedup_key not in auto_targets:
                all_proposals.append(raw)

        print(f"--- Total Actions to Process: {len(all_proposals)} ---\n")
        
        results = []
        for i, raw in enumerate(all_proposals, 1):
            try:
                action = ProposedAction(**raw)
            except Exception:
                print(f"❌ Action {i}: Malformed proposal, skipping")
                continue  # skip malformed proposals rather than crash the run

            # Risk is derived from trusted evidence. Any LLM-supplied risk
            # fields are overwritten and can never authorize execution.
            action = action.model_copy(update={
                "risk_score": risk.score,
                "risk_factors": risk.factors,
                "risk_version": risk.version,
            })

            print(f"--- Action {i}: {action.action_type} on {action.target} ---")
            print(f"  Rationale: {action.rationale}")
            print(f"  Severity: {action.severity}")
            print(f"  Risk Score: {action.risk_score}/100")
            print(f"  Related Technique: {action.technique_id or 'N/A'}")
            
            # Show relation to events/IOCs
            if action.technique_id:
                related_tech = next((t for t in techniques if t.get('id') == action.technique_id), None)
                if related_tech:
                    print(f"  Related to technique: {related_tech.get('name', 'N/A')}")
            
            if action.action_type == "block_ip":
                related_ioc = next((ioc for ioc in iocs if ioc.get('value') == action.target), None)
                if related_ioc:
                    print(f"  Related IOC: {related_ioc.get('value')} (reputation: {related_ioc.get('reputation')}, confidence: {related_ioc.get('confidence')})")

            decision = policy.evaluate(action)
            print(f"  Policy Decision: {decision}")
            
            result = self._handle_decision(action, decision)
            
            print(f"  Final Status: {result.status}")
            print(f"  Detail: {result.detail}")
            print(f"  Dry Run: {result.dry_run}")
            
            audit_log.record(result, campaign_id=campaign.get("campaign_id", ""))
            results.append(result)
            print()
        
        print(f"--- Summary ---")
        print(f"Total actions proposed: {len(all_proposals)}")
        print(f"Executed: {sum(1 for r in results if r.status == 'executed')}")
        print(f"Pending: {sum(1 for r in results if r.status == 'pending_approval')}")
        print(f"Denied: {sum(1 for r in results if r.status == 'denied')}")
        print(f"Failed: {sum(1 for r in results if r.status == 'failed')}")
        print("===========================\n")
        
        return results

    def _extract_valid_targets(self, threat_summary: Dict[str, Any], iocs: List[Dict]) -> List[str]:
        """Collect action targets from the bounded summary and IOC evidence."""
        targets: Set[str] = set()

        # IOC values are first-class targets (IPs, domains, hashes, etc.)
        for ioc in iocs:
            val = ioc.get("value")
            if val:
                targets.add(str(val))

        for value in threat_summary.get("valid_action_targets", []) or []:
            if value:
                targets.add(str(value))

        # Notification target comes from deployment configuration.
        if config.ANALYST_NOTIFICATION_TARGET:
            targets.add(config.ANALYST_NOTIFICATION_TARGET)

        return sorted(t for t in targets if t)

    def _sanitize_llm_proposals(
        self,
        proposals: List[Dict],
        valid_targets: List[str],
        victim_isolation_targets: List[str],
        attacker_source_ips: Set[str],
    ) -> List[Dict]:
        """Drop hallucinated targets, normalize notify targets, and enforce safe isolate targeting."""
        if not isinstance(proposals, list):
            return []

        allowed = set(valid_targets) | set(victim_isolation_targets)
        victim_targets = set(victim_isolation_targets)
        preferred_victim = victim_isolation_targets[0] if victim_isolation_targets else None
        sanitized: List[Dict] = []

        for proposal in proposals:
            if not isinstance(proposal, dict):
                continue

            action_type = str(proposal.get("action_type", "")).strip()
            target = proposal.get("target")

            if action_type == "notify_analyst":
                # Notification delivery is deployment-configured, not LLM-selected.
                proposal["target"] = config.ANALYST_NOTIFICATION_TARGET
                sanitized.append(proposal)
                continue

            if not target:
                continue

            normalized_target = str(target).strip()

            # Critical guardrail: never isolate a source/attacker IP.
            # isolate_host must target the monitored/compromised endpoint only.
            if action_type == "isolate_host":
                if normalized_target in attacker_source_ips or normalized_target not in victim_targets:
                    if preferred_victim:
                        print(
                            f"Rewriting isolate_host target from '{normalized_target}' "
                            f"to victim endpoint '{preferred_victim}'"
                        )
                        proposal["target"] = preferred_victim
                        normalized_target = preferred_victim
                    else:
                        print(
                            f"Discarding isolate_host action: no trusted victim endpoint available "
                            f"(proposed target: {normalized_target})"
                        )
                        continue

            if normalized_target not in allowed:
                # Keep protected targets so deterministic policy can explicitly deny them.
                if is_protected_target(normalized_target):
                    sanitized.append(proposal)
                    continue
                print(f"Discarding LLM action with ungrounded target: {target}")
                continue

            sanitized.append(proposal)

        return sanitized

    @staticmethod
    def _ensure_analyst_notification(
        proposals: List[Dict], campaign: Dict[str, Any]
    ) -> List[Dict]:
        """Always add one deterministic notification when the LLM omits it."""
        if any(item.get("action_type") == "notify_analyst" for item in proposals):
            return proposals
        campaign_name = str(campaign.get("name") or "Unclassified Activity")
        return [
            *proposals,
            {
                "action_type": "notify_analyst",
                "target": config.ANALYST_NOTIFICATION_TARGET,
                "severity": str(campaign.get("severity") or "medium"),
                "rationale": f"Response review required for campaign {campaign_name}.",
                "technique_id": "",
                "confidence": float(campaign.get("confidence") or 0.0),
            },
        ]

    @staticmethod
    def _extract_victim_isolation_targets(threat_summary: Dict[str, Any]) -> List[str]:
        """Use only response-safe victim endpoints selected by the summary."""
        return [
            str(target).strip()
            for target in threat_summary.get("victim_isolation_targets", []) or []
            if str(target).strip() != config.ANALYST_NOTIFICATION_TARGET
        ]

    @staticmethod
    def _extract_attacker_source_ips(threat_summary: Dict[str, Any]) -> Set[str]:
        """Read attacker/prober IPs from the bounded summary."""
        return {
            str(ip).strip()
            for ip in threat_summary.get("attacker_source_ips", []) or []
            if str(ip).strip()
        }

    def _auto_propose_high_confidence_actions(self, iocs: List[Dict]) -> List[Dict]:
        """Deterministically proposes block_ip for high-confidence malicious IOCs.

        This runs BEFORE the LLM so critical blocking actions are never omitted
        due to LLM conservatism. Only fires when:
        - IOC reputation == 'malicious'
        - IOC confidence >= configured malicious-IOC threshold
        - IOC type is 'ip' or 'ipv4'

        Returns a list of raw proposal dicts suitable for ProposedAction(**raw).
        """
        proposals = []
        for ioc in iocs:
            reputation = ioc.get("reputation", "")
            confidence = float(ioc.get("confidence", 0.0))
            ioc_type = ioc.get("ioc_type") or ioc.get("type", "")
            value = ioc.get("value", "")

            if (
                reputation == "malicious"
                and confidence >= config.RISK_MALICIOUS_IOC_MIN_CONFIDENCE
                and ioc_type.lower() in ("ip", "ipv4", "ip_address")
                and value
                and not is_protected_target(str(value))
            ):
                proposals.append({
                    "action_type": "block_ip",
                    "target": value,
                    "severity": "high" if confidence >= 0.9 else "medium",
                    "rationale": (
                        f"IP {value} has AbuseIPDB confidence {confidence:.2f} with "
                        f"reputation '{reputation}'. Automatic block proposed per "
                        "configured malicious-IOC proposal threshold."
                    ),
                    "technique_id": "",
                    "confidence": confidence,
                })
        return proposals

    @staticmethod
    def _handle_decision(action: ProposedAction, decision: str) -> ActionResult:
        if decision == "denied":
            return ActionResult(action=action, status="denied", detail="Target is protected.", dry_run=config.DRY_RUN)

        if decision == "pending_approval":
            return ActionResult(
                action=action,
                status="pending_approval",
                detail="Awaiting human approval (run actions/review_pending.py).",
                dry_run=config.DRY_RUN,
            )

        # auto_execute
        handler = ACTION_DISPATCH.get(action.action_type)
        if not handler:
            return ActionResult(action=action, status="failed", detail="No connector registered.", dry_run=config.DRY_RUN)

        try:
            # notify_analyst expects a human-readable message body; other connectors
            # still receive the action target as before.
            if action.action_type.value == "notify_analyst":
                notify_message = (
                    f"Notify target: {action.target} | "
                    f"Technique: {action.technique_id or 'N/A'} | "
                    f"Confidence: {action.confidence:.2f} | "
                    f"Rationale: {action.rationale}"
                )
                raw_output = handler(notify_message)
            else:
                raw_output = handler(action.target)

            # Connectors now return JSON strings; parse to extract the detail field
            import json
            try:
                parsed = json.loads(raw_output)
                detail = parsed.get("detail", raw_output)
                connector_status = parsed.get("status")
            except (json.JSONDecodeError, TypeError):
                detail = raw_output
                connector_status = None
            if connector_status == "failed":
                return ActionResult(
                    action=action,
                    status="failed",
                    detail=detail,
                    dry_run=config.DRY_RUN,
                )
            return ActionResult(action=action, status="executed", detail=detail, dry_run=config.DRY_RUN)
        except Exception as e:
            return ActionResult(action=action, status="failed", detail=str(e), dry_run=config.DRY_RUN)

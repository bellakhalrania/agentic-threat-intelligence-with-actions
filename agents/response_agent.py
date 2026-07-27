"""
agents/response_agent.py
Seventh pipeline stage (optional - wire into graph/workflow.py to enable).

Takes the campaign + techniques + prediction and proposes concrete response
actions. Critically: the LLM only ever PROPOSES a structured action. Every
proposal is passed through actions/policy.py (deterministic, non-LLM logic)
before anything is allowed to actually execute, and every outcome - executed,
pending, or denied - is written to the audit log.
"""

from typing import List, Dict
from llm.groq_client import invoke_llm
from llm.output_parsers import extract_json
from actions.action_models import ProposedAction, ActionResult
from actions.connectors import ACTION_DISPATCH
from actions import policy, audit_log
from config import config

RESPONSE_SYSTEM_PROMPT = """You are an incident response analyst. Given a
threat campaign with mapped ATT&CK techniques and IOCs, propose concrete
response actions. For each action, output:
{"action_type": "block_ip|isolate_host|disable_account|kill_process|quarantine_file|notify_analyst",
 "target": "...", "severity": "low|medium|high", "rationale": "...",
 "technique_id": "...", "confidence": 0.0}
Respond ONLY with a JSON array of action objects. Be conservative: only
propose disruptive actions (isolate_host, disable_account) when evidence is
strong. Thresholds:
- block_ip: when IOC confidence >= 0.8 AND reputation == malicious
- isolate_host: when IOC confidence >= 0.9 OR multiple high-confidence techniques observed
- notify_analyst: ALWAYS include at least one notify_analyst action summarizing the situation."""


class ResponseAgent:
    # Confidence threshold above which a malicious IOC automatically triggers
    # a block_ip proposal without waiting for the LLM.
    BLOCK_IP_AUTO_THRESHOLD = 0.8

    def run(self, campaign: Dict, techniques: List[Dict], iocs: List[Dict]) -> List[ActionResult]:
        print("\n========== RESPONSE AGENT ==========\n")
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

        # Build a compact prompt to avoid token limit issues
        campaign_summary = {
            "name": campaign.get("name"),
            "objective": campaign.get("objective"),
            "confidence": campaign.get("confidence")
        }
        
        techniques_summary = [
            {
                "id": t.get("attack_id"),
                "name": t.get("technique_name"),
                "confidence": t.get("confidence")
            }
            for t in techniques
        ]
        
        iocs_summary = [
            {
                "value": i.get("value"),
                "type": i.get("type"),
                "reputation": i.get("reputation"),
                "confidence": i.get("confidence")
            }
            for i in iocs
        ]
        
        prompt = f"Campaign:\n{campaign_summary}\n\nTechniques:\n{techniques_summary}\n\nIOCs:\n{iocs_summary}"
        print("Invoking LLM for action proposals...")
        response = invoke_llm(system_prompt=RESPONSE_SYSTEM_PROMPT, user_prompt=prompt)

        try:
            llm_proposals = extract_json(response)
            print(f"LLM proposed {len(llm_proposals)} action(s)")
        except ValueError:
            llm_proposals = []
            print("LLM failed to return valid JSON")

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

            print(f"--- Action {i}: {action.action_type} on {action.target} ---")
            print(f"  Rationale: {action.rationale}")
            print(f"  Severity: {action.severity}")
            print(f"  Related Technique: {action.technique_id or 'N/A'}")
            
            # Show relation to events/IOCs
            if action.technique_id:
                related_tech = next((t for t in techniques if t.get('attack_id') == action.technique_id), None)
                if related_tech:
                    print(f"  Related to technique: {related_tech.get('technique_name', 'N/A')}")
                    event_id = related_tech.get('evidence_event_id', 'N/A')
                    print(f"  Evidence from event: {event_id}")
            
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

    def _auto_propose_high_confidence_actions(self, iocs: List[Dict]) -> List[Dict]:
        """Deterministically proposes block_ip for high-confidence malicious IOCs.

        This runs BEFORE the LLM so critical blocking actions are never omitted
        due to LLM conservatism. Only fires when:
        - IOC reputation == 'malicious'
        - IOC confidence >= BLOCK_IP_AUTO_THRESHOLD (default 0.8)
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
                and confidence >= self.BLOCK_IP_AUTO_THRESHOLD
                and ioc_type.lower() in ("ip", "ipv4", "ip_address")
                and value
            ):
                proposals.append({
                    "action_type": "block_ip",
                    "target": value,
                    "severity": "high" if confidence >= 0.9 else "medium",
                    "rationale": (
                        f"IP {value} has AbuseIPDB confidence {confidence:.2f} with "
                        f"reputation '{reputation}'. Automatic block proposed per "
                        f"policy threshold (>= {self.BLOCK_IP_AUTO_THRESHOLD})."
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
            raw_output = handler(action.target)
            # Connectors now return JSON strings; parse to extract the detail field
            import json
            try:
                parsed = json.loads(raw_output)
                detail = parsed.get("detail", raw_output)
            except (json.JSONDecodeError, TypeError):
                detail = raw_output
            return ActionResult(action=action, status="executed", detail=detail, dry_run=config.DRY_RUN)
        except Exception as e:
            return ActionResult(action=action, status="failed", detail=str(e), dry_run=config.DRY_RUN)

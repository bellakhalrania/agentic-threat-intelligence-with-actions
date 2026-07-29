"""
graph/nodes.py
Thin wrapper functions that adapt each Agent class into a LangGraph node
(a callable that takes the state dict and returns a partial state update).
"""

from graph.state import InvestigationState
from agents.collection_agent import CollectionAgent
from agents.enrichment_agent import EnrichmentAgent
from agents.attack_mapping_agent import AttackMappingAgent
from agents.correlation_agent import CorrelationAgent
from agents.prediction_agent import PredictionAgent
from agents.reporting_agent import ReportingAgent
from agents.response_agent import ResponseAgent
from agents.execution_translation_agent import ExecutionTranslationAgent
from intelligence.threat_intel.registry import ProviderRegistry

# Initialize provider registry with available threat intelligence sources
provider_registry = ProviderRegistry()

# Register AbuseIPDB provider (requests is a dependency)
try:
    from intelligence.threat_intel.abuseipdb_provider import AbuseIPDBProvider
    provider_registry.register(AbuseIPDBProvider())
except ImportError:
    pass

# Register OTX provider (OTXv2 is an optional dependency)
try:
    from intelligence.threat_intel.otx_provider import OTXProvider
    provider_registry.register(OTXProvider())
except ImportError:
    pass

collection_agent = CollectionAgent()
enrichment_agent = EnrichmentAgent(registry=provider_registry)
mapping_agent = AttackMappingAgent()
correlation_agent = CorrelationAgent()
prediction_agent = PredictionAgent()
reporting_agent = ReportingAgent()
response_agent = ResponseAgent()
execution_translation_agent = ExecutionTranslationAgent()


def collection_node(state: InvestigationState) -> dict:
    events = collection_agent.run(state.get("raw_events", []))
    return {"events": events}


def enrichment_node(state: InvestigationState) -> dict:
    iocs = enrichment_agent.run(state.get("events", []))
    return {"iocs": iocs}


def mapping_node(state: InvestigationState) -> dict:
    techniques = mapping_agent.run(state.get("events", []))
    return {"techniques": techniques}


def correlation_node(state: InvestigationState) -> dict:
    campaign = correlation_agent.run(
        events=state.get("events", []),
        iocs=state.get("iocs", []),
        techniques=state.get("techniques", []),
    )
    return {"campaign": campaign}


def prediction_node(state: InvestigationState) -> dict:
    prediction = prediction_agent.run(
        techniques=state.get("techniques", []),
        campaign=state.get("campaign", {}),
    )
    return {"prediction": prediction}


def reporting_node(state: InvestigationState) -> dict:
    report = reporting_agent.run(state)
    return {"report": report}


def response_node(state: InvestigationState) -> dict:
    results = response_agent.run(
        campaign=state.get("campaign", {}),
        techniques=state.get("techniques", []),
        iocs=state.get("iocs", []),
        events=state.get("events", []),
    )
    return {"actions_taken": [r.model_dump() for r in results]}


def execution_translation_node(state: InvestigationState) -> dict:
    """Translate approved response actions into executable scripts.

    The generated combined script is automatically saved to disk under
    data/generated_scripts/ so it can be downloaded or deployed.

    If REMOTE_AGENT_ENABLED is True, the script is also pushed to the
    Remote Response Agent on Machine 2 for immediate execution.
    """
    import os
    from config import config
    from actions.remote_push import push_script_to_remote, verify_remote_connection

    actions_taken = state.get("actions_taken", [])
    platform = state.get("metadata", {}).get("target_platform", "linux")
    campaign = state.get("campaign", {})
    campaign_id = campaign.get("campaign_id", "")

    result = execution_translation_agent.run(
        actions_taken=actions_taken,
        platform=platform,
    )

    combined_script = result.get("combined_script", "")
    combined_filename = result.get("combined_filename", "")

    remote_execution_result = None

    # Write the combined script to disk
    if combined_script and combined_filename:
        output_dir = "data/generated_scripts"
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, combined_filename)
        with open(output_path, "w") as f:
            f.write(combined_script)
        # Make the script executable on Linux/macOS
        if not platform == "windows":
            os.chmod(output_path, 0o755)
        print(f"Generated script saved to: {output_path}")

        # --- Push to Remote Agent (Machine 2) if enabled ---
        if config.REMOTE_AGENT_ENABLED:
            remote_url = config.REMOTE_AGENT_URL
            api_key = config.REMOTE_AGENT_API_KEY
            timeout = config.REMOTE_AGENT_TIMEOUT

            # Safety gate: only actions already approved/executed are eligible
            # for remote execution. pending_approval/denied/failed must never
            # be executed automatically on the target.
            remotely_executable_actions = [
                action for action in actions_taken
                if action.get("status") == "executed"
            ]

            if not remotely_executable_actions:
                print("\n--- Remote push skipped: no policy-approved actions to execute (only 'executed' actions are pushed). ---")
            elif not remote_url:
                print("WARNING: REMOTE_AGENT_ENABLED is True but REMOTE_AGENT_URL is not set. Skipping push.")
            else:
                print(f"\n--- Pushing script to remote agent at {remote_url} ---")
                # Verify connection first
                healthy = verify_remote_connection(remote_url=remote_url, api_key=api_key)
                if not healthy:
                    print(f"WARNING: Remote agent at {remote_url} is not reachable. Skipping push.")
                else:
                    try:
                        remote_translation = execution_translation_agent.run(
                            actions_taken=remotely_executable_actions,
                            platform=platform,
                        )
                        remote_script = remote_translation.get("combined_script", "")
                        remote_filename = remote_translation.get("combined_filename", combined_filename)
                        execution_packages = remote_translation.get("execution_packages", [])
                        action_count = len(execution_packages)

                        if not remote_script or action_count == 0:
                            print("WARNING: No executable remote script produced after approval filtering. Skipping push.")
                        else:
                            remote_result = push_script_to_remote(
                                script=remote_script,
                                filename=remote_filename,
                                campaign_id=campaign_id,
                                action_count=action_count,
                                platform=platform,
                                remote_url=remote_url,
                                api_key=api_key,
                                hmac_secret=config.REMOTE_AGENT_HMAC_SECRET,
                                timeout=timeout,
                                execution_packages=execution_packages,
                            )
                            remote_execution_result = remote_result
                            print(f"Remote execution completed:")
                            print(f"  Status: {remote_result.get('status')}")
                            print(f"  Exit code: {remote_result.get('exit_code')}")
                            print(f"  Duration: {remote_result.get('duration_ms')}ms")
                            print(f"  Execution ID: {remote_result.get('execution_id')}")
                            if remote_result.get("stdout"):
                                print(f"  stdout: {remote_result['stdout'][:500]}")
                            if remote_result.get("stderr"):
                                print(f"  stderr: {remote_result['stderr'][:500]}")
                    except Exception as e:
                        print(f"ERROR: Failed to push script to remote agent: {e}")
            print()

    return {
        "execution_packages": result.get("execution_packages", []),
        "combined_script": combined_script,
        "combined_filename": combined_filename,
        "remote_execution_result": remote_execution_result,
    }

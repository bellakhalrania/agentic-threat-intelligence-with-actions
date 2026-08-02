"""
main.py
Entrypoint: loads sample (or real) telemetry, runs it through the full
LangGraph agent pipeline, and prints/saves the resulting intelligence report.

Usage:
    # Offline mode: Load events from JSON file
    python main.py --events data/sample_events/sample_events.json
    
    # Live mode: Fetch events from Wazuh connector
    python main.py --source wazuh
"""

import argparse
import json

from config import config
from graph.state import new_investigation_state
from graph.workflow import threat_intel_workflow
from memory.investigation_memory import investigation_memory
from connectors.wazuh_connector import WazuhConnector


def load_events(path: str) -> list[dict]:
    """Load events from a JSON file (offline mode)."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def fetch_from_connector(source: str, test_data_path: str = None) -> list[dict]:
    """Fetch events from a connector (live mode)."""
    if source == "wazuh":
        connector = WazuhConnector(
            use_api=False, 
            test_data_path=test_data_path
        )
        return connector.fetch_events()
    else:
        raise ValueError(f"Unknown connector source: {source}")


def main():
    parser = argparse.ArgumentParser(description="Agentic Threat Intelligence Platform")
    
    # Source selection: either file-based or connector-based
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "--events",
        help="Path to a JSON file of raw events to investigate (offline mode)",
    )
    source_group.add_argument(
        "--source",
        choices=["wazuh"],
        help="Connector to fetch events from (live mode)",
    )
    parser.add_argument(
        "--test-data",
        help="Path to sample data file for testing connector (overrides default path)",
    )
    
    args = parser.parse_args()

    config.validate()

    # Load events based on source type
    if args.events:
        raw_events = load_events(args.events)
        print(f"Loaded {len(raw_events)} events from {args.events}")
    else:
        raw_events = fetch_from_connector(args.source, test_data_path=args.test_data)
        print(f"Fetched {len(raw_events)} events from {args.source} connector")

    if not raw_events:
        print("No events to process. Exiting.")
        return

    initial_state = new_investigation_state(raw_events=raw_events)

    print(f"\nRunning investigation on {len(raw_events)} raw events...\n")
    final_state = threat_intel_workflow.invoke(initial_state)

    investigation_memory.save(final_state)

    print("=" * 60)
    print("INTELLIGENCE REPORT")
    print("=" * 60)
    print(final_state.get("report", "(no report generated)"))

    print("\n" + "=" * 60)
    print("RESPONSE ACTIONS")
    print("=" * 60)
    actions = final_state.get("actions_taken", [])
    if not actions:
        print("(no actions proposed)")
    for a in actions:
        action = a["action"]
        print(f"[{a['status'].upper()}] {action['action_type']} -> {action['target']} | {a['detail']}")


if __name__ == "__main__":
    main()

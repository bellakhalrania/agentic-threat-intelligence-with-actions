"""
monitor.py
Continuous monitoring script that polls Wazuh for new alerts and processes
them through the investigation pipeline in real-time.

Usage:
    python monitor.py --source wazuh --interval 30
"""

import argparse
import logging
import signal
import sys
import time
from typing import Optional

from config import config
from connectors.wazuh_connector import WazuhConnector
from graph.state import new_investigation_state
from graph.workflow import threat_intel_workflow
from memory.investigation_memory import investigation_memory

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class Monitor:
    """Continuous monitor for processing security events in real-time."""
    
    def __init__(self, connector: WazuhConnector, interval: int = 30):
        """Initialize the monitor.
        
        Args:
            connector: The connector to fetch events from.
            interval: Polling interval in seconds.
        """
        self.connector = connector
        self.interval = interval
        self.running = False
        self.processed_count = 0
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
    
    def process_events(self, events: list) -> None:
        """Process a batch of events through the investigation pipeline.
        
        Args:
            events: List of raw events to process.
        """
        if not events:
            return
        
        logger.info(f"Processing {len(events)} new events...")
        
        try:
            # Create investigation state
            initial_state = new_investigation_state(raw_events=events)
            
            # Run through the workflow
            final_state = threat_intel_workflow.invoke(initial_state)
            
            # Save to memory
            investigation_memory.save(final_state)
            
            # Print report
            print("\n" + "=" * 60)
            print("INTELLIGENCE REPORT")
            print("=" * 60)
            print(final_state.get("report", "(no report generated)"))
            
            # Print response actions
            print("\n" + "=" * 60)
            print("RESPONSE ACTIONS")
            print("=" * 60)
            actions = final_state.get("actions_taken", [])
            if not actions:
                print("(no actions proposed)")
            for a in actions:
                action = a["action"]
                print(f"[{a['status'].upper()}] {action['action_type']} -> {action['target']} | {a['detail']}")
            
            self.processed_count += len(events)
            logger.info(f"Successfully processed {len(events)} events (total: {self.processed_count})")
            
        except Exception as e:
            logger.error(f"Error processing events: {e}", exc_info=True)
    
    def run(self) -> None:
        """Run the continuous monitoring loop."""
        logger.info(f"Starting monitor with {self.interval}s interval...")
        self.running = True
        
        while self.running:
            try:
                # Fetch new events
                events = self.connector.fetch_events()
                
                if events:
                    self.process_events(events)
                else:
                    logger.debug("No new events to process")
                
                # Wait for next poll
                for _ in range(self.interval):
                    if not self.running:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}", exc_info=True)
                # Continue running despite errors
                time.sleep(self.interval)
        
        logger.info(f"Monitor stopped. Total events processed: {self.processed_count}")


def main():
    parser = argparse.ArgumentParser(description="Continuous security event monitor")
    parser.add_argument(
        "--source",
        choices=["wazuh"],
        default="wazuh",
        help="Connector to fetch events from",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=config.WAZUH_POLL_INTERVAL,
        help=f"Polling interval in seconds (default: {config.WAZUH_POLL_INTERVAL})",
    )
    parser.add_argument(
        "--use-api",
        action="store_true",
        help="Use Wazuh REST API instead of file-based reading",
    )
    parser.add_argument(
        "--test-data",
        help="Path to sample data file for testing connector (overrides default path)",
    )
    args = parser.parse_args()
    
    # Create connector
    if args.source == "wazuh":
        connector = WazuhConnector(
            use_api=args.use_api,
            test_data_path=args.test_data
        )
    else:
        logger.error(f"Unknown source: {args.source}")
        sys.exit(1)
    
    # Create and run monitor
    monitor = Monitor(connector, interval=args.interval)
    monitor.run()


if __name__ == "__main__":
    main()

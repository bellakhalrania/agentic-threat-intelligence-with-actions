"""
config.py
Central configuration for the Agentic Threat Intelligence Platform.
All values are loaded from environment variables (.env file) so secrets
never live in source control.
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # ---------------- Groq LLM (optional after refactor) ----------------
    GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    GROQ_TEMPERATURE = float(os.getenv("GROQ_TEMPERATURE", "0.1"))

    # ---------------- Threat Intelligence Providers ----------------
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
    OTX_API_KEY = os.getenv("OTX_API_KEY", "")

    # ---------------- ChromaDB ----------------
    CHROMA_PERSIST_DIR = os.getenv("CHROMA_PERSIST_DIR", "./data/chroma_store")
    CHROMA_COLLECTION_ATTACK = os.getenv("CHROMA_COLLECTION_ATTACK", "attack_techniques")
    CHROMA_COLLECTION_ATTACK_CHAIN = os.getenv("CHROMA_COLLECTION_ATTACK_CHAIN", "attack_chain")
    EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")

    # ---------------- Neo4j ----------------
    NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "changeme")

    # ---------------- MITRE ATT&CK data ----------------
    ATTACK_DATA_PATH = os.getenv(
        "ATTACK_DATA_PATH", "./data/attack_data/enterprise-attack.json"
    )

    # ---------------- Telemetry inputs ----------------
    RAW_LOGS_DIR = os.getenv("RAW_LOGS_DIR", "./data/raw_logs")
    SAMPLE_EVENTS_DIR = os.getenv("SAMPLE_EVENTS_DIR", "./data/sample_events")

    # ---------------- Wazuh Connector ----------------
    WAZUH_API_URL = os.getenv("WAZUH_API_URL", "https://localhost:55000")
    WAZUH_API_USER = os.getenv("WAZUH_API_USER", "wazuh-wui")
    WAZUH_API_PASSWORD = os.getenv("WAZUH_API_PASSWORD", "")
    # Default to Docker volume path in container, fallback to local path
    WAZUH_ALERTS_PATH = os.getenv("WAZUH_ALERTS_PATH", "/app/data/wazuh_logs/alerts.json")
    # Persistent cursor file used to remember last processed alerts across runs.
    WAZUH_CURSOR_PATH = os.getenv("WAZUH_CURSOR_PATH", "./data/state/wazuh_cursor.json")
    # Maximum number of processed alert IDs cached in the cursor (bounded memory/state).
    WAZUH_CURSOR_MAX_IDS = int(os.getenv("WAZUH_CURSOR_MAX_IDS", "5000"))
    WAZUH_POLL_INTERVAL = int(os.getenv("WAZUH_POLL_INTERVAL", "30"))  # seconds
    WAZUH_VERIFY_SSL = os.getenv("WAZUH_VERIFY_SSL", "false").lower() == "true"




    # ---------------- Reporting ----------------

    REPORTS_OUTPUT_DIR = os.getenv("REPORTS_OUTPUT_DIR", "./reports/generated_reports")

    # ---------------- Response / Action layer ----------------
    # Global kill switch. Default OFF: every action requires human approval
    # until you've tested the policy and connectors and explicitly opt in.
    AUTO_RESPONSE_ENABLED = os.getenv("AUTO_RESPONSE_ENABLED", "false").lower() == "true"
    # Dry run: when true, connectors log what they WOULD do instead of
    # calling the real firewall/EDR/IAM API. Keep this true until connectors
    # are wired to your real infrastructure and you trust the policy.
    DRY_RUN = os.getenv("DRY_RUN", "true").lower() == "true"

    # Safe mode guardrails:
    # - notify_analyst can still auto-execute (low risk)
    # - isolate_host requires explicit approval by target allowlist
    SAFE_MODE_ENFORCED = os.getenv("SAFE_MODE_ENFORCED", "true").lower() == "true"
    SAFE_MODE_NOTIFY_ANALYST_AUTO = os.getenv("SAFE_MODE_NOTIFY_ANALYST_AUTO", "true").lower() == "true"
    APPROVED_ISOLATION_TARGETS = {
        t.strip() for t in os.getenv("APPROVED_ISOLATION_TARGETS", "").split(",") if t.strip()
    }

    # ---------------- Remote Response Agent (Machine 2) ----------------
    # URL of the Remote Response Agent running on the target machine.
    # Example: http://192.168.1.100:9001
    REMOTE_AGENT_URL = os.getenv("REMOTE_AGENT_URL", "")
    # API key for authenticating with the remote agent.
    REMOTE_AGENT_API_KEY = os.getenv("REMOTE_AGENT_API_KEY", "")
    # Enable automatic push of generated scripts to the remote agent.
    REMOTE_AGENT_ENABLED = os.getenv("REMOTE_AGENT_ENABLED", "false").lower() == "true"
    # Timeout (seconds) for remote script execution.
    REMOTE_AGENT_TIMEOUT = int(os.getenv("REMOTE_AGENT_TIMEOUT", "3600"))
    # If true, allow pushing pending_approval actions remotely (unsafe).
    # Keep false in safe-mode lab/testing to avoid accidental disruptive actions.
    REMOTE_ALLOW_PENDING_EXECUTION = os.getenv("REMOTE_ALLOW_PENDING_EXECUTION", "false").lower() == "true"
    # HMAC-SHA256 shared secret for payload signing.
    # Must be the same on Machine 1 and Machine 2.
    REMOTE_AGENT_HMAC_SECRET = os.getenv("REMOTE_AGENT_HMAC_SECRET", "")

    @classmethod
    def validate(cls):
        missing = []
        if not cls.GROQ_API_KEY:
            missing.append("GROQ_API_KEY")
        if missing:
            raise EnvironmentError(
                f"Missing required environment variables: {', '.join(missing)}. "
                f"Copy .env.example to .env and fill in the values."
            )


config = Config()

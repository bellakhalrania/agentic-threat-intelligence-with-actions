"""Sanity tests for protected-target handling in config + enrichment (Option A)."""
import importlib

import pytest

import config as config_mod
from agents.enrichment_agent import EnrichmentAgent
from intelligence.threat_intel.registry import ProviderRegistry


@pytest.fixture(autouse=True)
def _managed_env(monkeypatch):
    monkeypatch.setenv("MANAGEMENT_SOURCE_IP", "100.76.226.30")
    monkeypatch.setenv("PROTECTED_MANAGEMENT_IPS", "100.76.226.30,100.123.23.97")
    monkeypatch.setenv("PROTECTED_TARGET_HOSTS", "control-node1")
    # Re-read the env into a fresh Config so tests don't depend on the real .env
    importlib.reload(config_mod)


def test_is_protected_target_matches_ips_and_hosts():
    assert config_mod.is_protected_target("100.76.226.30") is True
    assert config_mod.is_protected_target("100.123.23.97") is True
    assert config_mod.is_protected_target("8.8.8.8") is False
    assert config_mod.is_protected_target("control-node1") is True
    assert config_mod.is_protected_target("CONTROL-NODE1") is True
    assert config_mod.is_protected_target("evil.com") is False


def test_enrichment_marks_protected_ip_as_trusted_benign():
    agent = EnrichmentAgent(registry=ProviderRegistry())
    events = [
        {
            "event_id": "e1",
            "src_ip": "100.76.226.30",
            "host": "control-node1",
            "dst_ip": "8.8.8.8",
        }
    ]
    results = agent.run(events)
    by_value = {r["value"]: r for r in results}

    assert "100.76.226.30" in by_value
    protected = by_value["100.76.226.30"]
    assert protected["reputation"] == "benign"
    assert protected["confidence"] == 1.0
    assert protected["tags"] == ["protected_management", "trusted"]
    assert protected["source"] == "local-policy"

    # Non-protected IOC follows the normal (provider) path
    assert "8.8.8.8" in by_value
    assert by_value["8.8.8.8"]["reputation"] == "unknown"
from pathlib import Path

import pytest

from attack_simulation_agent.config import Settings
from attack_simulation_agent.scenarios import SSHBruteForceScenario


def test_unapproved_target_is_rejected(tmp_path: Path) -> None:
    settings = Settings(
        attack_type="ssh_bruteforce", target="192.0.2.99", username="lab_user",
        approved_targets=frozenset({"192.0.2.20"}), dry_run=True, allow_live_attacks=False,
        password_file=None, hydra_binary="hydra", ssh_port=22, max_attempts=3,
        max_duration_seconds=60, max_parallel_tasks=1, event_log=tmp_path / "events.jsonl",
        webhook_url="", webhook_key="", webhook_timeout_seconds=10, webhook_verify_ssl=True,
    )
    with pytest.raises(ValueError, match="APPROVED_TARGETS"):
        settings.validate()


def test_dry_run_never_starts_hydra(tmp_path: Path) -> None:
    settings = Settings(
        attack_type="ssh_bruteforce", target="192.0.2.20", username="lab_user",
        approved_targets=frozenset({"192.0.2.20"}), dry_run=True, allow_live_attacks=False,
        password_file=None, hydra_binary="does-not-exist", ssh_port=22, max_attempts=3,
        max_duration_seconds=60, max_parallel_tasks=1, event_log=tmp_path / "events.jsonl",
        webhook_url="", webhook_key="", webhook_timeout_seconds=10, webhook_verify_ssl=True,
    )
    status, code, detail = SSHBruteForceScenario(settings).run(lambda _: None)
    assert (status, code) == ("dry_run", None)
    assert "not invoked" in detail

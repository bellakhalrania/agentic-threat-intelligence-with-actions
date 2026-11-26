from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


@dataclass(frozen=True)
class Settings:
    attack_type: str
    target: str
    username: str
    approved_targets: frozenset[str]
    dry_run: bool
    allow_live_attacks: bool
    password_file: Path | None
    hydra_binary: str
    ssh_port: int
    max_attempts: int
    max_duration_seconds: int
    max_parallel_tasks: int
    event_log: Path
    webhook_url: str
    webhook_key: str
    webhook_timeout_seconds: int
    webhook_verify_ssl: bool

    @classmethod
    def from_env(cls) -> "Settings":
        approved = frozenset(
            value.strip() for value in os.getenv("APPROVED_TARGETS", "").split(",") if value.strip()
        )
        password_file_value = os.getenv("ATTACK_PASSWORD_FILE", "").strip()
        return cls(
            attack_type=os.getenv("ATTACK_TYPE", "ssh_bruteforce").strip(),
            target=os.getenv("TARGET", "").strip(),
            username=os.getenv("USERNAME", "").strip(),
            approved_targets=approved,
            dry_run=_bool("DRY_RUN", True),
            allow_live_attacks=_bool("ALLOW_LIVE_ATTACKS", False),
            password_file=Path(password_file_value).resolve() if password_file_value else None,
            hydra_binary=os.getenv("HYDRA_BINARY", "hydra").strip(),
            ssh_port=_int("SSH_PORT", 22, 1, 65535),
            max_attempts=_int("MAX_ATTEMPTS", 3, 1, 10),
            max_duration_seconds=_int("MAX_DURATION_SECONDS", 60, 1, 300),
            max_parallel_tasks=_int("MAX_PARALLEL_TASKS", 1, 1, 2),
            event_log=Path(os.getenv("ATTACK_EVENT_LOG", "./logs/attack_events.jsonl")).resolve(),
            webhook_url=os.getenv("ATTACK_EVENT_WEBHOOK_URL", "").strip(),
            webhook_key=os.getenv("ATTACK_EVENT_WEBHOOK_KEY", ""),
            webhook_timeout_seconds=_int("ATTACK_WEBHOOK_TIMEOUT_SECONDS", 10, 1, 60),
            webhook_verify_ssl=_bool("ATTACK_WEBHOOK_VERIFY_SSL", True),
        )

    def validate(self) -> None:
        if self.attack_type != "ssh_bruteforce":
            raise ValueError("Only the predefined ssh_bruteforce scenario is supported")
        if not self.target or self.target not in self.approved_targets:
            raise ValueError("TARGET must exactly match an entry in APPROVED_TARGETS")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", self.username):
            raise ValueError("USERNAME contains unsupported characters")
        if not self.dry_run:
            if not self.allow_live_attacks:
                raise ValueError("Live simulation requires ALLOW_LIVE_ATTACKS=true")
            if self.password_file is None or not self.password_file.is_file():
                raise ValueError("Live simulation requires ATTACK_PASSWORD_FILE to be a readable regular file")

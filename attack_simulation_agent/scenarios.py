from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path
from typing import Callable

from .config import Settings


class ScenarioError(RuntimeError):
    pass


def _count_candidates(password_file: Path, maximum: int) -> int:
    """Count at most the policy maximum; never retain or log secret values."""
    with password_file.open("rb") as handle:
        return sum(1 for _ in range(maximum + 1))


class SSHBruteForceScenario:
    """The sole module permitted to invoke Hydra; it accepts no shell command text."""

    name = "ssh_bruteforce"

    def __init__(self, settings: Settings):
        self.settings = settings

    def run(self, on_process: Callable[[subprocess.Popen[bytes] | None], None]) -> tuple[str, int | None, str]:
        if self.settings.dry_run:
            return "dry_run", None, "Dry run: Hydra was not invoked."
        password_file = self.settings.password_file
        assert password_file is not None  # validated by Settings
        if _count_candidates(password_file, self.settings.max_attempts) > self.settings.max_attempts:
            raise ScenarioError("Password candidate file exceeds MAX_ATTEMPTS")
        hydra = shutil.which(self.settings.hydra_binary)
        if not hydra:
            raise ScenarioError("Hydra executable was not found")

        # argv-only invocation prevents shell interpretation. Password values remain in the file.
        command = [
            hydra, "-l", self.settings.username, "-P", str(password_file),
            "-s", str(self.settings.ssh_port), "-t", str(self.settings.max_parallel_tasks),
            "-f", "-W", "1", self.settings.target, "ssh",
        ]
        started = time.monotonic()
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        on_process(process)
        try:
            _, stderr = process.communicate(timeout=self.settings.max_duration_seconds)
        except subprocess.TimeoutExpired:
            return "failed", None, "Hydra exceeded the configured duration limit"
        finally:
            on_process(None)

        # Never emit Hydra stdout/stderr: both may disclose authentication material.
        if process.returncode == 0:
            return "completed", process.returncode, "Hydra completed within policy limits"
        detail = "Hydra exited with a non-zero status"
        if stderr:
            detail += " (diagnostic output withheld to avoid secret exposure)"
        return "failed", process.returncode, detail

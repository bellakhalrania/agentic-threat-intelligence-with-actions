"""Configuration for the MITRE ATT&CK knowledge layer.

This module centralizes all configurable values (paths, logger name,
default limits) used by the ``knowledge.attack`` package. It contains
no SQL and no business logic; it exists purely so that other modules
do not hardcode paths or magic numbers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

_PACKAGE_DIR = Path(__file__).resolve().parent
_DATA_DIR = _PACKAGE_DIR / "data"

#: Default logger name used throughout the ATT&CK knowledge layer.
LOGGER_NAME = "knowledge.attack"

#: Default path to the STIX 2.1 enterprise ATT&CK dataset.
DEFAULT_DATASET_PATH = _DATA_DIR / "enterprise-attack.json"

#: Default path to the SQLite database file.
DEFAULT_DATABASE_PATH = _DATA_DIR / "attack.db"

#: Default maximum number of rows returned by a single search call.
DEFAULT_SEARCH_LIMIT = 25

#: Absolute maximum number of rows a caller may request from a search.
MAX_SEARCH_LIMIT = 200

#: STIX object types the loader understands, mapped to the domain
#: object they represent.
SUPPORTED_STIX_TYPES: tuple[str, ...] = (
    "attack-pattern",
    "intrusion-set",
    "malware",
    "tool",
    "course-of-action",
    "x-mitre-tactic",
    "relationship",
)

#: Columns that should be indexed for fast keyword search, per table.
SEARCHABLE_COLUMNS: dict[str, tuple[str, ...]] = {
    "techniques": ("attack_id", "name", "description"),
    "tactics": ("attack_id", "name", "description"),
    "software": ("attack_id", "name", "description"),
    "groups": ("attack_id", "name", "description"),
    "mitigations": ("attack_id", "name", "description"),
}


@dataclass(frozen=True, slots=True)
class AttackConfig:
    """Runtime configuration for the ATT&CK knowledge layer.

    Attributes:
        database_path: Filesystem path to the SQLite database file.
        dataset_path: Filesystem path to the STIX 2.1 dataset JSON file.
        logger_name: Name used when acquiring loggers in this package.
        default_search_limit: Default row limit applied to searches
            when the caller does not specify one.
        max_search_limit: Hard ceiling on the number of rows any single
            search may return, regardless of caller input.
    """

    database_path: Path = field(default=DEFAULT_DATABASE_PATH)
    dataset_path: Path = field(default=DEFAULT_DATASET_PATH)
    logger_name: str = field(default=LOGGER_NAME)
    default_search_limit: int = field(default=DEFAULT_SEARCH_LIMIT)
    max_search_limit: int = field(default=MAX_SEARCH_LIMIT)

    def clamped_limit(self, requested: int | None) -> int:
        """Clamps a caller-supplied limit to a safe, positive range.

        Args:
            requested: The limit requested by the caller, or ``None`` to
                use the configured default.

        Returns:
            An integer between 1 and :attr:`max_search_limit`.
        """
        if requested is None:
            requested = self.default_search_limit
        return max(1, min(requested, self.max_search_limit))

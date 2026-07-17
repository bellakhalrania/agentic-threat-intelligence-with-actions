"""High-level search engine for the MITRE ATT&CK knowledge layer.

This module offers convenience search operations built strictly on top
of :class:`~knowledge.attack.repository.AttackRepository`. It contains
no SQL of its own and no telemetry-matching logic — it exists purely to
give callers ergonomic, type-specific search methods.
"""

from __future__ import annotations

import logging

from knowledge.attack.config import AttackConfig
from knowledge.attack.models import Group, Mitigation, ObjectType, SearchResult, Software, Tactic, Technique
from knowledge.attack.repository import AttackRepository
from knowledge.base.exceptions import SearchError

logger = logging.getLogger(__name__)


class AttackSearchEngine:
    """Deterministic, keyword/attribute-based ATT&CK search.

    Attributes:
        repository: The injected repository used for all lookups.
        config: Runtime configuration, used to clamp result limits.
    """

    def __init__(self, repository: AttackRepository, config: AttackConfig | None = None) -> None:
        """Initializes the search engine.

        Args:
            repository: An :class:`~knowledge.attack.repository.AttackRepository`
                instance.
            config: Optional :class:`~knowledge.attack.config.AttackConfig`.
                Defaults to a config with library defaults if omitted.
        """
        self.repository = repository
        self.config = config or AttackConfig()

    # ------------------------------------------------------------------
    # Type-specific keyword search
    # ------------------------------------------------------------------

    def search_techniques(self, keyword: str, *, limit: int | None = None) -> list[SearchResult]:
        """Searches only techniques matching a keyword.

        Args:
            keyword: Keyword or phrase to search for.
            limit: Maximum number of results. Defaults to the
                configured default and is clamped to the configured max.

        Returns:
            Matching :class:`~knowledge.attack.models.SearchResult` items
            of type :attr:`~knowledge.attack.models.ObjectType.TECHNIQUE`.
        """
        return self._filter_by_type(self.search(keyword, limit=limit), ObjectType.TECHNIQUE)

    def search_software(self, keyword: str, *, limit: int | None = None) -> list[SearchResult]:
        """Searches only software matching a keyword.

        Args:
            keyword: Keyword or phrase to search for.
            limit: Maximum number of results.

        Returns:
            Matching :class:`~knowledge.attack.models.SearchResult` items
            of type :attr:`~knowledge.attack.models.ObjectType.SOFTWARE`.
        """
        return self._filter_by_type(self.search(keyword, limit=limit), ObjectType.SOFTWARE)

    def search_groups(self, keyword: str, *, limit: int | None = None) -> list[SearchResult]:
        """Searches only groups matching a keyword.

        Args:
            keyword: Keyword or phrase to search for.
            limit: Maximum number of results.

        Returns:
            Matching :class:`~knowledge.attack.models.SearchResult` items
            of type :attr:`~knowledge.attack.models.ObjectType.GROUP`.
        """
        return self._filter_by_type(self.search(keyword, limit=limit), ObjectType.GROUP)

    def search_mitigations(self, keyword: str, *, limit: int | None = None) -> list[SearchResult]:
        """Searches only mitigations matching a keyword.

        Args:
            keyword: Keyword or phrase to search for.
            limit: Maximum number of results.

        Returns:
            Matching :class:`~knowledge.attack.models.SearchResult` items
            of type :attr:`~knowledge.attack.models.ObjectType.MITIGATION`.
        """
        return self._filter_by_type(self.search(keyword, limit=limit), ObjectType.MITIGATION)

    def search_tactics(self, keyword: str, *, limit: int | None = None) -> list[SearchResult]:
        """Searches only tactics matching a keyword.

        Args:
            keyword: Keyword or phrase to search for.
            limit: Maximum number of results.

        Returns:
            Matching :class:`~knowledge.attack.models.SearchResult` items
            of type :attr:`~knowledge.attack.models.ObjectType.TACTIC`.
        """
        return self._filter_by_type(self.search(keyword, limit=limit), ObjectType.TACTIC)

    # ------------------------------------------------------------------
    # Generic search
    # ------------------------------------------------------------------

    def search(self, keyword: str, *, limit: int | None = None) -> list[SearchResult]:
        """Searches every ATT&CK object type for a keyword.

        Args:
            keyword: Keyword or phrase to search for.
            limit: Maximum number of results across all object types.

        Returns:
            A list of :class:`~knowledge.attack.models.SearchResult`,
            ordered by descending relevance.

        Raises:
            SearchError: If the keyword is empty or the search fails.
        """
        if not keyword or not keyword.strip():
            raise SearchError("Search keyword must not be empty")
        clamped_limit = self.config.clamped_limit(limit)
        try:
            return self.repository.search(keyword.strip(), limit=clamped_limit)
        except Exception as exc:
            raise SearchError(f"Search failed for keyword {keyword!r}: {exc}") from exc

    def by_attack_id(self, attack_id: str) -> SearchResult | None:
        """Finds any ATT&CK object by its exact ID.

        Args:
            attack_id: Exact ATT&CK ID (e.g. ``"T1059.001"``).

        Returns:
            The matching :class:`~knowledge.attack.models.SearchResult`,
            or ``None`` if not found.

        Raises:
            SearchError: If the lookup is malformed or fails.
        """
        if not attack_id or not attack_id.strip():
            raise SearchError("ATT&CK ID must not be empty")
        try:
            return self.repository.find_by_attack_id(attack_id.strip())
        except Exception as exc:
            raise SearchError(f"Lookup failed for ATT&CK ID {attack_id!r}: {exc}") from exc

    def by_name(self, name: str, *, limit: int | None = None) -> list[SearchResult]:
        """Finds ATT&CK objects with an exact (case-insensitive) name match.

        Args:
            name: Exact object name to look up.
            limit: Maximum number of results.

        Returns:
            A list of matching :class:`~knowledge.attack.models.SearchResult`.

        Raises:
            SearchError: If the name is empty or the lookup fails.
        """
        if not name or not name.strip():
            raise SearchError("Name must not be empty")
        clamped_limit = self.config.clamped_limit(limit)
        try:
            return self.repository.find_by_name(name.strip(), limit=clamped_limit)
        except Exception as exc:
            raise SearchError(f"Lookup failed for name {name!r}: {exc}") from exc

    def by_platform(self, platform: str, *, limit: int | None = None) -> list[Technique]:
        """Finds techniques applicable to a given platform.

        Args:
            platform: Platform name (e.g. ``"Windows"``).
            limit: Maximum number of results.

        Returns:
            A list of matching :class:`~knowledge.attack.models.Technique`.

        Raises:
            SearchError: If the platform is empty or the lookup fails.
        """
        if not platform or not platform.strip():
            raise SearchError("Platform must not be empty")
        clamped_limit = self.config.clamped_limit(limit)
        try:
            return self.repository.find_techniques_by_platform(platform.strip(), limit=clamped_limit)
        except Exception as exc:
            raise SearchError(f"Lookup failed for platform {platform!r}: {exc}") from exc

    def by_tactic(self, tactic_attack_id: str, *, limit: int | None = None) -> list[Technique]:
        """Finds techniques belonging to a given tactic.

        Args:
            tactic_attack_id: ATT&CK ID of the tactic (e.g. ``"TA0002"``).
            limit: Maximum number of results.

        Returns:
            A list of matching :class:`~knowledge.attack.models.Technique`.

        Raises:
            SearchError: If the tactic ID is empty or the lookup fails.
        """
        if not tactic_attack_id or not tactic_attack_id.strip():
            raise SearchError("Tactic ATT&CK ID must not be empty")
        clamped_limit = self.config.clamped_limit(limit)
        try:
            return self.repository.find_techniques_by_tactic(tactic_attack_id.strip(), limit=clamped_limit)
        except Exception as exc:
            raise SearchError(f"Lookup failed for tactic {tactic_attack_id!r}: {exc}") from exc

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _filter_by_type(results: list[SearchResult], object_type: ObjectType) -> list[SearchResult]:
        """Filters a list of search results down to a single object type.

        Args:
            results: The full, mixed-type result list.
            object_type: The object type to keep.

        Returns:
            The filtered list, preserving original order.
        """
        return [result for result in results if result.object_type == object_type]

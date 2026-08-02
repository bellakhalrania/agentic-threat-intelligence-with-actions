"""Facade service for the MITRE ATT&CK knowledge layer.

This module is the single entry point the rest of the platform (e.g. a
``MitreAgent``, ``CampaignAgent``, or ``ReportingAgent``) should use to
interact with ATT&CK knowledge. It composes the database, repository,
search engine, and matcher, and exposes a small, stable API surface.
No caller outside this module should ever touch SQL, and this module
itself contains no SQL and no knowledge of how SQLite works — it
delegates entirely to the repository.
"""

from __future__ import annotations

import logging

from knowledge.attack.config import AttackConfig
from knowledge.attack.matcher import AttackMatcher, MatchResult, TelemetryEvent
from knowledge.attack.models import Group, Mitigation, SearchResult, Software, Technique
from knowledge.attack.repository import AttackRepository
from knowledge.attack.search import AttackSearchEngine
from knowledge.base.database import Database
from knowledge.base.exceptions import KnowledgeLayerError, ServiceError

logger = logging.getLogger(__name__)


class AttackService:
    """Facade exposing deterministic MITRE ATT&CK knowledge to agents.

    Attributes:
        database: The underlying :class:`~knowledge.base.database.Database`.
        repository: The :class:`~knowledge.attack.repository.AttackRepository`.
        search_engine: The :class:`~knowledge.attack.search.AttackSearchEngine`.
        matcher: The :class:`~knowledge.attack.matcher.AttackMatcher`.
    """

    def __init__(
        self,
        database: Database,
        repository: AttackRepository,
        search_engine: AttackSearchEngine,
        matcher: AttackMatcher,
    ) -> None:
        """Initializes the service via dependency injection.

        Args:
            database: An open (or lazily-opened)
                :class:`~knowledge.base.database.Database`.
            repository: The repository used for all data access.
            search_engine: The search engine used for keyword/attribute
                search.
            matcher: The matcher used for telemetry-to-technique mapping.
        """
        self.database = database
        self.repository = repository
        self.search_engine = search_engine
        self.matcher = matcher

    @classmethod
    def create(cls, config: AttackConfig | None = None) -> "AttackService":
        """Builds a fully-wired :class:`AttackService` from configuration.

        This factory is a convenience for callers who do not need custom
        dependency injection (e.g. CLI entry points, simple agent
        wiring). It ensures the schema exists before returning.

        Args:
            config: Optional :class:`~knowledge.attack.config.AttackConfig`.
                Defaults to library defaults when omitted.

        Returns:
            A ready-to-use :class:`AttackService`.

        Raises:
            ServiceError: If the underlying components fail to initialize.
        """
        resolved_config = config or AttackConfig()
        try:
            database = Database(resolved_config.database_path)
            repository = AttackRepository(database)
            repository.create_schema()
            search_engine = AttackSearchEngine(repository, resolved_config)
            matcher = AttackMatcher()
            return cls(database, repository, search_engine, matcher)
        except Exception as exc:
            raise ServiceError(f"Failed to initialize AttackService: {exc}") from exc

    def __enter__(self) -> "AttackService":
        """Enters the context manager, ensuring the database is open.

        Returns:
            This :class:`AttackService` instance.
        """
        self.database.connect()
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        """Exits the context manager, closing the underlying database."""
        self.close()

    def close(self) -> None:
        """Closes the underlying database connection."""
        self.database.close()

    # ------------------------------------------------------------------
    # Telemetry matching
    # ------------------------------------------------------------------

    def match_event(self, event: TelemetryEvent) -> list[MatchResult]:
        """Maps a single normalized telemetry event to ATT&CK techniques.

        Args:
            event: A normalized :class:`~knowledge.attack.matcher.TelemetryEvent`.

        Returns:
            A list of :class:`~knowledge.attack.matcher.MatchResult`,
            possibly empty if no rule matched.

        Raises:
            ServiceError: If matching fails unexpectedly.
        """
        try:
            return self.matcher.match(event)
        except KnowledgeLayerError:
            raise
        except Exception as exc:
            raise ServiceError(f"Failed to match telemetry event: {exc}") from exc

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------

    def get_technique(self, attack_id: str) -> Technique:
        """Fetches a single technique, enriched with platforms and tactics.

        Args:
            attack_id: ATT&CK technique ID (e.g. ``"T1059.001"``).

        Returns:
            The matching :class:`~knowledge.attack.models.Technique`.

        Raises:
            RecordNotFoundError: If no technique with that ID exists.
            ServiceError: If the lookup fails unexpectedly.
        """
        try:
            return self.repository.get_technique(attack_id)
        except KnowledgeLayerError:
            raise
        except Exception as exc:
            raise ServiceError(f"Failed to fetch technique {attack_id}: {exc}") from exc

    def get_groups(self, technique_attack_id: str) -> list[Group]:
        """Fetches all groups known to use a given technique.

        Args:
            technique_attack_id: ATT&CK ID of the technique.

        Returns:
            A list of :class:`~knowledge.attack.models.Group`.

        Raises:
            ServiceError: If the lookup fails unexpectedly.
        """
        try:
            return self.repository.get_groups_using(technique_attack_id)
        except KnowledgeLayerError:
            raise
        except Exception as exc:
            raise ServiceError(
                f"Failed to fetch groups using technique {technique_attack_id}: {exc}"
            ) from exc

    def get_software(self, technique_attack_id: str) -> list[Software]:
        """Fetches all software known to implement a given technique.

        Args:
            technique_attack_id: ATT&CK ID of the technique.

        Returns:
            A list of :class:`~knowledge.attack.models.Software`.

        Raises:
            ServiceError: If the lookup fails unexpectedly.
        """
        try:
            return self.repository.get_software_using(technique_attack_id)
        except KnowledgeLayerError:
            raise
        except Exception as exc:
            raise ServiceError(
                f"Failed to fetch software using technique {technique_attack_id}: {exc}"
            ) from exc

    def get_mitigations(self, technique_attack_id: str) -> list[Mitigation]:
        """Fetches all mitigations that address a given technique.

        Args:
            technique_attack_id: ATT&CK ID of the technique.

        Returns:
            A list of :class:`~knowledge.attack.models.Mitigation`.

        Raises:
            ServiceError: If the lookup fails unexpectedly.
        """
        try:
            return self.repository.get_mitigations(technique_attack_id)
        except KnowledgeLayerError:
            raise
        except Exception as exc:
            raise ServiceError(
                f"Failed to fetch mitigations for technique {technique_attack_id}: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def search(self, keyword: str, *, limit: int | None = None) -> list[SearchResult]:
        """Searches every ATT&CK object type for a keyword.

        Args:
            keyword: Keyword or phrase to search for.
            limit: Maximum number of results to return.

        Returns:
            A list of :class:`~knowledge.attack.models.SearchResult`,
            ordered by descending relevance.

        Raises:
            ServiceError: If the search fails unexpectedly.
        """
        try:
            return self.search_engine.search(keyword, limit=limit)
        except KnowledgeLayerError:
            raise
        except Exception as exc:
            raise ServiceError(f"Failed to search for keyword {keyword!r}: {exc}") from exc

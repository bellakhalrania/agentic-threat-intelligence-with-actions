"""Repository for the MITRE ATT&CK knowledge layer.

This module is the only place in the package that speaks SQL against
the domain tables. It uses a :class:`~knowledge.base.database.Database`
instance through composition (dependency injection), never through
inheritance, and translates raw rows into the typed dataclasses defined
in :mod:`knowledge.attack.models`.

The repository never parses STIX and never interprets telemetry — it
only stores and retrieves normalized records.
"""

from __future__ import annotations

import logging
import sqlite3
from typing import Iterable

from knowledge.attack.models import (
    Group,
    Mitigation,
    ObjectType,
    Relationship,
    SearchResult,
    Software,
    Tactic,
    Technique,
)
from knowledge.attack.schema import create_schema
from knowledge.base.database import Database
from knowledge.base.exceptions import DuplicateRecordError, RecordNotFoundError, RepositoryError

logger = logging.getLogger(__name__)


class AttackRepository:
    """Data access layer for MITRE ATT&CK objects.

    The repository owns no connection of its own; it is composed with
    a :class:`~knowledge.base.database.Database` instance supplied by
    the caller (dependency injection), which keeps this class fully
    unit-test friendly (it can be given an in-memory database).

    Attributes:
        database: The injected :class:`~knowledge.base.database.Database`.
    """

    def __init__(self, database: Database) -> None:
        """Initializes the repository.

        Args:
            database: An already-constructed
                :class:`~knowledge.base.database.Database` instance.
        """
        self.database = database

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def create_schema(self) -> None:
        """Creates the ATT&CK schema if it does not already exist."""
        create_schema(self.database)

    # ------------------------------------------------------------------
    # Insertion
    # ------------------------------------------------------------------

    def insert_technique(self, technique: Technique) -> None:
        """Inserts (or replaces) a technique and its platform/tactic links.

        Args:
            technique: The technique to persist.

        Raises:
            DuplicateRecordError: If a conflicting unique constraint is
                violated for a reason other than an identical replace.
            RepositoryError: If the insert fails for any other reason.
        """
        try:
            with self.database.transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO techniques (
                        attack_id, stix_id, name, description,
                        is_subtechnique, parent_attack_id, detection, url
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(attack_id) DO UPDATE SET
                        stix_id=excluded.stix_id,
                        name=excluded.name,
                        description=excluded.description,
                        is_subtechnique=excluded.is_subtechnique,
                        parent_attack_id=excluded.parent_attack_id,
                        detection=excluded.detection,
                        url=excluded.url;
                    """,
                    (
                        technique.attack_id,
                        technique.stix_id,
                        technique.name,
                        technique.description,
                        int(technique.is_subtechnique),
                        technique.parent_attack_id,
                        technique.detection,
                        technique.url,
                    ),
                )
                for platform in technique.platforms:
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO technique_platforms (technique_attack_id, platform)
                        VALUES (?, ?);
                        """,
                        (technique.attack_id, platform),
                    )
                for tactic_attack_id in technique.tactics:
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO technique_tactics (technique_attack_id, tactic_attack_id)
                        VALUES (?, ?);
                        """,
                        (technique.attack_id, tactic_attack_id),
                    )
        except sqlite3.IntegrityError as exc:
            raise DuplicateRecordError(f"Duplicate technique {technique.attack_id}: {exc}") from exc
        except Exception as exc:
            raise RepositoryError(f"Failed to insert technique {technique.attack_id}: {exc}") from exc

    def insert_tactic(self, tactic: Tactic) -> None:
        """Inserts (or replaces) a tactic.

        Args:
            tactic: The tactic to persist.

        Raises:
            RepositoryError: If the insert fails.
        """
        try:
            self.database.execute(
                """
                INSERT INTO tactics (attack_id, stix_id, name, description, shortname)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(attack_id) DO UPDATE SET
                    stix_id=excluded.stix_id,
                    name=excluded.name,
                    description=excluded.description,
                    shortname=excluded.shortname;
                """,
                (tactic.attack_id, tactic.stix_id, tactic.name, tactic.description, tactic.shortname),
            )
        except Exception as exc:
            raise RepositoryError(f"Failed to insert tactic {tactic.attack_id}: {exc}") from exc

    def insert_group(self, group: Group) -> None:
        """Inserts (or replaces) an intrusion set / group.

        Args:
            group: The group to persist.

        Raises:
            RepositoryError: If the insert fails.
        """
        try:
            self.database.execute(
                """
                INSERT INTO groups (attack_id, stix_id, name, description, aliases)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(attack_id) DO UPDATE SET
                    stix_id=excluded.stix_id,
                    name=excluded.name,
                    description=excluded.description,
                    aliases=excluded.aliases;
                """,
                (group.attack_id, group.stix_id, group.name, group.description, "|".join(group.aliases)),
            )
        except Exception as exc:
            raise RepositoryError(f"Failed to insert group {group.attack_id}: {exc}") from exc

    def insert_software(self, software: Software) -> None:
        """Inserts (or replaces) a piece of software (malware or tool).

        Args:
            software: The software to persist.

        Raises:
            RepositoryError: If the insert fails.
        """
        try:
            self.database.execute(
                """
                INSERT INTO software (attack_id, stix_id, name, description, software_type)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(attack_id) DO UPDATE SET
                    stix_id=excluded.stix_id,
                    name=excluded.name,
                    description=excluded.description,
                    software_type=excluded.software_type;
                """,
                (software.attack_id, software.stix_id, software.name, software.description, software.software_type),
            )
        except Exception as exc:
            raise RepositoryError(f"Failed to insert software {software.attack_id}: {exc}") from exc

    def insert_mitigation(self, mitigation: Mitigation) -> None:
        """Inserts (or replaces) a mitigation (course of action).

        Args:
            mitigation: The mitigation to persist.

        Raises:
            RepositoryError: If the insert fails.
        """
        try:
            self.database.execute(
                """
                INSERT INTO mitigations (attack_id, stix_id, name, description)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(attack_id) DO UPDATE SET
                    stix_id=excluded.stix_id,
                    name=excluded.name,
                    description=excluded.description;
                """,
                (mitigation.attack_id, mitigation.stix_id, mitigation.name, mitigation.description),
            )
        except Exception as exc:
            raise RepositoryError(f"Failed to insert mitigation {mitigation.attack_id}: {exc}") from exc

    def insert_relationship(self, relationship: Relationship) -> None:
        """Inserts (or replaces) a relationship between two STIX objects.

        Args:
            relationship: The relationship to persist.

        Raises:
            RepositoryError: If the insert fails.
        """
        try:
            self.database.execute(
                """
                INSERT INTO relationships (
                    stix_id, relationship_type, description,
                    source_stix_id, source_attack_id, source_type,
                    target_stix_id, target_attack_id, target_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(stix_id) DO UPDATE SET
                    relationship_type=excluded.relationship_type,
                    description=excluded.description,
                    source_stix_id=excluded.source_stix_id,
                    source_attack_id=excluded.source_attack_id,
                    source_type=excluded.source_type,
                    target_stix_id=excluded.target_stix_id,
                    target_attack_id=excluded.target_attack_id,
                    target_type=excluded.target_type;
                """,
                (
                    relationship.stix_id,
                    relationship.relationship_type,
                    relationship.description,
                    relationship.source_stix_id,
                    relationship.source_attack_id,
                    relationship.source_type,
                    relationship.target_stix_id,
                    relationship.target_attack_id,
                    relationship.target_type,
                ),
            )
        except Exception as exc:
            raise RepositoryError(f"Failed to insert relationship {relationship.stix_id}: {exc}") from exc

    def insert_platform(self, technique_attack_id: str, platform: str) -> None:
        """Links a platform to a technique.

        Args:
            technique_attack_id: ATT&CK ID of the technique.
            platform: Platform name (e.g. ``"Windows"``, ``"Linux"``).

        Raises:
            RepositoryError: If the insert fails.
        """
        try:
            self.database.execute(
                "INSERT OR IGNORE INTO technique_platforms (technique_attack_id, platform) VALUES (?, ?);",
                (technique_attack_id, platform),
            )
        except Exception as exc:
            raise RepositoryError(
                f"Failed to insert platform {platform!r} for {technique_attack_id}: {exc}"
            ) from exc

    def insert_tactic_mapping(self, technique_attack_id: str, tactic_attack_id: str) -> None:
        """Links a technique to a tactic.

        Args:
            technique_attack_id: ATT&CK ID of the technique.
            tactic_attack_id: ATT&CK ID of the tactic.

        Raises:
            RepositoryError: If the insert fails.
        """
        try:
            self.database.execute(
                """
                INSERT OR IGNORE INTO technique_tactics (technique_attack_id, tactic_attack_id)
                VALUES (?, ?);
                """,
                (technique_attack_id, tactic_attack_id),
            )
        except Exception as exc:
            raise RepositoryError(
                f"Failed to map technique {technique_attack_id} to tactic {tactic_attack_id}: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Point queries
    # ------------------------------------------------------------------

    def get_technique(self, attack_id: str) -> Technique:
        """Fetches a single technique by its ATT&CK ID.

        Args:
            attack_id: The ATT&CK technique ID (e.g. ``"T1059.001"``).

        Returns:
            The matching :class:`~knowledge.attack.models.Technique`.

        Raises:
            RecordNotFoundError: If no technique with that ID exists.
            RepositoryError: If the query fails.
        """
        try:
            row = self.database.fetchone("SELECT * FROM techniques WHERE attack_id = ?;", (attack_id,))
        except Exception as exc:
            raise RepositoryError(f"Failed to fetch technique {attack_id}: {exc}") from exc
        if row is None:
            raise RecordNotFoundError(f"Technique not found: {attack_id}")
        return self._row_to_technique(row)

    def get_group(self, attack_id: str) -> Group:
        """Fetches a single group by its ATT&CK ID.

        Args:
            attack_id: The ATT&CK group ID (e.g. ``"G0016"``).

        Returns:
            The matching :class:`~knowledge.attack.models.Group`.

        Raises:
            RecordNotFoundError: If no group with that ID exists.
            RepositoryError: If the query fails.
        """
        try:
            row = self.database.fetchone("SELECT * FROM groups WHERE attack_id = ?;", (attack_id,))
        except Exception as exc:
            raise RepositoryError(f"Failed to fetch group {attack_id}: {exc}") from exc
        if row is None:
            raise RecordNotFoundError(f"Group not found: {attack_id}")
        return self._row_to_group(row)

    def get_software(self, attack_id: str) -> Software:
        """Fetches a single piece of software by its ATT&CK ID.

        Args:
            attack_id: The ATT&CK software ID (e.g. ``"S0002"``).

        Returns:
            The matching :class:`~knowledge.attack.models.Software`.

        Raises:
            RecordNotFoundError: If no software with that ID exists.
            RepositoryError: If the query fails.
        """
        try:
            row = self.database.fetchone("SELECT * FROM software WHERE attack_id = ?;", (attack_id,))
        except Exception as exc:
            raise RepositoryError(f"Failed to fetch software {attack_id}: {exc}") from exc
        if row is None:
            raise RecordNotFoundError(f"Software not found: {attack_id}")
        return self._row_to_software(row)

    def get_mitigation(self, attack_id: str) -> Mitigation:
        """Fetches a single mitigation by its ATT&CK ID.

        Args:
            attack_id: The ATT&CK mitigation ID (e.g. ``"M1038"``).

        Returns:
            The matching :class:`~knowledge.attack.models.Mitigation`.

        Raises:
            RecordNotFoundError: If no mitigation with that ID exists.
            RepositoryError: If the query fails.
        """
        try:
            row = self.database.fetchone("SELECT * FROM mitigations WHERE attack_id = ?;", (attack_id,))
        except Exception as exc:
            raise RepositoryError(f"Failed to fetch mitigation {attack_id}: {exc}") from exc
        if row is None:
            raise RecordNotFoundError(f"Mitigation not found: {attack_id}")
        return self._row_to_mitigation(row)

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def find_by_attack_id(self, attack_id: str) -> SearchResult | None:
        """Finds any ATT&CK object (of any type) by its exact ATT&CK ID.

        Args:
            attack_id: The exact ATT&CK ID to look up (e.g. ``"T1059"``).

        Returns:
            A :class:`~knowledge.attack.models.SearchResult` if found,
            otherwise ``None``.

        Raises:
            RepositoryError: If the query fails.
        """
        table_map: tuple[tuple[str, ObjectType], ...] = (
            ("techniques", ObjectType.TECHNIQUE),
            ("tactics", ObjectType.TACTIC),
            ("software", ObjectType.SOFTWARE),
            ("groups", ObjectType.GROUP),
            ("mitigations", ObjectType.MITIGATION),
        )
        try:
            for table, object_type in table_map:
                row = self.database.fetchone(
                    f"SELECT attack_id, name, description FROM {table} WHERE attack_id = ?;",
                    (attack_id,),
                )
                if row is not None:
                    return SearchResult(
                        object_type=object_type,
                        attack_id=row["attack_id"],
                        name=row["name"],
                        description=row["description"],
                        score=1.0,
                    )
        except Exception as exc:
            raise RepositoryError(f"Failed to find object by ATT&CK ID {attack_id}: {exc}") from exc
        return None

    def find_by_name(self, name: str, *, limit: int = 25) -> list[SearchResult]:
        """Finds ATT&CK objects (of any type) whose name matches exactly.

        Args:
            name: The exact (case-insensitive) name to look up.
            limit: Maximum number of results to return.

        Returns:
            A list of matching :class:`~knowledge.attack.models.SearchResult`.

        Raises:
            RepositoryError: If the query fails.
        """
        table_map: tuple[tuple[str, ObjectType], ...] = (
            ("techniques", ObjectType.TECHNIQUE),
            ("tactics", ObjectType.TACTIC),
            ("software", ObjectType.SOFTWARE),
            ("groups", ObjectType.GROUP),
            ("mitigations", ObjectType.MITIGATION),
        )
        results: list[SearchResult] = []
        try:
            for table, object_type in table_map:
                rows = self.database.fetchall(
                    f"""
                    SELECT attack_id, name, description FROM {table}
                    WHERE name = ? COLLATE NOCASE
                    LIMIT ?;
                    """,
                    (name, limit),
                )
                for row in rows:
                    results.append(
                        SearchResult(
                            object_type=object_type,
                            attack_id=row["attack_id"],
                            name=row["name"],
                            description=row["description"],
                            score=1.0,
                        )
                    )
        except Exception as exc:
            raise RepositoryError(f"Failed to find objects by name {name!r}: {exc}") from exc
        return results[:limit]

    def search(self, keyword: str, *, limit: int = 25) -> list[SearchResult]:
        """Performs a keyword search across every ATT&CK object type.

        Matches are found in the ``name`` and ``description`` columns
        using a case-insensitive ``LIKE`` match. Name matches are
        ranked above description-only matches.

        Args:
            keyword: The keyword or phrase to search for.
            limit: Maximum number of results to return, across all
                object types combined.

        Returns:
            A list of :class:`~knowledge.attack.models.SearchResult`,
            ordered by descending relevance score.

        Raises:
            RepositoryError: If the query fails.
        """
        table_map: tuple[tuple[str, ObjectType], ...] = (
            ("techniques", ObjectType.TECHNIQUE),
            ("tactics", ObjectType.TACTIC),
            ("software", ObjectType.SOFTWARE),
            ("groups", ObjectType.GROUP),
            ("mitigations", ObjectType.MITIGATION),
        )
        pattern = f"%{keyword}%"
        results: list[SearchResult] = []
        try:
            for table, object_type in table_map:
                rows = self.database.fetchall(
                    f"""
                    SELECT attack_id, name, description,
                        CASE
                            WHEN attack_id = ? COLLATE NOCASE THEN 3.0
                            WHEN name LIKE ? COLLATE NOCASE THEN 2.0
                            ELSE 1.0
                        END AS score
                    FROM {table}
                    WHERE attack_id = ? COLLATE NOCASE
                        OR name LIKE ? COLLATE NOCASE
                        OR description LIKE ? COLLATE NOCASE
                    ORDER BY score DESC, name ASC
                    LIMIT ?;
                    """,
                    (keyword, pattern, keyword, pattern, pattern, limit),
                )
                for row in rows:
                    results.append(
                        SearchResult(
                            object_type=object_type,
                            attack_id=row["attack_id"],
                            name=row["name"],
                            description=row["description"],
                            score=float(row["score"]),
                        )
                    )
        except Exception as exc:
            raise RepositoryError(f"Failed to search for keyword {keyword!r}: {exc}") from exc
        results.sort(key=lambda result: result.score, reverse=True)
        return results[:limit]

    # ------------------------------------------------------------------
    # Relationship queries
    # ------------------------------------------------------------------

    def get_groups_using(self, technique_attack_id: str) -> list[Group]:
        """Finds all groups known to use a given technique.

        Args:
            technique_attack_id: ATT&CK ID of the technique.

        Returns:
            A list of :class:`~knowledge.attack.models.Group` objects.

        Raises:
            RepositoryError: If the query fails.
        """
        try:
            rows = self.database.fetchall(
                """
                SELECT g.* FROM groups g
                JOIN relationships r ON r.source_attack_id = g.attack_id
                WHERE r.relationship_type = 'uses'
                    AND r.target_attack_id = ?
                    AND r.source_type = ?;
                """,
                (technique_attack_id, ObjectType.GROUP.value),
            )
        except Exception as exc:
            raise RepositoryError(
                f"Failed to fetch groups using technique {technique_attack_id}: {exc}"
            ) from exc
        return [self._row_to_group(row) for row in rows]

    def get_software_using(self, technique_attack_id: str) -> list[Software]:
        """Finds all software known to implement a given technique.

        Args:
            technique_attack_id: ATT&CK ID of the technique.

        Returns:
            A list of :class:`~knowledge.attack.models.Software` objects.

        Raises:
            RepositoryError: If the query fails.
        """
        try:
            rows = self.database.fetchall(
                """
                SELECT s.* FROM software s
                JOIN relationships r ON r.source_attack_id = s.attack_id
                WHERE r.relationship_type = 'uses'
                    AND r.target_attack_id = ?
                    AND r.source_type = ?;
                """,
                (technique_attack_id, ObjectType.SOFTWARE.value),
            )
        except Exception as exc:
            raise RepositoryError(
                f"Failed to fetch software using technique {technique_attack_id}: {exc}"
            ) from exc
        return [self._row_to_software(row) for row in rows]

    def get_mitigations(self, technique_attack_id: str) -> list[Mitigation]:
        """Finds all mitigations that address a given technique.

        Args:
            technique_attack_id: ATT&CK ID of the technique.

        Returns:
            A list of :class:`~knowledge.attack.models.Mitigation` objects.

        Raises:
            RepositoryError: If the query fails.
        """
        try:
            rows = self.database.fetchall(
                """
                SELECT m.* FROM mitigations m
                JOIN relationships r ON r.source_attack_id = m.attack_id
                WHERE r.relationship_type = 'mitigates'
                    AND r.target_attack_id = ?
                    AND r.source_type = ?;
                """,
                (technique_attack_id, ObjectType.MITIGATION.value),
            )
        except Exception as exc:
            raise RepositoryError(
                f"Failed to fetch mitigations for technique {technique_attack_id}: {exc}"
            ) from exc
        return [self._row_to_mitigation(row) for row in rows]

    def get_platforms(self, technique_attack_id: str) -> list[str]:
        """Finds all platforms a given technique applies to.

        Args:
            technique_attack_id: ATT&CK ID of the technique.

        Returns:
            A list of platform names.

        Raises:
            RepositoryError: If the query fails.
        """
        try:
            rows = self.database.fetchall(
                "SELECT platform FROM technique_platforms WHERE technique_attack_id = ? ORDER BY platform;",
                (technique_attack_id,),
            )
        except Exception as exc:
            raise RepositoryError(
                f"Failed to fetch platforms for technique {technique_attack_id}: {exc}"
            ) from exc
        return [row["platform"] for row in rows]

    def get_tactics(self, technique_attack_id: str) -> list[Tactic]:
        """Finds all tactics a given technique belongs to.

        Args:
            technique_attack_id: ATT&CK ID of the technique.

        Returns:
            A list of :class:`~knowledge.attack.models.Tactic` objects.

        Raises:
            RepositoryError: If the query fails.
        """
        try:
            rows = self.database.fetchall(
                """
                SELECT t.* FROM tactics t
                JOIN technique_tactics tt ON tt.tactic_attack_id = t.attack_id
                WHERE tt.technique_attack_id = ?
                ORDER BY t.name;
                """,
                (technique_attack_id,),
            )
        except Exception as exc:
            raise RepositoryError(
                f"Failed to fetch tactics for technique {technique_attack_id}: {exc}"
            ) from exc
        return [self._row_to_tactic(row) for row in rows]

    def find_techniques_by_platform(self, platform: str, *, limit: int = 25) -> list[Technique]:
        """Finds techniques applicable to a given platform.

        Args:
            platform: Platform name (e.g. ``"Windows"``, ``"Linux"``,
                ``"macOS"``). Matched case-insensitively.
            limit: Maximum number of results to return.

        Returns:
            A list of matching :class:`~knowledge.attack.models.Technique`.

        Raises:
            RepositoryError: If the query fails.
        """
        try:
            rows = self.database.fetchall(
                """
                SELECT t.* FROM techniques t
                JOIN technique_platforms tp ON tp.technique_attack_id = t.attack_id
                WHERE tp.platform = ? COLLATE NOCASE
                ORDER BY t.attack_id
                LIMIT ?;
                """,
                (platform, limit),
            )
        except Exception as exc:
            raise RepositoryError(f"Failed to find techniques for platform {platform!r}: {exc}") from exc
        return [self._row_to_technique(row) for row in rows]

    def find_techniques_by_tactic(self, tactic_attack_id: str, *, limit: int = 25) -> list[Technique]:
        """Finds techniques belonging to a given tactic.

        Args:
            tactic_attack_id: ATT&CK ID of the tactic (e.g. ``"TA0002"``).
            limit: Maximum number of results to return.

        Returns:
            A list of matching :class:`~knowledge.attack.models.Technique`.

        Raises:
            RepositoryError: If the query fails.
        """
        try:
            rows = self.database.fetchall(
                """
                SELECT t.* FROM techniques t
                JOIN technique_tactics tt ON tt.technique_attack_id = t.attack_id
                WHERE tt.tactic_attack_id = ?
                ORDER BY t.attack_id
                LIMIT ?;
                """,
                (tactic_attack_id, limit),
            )
        except Exception as exc:
            raise RepositoryError(
                f"Failed to find techniques for tactic {tactic_attack_id}: {exc}"
            ) from exc
        return [self._row_to_technique(row) for row in rows]

    # ------------------------------------------------------------------
    # Row -> dataclass conversion helpers
    # ------------------------------------------------------------------

    def _row_to_technique(self, row: sqlite3.Row) -> Technique:
        """Converts a raw ``techniques`` row into a :class:`Technique`."""
        attack_id = row["attack_id"]
        return Technique(
            attack_id=attack_id,
            stix_id=row["stix_id"],
            name=row["name"],
            description=row["description"],
            is_subtechnique=bool(row["is_subtechnique"]),
            parent_attack_id=row["parent_attack_id"],
            detection=row["detection"],
            url=row["url"],
            platforms=tuple(self.get_platforms(attack_id)),
            tactics=tuple(tactic.attack_id for tactic in self.get_tactics(attack_id)),
        )

    @staticmethod
    def _row_to_tactic(row: sqlite3.Row) -> Tactic:
        """Converts a raw ``tactics`` row into a :class:`Tactic`."""
        return Tactic(
            attack_id=row["attack_id"],
            stix_id=row["stix_id"],
            name=row["name"],
            description=row["description"],
            shortname=row["shortname"],
        )

    @staticmethod
    def _row_to_software(row: sqlite3.Row) -> Software:
        """Converts a raw ``software`` row into a :class:`Software`."""
        return Software(
            attack_id=row["attack_id"],
            stix_id=row["stix_id"],
            name=row["name"],
            description=row["description"],
            software_type=row["software_type"],
        )

    @staticmethod
    def _row_to_group(row: sqlite3.Row) -> Group:
        """Converts a raw ``groups`` row into a :class:`Group`."""
        aliases_raw = row["aliases"] or ""
        aliases: Iterable[str] = (alias for alias in aliases_raw.split("|") if alias)
        return Group(
            attack_id=row["attack_id"],
            stix_id=row["stix_id"],
            name=row["name"],
            description=row["description"],
            aliases=tuple(aliases),
        )

    @staticmethod
    def _row_to_mitigation(row: sqlite3.Row) -> Mitigation:
        """Converts a raw ``mitigations`` row into a :class:`Mitigation`."""
        return Mitigation(
            attack_id=row["attack_id"],
            stix_id=row["stix_id"],
            name=row["name"],
            description=row["description"],
        )

"""STIX 2.1 dataset loader for the MITRE ATT&CK knowledge layer.

This module reads the official ``enterprise-attack.json`` STIX 2.1
bundle and populates every normalized table through
:class:`~knowledge.attack.repository.AttackRepository`. It never
executes SQL directly — all persistence goes through repository
methods.

Running this module as a script (``python -m knowledge.attack.loader``
or ``python loader.py``) loads the configured dataset into the
configured database.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any, Iterable

from knowledge.attack.config import AttackConfig
from knowledge.attack.models import Group, Mitigation, ObjectType, Relationship, Software, Tactic, Technique
from knowledge.attack.repository import AttackRepository
from knowledge.base.database import Database
from knowledge.base.exceptions import DatasetNotFoundError, StixParsingError

logger = logging.getLogger(__name__)

_MITRE_SOURCE_NAMES = ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack")
_KILL_CHAIN_NAME = "mitre-attack"


class AttackLoader:
    """Loads a STIX 2.1 ATT&CK Enterprise dataset into the repository.

    Attributes:
        repository: The repository used to persist parsed objects.
        dataset_path: Path to the STIX 2.1 JSON dataset file.
    """

    def __init__(self, repository: AttackRepository, dataset_path: str | Path) -> None:
        """Initializes the loader.

        Args:
            repository: An :class:`~knowledge.attack.repository.AttackRepository`
                instance to persist parsed objects into.
            dataset_path: Path to the STIX 2.1 ``enterprise-attack.json``
                dataset file.
        """
        self.repository = repository
        self.dataset_path = Path(dataset_path)

    def load(self) -> None:
        """Loads the dataset end-to-end: read, parse, and persist.

        Raises:
            DatasetNotFoundError: If the dataset file does not exist.
            StixParsingError: If the dataset cannot be parsed as STIX.
        """
        logger.info("Loading ATT&CK dataset from %s", self.dataset_path)
        self.repository.create_schema()
        objects = self._read_objects()

        active_objects = [obj for obj in objects if not self._is_revoked_or_deprecated(obj)]
        logger.info(
            "Read %d STIX objects (%d active after filtering revoked/deprecated)",
            len(objects),
            len(active_objects),
        )

        objects_by_type: dict[str, list[dict[str, Any]]] = {}
        for obj in active_objects:
            objects_by_type.setdefault(obj.get("type", ""), []).append(obj)

        tactics, shortname_to_attack_id, tactic_stix_to_attack_id = self._parse_tactics(
            objects_by_type.get("x-mitre-tactic", [])
        )
        mitigations, mitigation_stix_to_attack_id = self._parse_mitigations(
            objects_by_type.get("course-of-action", [])
        )
        groups, group_stix_to_attack_id = self._parse_groups(objects_by_type.get("intrusion-set", []))
        software_list, software_stix_to_attack_id = self._parse_software(
            objects_by_type.get("malware", []) + objects_by_type.get("tool", [])
        )

        subtechnique_parent_map = self._build_subtechnique_parent_map(
            objects_by_type.get("relationship", [])
        )
        technique_stix_to_attack_id: dict[str, str] = {}
        techniques = self._parse_techniques(
            objects_by_type.get("attack-pattern", []),
            shortname_to_attack_id,
            subtechnique_parent_map,
            technique_stix_to_attack_id,
        )

        stix_to_attack_id: dict[str, tuple[str, ObjectType]] = {}
        stix_to_attack_id.update({sid: (aid, ObjectType.TACTIC) for sid, aid in tactic_stix_to_attack_id.items()})
        stix_to_attack_id.update(
            {sid: (aid, ObjectType.MITIGATION) for sid, aid in mitigation_stix_to_attack_id.items()}
        )
        stix_to_attack_id.update({sid: (aid, ObjectType.GROUP) for sid, aid in group_stix_to_attack_id.items()})
        stix_to_attack_id.update(
            {sid: (aid, ObjectType.SOFTWARE) for sid, aid in software_stix_to_attack_id.items()}
        )
        stix_to_attack_id.update(
            {sid: (aid, ObjectType.TECHNIQUE) for sid, aid in technique_stix_to_attack_id.items()}
        )

        relationships = self._parse_relationships(objects_by_type.get("relationship", []), stix_to_attack_id)

        self._persist(tactics, mitigations, groups, software_list, techniques, relationships)
        logger.info(
            "Loaded %d tactics, %d mitigations, %d groups, %d software, %d techniques, %d relationships",
            len(tactics),
            len(mitigations),
            len(groups),
            len(software_list),
            len(techniques),
            len(relationships),
        )

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------

    def _read_objects(self) -> list[dict[str, Any]]:
        """Reads and returns the raw STIX objects from the dataset file.

        Returns:
            The list of STIX objects found in the bundle's ``objects``
            field.

        Raises:
            DatasetNotFoundError: If the dataset file does not exist.
            StixParsingError: If the file is not valid JSON or lacks the
                expected STIX bundle structure.
        """
        if not self.dataset_path.exists():
            raise DatasetNotFoundError(f"ATT&CK dataset not found at {self.dataset_path}")
        try:
            with self.dataset_path.open("r", encoding="utf-8") as handle:
                bundle = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise StixParsingError(f"Failed to read/parse dataset at {self.dataset_path}: {exc}") from exc

        objects = bundle.get("objects")
        if not isinstance(objects, list):
            raise StixParsingError("STIX bundle is missing a top-level 'objects' list")
        return objects

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------

    @staticmethod
    def _is_revoked_or_deprecated(obj: dict[str, Any]) -> bool:
        """Determines whether a STIX object should be ignored.

        Args:
            obj: A raw STIX object.

        Returns:
            ``True`` if the object is revoked or deprecated and should
            be skipped, ``False`` otherwise.
        """
        return bool(obj.get("revoked", False)) or bool(obj.get("x_mitre_deprecated", False))

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_attack_id(obj: dict[str, Any]) -> str | None:
        """Extracts the ATT&CK ID from a STIX object's external references.

        Args:
            obj: A raw STIX object.

        Returns:
            The ATT&CK ID (e.g. ``"T1059.001"``), or ``None`` if the
            object has no matching external reference.
        """
        for reference in obj.get("external_references", []):
            if reference.get("source_name") in _MITRE_SOURCE_NAMES and reference.get("external_id"):
                return str(reference["external_id"])
        return None

    @staticmethod
    def _extract_url(obj: dict[str, Any]) -> str | None:
        """Extracts the canonical ATT&CK URL from external references.

        Args:
            obj: A raw STIX object.

        Returns:
            The URL string, or ``None`` if not present.
        """
        for reference in obj.get("external_references", []):
            if reference.get("source_name") in _MITRE_SOURCE_NAMES and reference.get("url"):
                return str(reference["url"])
        return None

    # ------------------------------------------------------------------
    # Per-type parsing
    # ------------------------------------------------------------------

    def _parse_tactics(
        self, raw_tactics: Iterable[dict[str, Any]]
    ) -> tuple[list[Tactic], dict[str, str], dict[str, str]]:
        """Parses ``x-mitre-tactic`` objects into :class:`Tactic` models.

        Args:
            raw_tactics: Raw STIX ``x-mitre-tactic`` objects.

        Returns:
            A tuple of ``(tactics, shortname_to_attack_id, stix_to_attack_id)``.
        """
        tactics: list[Tactic] = []
        shortname_to_attack_id: dict[str, str] = {}
        stix_to_attack_id: dict[str, str] = {}
        for obj in raw_tactics:
            attack_id = self._extract_attack_id(obj)
            if attack_id is None:
                logger.warning("Skipping tactic %s: no ATT&CK ID found", obj.get("id"))
                continue
            shortname = str(obj.get("x_mitre_shortname", ""))
            tactic = Tactic(
                attack_id=attack_id,
                stix_id=obj["id"],
                name=str(obj.get("name", "")),
                description=obj.get("description"),
                shortname=shortname,
            )
            tactics.append(tactic)
            stix_to_attack_id[obj["id"]] = attack_id
            if shortname:
                shortname_to_attack_id[shortname] = attack_id
        return tactics, shortname_to_attack_id, stix_to_attack_id

    def _parse_mitigations(
        self, raw_mitigations: Iterable[dict[str, Any]]
    ) -> tuple[list[Mitigation], dict[str, str]]:
        """Parses ``course-of-action`` objects into :class:`Mitigation` models.

        Args:
            raw_mitigations: Raw STIX ``course-of-action`` objects.

        Returns:
            A tuple of ``(mitigations, stix_to_attack_id)``.
        """
        mitigations: list[Mitigation] = []
        stix_to_attack_id: dict[str, str] = {}
        for obj in raw_mitigations:
            attack_id = self._extract_attack_id(obj)
            if attack_id is None:
                logger.warning("Skipping mitigation %s: no ATT&CK ID found", obj.get("id"))
                continue
            mitigation = Mitigation(
                attack_id=attack_id,
                stix_id=obj["id"],
                name=str(obj.get("name", "")),
                description=obj.get("description"),
            )
            mitigations.append(mitigation)
            stix_to_attack_id[obj["id"]] = attack_id
        return mitigations, stix_to_attack_id

    def _parse_groups(self, raw_groups: Iterable[dict[str, Any]]) -> tuple[list[Group], dict[str, str]]:
        """Parses ``intrusion-set`` objects into :class:`Group` models.

        Args:
            raw_groups: Raw STIX ``intrusion-set`` objects.

        Returns:
            A tuple of ``(groups, stix_to_attack_id)``.
        """
        groups: list[Group] = []
        stix_to_attack_id: dict[str, str] = {}
        for obj in raw_groups:
            attack_id = self._extract_attack_id(obj)
            if attack_id is None:
                logger.warning("Skipping group %s: no ATT&CK ID found", obj.get("id"))
                continue
            aliases = tuple(str(alias) for alias in obj.get("aliases", []))
            group = Group(
                attack_id=attack_id,
                stix_id=obj["id"],
                name=str(obj.get("name", "")),
                description=obj.get("description"),
                aliases=aliases,
            )
            groups.append(group)
            stix_to_attack_id[obj["id"]] = attack_id
        return groups, stix_to_attack_id

    def _parse_software(
        self, raw_software: Iterable[dict[str, Any]]
    ) -> tuple[list[Software], dict[str, str]]:
        """Parses ``malware``/``tool`` objects into :class:`Software` models.

        Args:
            raw_software: Raw STIX ``malware`` and ``tool`` objects.

        Returns:
            A tuple of ``(software_list, stix_to_attack_id)``.
        """
        software_list: list[Software] = []
        stix_to_attack_id: dict[str, str] = {}
        for obj in raw_software:
            attack_id = self._extract_attack_id(obj)
            if attack_id is None:
                logger.warning("Skipping software %s: no ATT&CK ID found", obj.get("id"))
                continue
            software_type = "malware" if obj.get("type") == "malware" else "tool"
            software = Software(
                attack_id=attack_id,
                stix_id=obj["id"],
                name=str(obj.get("name", "")),
                description=obj.get("description"),
                software_type=software_type,
            )
            software_list.append(software)
            stix_to_attack_id[obj["id"]] = attack_id
        return software_list, stix_to_attack_id

    def _build_subtechnique_parent_map(
        self, raw_relationships: Iterable[dict[str, Any]]
    ) -> dict[str, str]:
        """Builds a map of sub-technique STIX ID to parent technique STIX ID.

        Args:
            raw_relationships: Raw STIX ``relationship`` objects.

        Returns:
            A dict mapping a sub-technique's STIX ID to its parent
            technique's STIX ID, derived from ``subtechnique-of``
            relationships.
        """
        parent_map: dict[str, str] = {}
        for obj in raw_relationships:
            if obj.get("relationship_type") == "subtechnique-of":
                source_ref = obj.get("source_ref")
                target_ref = obj.get("target_ref")
                if source_ref and target_ref:
                    parent_map[source_ref] = target_ref
        return parent_map

    def _parse_techniques(
        self,
        raw_techniques: Iterable[dict[str, Any]],
        shortname_to_attack_id: dict[str, str],
        subtechnique_parent_map: dict[str, str],
        stix_to_attack_id_out: dict[str, str],
    ) -> list[Technique]:
        """Parses ``attack-pattern`` objects into :class:`Technique` models.

        Args:
            raw_techniques: Raw STIX ``attack-pattern`` objects.
            shortname_to_attack_id: Map of tactic shortname to tactic
                ATT&CK ID, used to resolve ``kill_chain_phases``.
            subtechnique_parent_map: Map of sub-technique STIX ID to
                parent technique STIX ID.
            stix_to_attack_id_out: Output dict populated with this
                technique's STIX ID to ATT&CK ID mapping, so callers can
                resolve relationships that reference techniques.

        Returns:
            A list of parsed :class:`Technique` models, sorted so that
            parent techniques precede their sub-techniques (required so
            the ``parent_attack_id`` foreign key can be satisfied on
            insert).
        """
        stix_id_to_attack_id: dict[str, str] = {}
        raw_list = list(raw_techniques)

        for obj in raw_list:
            attack_id = self._extract_attack_id(obj)
            if attack_id is not None:
                stix_id_to_attack_id[obj["id"]] = attack_id
                stix_to_attack_id_out[obj["id"]] = attack_id

        techniques: list[Technique] = []
        for obj in raw_list:
            attack_id = stix_id_to_attack_id.get(obj["id"])
            if attack_id is None:
                logger.warning("Skipping technique %s: no ATT&CK ID found", obj.get("id"))
                continue

            is_subtechnique = bool(obj.get("x_mitre_is_subtechnique", False))
            parent_attack_id = None
            if is_subtechnique:
                parent_stix_id = subtechnique_parent_map.get(obj["id"])
                if parent_stix_id is not None:
                    parent_attack_id = stix_id_to_attack_id.get(parent_stix_id)

            platforms = tuple(str(platform) for platform in obj.get("x_mitre_platforms", []))

            tactic_ids: list[str] = []
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == _KILL_CHAIN_NAME:
                    phase_name = phase.get("phase_name", "")
                    tactic_attack_id = shortname_to_attack_id.get(phase_name)
                    if tactic_attack_id:
                        tactic_ids.append(tactic_attack_id)

            technique = Technique(
                attack_id=attack_id,
                stix_id=obj["id"],
                name=str(obj.get("name", "")),
                description=obj.get("description"),
                is_subtechnique=is_subtechnique,
                parent_attack_id=parent_attack_id,
                detection=obj.get("x_mitre_detection"),
                url=self._extract_url(obj),
                platforms=platforms,
                tactics=tuple(tactic_ids),
            )
            techniques.append(technique)

        # Parents must be inserted before children to satisfy the
        # self-referential foreign key on techniques.parent_attack_id.
        techniques.sort(key=lambda technique: technique.is_subtechnique)
        return techniques

    def _parse_relationships(
        self,
        raw_relationships: Iterable[dict[str, Any]],
        stix_to_attack_id: dict[str, tuple[str, ObjectType]],
    ) -> list[Relationship]:
        """Parses ``relationship`` objects into :class:`Relationship` models.

        Args:
            raw_relationships: Raw STIX ``relationship`` objects.
            stix_to_attack_id: Map of every known STIX ID to its
                resolved ``(attack_id, object_type)`` tuple, used to
                enrich each relationship's source and target.

        Returns:
            A list of parsed :class:`Relationship` models.
        """
        relationships: list[Relationship] = []
        for obj in raw_relationships:
            source_ref = obj.get("source_ref")
            target_ref = obj.get("target_ref")
            if not source_ref or not target_ref:
                continue

            source_attack_id, source_type = stix_to_attack_id.get(source_ref, (None, None))
            target_attack_id, target_type = stix_to_attack_id.get(target_ref, (None, None))

            relationship = Relationship(
                stix_id=obj["id"],
                relationship_type=str(obj.get("relationship_type", "")),
                description=obj.get("description"),
                source_stix_id=source_ref,
                source_attack_id=source_attack_id,
                source_type=source_type.value if isinstance(source_type, ObjectType) else source_type,
                target_stix_id=target_ref,
                target_attack_id=target_attack_id,
                target_type=target_type.value if isinstance(target_type, ObjectType) else target_type,
            )
            relationships.append(relationship)
        return relationships

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _persist(
        self,
        tactics: list[Tactic],
        mitigations: list[Mitigation],
        groups: list[Group],
        software_list: list[Software],
        techniques: list[Technique],
        relationships: list[Relationship],
    ) -> None:
        """Persists every parsed object through the repository.

        Args:
            tactics: Parsed tactics.
            mitigations: Parsed mitigations.
            groups: Parsed groups.
            software_list: Parsed software.
            techniques: Parsed techniques, parents-first.
            relationships: Parsed relationships.
        """
        for tactic in tactics:
            self.repository.insert_tactic(tactic)
        for mitigation in mitigations:
            self.repository.insert_mitigation(mitigation)
        for group in groups:
            self.repository.insert_group(group)
        for software in software_list:
            self.repository.insert_software(software)
        for technique in techniques:
            self.repository.insert_technique(technique)
        for relationship in relationships:
            self.repository.insert_relationship(relationship)


def _configure_logging() -> None:
    """Configures a sane default logging setup for standalone execution."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stdout,
    )


def main() -> int:
    """Entry point for running the loader as a standalone script.

    Reads the configured dataset path and loads it into the configured
    database.

    Returns:
        Process exit code: ``0`` on success, ``1`` on failure.
    """
    _configure_logging()
    config = AttackConfig()
    database = Database(config.database_path)
    try:
        with database:
            repository = AttackRepository(database)
            loader = AttackLoader(repository, config.dataset_path)
            loader.load()
    except Exception:
        logger.exception("Failed to load ATT&CK dataset")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

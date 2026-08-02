"""Unit tests for :mod:`knowledge.attack.service`."""

from __future__ import annotations

import unittest

from knowledge.attack.config import AttackConfig
from knowledge.attack.matcher import AttackMatcher, TelemetryEvent
from knowledge.attack.models import Group, Mitigation, Relationship, Technique
from knowledge.attack.repository import AttackRepository
from knowledge.attack.search import AttackSearchEngine
from knowledge.attack.service import AttackService
from knowledge.base.database import Database


class AttackServiceTestCase(unittest.TestCase):
    """Tests the facade wiring and its public methods."""

    def setUp(self) -> None:
        """Builds a fully-wired AttackService over an in-memory database."""
        self.database = Database(":memory:")
        self.database.connect()
        repository = AttackRepository(self.database)
        repository.create_schema()

        repository.insert_technique(
            Technique(attack_id="T1059.001", stix_id="attack-pattern--1", name="PowerShell")
        )
        repository.insert_group(Group(attack_id="G0016", stix_id="intrusion-set--1", name="APT29"))
        repository.insert_mitigation(
            Mitigation(attack_id="M1038", stix_id="course-of-action--1", name="Execution Prevention")
        )
        repository.insert_relationship(
            Relationship(
                stix_id="relationship--1",
                relationship_type="uses",
                source_stix_id="intrusion-set--1",
                source_attack_id="G0016",
                source_type="group",
                target_stix_id="attack-pattern--1",
                target_attack_id="T1059.001",
                target_type="technique",
            )
        )
        repository.insert_relationship(
            Relationship(
                stix_id="relationship--2",
                relationship_type="mitigates",
                source_stix_id="course-of-action--1",
                source_attack_id="M1038",
                source_type="mitigation",
                target_stix_id="attack-pattern--1",
                target_attack_id="T1059.001",
                target_type="technique",
            )
        )

        search_engine = AttackSearchEngine(repository, AttackConfig())
        matcher = AttackMatcher()
        self.service = AttackService(self.database, repository, search_engine, matcher)

    def tearDown(self) -> None:
        """Closes the service (and its underlying database)."""
        self.service.close()

    def test_get_technique(self) -> None:
        """get_technique returns the expected technique."""
        technique = self.service.get_technique("T1059.001")
        self.assertEqual(technique.name, "PowerShell")

    def test_get_groups_and_mitigations(self) -> None:
        """get_groups and get_mitigations return linked records."""
        groups = self.service.get_groups("T1059.001")
        mitigations = self.service.get_mitigations("T1059.001")
        self.assertEqual([g.attack_id for g in groups], ["G0016"])
        self.assertEqual([m.attack_id for m in mitigations], ["M1038"])

    def test_search(self) -> None:
        """search finds the seeded technique by name."""
        results = self.service.search("PowerShell")
        self.assertTrue(any(r.attack_id == "T1059.001" for r in results))

    def test_match_event(self) -> None:
        """match_event maps a telemetry event to the expected technique."""
        results = self.service.match_event(TelemetryEvent(process_name="powershell.exe"))
        technique_ids = {r.technique_attack_id for r in results}
        self.assertIn("T1059.001", technique_ids)

    def test_context_manager(self) -> None:
        """AttackService can be used as a context manager."""
        with self.service as svc:
            self.assertIs(svc, self.service)


if __name__ == "__main__":
    unittest.main()

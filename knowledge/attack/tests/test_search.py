"""Unit tests for :mod:`knowledge.attack.search`."""

from __future__ import annotations

import unittest

from knowledge.attack.config import AttackConfig
from knowledge.attack.models import ObjectType, Tactic, Technique
from knowledge.attack.repository import AttackRepository
from knowledge.attack.search import AttackSearchEngine
from knowledge.base.database import Database
from knowledge.base.exceptions import SearchError


class AttackSearchEngineTestCase(unittest.TestCase):
    """Tests type-specific and generic search behavior."""

    def setUp(self) -> None:
        """Seeds an in-memory database with a small, known dataset."""
        self.database = Database(":memory:")
        self.database.connect()
        self.repository = AttackRepository(self.database)
        self.repository.create_schema()

        tactic = Tactic(attack_id="TA0002", stix_id="x-mitre-tactic--1", name="Execution", shortname="execution")
        self.repository.insert_tactic(tactic)

        self.repository.insert_technique(
            Technique(
                attack_id="T1059.001",
                stix_id="attack-pattern--1",
                name="PowerShell",
                description="Adversaries may abuse PowerShell.",
                platforms=("Windows",),
                tactics=("TA0002",),
            )
        )
        self.repository.insert_technique(
            Technique(
                attack_id="T1105",
                stix_id="attack-pattern--2",
                name="Ingress Tool Transfer",
                description="Adversaries may transfer tools.",
                platforms=("Windows", "Linux"),
            )
        )

        self.search_engine = AttackSearchEngine(self.repository, AttackConfig())

    def tearDown(self) -> None:
        """Closes the in-memory database."""
        self.database.close()

    def test_search_by_keyword_returns_matches(self) -> None:
        """A keyword present in a description returns the matching object."""
        results = self.search_engine.search("PowerShell")
        self.assertTrue(any(r.attack_id == "T1059.001" for r in results))

    def test_search_techniques_filters_by_type(self) -> None:
        """search_techniques only returns technique-typed results."""
        results = self.search_engine.search_techniques("Adversaries")
        self.assertTrue(all(r.object_type == ObjectType.TECHNIQUE for r in results))
        self.assertGreaterEqual(len(results), 2)

    def test_empty_keyword_raises(self) -> None:
        """An empty search keyword raises SearchError."""
        with self.assertRaises(SearchError):
            self.search_engine.search("   ")

    def test_by_attack_id_exact_match(self) -> None:
        """by_attack_id finds an exact ATT&CK ID."""
        result = self.search_engine.by_attack_id("T1105")
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.name, "Ingress Tool Transfer")

    def test_by_platform(self) -> None:
        """by_platform finds techniques applicable to the given platform."""
        results = self.search_engine.by_platform("Linux")
        self.assertEqual([t.attack_id for t in results], ["T1105"])

    def test_by_tactic(self) -> None:
        """by_tactic finds techniques mapped to the given tactic."""
        results = self.search_engine.by_tactic("TA0002")
        self.assertEqual([t.attack_id for t in results], ["T1059.001"])


if __name__ == "__main__":
    unittest.main()

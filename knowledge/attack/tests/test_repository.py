"""Unit tests for :mod:`knowledge.attack.repository`."""

from __future__ import annotations

import unittest

from knowledge.attack.models import Group, Mitigation, Relationship, Software, Tactic, Technique
from knowledge.attack.repository import AttackRepository
from knowledge.base.database import Database
from knowledge.base.exceptions import RecordNotFoundError


class AttackRepositoryTestCase(unittest.TestCase):
    """Tests basic CRUD and relationship-query behavior of the repository."""

    def setUp(self) -> None:
        """Creates a fresh in-memory database and repository per test."""
        self.database = Database(":memory:")
        self.database.connect()
        self.repository = AttackRepository(self.database)
        self.repository.create_schema()

    def tearDown(self) -> None:
        """Closes the in-memory database."""
        self.database.close()

    def test_insert_and_get_technique(self) -> None:
        """A technique inserted with platforms/tactics is retrievable."""
        tactic = Tactic(attack_id="TA0002", stix_id="x-mitre-tactic--1", name="Execution", shortname="execution")
        self.repository.insert_tactic(tactic)

        technique = Technique(
            attack_id="T1059",
            stix_id="attack-pattern--1",
            name="Command and Scripting Interpreter",
            description="Adversaries may abuse command interpreters.",
            platforms=("Windows", "Linux"),
            tactics=("TA0002",),
        )
        self.repository.insert_technique(technique)

        fetched = self.repository.get_technique("T1059")
        self.assertEqual(fetched.name, "Command and Scripting Interpreter")
        self.assertEqual(set(fetched.platforms), {"Windows", "Linux"})
        self.assertEqual(fetched.tactics, ("TA0002",))

    def test_get_technique_not_found_raises(self) -> None:
        """Fetching a non-existent technique raises RecordNotFoundError."""
        with self.assertRaises(RecordNotFoundError):
            self.repository.get_technique("T9999")

    def test_subtechnique_parent_relationship(self) -> None:
        """A sub-technique correctly references its parent technique."""
        parent = Technique(attack_id="T1059", stix_id="attack-pattern--1", name="Command Interpreter")
        child = Technique(
            attack_id="T1059.001",
            stix_id="attack-pattern--2",
            name="PowerShell",
            is_subtechnique=True,
            parent_attack_id="T1059",
        )
        self.repository.insert_technique(parent)
        self.repository.insert_technique(child)

        fetched = self.repository.get_technique("T1059.001")
        self.assertTrue(fetched.is_subtechnique)
        self.assertEqual(fetched.parent_attack_id, "T1059")

    def test_relationship_queries(self) -> None:
        """Groups, software, and mitigations linked to a technique are found."""
        technique = Technique(attack_id="T1059.001", stix_id="attack-pattern--1", name="PowerShell")
        group = Group(attack_id="G0016", stix_id="intrusion-set--1", name="APT29")
        software = Software(
            attack_id="S0002", stix_id="malware--1", name="Mimikatz", software_type="malware"
        )
        mitigation = Mitigation(attack_id="M1038", stix_id="course-of-action--1", name="Execution Prevention")

        self.repository.insert_technique(technique)
        self.repository.insert_group(group)
        self.repository.insert_software(software)
        self.repository.insert_mitigation(mitigation)

        self.repository.insert_relationship(
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
        self.repository.insert_relationship(
            Relationship(
                stix_id="relationship--2",
                relationship_type="uses",
                source_stix_id="malware--1",
                source_attack_id="S0002",
                source_type="software",
                target_stix_id="attack-pattern--1",
                target_attack_id="T1059.001",
                target_type="technique",
            )
        )
        self.repository.insert_relationship(
            Relationship(
                stix_id="relationship--3",
                relationship_type="mitigates",
                source_stix_id="course-of-action--1",
                source_attack_id="M1038",
                source_type="mitigation",
                target_stix_id="attack-pattern--1",
                target_attack_id="T1059.001",
                target_type="technique",
            )
        )

        groups = self.repository.get_groups_using("T1059.001")
        software_list = self.repository.get_software_using("T1059.001")
        mitigations = self.repository.get_mitigations("T1059.001")

        self.assertEqual([g.attack_id for g in groups], ["G0016"])
        self.assertEqual([s.attack_id for s in software_list], ["S0002"])
        self.assertEqual([m.attack_id for m in mitigations], ["M1038"])

    def test_search_finds_by_keyword(self) -> None:
        """A keyword search finds an object by a substring of its name."""
        technique = Technique(attack_id="T1105", stix_id="attack-pattern--3", name="Ingress Tool Transfer")
        self.repository.insert_technique(technique)

        results = self.repository.search("Ingress")
        self.assertTrue(any(r.attack_id == "T1105" for r in results))


if __name__ == "__main__":
    unittest.main()

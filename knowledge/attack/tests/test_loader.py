"""Unit tests for :mod:`knowledge.attack.loader`."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from knowledge.attack.loader import AttackLoader
from knowledge.attack.repository import AttackRepository
from knowledge.base.database import Database
from knowledge.base.exceptions import DatasetNotFoundError


def _build_minimal_bundle() -> dict:
    """Builds a minimal, well-formed STIX bundle for testing.

    Returns:
        A dict resembling a small slice of ``enterprise-attack.json``
        with one tactic, one mitigation, one group, one piece of
        software, two techniques (parent + sub-technique), and the
        relationships tying them together.
    """
    return {
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            {
                "type": "x-mitre-tactic",
                "id": "x-mitre-tactic--exec",
                "name": "Execution",
                "x_mitre_shortname": "execution",
                "external_references": [{"source_name": "mitre-attack", "external_id": "TA0002"}],
            },
            {
                "type": "course-of-action",
                "id": "course-of-action--1",
                "name": "Execution Prevention",
                "description": "Block execution of malicious binaries.",
                "external_references": [{"source_name": "mitre-attack", "external_id": "M1038"}],
            },
            {
                "type": "intrusion-set",
                "id": "intrusion-set--1",
                "name": "APT29",
                "aliases": ["APT29", "Cozy Bear"],
                "external_references": [{"source_name": "mitre-attack", "external_id": "G0016"}],
            },
            {
                "type": "malware",
                "id": "malware--1",
                "name": "Mimikatz",
                "external_references": [{"source_name": "mitre-attack", "external_id": "S0002"}],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--parent",
                "name": "Command and Scripting Interpreter",
                "x_mitre_is_subtechnique": False,
                "x_mitre_platforms": ["Windows", "Linux"],
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1059",
                        "url": "https://attack.mitre.org/techniques/T1059",
                    }
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--child",
                "name": "PowerShell",
                "x_mitre_is_subtechnique": True,
                "x_mitre_platforms": ["Windows"],
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001"}],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--revoked",
                "name": "Should Be Skipped",
                "revoked": True,
                "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}],
            },
            {
                "type": "relationship",
                "id": "relationship--subtechnique",
                "relationship_type": "subtechnique-of",
                "source_ref": "attack-pattern--child",
                "target_ref": "attack-pattern--parent",
            },
            {
                "type": "relationship",
                "id": "relationship--uses",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--1",
                "target_ref": "attack-pattern--child",
            },
            {
                "type": "relationship",
                "id": "relationship--mitigates",
                "relationship_type": "mitigates",
                "source_ref": "course-of-action--1",
                "target_ref": "attack-pattern--child",
            },
        ],
    }


class AttackLoaderTestCase(unittest.TestCase):
    """Tests dataset loading end-to-end against an in-memory database."""

    def setUp(self) -> None:
        """Creates a temp dataset file and an in-memory database/repository."""
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.dataset_path = Path(self._tmp_dir.name) / "enterprise-attack.json"
        with self.dataset_path.open("w", encoding="utf-8") as handle:
            json.dump(_build_minimal_bundle(), handle)

        self.database = Database(":memory:")
        self.database.connect()
        self.repository = AttackRepository(self.database)
        self.loader = AttackLoader(self.repository, self.dataset_path)

    def tearDown(self) -> None:
        """Cleans up the temp directory and closes the database."""
        self.database.close()
        self._tmp_dir.cleanup()

    def test_missing_dataset_raises(self) -> None:
        """Loading a nonexistent dataset raises DatasetNotFoundError."""
        loader = AttackLoader(self.repository, Path(self._tmp_dir.name) / "missing.json")
        with self.assertRaises(DatasetNotFoundError):
            loader.load()

    def test_load_populates_repository(self) -> None:
        """A full load populates every table and resolves relationships."""
        self.loader.load()

        parent = self.repository.get_technique("T1059")
        child = self.repository.get_technique("T1059.001")
        self.assertFalse(parent.is_subtechnique)
        self.assertTrue(child.is_subtechnique)
        self.assertEqual(child.parent_attack_id, "T1059")
        self.assertIn("TA0002", child.tactics)
        self.assertIn("Windows", child.platforms)

        with self.assertRaises(Exception):
            self.repository.get_technique("T9999")

        groups = self.repository.get_groups_using("T1059.001")
        mitigations = self.repository.get_mitigations("T1059.001")
        self.assertEqual([g.attack_id for g in groups], ["G0016"])
        self.assertEqual([m.attack_id for m in mitigations], ["M1038"])


if __name__ == "__main__":
    unittest.main()

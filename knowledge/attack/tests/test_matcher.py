"""Unit tests for :mod:`knowledge.attack.matcher`."""

from __future__ import annotations

import unittest

from knowledge.attack.matcher import AttackMatcher, MatchingRule, TelemetryEvent
from knowledge.base.exceptions import InvalidTelemetryEventError


class TelemetryEventTestCase(unittest.TestCase):
    """Tests validation of the TelemetryEvent value object."""

    def test_empty_event_raises(self) -> None:
        """An event with no usable fields raises InvalidTelemetryEventError."""
        with self.assertRaises(InvalidTelemetryEventError):
            TelemetryEvent()

    def test_event_with_process_name_is_valid(self) -> None:
        """An event with only a process name is considered valid."""
        event = TelemetryEvent(process_name="cmd.exe")
        self.assertEqual(event.process_name, "cmd.exe")


class AttackMatcherTestCase(unittest.TestCase):
    """Tests the default rule set and matcher extensibility."""

    def setUp(self) -> None:
        """Creates a matcher using the default rule set."""
        self.matcher = AttackMatcher()

    def test_powershell_maps_to_t1059_001(self) -> None:
        """powershell.exe maps to T1059.001."""
        event = TelemetryEvent(process_name="powershell.exe")
        results = self.matcher.match(event)
        technique_ids = {r.technique_attack_id for r in results}
        self.assertIn("T1059.001", technique_ids)

    def test_wmic_maps_to_t1047(self) -> None:
        """wmic.exe maps to T1047."""
        event = TelemetryEvent(process_name="wmic.exe")
        results = self.matcher.match(event)
        self.assertEqual([r.technique_attack_id for r in results], ["T1047"])

    def test_mimikatz_maps_to_t1003(self) -> None:
        """mimikatz.exe maps to T1003."""
        event = TelemetryEvent(process_name="mimikatz.exe")
        results = self.matcher.match(event)
        self.assertEqual([r.technique_attack_id for r in results], ["T1003"])

    def test_rundll32_maps_to_t1218(self) -> None:
        """rundll32.exe maps to T1218."""
        event = TelemetryEvent(process_name="rundll32.exe")
        results = self.matcher.match(event)
        self.assertEqual([r.technique_attack_id for r in results], ["T1218"])

    def test_certutil_maps_to_t1105(self) -> None:
        """certutil.exe maps to T1105."""
        event = TelemetryEvent(process_name="certutil.exe")
        results = self.matcher.match(event)
        self.assertEqual([r.technique_attack_id for r in results], ["T1105"])

    def test_unknown_process_produces_no_matches(self) -> None:
        """An unrecognized process name produces an empty match list."""
        event = TelemetryEvent(process_name="notepad.exe")
        results = self.matcher.match(event)
        self.assertEqual(results, [])

    def test_encoded_powershell_command_line_matches_obfuscation_rule(self) -> None:
        """A -enc flag in the command line triggers the obfuscation rule."""
        event = TelemetryEvent(process_name="powershell.exe", command_line="powershell.exe -enc SGVsbG8=")
        results = self.matcher.match(event)
        technique_ids = {r.technique_attack_id for r in results}
        self.assertIn("T1059.001", technique_ids)
        self.assertIn("T1027", technique_ids)

    def test_matcher_is_extensible_with_custom_rules(self) -> None:
        """A caller-supplied rule set participates in matching."""
        custom_rule = MatchingRule(
            name="custom_tool",
            technique_attack_id="T9999",
            predicate=lambda event: "custom" if event.process_name == "customtool.exe" else None,
        )
        matcher = AttackMatcher(rules=(custom_rule,))
        results = matcher.match(TelemetryEvent(process_name="customtool.exe"))
        self.assertEqual([r.technique_attack_id for r in results], ["T9999"])

    def test_invalid_event_type_raises(self) -> None:
        """Passing a non-TelemetryEvent to match raises InvalidTelemetryEventError."""
        with self.assertRaises(InvalidTelemetryEventError):
            self.matcher.match("not-an-event")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()

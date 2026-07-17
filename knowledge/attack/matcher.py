"""Deterministic ATT&CK matcher for the MITRE ATT&CK knowledge layer.

This module maps normalized telemetry events (e.g. process execution
events from an EDR) to MITRE ATT&CK technique IDs using explicit,
inspectable rules. It contains no LLM logic, no embeddings, and no
statistical scoring — every match is the result of a deterministic
predicate a human wrote and can audit.

The rule set is intentionally simple to extend: add a
:class:`MatchingRule` to :data:`DEFAULT_RULES` (or pass a custom list
to :class:`AttackMatcher`) and it participates in matching immediately.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable

from knowledge.base.exceptions import InvalidTelemetryEventError

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class TelemetryEvent:
    """A normalized telemetry event to be matched against ATT&CK.

    Producers of telemetry (EDR agents, log parsers, etc.) are expected
    to normalize their raw events into this shape before calling the
    matcher. Fields are intentionally generic so the matcher stays
    agnostic to any single telemetry source.

    Attributes:
        process_name: The executable image name (e.g. ``"powershell.exe"``),
            lower-cased by the caller or normalized here on construction.
        command_line: The full command line used to launch the process,
            if available.
        parent_process_name: The parent process's image name, if
            available.
        file_name: A file name involved in the event (e.g. a dropped or
            accessed file), if applicable.
        network_destination: A network destination (domain or IP)
            involved in the event, if applicable.
        raw: The original, unnormalized event payload, kept for
            auditing/debugging purposes.
    """

    process_name: str | None = None
    command_line: str | None = None
    parent_process_name: str | None = None
    file_name: str | None = None
    network_destination: str | None = None
    raw: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validates that the event carries at least one usable field.

        Raises:
            InvalidTelemetryEventError: If every matchable field is
                empty, making this event unusable for matching.
        """
        if not any(
            (
                self.process_name,
                self.command_line,
                self.parent_process_name,
                self.file_name,
                self.network_destination,
            )
        ):
            raise InvalidTelemetryEventError(
                "Telemetry event has no usable fields (process_name, command_line, "
                "parent_process_name, file_name, network_destination are all empty)"
            )


@dataclass(frozen=True, slots=True)
class MatchResult:
    """A single deterministic match between a telemetry event and ATT&CK.

    Attributes:
        technique_attack_id: The matched ATT&CK technique ID.
        rule_name: Name of the rule that produced this match.
        confidence: A fixed, rule-defined confidence score in ``(0, 1]``.
        matched_on: A short human-readable description of what field
            and value triggered the match, for auditability.
    """

    technique_attack_id: str
    rule_name: str
    confidence: float
    matched_on: str


@dataclass(frozen=True, slots=True)
class MatchingRule:
    """A single deterministic rule mapping telemetry to a technique.

    Attributes:
        name: A short, unique, human-readable rule identifier.
        technique_attack_id: The ATT&CK technique ID this rule maps to.
        predicate: A callable that inspects a :class:`TelemetryEvent`
            and returns a human-readable match description if the rule
            fires, or ``None`` if it does not.
        confidence: A fixed confidence score in ``(0, 1]`` assigned to
            matches produced by this rule.
    """

    name: str
    technique_attack_id: str
    predicate: Callable[[TelemetryEvent], str | None]
    confidence: float = 1.0


def _process_equals(*names: str) -> Callable[[TelemetryEvent], str | None]:
    """Builds a predicate matching an exact (case-insensitive) process name.

    Args:
        *names: One or more acceptable process image names.

    Returns:
        A predicate function usable as a :class:`MatchingRule` predicate.
    """
    lowered = {name.lower() for name in names}

    def predicate(event: TelemetryEvent) -> str | None:
        if event.process_name and event.process_name.lower() in lowered:
            return f"process_name == {event.process_name!r}"
        return None

    return predicate


def _command_line_contains(*substrings: str) -> Callable[[TelemetryEvent], str | None]:
    """Builds a predicate matching a substring in the command line.

    Args:
        *substrings: One or more substrings, any of which trigger a match.

    Returns:
        A predicate function usable as a :class:`MatchingRule` predicate.
    """
    lowered = [substring.lower() for substring in substrings]

    def predicate(event: TelemetryEvent) -> str | None:
        if not event.command_line:
            return None
        command_lower = event.command_line.lower()
        for substring in lowered:
            if substring in command_lower:
                return f"command_line contains {substring!r}"
        return None

    return predicate


#: Default, easily-extended rule set covering common living-off-the-land
#: binaries and techniques. Add new :class:`MatchingRule` entries here
#: (or supply an alternate list to :class:`AttackMatcher`) to extend
#: coverage without touching any matching logic.
DEFAULT_RULES: tuple[MatchingRule, ...] = (
    MatchingRule(
        name="powershell_execution",
        technique_attack_id="T1059.001",
        predicate=_process_equals("powershell.exe", "pwsh.exe"),
    ),
    MatchingRule(
        name="wmic_execution",
        technique_attack_id="T1047",
        predicate=_process_equals("wmic.exe"),
    ),
    MatchingRule(
        name="mimikatz_credential_dumping",
        technique_attack_id="T1003",
        predicate=_process_equals("mimikatz.exe"),
    ),
    MatchingRule(
        name="rundll32_proxy_execution",
        technique_attack_id="T1218",
        predicate=_process_equals("rundll32.exe"),
    ),
    MatchingRule(
        name="certutil_ingress_tool_transfer",
        technique_attack_id="T1105",
        predicate=_process_equals("certutil.exe"),
    ),
    MatchingRule(
        name="cmd_execution",
        technique_attack_id="T1059.003",
        predicate=_process_equals("cmd.exe"),
    ),
    MatchingRule(
        name="windows_script_host_execution",
        technique_attack_id="T1059.005",
        predicate=_process_equals("wscript.exe", "cscript.exe"),
    ),
    MatchingRule(
        name="scheduled_task_persistence",
        technique_attack_id="T1053.005",
        predicate=_process_equals("schtasks.exe"),
    ),
    MatchingRule(
        name="registry_modification",
        technique_attack_id="T1112",
        predicate=_process_equals("reg.exe"),
    ),
    MatchingRule(
        name="bitsadmin_ingress_tool_transfer",
        technique_attack_id="T1197",
        predicate=_process_equals("bitsadmin.exe"),
    ),
    MatchingRule(
        name="psexec_lateral_movement",
        technique_attack_id="T1569.002",
        predicate=_process_equals("psexec.exe", "psexesvc.exe"),
    ),
    MatchingRule(
        name="powershell_encoded_command",
        technique_attack_id="T1027",
        predicate=_command_line_contains("-enc", "-encodedcommand"),
    ),
)


class AttackMatcher:
    """Deterministic, rule-based telemetry-to-ATT&CK mapper.

    Attributes:
        rules: The ordered tuple of :class:`MatchingRule` this matcher
            evaluates. All rules are evaluated for every event, so a
            single event may produce multiple matches.
    """

    def __init__(self, rules: tuple[MatchingRule, ...] | None = None) -> None:
        """Initializes the matcher.

        Args:
            rules: Optional custom rule set. Defaults to
                :data:`DEFAULT_RULES` when omitted, which keeps the
                matcher trivially extensible: callers can pass
                ``DEFAULT_RULES + (my_new_rule,)``.
        """
        self.rules: tuple[MatchingRule, ...] = rules if rules is not None else DEFAULT_RULES

    def match(self, event: TelemetryEvent) -> list[MatchResult]:
        """Matches a single telemetry event against every configured rule.

        Args:
            event: A normalized :class:`TelemetryEvent`.

        Returns:
            A list of :class:`MatchResult`, one per rule that fired.
            Empty if no rule matched. Never raises for "no match" —
            that is an expected, valid outcome.

        Raises:
            InvalidTelemetryEventError: If ``event`` is not a valid
                :class:`TelemetryEvent` instance.
        """
        if not isinstance(event, TelemetryEvent):
            raise InvalidTelemetryEventError(f"Expected TelemetryEvent, got {type(event).__name__}")

        matches: list[MatchResult] = []
        for rule in self.rules:
            matched_on = rule.predicate(event)
            if matched_on is not None:
                matches.append(
                    MatchResult(
                        technique_attack_id=rule.technique_attack_id,
                        rule_name=rule.name,
                        confidence=rule.confidence,
                        matched_on=matched_on,
                    )
                )
        if matches:
            logger.debug(
                "Matched telemetry event (process=%s) to %d technique(s): %s",
                event.process_name,
                len(matches),
                [m.technique_attack_id for m in matches],
            )
        return matches

    def match_many(self, events: list[TelemetryEvent]) -> dict[int, list[MatchResult]]:
        """Matches a batch of telemetry events.

        Args:
            events: A list of normalized :class:`TelemetryEvent` items.

        Returns:
            A dict mapping each event's index in ``events`` to its list
            of :class:`MatchResult` (possibly empty).

        Raises:
            InvalidTelemetryEventError: If any event is invalid.
        """
        return {index: self.match(event) for index, event in enumerate(events)}

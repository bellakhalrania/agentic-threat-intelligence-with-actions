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
        # Allow events with raw data even if standard fields are empty
        # (e.g., Wazuh authentication events with rule.groups)
        has_standard_fields = any(
            (
                self.process_name,
                self.command_line,
                self.parent_process_name,
                self.file_name,
                self.network_destination,
            )
        )
        has_raw_data = bool(self.raw)

        if not has_standard_fields and not has_raw_data:
            raise InvalidTelemetryEventError(
                "Telemetry event has no usable fields (process_name, command_line, "
                "parent_process_name, file_name, network_destination are all empty and no raw data)"
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
        # Check command_line first
        if event.command_line:
            command_lower = event.command_line.lower()
            for substring in lowered:
                if substring in command_lower:
                    return f"command_line contains {substring!r}"
        return None

    return predicate


def _rule_groups_contains(*groups: str) -> Callable[[TelemetryEvent], str | None]:
    """Builds a predicate matching Wazuh rule groups in the raw event.

    Args:
        *groups: One or more rule group names, any of which trigger a match.

    Returns:
        A predicate function usable as a :class:`MatchingRule` predicate.
    """
    lowered = {group.lower() for group in groups}

    def predicate(event: TelemetryEvent) -> str | None:
        # Check raw event for rule.groups
        raw_event = event.raw if isinstance(event.raw, dict) else {}
        
        # The AttackMappingAgent passes the normalized event as TelemetryEvent.raw
        # Normalized events have 'rule_groups' at the top level
        rule_groups = raw_event.get("rule_groups")
        
        # If not found, look inside the nested 'raw' original event (if available)
        if not rule_groups:
            rule_groups = raw_event.get("raw", {}).get("rule", {}).get("groups", [])
            
        # Fallback if raw_event is the original wazuh event itself
        if not rule_groups:
            rule_groups = raw_event.get("rule", {}).get("groups", [])

        if isinstance(rule_groups, list):
            for group in rule_groups:
                if group.lower() in lowered:
                    return f"rule_groups contains {group!r}"
        return None

    return predicate


def _signature_contains(*substrings: str) -> Callable[[TelemetryEvent], str | None]:
    """Builds a predicate matching Suricata signature or category fields.

    Args:
        *substrings: One or more substrings to match in signature or category.

    Returns:
        A predicate function usable as a :class:`MatchingRule` predicate.
    """
    lowered = [substring.lower() for substring in substrings]

    def predicate(event: TelemetryEvent) -> str | None:
        raw_event = event.raw if isinstance(event.raw, dict) else {}
        
        # Check signature field (Suricata)
        signature = raw_event.get("signature")
        if signature and isinstance(signature, str):
            signature_lower = signature.lower()
            for substring in lowered:
                if substring in signature_lower:
                    return f"signature contains {substring!r}"
        
        # Check category field (Suricata)
        category = raw_event.get("category")
        if category and isinstance(category, str):
            category_lower = category.lower()
            for substring in lowered:
                if substring in category_lower:
                    return f"category contains {substring!r}"
        
        return None

    return predicate


def _rule_description_contains(*substrings: str) -> Callable[[TelemetryEvent], str | None]:
    """Builds a predicate matching Wazuh rule description field.

    Args:
        *substrings: One or more substrings to match in rule_description.

    Returns:
        A predicate function usable as a :class:`MatchingRule` predicate.
    """
    lowered = [substring.lower() for substring in substrings]

    def predicate(event: TelemetryEvent) -> str | None:
        raw_event = event.raw if isinstance(event.raw, dict) else {}
        
        # Check rule_description field (Wazuh)
        rule_description = raw_event.get("rule_description")
        if rule_description and isinstance(rule_description, str):
            desc_lower = rule_description.lower()
            for substring in lowered:
                if substring in desc_lower:
                    return f"rule_description contains {substring!r}"
        
        return None

    return predicate


def _service_and_event_type_equals(service: str, event_type: str) -> Callable[[TelemetryEvent], str | None]:
    """Builds a predicate matching service and event_type fields.

    Args:
        service: The service name to match (e.g., "ssh").
        event_type: The event type to match (e.g., "authentication_failed").

    Returns:
        A predicate function usable as a :class:`MatchingRule` predicate.
    """
    def predicate(event: TelemetryEvent) -> str | None:
        raw_event = event.raw if isinstance(event.raw, dict) else {}
        
        event_service = raw_event.get("service")
        event_type_val = raw_event.get("event_type")
        
        if event_service == service and event_type_val == event_type:
            return f"service={service!r} and event_type={event_type!r}"
        
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
        predicate=_process_equals("powershell.exe", "pwsh.exe", "powershell"),
    ),
    MatchingRule(
        name="wmic_execution",
        technique_attack_id="T1047",
        predicate=_process_equals("wmic.exe", "wmic"),
    ),
    MatchingRule(
        name="mimikatz_credential_dumping",
        technique_attack_id="T1003",
        predicate=_process_equals("mimikatz.exe", "mimikatz"),
    ),
    MatchingRule(
        name="rundll32_proxy_execution",
        technique_attack_id="T1218",
        predicate=_process_equals("rundll32.exe", "rundll32"),
    ),
    MatchingRule(
        name="certutil_ingress_tool_transfer",
        technique_attack_id="T1105",
        predicate=_process_equals("certutil.exe", "certutil"),
    ),
    MatchingRule(
        name="cmd_execution",
        technique_attack_id="T1059.003",
        predicate=_process_equals("cmd.exe", "cmd"),
    ),
    MatchingRule(
        name="windows_script_host_execution",
        technique_attack_id="T1059.005",
        predicate=_process_equals("wscript.exe", "cscript.exe", "wscript", "cscript"),
    ),
    MatchingRule(
        name="scheduled_task_persistence",
        technique_attack_id="T1053.005",
        predicate=_process_equals("schtasks.exe", "schtasks"),
    ),
    MatchingRule(
        name="registry_modification",
        technique_attack_id="T1112",
        predicate=_process_equals("reg.exe", "reg"),
    ),
    MatchingRule(
        name="bitsadmin_ingress_tool_transfer",
        technique_attack_id="T1197",
        predicate=_process_equals("bitsadmin.exe", "bitsadmin"),
    ),
    MatchingRule(
        name="psexec_lateral_movement",
        technique_attack_id="T1569.002",
        predicate=_process_equals("psexec.exe", "psexesvc.exe", "psexec"),
    ),
    MatchingRule(
        name="powershell_encoded_command",
        technique_attack_id="T1027",
        predicate=_command_line_contains("-enc", "-encodedcommand"),
    ),
    MatchingRule(
        name="malicious_file_execution",
        technique_attack_id="T1204.002",
        predicate=_command_line_contains("malicious", "invoice.exe", "malware", "virus", "trojan"),
    ),
    MatchingRule(
        name="ingress_tool_transfer",
        technique_attack_id="T1105",
        predicate=_command_line_contains("download", "downloaded", "curl", "wget", "certutil -urlcache", "bitsadmin"),
    ),
    MatchingRule(
        name="ssh_brute_force",
        technique_attack_id="T1110",
        predicate=_rule_groups_contains("ssh", "brute_force"),
    ),
    # Rule-groups-based rules for events that carry Wazuh/EDR rule group context
    MatchingRule(
        name="scheduled_task_persistence_by_groups",
        technique_attack_id="T1053.005",
        predicate=_rule_groups_contains("scheduled_task"),
    ),
    # Suricata C2 beacon detection rules
    MatchingRule(
        name="c2_beacon_suricata",
        technique_attack_id="T1071.001",
        predicate=_signature_contains("c2", "beacon", "command and control"),
        confidence=0.9,
    ),
    # Wazuh scheduled task detection by rule description
    MatchingRule(
        name="scheduled_task_wazuh_description",
        technique_attack_id="T1053.005",
        predicate=_rule_description_contains("scheduled task", "task created", "task scheduler"),
        confidence=0.85,
    ),
    # SSH authentication failure (Brute Force)
    MatchingRule(
        name="ssh_authentication_failed",
        technique_attack_id="T1110",
        predicate=_service_and_event_type_equals("ssh", "authentication_failed"),
        confidence=0.7,
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

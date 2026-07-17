"""Domain models for the MITRE ATT&CK knowledge layer.

This module contains only plain, fully-typed dataclasses. It has no
knowledge of SQL, STIX, or search — it exists purely to give the rest
of the package a shared vocabulary for ATT&CK objects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ObjectType(str, Enum):
    """Enumerates the ATT&CK object kinds tracked by this layer."""

    TECHNIQUE = "technique"
    TACTIC = "tactic"
    SOFTWARE = "software"
    GROUP = "group"
    MITIGATION = "mitigation"


@dataclass(frozen=True, slots=True)
class Technique:
    """A single ATT&CK technique or sub-technique.

    Attributes:
        attack_id: The ATT&CK technique ID (e.g. ``"T1059.001"``).
        stix_id: The STIX 2.1 object ID this technique was parsed from.
        name: Human-readable technique name.
        description: Full technique description.
        is_subtechnique: Whether this technique is a sub-technique.
        parent_attack_id: The parent technique's ATT&CK ID, if this is
            a sub-technique; otherwise ``None``.
        detection: Detection guidance text, if available.
        url: Canonical MITRE ATT&CK URL for this technique.
        platforms: Platforms this technique applies to (e.g. ``"Windows"``).
        tactics: ATT&CK IDs of tactics this technique belongs to.
    """

    attack_id: str
    stix_id: str
    name: str
    description: str | None = None
    is_subtechnique: bool = False
    parent_attack_id: str | None = None
    detection: str | None = None
    url: str | None = None
    platforms: tuple[str, ...] = field(default_factory=tuple)
    tactics: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class Tactic:
    """A single ATT&CK tactic (a column in the ATT&CK matrix).

    Attributes:
        attack_id: The ATT&CK tactic ID (e.g. ``"TA0002"``).
        stix_id: The STIX 2.1 object ID this tactic was parsed from.
        name: Human-readable tactic name (e.g. ``"Execution"``).
        description: Full tactic description.
        shortname: The kebab-case shortname used to link techniques to
            tactics (e.g. ``"execution"``).
    """

    attack_id: str
    stix_id: str
    name: str
    description: str | None = None
    shortname: str = ""


@dataclass(frozen=True, slots=True)
class Software:
    """A piece of ATT&CK software (malware or tool).

    Attributes:
        attack_id: The ATT&CK software ID (e.g. ``"S0002"``).
        stix_id: The STIX 2.1 object ID this software was parsed from.
        name: Human-readable software name.
        description: Full software description.
        software_type: Either ``"malware"`` or ``"tool"``.
    """

    attack_id: str
    stix_id: str
    name: str
    description: str | None = None
    software_type: str = "tool"


@dataclass(frozen=True, slots=True)
class Group:
    """A single ATT&CK intrusion set / threat actor group.

    Attributes:
        attack_id: The ATT&CK group ID (e.g. ``"G0016"``).
        stix_id: The STIX 2.1 object ID this group was parsed from.
        name: Human-readable group name.
        description: Full group description.
        aliases: Known aliases for this group.
    """

    attack_id: str
    stix_id: str
    name: str
    description: str | None = None
    aliases: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class Mitigation:
    """A single ATT&CK mitigation (course of action).

    Attributes:
        attack_id: The ATT&CK mitigation ID (e.g. ``"M1038"``).
        stix_id: The STIX 2.1 object ID this mitigation was parsed from.
        name: Human-readable mitigation name.
        description: Full mitigation description.
    """

    attack_id: str
    stix_id: str
    name: str
    description: str | None = None


@dataclass(frozen=True, slots=True)
class Relationship:
    """A single ATT&CK relationship between two STIX objects.

    Attributes:
        stix_id: The STIX 2.1 object ID this relationship was parsed
            from.
        relationship_type: The STIX relationship type (e.g.
            ``"uses"``, ``"mitigates"``, ``"subtechnique-of"``).
        description: Free-text description of the relationship.
        source_stix_id: STIX ID of the relationship's source object.
        source_attack_id: Resolved ATT&CK ID of the source object, if
            it could be resolved.
        source_type: Resolved :class:`ObjectType` value of the source
            object, if known.
        target_stix_id: STIX ID of the relationship's target object.
        target_attack_id: Resolved ATT&CK ID of the target object, if
            it could be resolved.
        target_type: Resolved :class:`ObjectType` value of the target
            object, if known.
    """

    stix_id: str
    relationship_type: str
    source_stix_id: str
    target_stix_id: str
    description: str | None = None
    source_attack_id: str | None = None
    source_type: str | None = None
    target_attack_id: str | None = None
    target_type: str | None = None


@dataclass(frozen=True, slots=True)
class SearchResult:
    """A single normalized hit returned by the search engine.

    Attributes:
        object_type: The kind of ATT&CK object this result represents.
        attack_id: The ATT&CK ID of the matched object.
        name: The name of the matched object.
        description: The description of the matched object, if any.
        score: A relevance score; higher means a better match. This is
            deterministic (based on match type), never learned.
    """

    object_type: ObjectType
    attack_id: str
    name: str
    description: str | None = None
    score: float = 0.0

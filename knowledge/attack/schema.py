"""SQL DDL for the MITRE ATT&CK knowledge layer.

This module contains ONLY schema definitions. It knows nothing about
STIX parsing, repositories, or search. Its single public entry point,
:func:`create_schema`, creates every table, index, and foreign key
required by the rest of the ``knowledge.attack`` package.
"""

from __future__ import annotations

import logging

from knowledge.base.database import Database
from knowledge.base.exceptions import SchemaError

logger = logging.getLogger(__name__)

_CREATE_TECHNIQUES = """
CREATE TABLE IF NOT EXISTS techniques (
    attack_id           TEXT PRIMARY KEY,
    stix_id             TEXT NOT NULL UNIQUE,
    name                TEXT NOT NULL,
    description         TEXT,
    is_subtechnique     INTEGER NOT NULL DEFAULT 0,
    parent_attack_id    TEXT,
    detection           TEXT,
    url                 TEXT,
    FOREIGN KEY (parent_attack_id) REFERENCES techniques (attack_id)
        ON DELETE SET NULL
);
"""

_CREATE_TACTICS = """
CREATE TABLE IF NOT EXISTS tactics (
    attack_id       TEXT PRIMARY KEY,
    stix_id         TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    description     TEXT,
    shortname       TEXT NOT NULL
);
"""

_CREATE_SOFTWARE = """
CREATE TABLE IF NOT EXISTS software (
    attack_id       TEXT PRIMARY KEY,
    stix_id         TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    description     TEXT,
    software_type   TEXT NOT NULL CHECK (software_type IN ('malware', 'tool'))
);
"""

_CREATE_GROUPS = """
CREATE TABLE IF NOT EXISTS groups (
    attack_id       TEXT PRIMARY KEY,
    stix_id         TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    description     TEXT,
    aliases         TEXT
);
"""

_CREATE_MITIGATIONS = """
CREATE TABLE IF NOT EXISTS mitigations (
    attack_id       TEXT PRIMARY KEY,
    stix_id         TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    description     TEXT
);
"""

_CREATE_RELATIONSHIPS = """
CREATE TABLE IF NOT EXISTS relationships (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    stix_id             TEXT NOT NULL UNIQUE,
    relationship_type   TEXT NOT NULL,
    description         TEXT,
    source_stix_id      TEXT NOT NULL,
    source_attack_id    TEXT,
    source_type         TEXT,
    target_stix_id      TEXT NOT NULL,
    target_attack_id    TEXT,
    target_type         TEXT
);
"""

_CREATE_TECHNIQUE_PLATFORMS = """
CREATE TABLE IF NOT EXISTS technique_platforms (
    technique_attack_id TEXT NOT NULL,
    platform            TEXT NOT NULL,
    PRIMARY KEY (technique_attack_id, platform),
    FOREIGN KEY (technique_attack_id) REFERENCES techniques (attack_id)
        ON DELETE CASCADE
);
"""

_CREATE_TECHNIQUE_TACTICS = """
CREATE TABLE IF NOT EXISTS technique_tactics (
    technique_attack_id TEXT NOT NULL,
    tactic_attack_id    TEXT NOT NULL,
    PRIMARY KEY (technique_attack_id, tactic_attack_id),
    FOREIGN KEY (technique_attack_id) REFERENCES techniques (attack_id)
        ON DELETE CASCADE,
    FOREIGN KEY (tactic_attack_id) REFERENCES tactics (attack_id)
        ON DELETE CASCADE
);
"""

_CREATE_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_techniques_name ON techniques (name);
CREATE INDEX IF NOT EXISTS idx_techniques_parent ON techniques (parent_attack_id);
CREATE INDEX IF NOT EXISTS idx_tactics_name ON tactics (name);
CREATE INDEX IF NOT EXISTS idx_software_name ON software (name);
CREATE INDEX IF NOT EXISTS idx_groups_name ON groups (name);
CREATE INDEX IF NOT EXISTS idx_mitigations_name ON mitigations (name);
CREATE INDEX IF NOT EXISTS idx_relationships_source ON relationships (source_attack_id, relationship_type);
CREATE INDEX IF NOT EXISTS idx_relationships_target ON relationships (target_attack_id, relationship_type);
CREATE INDEX IF NOT EXISTS idx_relationships_type ON relationships (relationship_type);
CREATE INDEX IF NOT EXISTS idx_technique_platforms_platform ON technique_platforms (platform);
CREATE INDEX IF NOT EXISTS idx_technique_tactics_tactic ON technique_tactics (tactic_attack_id);
"""

_ALL_STATEMENTS: tuple[str, ...] = (
    _CREATE_TECHNIQUES,
    _CREATE_TACTICS,
    _CREATE_SOFTWARE,
    _CREATE_GROUPS,
    _CREATE_MITIGATIONS,
    _CREATE_RELATIONSHIPS,
    _CREATE_TECHNIQUE_PLATFORMS,
    _CREATE_TECHNIQUE_TACTICS,
    _CREATE_INDEXES,
)


def create_schema(database: Database) -> None:
    """Creates every ATT&CK table, index, and foreign key if not present.

    This is the only public function in this module. It is idempotent:
    running it against an already-initialized database is a no-op.

    Args:
        database: An open :class:`~knowledge.base.database.Database`
            instance to create the schema in.

    Raises:
        SchemaError: If any DDL statement fails to execute.
    """
    # Note: sqlite3's executescript() implicitly commits any open
    # transaction before running and is not itself transactional across
    # multiple calls, so DDL is applied directly via the connection
    # rather than through Database.transaction().
    try:
        connection = database.connection
        for statement in _ALL_STATEMENTS:
            connection.executescript(statement)
        logger.info("ATT&CK schema created (or already present) at %s", database.path)
    except Exception as exc:
        raise SchemaError(f"Failed to create ATT&CK schema: {exc}") from exc

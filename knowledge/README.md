# MITRE ATT&CK Knowledge Layer

A deterministic, dependency-free MITRE ATT&CK knowledge layer for an agentic
threat-intelligence platform. Contains **no LLM logic, no LangGraph logic, and
no RAG** — every operation is deterministic SQL, deterministic rules, or plain
Python.

## Requirements

- Python 3.12
- Standard library only (`sqlite3`, `json`, `dataclasses`, `unittest`, ...)

## Layout

```
knowledge/
├── base/
│   ├── database.py      # Generic, domain-agnostic SQLite manager
│   └── exceptions.py    # Full exception hierarchy
└── attack/
    ├── config.py         # Paths, limits, logger name
    ├── schema.py         # SQL DDL only
    ├── models.py         # Typed dataclasses (Technique, Tactic, ...)
    ├── repository.py     # Repository pattern (all SQL access)
    ├── loader.py          # STIX 2.1 -> repository ETL, runnable standalone
    ├── search.py          # Keyword / attribute search built on the repository
    ├── matcher.py         # Deterministic, rule-based telemetry -> ATT&CK mapper
    ├── service.py          # Facade: the ONLY module other code should import
    ├── data/
    │   └── enterprise-attack.json  # <- put the official MITRE dataset here
    └── tests/              # unittest suite (29 tests, stdlib only)
```

## Getting the dataset

This repo does not vendor the ATT&CK dataset. Download the official STIX 2.1
Enterprise bundle from MITRE's `cti` GitHub repository and place it at
`knowledge/attack/data/enterprise-attack.json`:

```
https://github.com/mitre/cti/blob/master/enterprise-attack/enterprise-attack.json
```

## Loading the dataset

```bash
cd /path/to/project/root   # the directory that CONTAINS knowledge/
python -m knowledge.attack.loader
```

This creates/updates `knowledge/attack/data/attack.db`, parsing techniques,
sub-techniques, tactics, software, groups, mitigations, and every
relationship between them, while skipping revoked and deprecated STIX objects.

## Using it from the rest of the platform

Only `knowledge.attack.service.AttackService` should be imported by anything
outside this package (agents, APIs, etc.):

```python
from knowledge.attack.config import AttackConfig
from knowledge.attack.service import AttackService
from knowledge.attack.matcher import TelemetryEvent

service = AttackService.create(AttackConfig())

technique = service.get_technique("T1059.001")
groups = service.get_groups("T1059.001")
software = service.get_software("T1059.001")
mitigations = service.get_mitigations("T1059.001")
results = service.search("credential dumping")

matches = service.match_event(TelemetryEvent(process_name="mimikatz.exe"))
# -> [MatchResult(technique_attack_id='T1003', rule_name='mimikatz_credential_dumping', ...)]

service.close()
```

## Running the tests

```bash
cd /path/to/project/root
python -m unittest discover -s knowledge/attack/tests -p "test_*.py" -v
```

All 29 tests run against in-memory SQLite databases and the standard library
only — no network access or external dataset required.

## Design notes / where each rule lives

- **Repository never parses JSON.** `repository.py` only issues SQL and
  converts rows to dataclasses.
- **Loader never executes SQL.** `loader.py` only calls `AttackRepository`
  methods (`insert_technique`, `insert_relationship`, ...).
- **Search never parses telemetry.** `search.py` only calls repository
  query methods.
- **Matcher never executes SQL.** `matcher.py` is pure Python rule
  evaluation over a `TelemetryEvent`; it has no repository dependency at
  all, by design, so it can be unit tested and reused with zero I/O.
- **Service never knows how SQLite works.** `service.py` only calls
  `repository`, `search_engine`, and `matcher` methods.
- **Extending the matcher:** add a `MatchingRule(name=..., technique_attack_id=...,
  predicate=...)` to `DEFAULT_RULES` in `matcher.py`, or pass a custom
  `rules=(...)` tuple into `AttackMatcher()` — no other code changes needed.

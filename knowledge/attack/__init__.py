"""MITRE ATT&CK deterministic knowledge layer.

This package stores, queries, and enriches MITRE ATT&CK Enterprise
knowledge (techniques, tactics, software, groups, mitigations, and the
relationships between them) in a local SQLite database. It contains no
LLM logic, no LangGraph logic, and no RAG — every operation here is
deterministic.

The public entry point for consumers outside this package is
:class:`knowledge.attack.service.AttackService`.
"""

from knowledge.attack.service import AttackService

__all__ = ["AttackService"]

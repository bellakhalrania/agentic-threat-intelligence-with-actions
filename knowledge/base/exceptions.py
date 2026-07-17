"""Exception hierarchy for the Knowledge Layer.

This module defines every exception class used across the knowledge
layer. It contains no logic beyond exception definitions and exists to
give callers a single, consistent hierarchy they can catch at whatever
level of granularity they need (e.g. catch ``RepositoryError`` broadly,
or ``RecordNotFoundError`` specifically).
"""

from __future__ import annotations


class KnowledgeLayerError(Exception):
    """Base exception for all knowledge layer errors."""


class DatabaseError(KnowledgeLayerError):
    """Raised when a low-level database operation fails."""


class SchemaError(KnowledgeLayerError):
    """Raised when schema creation or validation fails."""


class RepositoryError(KnowledgeLayerError):
    """Base exception for repository-level errors."""


class RecordNotFoundError(RepositoryError):
    """Raised when a requested record does not exist."""


class DuplicateRecordError(RepositoryError):
    """Raised when attempting to insert a record that already exists."""


class LoaderError(KnowledgeLayerError):
    """Base exception for dataset loading errors."""


class DatasetNotFoundError(LoaderError):
    """Raised when the source dataset file cannot be located."""


class StixParsingError(LoaderError):
    """Raised when a STIX object cannot be parsed."""


class SearchError(KnowledgeLayerError):
    """Raised when a search operation fails."""


class MatcherError(KnowledgeLayerError):
    """Base exception for telemetry matching errors."""


class InvalidTelemetryEventError(MatcherError):
    """Raised when a telemetry event is malformed or unusable."""


class ServiceError(KnowledgeLayerError):
    """Raised when the facade service encounters an unrecoverable error."""

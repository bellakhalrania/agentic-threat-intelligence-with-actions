"""Generic SQLite database manager.

This module provides a thin, reusable wrapper around :mod:`sqlite3`
that has no knowledge of any particular domain (e.g. MITRE ATT&CK). It
exposes connection management, transactions, and common query
primitives so that higher layers (repositories) never touch a raw
``sqlite3`` connection directly.
"""

from __future__ import annotations

import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Sequence

from knowledge.base.exceptions import DatabaseError

logger = logging.getLogger(__name__)


class Database:
    """A generic, domain-agnostic SQLite database manager.

    The class manages a single SQLite connection configured with
    Write-Ahead Logging (WAL) and foreign key enforcement enabled. It
    provides context-manager based transactions and a small set of
    query helpers (``execute``, ``executemany``, ``fetchone``,
    ``fetchall``, ``fetch_scalar``) plus maintenance operations
    (``optimize``, ``vacuum``, ``integrity_check``, ``backup``).

    Attributes:
        path: Filesystem path to the SQLite database file.
    """

    def __init__(self, path: str | Path, *, timeout: float = 30.0) -> None:
        """Initializes the database manager.

        Args:
            path: Path to the SQLite database file. Parent directories
                are created automatically if they do not exist.
            timeout: Number of seconds to wait for a locked database
                before raising an error.
        """
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._timeout = timeout
        self._connection: sqlite3.Connection | None = None

    @property
    def connection(self) -> sqlite3.Connection:
        """Returns the active connection, opening it if necessary.

        Returns:
            The active :class:`sqlite3.Connection`.
        """
        if self._connection is None:
            self.connect()
        assert self._connection is not None
        return self._connection

    def connect(self) -> None:
        """Opens the SQLite connection and configures pragmas.

        Raises:
            DatabaseError: If the connection cannot be established.
        """
        if self._connection is not None:
            return
        try:
            connection = sqlite3.connect(
                str(self.path),
                timeout=self._timeout,
                isolation_level=None,  # autocommit; transactions are explicit
                check_same_thread=False,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA journal_mode = WAL;")
            connection.execute("PRAGMA foreign_keys = ON;")
            connection.execute("PRAGMA synchronous = NORMAL;")
            self._connection = connection
            logger.debug("Opened SQLite connection at %s", self.path)
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to connect to database at {self.path}: {exc}") from exc

    def close(self) -> None:
        """Closes the active connection, if any.

        Raises:
            DatabaseError: If closing the connection fails.
        """
        if self._connection is not None:
            try:
                self._connection.close()
                logger.debug("Closed SQLite connection at %s", self.path)
            except sqlite3.Error as exc:
                raise DatabaseError(f"Failed to close database at {self.path}: {exc}") from exc
            finally:
                self._connection = None

    def __enter__(self) -> "Database":
        """Enters the context manager, opening the connection.

        Returns:
            This :class:`Database` instance.
        """
        self.connect()
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        """Exits the context manager, closing the connection."""
        self.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Provides a transactional scope around a series of operations.

        On success the transaction is committed. On any exception it is
        rolled back and the exception is re-raised, wrapped in a
        :class:`DatabaseError` unless it already is one.

        Yields:
            The active :class:`sqlite3.Connection`.

        Raises:
            DatabaseError: If the transaction fails and is rolled back.
        """
        connection = self.connection
        try:
            connection.execute("BEGIN;")
            yield connection
            connection.execute("COMMIT;")
        except Exception as exc:
            connection.execute("ROLLBACK;")
            logger.error("Transaction rolled back: %s", exc)
            if isinstance(exc, DatabaseError):
                raise
            raise DatabaseError(f"Transaction failed: {exc}") from exc

    def execute(self, query: str, parameters: Sequence[Any] | dict[str, Any] = ()) -> sqlite3.Cursor:
        """Executes a single SQL statement.

        Args:
            query: SQL statement to execute.
            parameters: Positional or named parameters for the statement.

        Returns:
            The resulting :class:`sqlite3.Cursor`.

        Raises:
            DatabaseError: If execution fails.
        """
        try:
            return self.connection.execute(query, parameters)
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to execute query: {query!r}: {exc}") from exc

    def executemany(self, query: str, parameters: Sequence[Sequence[Any]]) -> sqlite3.Cursor:
        """Executes a SQL statement against a sequence of parameter sets.

        Args:
            query: SQL statement to execute.
            parameters: Sequence of parameter tuples/lists.

        Returns:
            The resulting :class:`sqlite3.Cursor`.

        Raises:
            DatabaseError: If execution fails.
        """
        try:
            return self.connection.executemany(query, parameters)
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to executemany query: {query!r}: {exc}") from exc

    def fetchone(self, query: str, parameters: Sequence[Any] | dict[str, Any] = ()) -> sqlite3.Row | None:
        """Executes a query and fetches a single row.

        Args:
            query: SQL query to execute.
            parameters: Positional or named parameters for the query.

        Returns:
            The first matching row, or ``None`` if no rows match.

        Raises:
            DatabaseError: If execution fails.
        """
        cursor = self.execute(query, parameters)
        return cursor.fetchone()

    def fetchall(self, query: str, parameters: Sequence[Any] | dict[str, Any] = ()) -> list[sqlite3.Row]:
        """Executes a query and fetches all matching rows.

        Args:
            query: SQL query to execute.
            parameters: Positional or named parameters for the query.

        Returns:
            A list of all matching rows.

        Raises:
            DatabaseError: If execution fails.
        """
        cursor = self.execute(query, parameters)
        return cursor.fetchall()

    def fetch_scalar(self, query: str, parameters: Sequence[Any] | dict[str, Any] = ()) -> Any:
        """Executes a query and returns the first column of the first row.

        Args:
            query: SQL query to execute.
            parameters: Positional or named parameters for the query.

        Returns:
            The scalar value, or ``None`` if no rows match.

        Raises:
            DatabaseError: If execution fails.
        """
        row = self.fetchone(query, parameters)
        if row is None:
            return None
        return row[0]

    def optimize(self) -> None:
        """Runs ``PRAGMA optimize`` to refresh query planner statistics.

        Raises:
            DatabaseError: If the operation fails.
        """
        try:
            self.connection.execute("PRAGMA optimize;")
            logger.debug("Ran PRAGMA optimize on %s", self.path)
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to optimize database: {exc}") from exc

    def vacuum(self) -> None:
        """Runs ``VACUUM`` to rebuild the database file and reclaim space.

        Raises:
            DatabaseError: If the operation fails.
        """
        try:
            self.connection.execute("VACUUM;")
            logger.debug("Vacuumed database at %s", self.path)
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to vacuum database: {exc}") from exc

    def integrity_check(self) -> bool:
        """Runs ``PRAGMA integrity_check`` against the database.

        Returns:
            ``True`` if the database reports ``ok``, ``False`` otherwise.

        Raises:
            DatabaseError: If the check cannot be executed.
        """
        try:
            result = self.fetch_scalar("PRAGMA integrity_check;")
            return str(result).lower() == "ok"
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to run integrity_check: {exc}") from exc

    def backup(self, destination: str | Path) -> None:
        """Creates a hot backup of the database to ``destination``.

        Args:
            destination: Filesystem path for the backup file. Parent
                directories are created if necessary.

        Raises:
            DatabaseError: If the backup fails.
        """
        destination_path = Path(destination)
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with sqlite3.connect(str(destination_path)) as backup_connection:
                self.connection.backup(backup_connection)
            logger.info("Backed up database %s to %s", self.path, destination_path)
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to back up database to {destination_path}: {exc}") from exc

"""Fernet secrets at rest (Phase 1, task 1.4).

``SECRETS_ENCRYPTION_KEY`` holds a comma-separated key list: the FIRST key
encrypts, ALL keys decrypt (rotation: prepend the new key, re-encrypt,
drop the old). Encrypted values carry the ``enc:v1:`` prefix so encryption
is idempotent and legacy plaintext stays readable until migrated.

Key resolution reads Django-style app settings on every call (no caching),
so tests can swap keys with ``monkeypatch`` and rotation takes effect
without a restart.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from sqlalchemy.types import TypeDecorator, String

PREFIX = "enc:v1:"

#: Table columns protected at rest: (table, column) pairs.
ENCRYPTED_COLUMNS: tuple[tuple[str, str], ...] = (
    ("alert_integrations", "secret"),
    ("alert_integrations", "jira_api_token"),
)

#: Values that are never valid secrets keys (fail fast with a clear message).
PLACEHOLDER_KEYS = frozenset({
    "", "change-me", "changeme", "secret", "password", "test", "test-key",
    "example", "placeholder",
})

_GENERATION_HINT = (
    'python -c "from cryptography.fernet import Fernet; '
    'print(Fernet.generate_key().decode())"'
)


class DecryptFailedError(ValueError):
    """A stored secret cannot be decrypted (wrong key or corrupt value).

    Never carries secret material: only key counts and row identifiers.
    """


def parse_keys(raw: str | None) -> list[str]:
    """Split a comma-separated key list, dropping blanks."""
    if not raw:
        return []
    return [part.strip() for part in raw.split(",") if part.strip()]


def _settings_key_list() -> list[str]:
    from app.core.config import settings
    return parse_keys(settings.secrets_encryption_key)


def _validated_key_list(keys: list[str] | None) -> list[str]:
    """Resolve + validate the key list (raises ``ValueError`` if unusable)."""
    resolved = list(keys) if keys is not None else _settings_key_list()
    if not resolved:
        raise ValueError(
            "SECRETS_ENCRYPTION_KEY is missing. Generate one with "
            f"{_GENERATION_HINT}"
        )
    for key in resolved:
        if key in PLACEHOLDER_KEYS:
            raise ValueError(
                "SECRETS_ENCRYPTION_KEY looks like a placeholder; generate a "
                f"real key with {_GENERATION_HINT}"
            )
        try:
            Fernet(key.encode("utf-8"))
        except (ValueError, TypeError) as exc:
            raise ValueError(
                "SECRETS_ENCRYPTION_KEY holds an invalid Fernet key; generate "
                f"a real one with {_GENERATION_HINT}"
            ) from exc
    return resolved


def make_fernet(keys: list[str] | None = None) -> MultiFernet:
    """Build a rotation-aware Fernet; first key encrypts, all decrypt.

    Raises ``ValueError`` when the list is empty, holds a placeholder, or
    holds anything that is not a valid Fernet key.
    """
    return MultiFernet(
        [Fernet(key.encode("utf-8")) for key in _validated_key_list(keys)]
    )


def is_encrypted(value: str | None) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def encrypt_value(value: str | None, keys: list[str] | None = None) -> str | None:
    """Encrypt; ``None`` and already-encrypted values pass through."""
    if value is None or is_encrypted(value):
        return value
    return PREFIX + make_fernet(keys).encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_value(stored: str | None, keys: list[str] | None = None) -> str | None:
    """Decrypt; ``None`` and legacy plaintext pass through.

    Raises :class:`DecryptFailedError` without secret material on failure.
    """
    if stored is None or not is_encrypted(stored):
        return stored
    try:
        return make_fernet(keys).decrypt(stored[len(PREFIX):].encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError) as exc:
        raise DecryptFailedError(
            "Stored secret cannot be decrypted with the configured "
            "SECRETS_ENCRYPTION_KEY."
        ) from exc


class EncryptedText(TypeDecorator):
    """Transparent column encryption (prefix-tagged, idempotent)."""

    impl = String
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return encrypt_value(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return decrypt_value(value)


def _rows_needing(conn, table: str, column: str, encrypted: bool):
    """Rows needing (en)cryption. Table/column come from the allowlist below."""
    from sqlalchemy import text

    if encrypted:
        filt = f"{column} IS NOT NULL AND {column} LIKE :prefix"
    else:
        filt = f"{column} IS NOT NULL AND {column} NOT LIKE :prefix"
    return conn.execute(
        text(f"SELECT id, {column} FROM {table} WHERE {filt}"),
        {"prefix": f"{PREFIX}%"},
    ).fetchall()


def _pending_counts(conn, encrypted: bool) -> dict[str, int]:
    """Row counts needing (en)cryption per column, without changing data."""
    return {
        f"{table}.{column}": len(_rows_needing(conn, table, column, encrypted))
        for table, column in ENCRYPTED_COLUMNS
    }


def _rewrite_rows(conn, encrypt: bool, keys: list[str] | None) -> dict[str, int]:
    counts: dict[str, int] = {}
    from sqlalchemy import text

    for table, column in ENCRYPTED_COLUMNS:
        done = 0
        for row_id, value in _rows_needing(conn, table, column, encrypted=encrypt):
            new_value = encrypt_value(value, keys) if encrypt else decrypt_value(value, keys)
            conn.execute(
                text(f"UPDATE {table} SET {column} = :value WHERE id = :id"),
                {"value": new_value, "id": row_id},
            )
            done += 1
        counts[f"{table}.{column}"] = done
    return counts


def encrypt_existing_rows(conn, keys: list[str] | None = None) -> dict[str, int]:
    """Encrypt plaintext rows in place; prefixed rows skipped.

    The key is only required when rows actually need encryption. The caller
    owns the transaction (Alembic and the script both commit/rollback).
    """
    if all(count == 0 for count in _pending_counts(conn, encrypted=False).values()):
        return {f"{t}.{c}": 0 for t, c in ENCRYPTED_COLUMNS}
    make_fernet(keys)  # fail fast before any write
    return _rewrite_rows(conn, encrypt=True, keys=keys)


def decrypt_existing_rows(conn, keys: list[str] | None = None) -> dict[str, int]:
    """Downgrade helper: decrypt prefixed rows back to plaintext.

    Fails loudly on the first undecryptable row (caller rolls back, so
    nothing is partially rewritten).
    """
    if all(count == 0 for count in _pending_counts(conn, encrypted=True).values()):
        return {f"{t}.{c}": 0 for t, c in ENCRYPTED_COLUMNS}
    make_fernet(keys)  # fail fast before any write
    return _rewrite_rows(conn, encrypt=False, keys=keys)


def rotate_existing_rows(conn, keys: list[str] | None = None) -> dict[str, int]:
    """Re-encrypt every prefixed row under the first key.

    Decrypts with the full list (so old-key rows work), then encrypts with
    the first key only. Any undecryptable value aborts the whole run.
    """
    fernet = make_fernet(keys)
    first = Fernet(_validated_key_list(keys)[0].encode("utf-8"))
    from sqlalchemy import text

    counts: dict[str, int] = {}
    for table, column in ENCRYPTED_COLUMNS:
        rows = conn.execute(text(
            f"SELECT id, {column} FROM {table} "
            f"WHERE {column} IS NOT NULL AND {column} LIKE :prefix"
        ), {"prefix": f"{PREFIX}%"}).fetchall()
        done = 0
        for row_id, value in rows:
            try:
                plain = fernet.decrypt(value[len(PREFIX):].encode("ascii")).decode("utf-8")
            except (InvalidToken, ValueError) as exc:
                raise DecryptFailedError(
                    f"Cannot rotate {table}.{column} id {row_id}: undecryptable "
                    "with the configured SECRETS_ENCRYPTION_KEY."
                ) from exc
            conn.execute(
                text(f"UPDATE {table} SET {column} = :value WHERE id = :id"),
                {"value": PREFIX + first.encrypt(plain.encode("utf-8")).decode("ascii"),
                 "id": row_id},
            )
            done += 1
        counts[f"{table}.{column}"] = done
    return counts

"""Make the test database a UTF-8 database on any PostgreSQL cluster.

The test database is created by Django with ``CREATE DATABASE ... TEMPLATE
<name>``, so it inherits the template's encoding. A cluster whose ``template1``
is ``SQL_ASCII`` — which is the default for a cluster created with a non-UTF-8
locale, and is the case for the local cluster this project runs against —
therefore hands every test run a database that cannot store the Intruder `§`
marker, a non-ASCII target name, or any other evidence the tool exists to
capture. The failure that follows is a ``DataError`` inside whichever test
happened to save such a value, and it names the server encoding rather than the
missing template.

So the template is created here, from the repository, on demand. The alternative
— documenting the one-time ``CREATE DATABASE`` and letting every new cluster
fall over it — is what produced a green test run that only worked on one
machine, which is worse than a loud failure: the number was real, the
environment was not reproducible.

What this module does is deliberately boring and deliberately visible:

* the template name comes from ``settings.POSTGRES_TEST_TEMPLATE``, so an
  operator can point it at a template their cluster already maintains;
* an existing template is never dropped, never re-encoded, and never modified;
* an existing template whose encoding is not UTF-8 is reported with the exact
  statement that fixes it, because silently re-encoding a shared template is
  not this code's decision to make;
* a missing template is created from ``template0`` with an explicit UTF-8
  encoding, and a concurrent creator losing the race is a success, not a
  failure.
"""

from __future__ import annotations

import logging
import re

import psycopg
from django.core.exceptions import ImproperlyConfigured
from psycopg import sql

logger = logging.getLogger(__name__)

#: Databases a ``CREATE DATABASE`` statement can be issued from. ``template0`` is
#: deliberately absent: PostgreSQL refuses to connect to it. ``template1`` is the
#: last resort for a cluster that has no ``postgres`` maintenance database.
MAINTENANCE_DATABASES = ("postgres",)

#: A database name that is safe to interpolate into DDL. ``psycopg.sql.Identifier``
#: already quotes the name, so this is a readability guard, not a security one:
#: a template name that is not a plain identifier is a configuration error and
#: reading it as one is more useful than quoting it.
PLAIN_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_$-]{0,62}$")

#: ``True`` once this process has verified the template, so a test run with many
#: aliases does not repeat the same catalogue query per alias.
_verified: set[str] = set()


def _as_text(value) -> str:
    """Read one catalogue value as text whatever the driver handed back.

    ``pg_encoding_to_char`` returns PostgreSQL's internal ``name`` type, which
    psycopg may surface as ``bytes`` depending on how the value was decoded.
    Comparing ``b'UTF8'`` with ``'UTF8'`` is a silent wrong answer, so the
    comparison is made on text.
    """
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def template_encoding(template: str, *, connection_kwargs: dict) -> str | None:
    """Return the encoding of ``template`` or ``None`` when it does not exist."""
    with _maintenance_connection(connection_kwargs) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_encoding_to_char(encoding) FROM pg_database "
                "WHERE datname = %s",
                [template],
            )
            row = cursor.fetchone()
    return None if row is None else _as_text(row[0]).upper()


def _maintenance_connection(connection_kwargs: dict) -> psycopg.Connection:
    """Return an autocommit connection to a database that can create databases.

    ``template1`` is the fallback because a cluster may not carry a ``postgres``
    database at all; both are guaranteed to exist on any healthy cluster. The
    caller closes the connection — the return value is not a context manager
    helper of this module's own.
    """
    candidates = list(MAINTENANCE_DATABASES) + ["template1"]
    last_error: Exception | None = None
    for name in candidates:
        try:
            connection = psycopg.connect(**{**connection_kwargs, "dbname": name})
        except psycopg.OperationalError as error:
            last_error = error
            continue
        try:
            # A CREATE DATABASE cannot run inside a transaction block, and
            # psycopg opens one implicitly on the first statement.
            connection.autocommit = True
        except Exception:  # pragma: no cover - psycopg always allows this
            connection.close()
            raise
        return connection
    raise ImproperlyConfigured(
        "cannot reach a PostgreSQL maintenance database to prepare the test "
        f"template (tried {', '.join(candidates)}): {last_error}"
    )


def create_template(template: str, *, connection_kwargs: dict) -> None:
    """Create ``template`` from ``template0`` with an explicit UTF-8 encoding.

    ``ALTER DATABASE ... ENCODING`` does not exist in PostgreSQL, so the
    template is created rather than converted.
    """
    if not PLAIN_IDENTIFIER.match(template):
        raise ImproperlyConfigured(
            f"POSTGRES_TEST_TEMPLATE ({template!r}) is not a plain database name"
        )
    connection = _maintenance_connection(connection_kwargs)
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                sql.SQL(
                    "CREATE DATABASE {name} TEMPLATE template0 "
                    "ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C'"
                ).format(name=sql.Identifier(template))
            )
    except psycopg.errors.DuplicateDatabase:
        # Another process created it between the check and the statement.
        logger.info("test template %s was created concurrently", template)
    except psycopg.errors.InsufficientPrivilege as error:
        connection.close()
        raise ImproperlyConfigured(
            f"the PostgreSQL test template {template!r} does not exist and the "
            f"role {connection_kwargs.get('user') or ''!r} may not create "
            "databases. Ask for CREATEDB once, or run this as an "
            f"administrator: CREATE DATABASE {template} TEMPLATE template0 "
            "ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C'"
        ) from error
    else:
        logger.warning(
            "created PostgreSQL test template %s (UTF8, LC_COLLATE C) for this "
            "cluster; set POSTGRES_TEST_TEMPLATE to reuse an existing template",
            template,
        )
    finally:
        connection.close()


def ensure_test_template(
    template: str,
    *,
    connection_kwargs: dict,
    allow_create: bool = True,
) -> str:
    """Guarantee that ``template`` exists and is UTF-8, and return its encoding.

    Raises ``ImproperlyConfigured`` with the statement that fixes the cluster
    when the template exists in the wrong encoding, or cannot be created
    because the role lacks ``CREATEDB``. A test run that cannot store a `§`
    marker should say so here, where the cause is legible, instead of inside an
    unrelated test.
    """
    if template in _verified:
        return "UTF8"
    encoding = template_encoding(template, connection_kwargs=connection_kwargs)
    if encoding is None:
        if not allow_create:
            raise ImproperlyConfigured(
                f"the PostgreSQL test template {template!r} does not exist on "
                "this cluster. Create it once, as a role with CREATEDB: "
                f"CREATE DATABASE {template} TEMPLATE template0 "
                "ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C'"
            )
        create_template(template, connection_kwargs=connection_kwargs)
        encoding = template_encoding(template, connection_kwargs=connection_kwargs)
    normalized = (encoding or "").upper().replace("-", "")
    if normalized not in {"UTF8"}:
        raise ImproperlyConfigured(
            f"the PostgreSQL test template {template!r} has encoding {encoding}, "
            "so a test database built from it cannot store the Intruder `§` "
            "marker. Point POSTGRES_TEST_TEMPLATE at a UTF-8 template, or "
            "create one as a role with CREATEDB: "
            f"CREATE DATABASE {template}_utf8 TEMPLATE template0 "
            "ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C'"
        )
    _verified.add(template)
    return "UTF8"


def connection_kwargs_from_settings(databases: dict) -> dict:
    """Build ``psycopg.connect`` keywords from a Django database config.

    The database name is deliberately absent: this connects to a maintenance
    database chosen by the caller, not to the database the process is
    configured for.
    """
    default = databases.get("default", {})
    kwargs = {
        "host": default.get("HOST") or "",
        "port": str(default.get("PORT") or 5432),
        "user": default.get("USER") or "",
    }
    password = default.get("PASSWORD") or ""
    if password:
        kwargs["password"] = password
    return kwargs

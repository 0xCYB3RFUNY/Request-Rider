"""Make an engine payload storable in a PostgreSQL JSONField.

Why this exists
---------------

The engine reports what a remote host actually served. A JavaScript bundle is
frequently not text: a minifier emits raw bytes, a server answers `text/html`
with a compressed or already-binary body, and a page can embed a NUL inside a
string literal. The crawler reads those bytes, extracts findings out of them
(`enrich` pattern values, `js` variable names, secret values) and publishes the
findings as JSON.

That JSON is valid and the browser renders it fine. PostgreSQL is the layer that
refuses: `text` and `jsonb` cannot hold `U+0000` at all, and psycopg raises
`DataError: unsupported Unicode escape sequence \\u0000 cannot be converted to
text` rather than truncating. Measured on the live cluster before this module
existed: a payload carrying `U+0000` in any string fails the write, while the
same payload carrying `U+FFFD` (the replacement character the JSON encoder emits
for an invalid byte) is stored without complaint.

The consequence was a whole endpoint, not one record. `GET /api/target-map`
writes the polled snapshot into `TargetJob.result` on **every** poll, so a single
page whose body held one NUL byte turned every subsequent poll of that crawl into
HTTP 500, and the operator watched a finished map stop rendering.

What this does, and what it deliberately does not do
---------------------------------------------------

A NUL byte is not evidence an operator can read, and PostgreSQL cannot store it
in any form, so the byte is rendered as its own escape text ``\\u0000``. The
finding survives as a string the operator can see and copy; nothing is silently
dropped, and no other value is touched. This is a storage-format adaptation, not
censoring: every other byte of the finding, including the credential, is written
exactly as the engine reported it.

``U+0000`` is the only character PostgreSQL rejects here. Measured: `U+FFFD`,
`U+0001`-`U+001F` and every other control character are accepted, so replacing
them would alter evidence for no reason. Lone surrogates are a different matter —
they have no UTF-8 encoding at all, so psycopg cannot send them either; they are
replaced the same way, and that case is covered by a test.

The recursion covers dict keys as well as values, because a JSON object key is
stored in the same `jsonb` text as a value and fails identically.
"""

from __future__ import annotations

NUL_ESCAPE = "\\u0000"

# PostgreSQL's `text` cannot hold U+0000. A lone surrogate cannot be encoded to
# UTF-8 at all, so psycopg cannot send it either — the same failure to store, one
# step earlier. Both are replaced with the escape text the operator reads.
_UNSTORABLE = str.maketrans({"\x00": NUL_ESCAPE, "\ud800": NUL_ESCAPE, "\udfff": NUL_ESCAPE})


def _clean_str(value: str) -> str:
    return value.translate(_UNSTORABLE)


def pg_storable(value):
    """Return `value` with every string PostgreSQL cannot store made readable.

    The structure is returned unchanged: dicts stay dicts, lists stay lists, and
    numbers, booleans and ``None`` are returned as they came in. Only strings are
    rewritten, and only where the database would otherwise refuse the write.

    Non-string keys and non-string dict keys are handled rather than assumed: a
    JSON document read back from the engine has string keys, but the payload also
    travels through ``json.dumps``/``json.loads`` round trips before it reaches
    here, and an int key survives that round trip as an int.
    """
    if isinstance(value, str):
        return _clean_str(value)
    if isinstance(value, dict):
        return {
            (_clean_str(key) if isinstance(key, str) else key): pg_storable(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [pg_storable(item) for item in value]
    return value
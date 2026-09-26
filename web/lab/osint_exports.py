"""File delivery for an OSINT transform that produced more rows than a graph can show.

A large zone is normal evidence, not an error: a single apex can yield hundreds
of thousands of certified names. Writing every one of them as a graph row costs
seconds per thousand on the way in and makes the canvas unusable on the way out,
so a large result is written to a file **in full** and the graph keeps one
entity that points at it.

Nothing is discarded. The file holds every row the transform produced, and the
analyst opens or downloads it. The row count that switches delivery is a
presentation choice, not a limit on what is collected.
"""
import csv
import io
import json
import re
from pathlib import Path

from django.conf import settings

from .osint_graph import OsintGraphError, _redact_text

# FILE_ENTITY_ROWS is the row count above which a result is delivered as a file
# instead of one graph row per finding. It changes only how the rows are handed
# over: below it they are graph entities, above it they are a complete file
# plus a single pointer entity.
FILE_ENTITY_ROWS = 2000

# FILE_NAME_PATTERN is the only file name shape this module will read back. A
# name that does not match is refused outright, so a request can never address
# anything outside the graph export directory.
FILE_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,80}$")

EXPORT_COLUMNS = ("type", "identity", "relation", "source", "target", "provenance")


def export_root():
    """Return the root directory that holds every graph export.

    An unset setting must not collapse to the current working directory: a
    `Path` object is always truthy, so `Path("") or default` would silently
    resolve to `.` and write the exports wherever the server happens to run. The
    setting is therefore checked as a string before it becomes a path.
    """
    configured = str(getattr(settings, "OSINT_EXPORT_DIR", "") or "").strip()
    if configured:
        return Path(configured)
    return Path(settings.BASE_DIR).parent / "data" / "osint-exports"


def export_directory(graph_id):
    """Return the export directory of one graph.

    The graph id is an integer from the database, so it cannot carry a path
    separator; the name is still built from the id alone rather than from
    anything the request supplied.
    """
    return export_root() / f"graph-{int(graph_id)}"


def needs_file_delivery(payload):
    """Report whether a transform result is too large for graph rows."""
    if not isinstance(payload, dict):
        return False
    entities = payload.get("entities")
    if not isinstance(entities, list):
        return False
    # The transform's own domain row is small and stays a graph entity, so it
    # does not count towards the switch.
    return len([item for item in entities if isinstance(item, dict) and item.get("type") != "domain"]) > FILE_ENTITY_ROWS


def _entity_rows(payload):
    for item in payload.get("entities") or []:
        if not isinstance(item, dict):
            continue
        provenance = item.get("provenance")
        yield {
            "type": str(item.get("type") or ""),
            "identity": str(item.get("identity") or ""),
            "relation": "",
            "source": "",
            "target": "",
            "provenance": json.dumps(provenance, sort_keys=True) if isinstance(provenance, dict) else "",
        }
    for item in payload.get("relations") or []:
        if not isinstance(item, dict):
            continue
        provenance = item.get("provenance")
        yield {
            "type": "",
            "identity": "",
            "relation": str(item.get("type") or ""),
            "source": str(item.get("source") or ""),
            "target": str(item.get("target") or ""),
            "provenance": json.dumps(provenance, sort_keys=True) if isinstance(provenance, dict) else "",
        }


def _safe_file_stem(transform, value):
    """Build a file stem from server-known strings only.

    The transform name and the target are attacker-influenced, so every
    character outside a conservative set collapses to a dash and the result is
    truncated. The name is a convenience, never an identity.
    """
    cleaned = []
    for character in f"{transform}-{value}".lower():
        cleaned.append(character if character.isalnum() else "-")
    stem = re.sub(r"-{2,}", "-", "".join(cleaned)).strip("-")
    return (stem or "osint")[:60]


def write_result_files(graph, payload, transform, value):
    """Write a complete CSV and JSONL copy of one transform result.

    Both files hold every row, so the analyst can open the CSV to read it and
    feed the JSONL to their own tooling without losing anything.
    """
    rows = list(_entity_rows(payload))
    directory = export_directory(graph.id)
    directory.mkdir(parents=True, exist_ok=True)
    stem = _safe_file_stem(transform, value)

    csv_path = directory / f"{stem}.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(EXPORT_COLUMNS))
        writer.writeheader()
        for row in rows:
            writer.writerow({column: _redact_text(str(row.get(column) or "")) for column in EXPORT_COLUMNS})

    jsonl_path = directory / f"{stem}.jsonl"
    with jsonl_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")

    return {
        "csv": csv_path.name,
        "jsonl": jsonl_path.name,
        "rows": len(rows),
        "bytes": csv_path.stat().st_size + jsonl_path.stat().st_size,
    }


def file_entity(graph, transform, value, files, row_count, origin=None):
    """Build the single graph entity that points at a written result file.

    The identity is an absolute same-origin URL, because the graph rules only
    store a URL identity as an absolute HTTP(S) address and the browser opens
    it directly. The origin comes from the request that triggered the write, so
    the identity is the address the analyst actually uses. A relative path would
    be rejected by the identity rules and never stored at all.
    """
    identity = f"{origin or 'http://localhost'}/api/osint/graphs/{graph.id}/files/{files['csv']}"
    return {
        "type": "url",
        "identity": identity,
        "properties": {
            "kind": "osint_result_file",
            "transform": transform,
            "value": value,
            "rows": row_count,
            "csv": files["csv"],
            "jsonl": files["jsonl"],
            "open_url": f"/api/osint/graphs/{graph.id}/files/{files['csv']}",
            "download_url": f"/api/osint/graphs/{graph.id}/files/{files['csv']}?download=1",
        },
        "provenance": {"source": "transform_file_delivery"},
    }


def resolve_export_path(graph_id, name, download=False):
    """Resolve one export file name to a path inside the graph export directory.

    The name is matched against a strict pattern and the resolved path is
    verified to sit inside the graph directory, so neither a crafted name nor a
    symlink can address a file the graph does not own.
    """
    clean = str(name or "").strip()
    if not FILE_NAME_PATTERN.match(clean) or ".." in clean:
        raise OsintGraphError("export file name is invalid")
    directory = export_directory(graph_id).resolve()
    target = (directory / clean).resolve()
    if target.parent != directory:
        raise OsintGraphError("export file name is invalid")
    if not target.is_file():
        raise OsintGraphError("export file was not found")
    return target


def format_inline(rows, columns=EXPORT_COLUMNS):
    """Render a result as a minimal HTML table for opening in a new tab.

    Every value is escaped here: the rows come from a third-party certificate
    index, so they are untrusted text and never markup.
    """
    from django.utils.html import escape

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(columns)
    for row in rows:
        writer.writerow([str(row.get(column) or "") for column in columns])
    body = escape(buffer.getvalue())
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        f"<title>OSINT result ({len(rows)} rows)</title><style>"
        "body{font:13px ui-monospace,SFMono-Regular,Menlo,monospace;margin:0;padding:16px;background:#0b1120;color:#e2e8f0}"
        "h1{font:600 15px system-ui,sans-serif;margin:0 0 4px}"
        "p.meta{font:12px system-ui,sans-serif;color:#94a3b8;margin:0 0 12px}"
        "table{border-collapse:collapse;width:100%}"
        "td{border:1px solid #1e293b;padding:4px 8px;vertical-align:top;word-break:break-all}"
        "</style></head><body><h1>OSINT result file</h1>"
        f"<p class=\"meta\">{len(rows)} rows. Open the CSV or JSONL file for the complete list.</p>"
        f"<pre>{body}</pre></body></html>"
    )

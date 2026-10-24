"""File delivery for an OSINT transform that produced more rows than a graph can show.

A large zone is normal evidence, not an error: a single apex can yield hundreds
of thousands of certified names. Writing every one of them as a graph row costs
seconds per thousand on the way in and makes the canvas unusable on the way out,
so a large result is written to a file **in full** and the graph keeps one
entity that points at it.

Nothing is discarded. The file holds every row the transform produced, and the
analyst reads it through a paginated viewer or downloads it verbatim. The row
count that switches delivery is a presentation choice, not a limit on what is
collected, and the page size of the viewer is a window onto the same complete
file rather than a truncation of it.
"""
import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from django.conf import settings

from .osint_graph import OsintGraphError, _clean_text

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


def _csv_safe(value):
    """Neutralise spreadsheet formula injection in one CSV field.

    `csv.DictWriter` quotes correctly for the CSV grammar, but Excel, LibreOffice
    and Google Sheets evaluate a leading `=`, `+`, `-` or `@` as a formula even
    inside quotes. Every column here comes from an OSINT entity identity or a
    relation target, and those come from certificate-transparency indexes,
    DNS records and HTTP responses — the operator opens this file expecting data,
    not a command run by his spreadsheet on the hostile hostname's behalf.

    A leading apostrophe is the neutral form: the cell reads as text and the value
    stays visible. The check looks past leading whitespace because the attacker
    chooses those bytes too.

    The browser exporters apply the same rule through `csvCellValue` in
    `index.html`; two languages cannot share one implementation, so the two are
    pinned to the same payloads by `test_csv_formula_guard.mjs` and this test.
    """
    text = str(value or "")
    if re.match(r"^[\s]*[=+\-@\t\r]", text):
        return "'" + text
    return text


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
        # `_csv_safe` still runs, and for a reason that has nothing to do with secrets:
        # it neutralises a leading `=`/`+`/`-`/`@` so a found value cannot be
        # executed as a formula when the CSV is opened in a spreadsheet. The
        # credential itself is written whole.
        for row in rows:
            writer.writerow({
                column: _csv_safe(_clean_text(str(row.get(column) or "")))
                for column in EXPORT_COLUMNS
            })

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

    The identity points at the viewer rather than at the raw file on purpose:
    the analyst came to read names, and the viewer is the form of that file
    which is readable. The verbatim bytes stay one query away, so pointing at
    the page loses nothing.
    """
    base = f"/api/osint/graphs/{graph.id}/files"
    identity = f"{origin or 'http://localhost'}{base}/{files['csv']}"
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
            "files_url": base,
            "open_url": f"{base}/{files['csv']}",
            "download_url": f"{base}/{files['csv']}?download=1",
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


# RESULT_PAGE_SIZES are the page sizes the viewer offers. A page is a window
# onto the complete file, so the largest one is a reading size and not a cap:
# every row stays reachable through the other page sizes, the search, the type
# filter, the raw text form and both downloads.
RESULT_PAGE_SIZES = (50, 100, 200, 500, 1000)
RESULT_PAGE_SIZE = 200

# _ROW_CACHE keeps the parsed rows of the files an analyst is paging through.
# The key carries the modification time and the size, so a rewritten file is
# read again instead of being served from a stale parse, and the entry count is
# bounded because one graph owns at most a handful of result files.
_ROW_CACHE = {}
_ROW_CACHE_LIMIT = 4


def _cache_key(path):
    stat = path.stat()
    return (str(path), stat.st_mtime_ns, stat.st_size)


def _parse_csv(path):
    with path.open("r", encoding="utf-8", newline="", errors="replace") as handle:
        reader = csv.DictReader(handle)
        columns = [column for column in (reader.fieldnames or []) if column]
        if not columns:
            columns = list(EXPORT_COLUMNS)
        rows = [
            {column: str(row.get(column) or "") for column in columns}
            for row in reader
        ]
    return columns, rows


def _parse_jsonl(path):
    rows = []
    columns = []
    seen = set()
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                # A truncated final line is reported as a row that carries its
                # own text rather than silently dropping evidence.
                rows.append({"identity": line})
                continue
            if not isinstance(item, dict):
                rows.append({"identity": json.dumps(item, ensure_ascii=False)})
                continue
            row = {str(key): "" if value is None else str(value) for key, value in item.items()}
            for key in row:
                if key not in seen:
                    seen.add(key)
                    columns.append(key)
            rows.append(row)
    if not columns:
        columns = list(EXPORT_COLUMNS)
    return columns, rows


def load_result_rows(path):
    """Read one written result file into columns and rows, with a small cache.

    The cache exists so that paging, searching and sorting a large result do
    not re-read the file on every click. It is keyed on the file's identity and
    modification time, so a file that changed is parsed again.
    """
    key = _cache_key(path)
    cached = _ROW_CACHE.get(key)
    if cached is not None:
        return cached
    if path.suffix.lower() == ".jsonl":
        columns, rows = _parse_jsonl(path)
    else:
        columns, rows = _parse_csv(path)
    while len(_ROW_CACHE) >= _ROW_CACHE_LIMIT:
        # Drop the oldest entry and any earlier parse of the same file, so a
        # rewritten file never leaves a stale row set behind.
        stale = next(iter(_ROW_CACHE))
        _ROW_CACHE.pop(stale, None)
    _ROW_CACHE[key] = (columns, rows)
    for existing in [item for item in _ROW_CACHE if item[0] == key[0] and item != key]:
        _ROW_CACHE.pop(existing, None)
    return columns, rows


def count_data_rows(path):
    """Count the data rows of a written file without parsing every field.

    The listing page needs a size for each file, and a line count answers that
    for a megabyte-scale file in milliseconds where a full parse would not.
    """
    newlines = 0
    tail = b"\n"
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1 << 20)
            if not chunk:
                break
            newlines += chunk.count(b"\n")
            tail = chunk[-1:]
    lines = newlines + (0 if tail == b"\n" else 1)
    # A CSV carries one header line; the JSONL copy is one object per line.
    return max(0, lines - 1) if path.suffix.lower() != ".jsonl" else lines


def list_graph_files(graph_id):
    """Describe every written result file of one graph, newest first."""
    directory = export_directory(graph_id)
    if not directory.is_dir():
        return []
    described = []
    for path in sorted(directory.iterdir()):
        if not path.is_file() or path.suffix.lower() not in {".csv", ".jsonl"}:
            continue
        if not FILE_NAME_PATTERN.match(path.name):
            continue
        stat = path.stat()
        # A file time is read on the machine that wrote the file, so it is
        # stamped as UTC rather than left to the viewer's timezone: two analysts
        # comparing the same export must read the same minute. The string is
        # prepared here because `date` would re-localize the value and then the
        # "UTC" suffix on the page would be a lie.
        modified = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
        described.append({
            "name": path.name,
            "kind": path.suffix.lower().lstrip("."),
            "bytes": stat.st_size,
            "rows": count_data_rows(path),
            "modified": modified,
            "modified_text": f"{modified:%Y-%m-%d %H:%M} UTC",
        })
    described.sort(key=lambda item: (item["name"].rsplit(".", 1)[0], item["kind"]))
    return described


def active_columns(columns, rows):
    """Return the columns that carry a value somewhere in the file.

    A subdomain result leaves `relation`, `source` and `target` empty on every
    row. Rendering three dead columns on nineteen thousand rows hides the one
    column the analyst came to read, so an entirely empty column is dropped and
    the page says which ones it hid.
    """
    active = []
    for column in columns:
        if any(str(row.get(column) or "").strip() for row in rows):
            active.append(column)
    return active or list(columns)


def provenance_parts(value):
    """Split a provenance cell into short labels for the viewer.

    The cell is a JSON object written by the transform. It is parsed here so the
    page can show `certificate_transparency` as a chip instead of a wall of
    escaped JSON, and a value that is not an object is shown as it arrived.
    """
    text = str(value or "").strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return [text]
    if not isinstance(parsed, dict):
        return [text]
    parts = []
    for key, item in parsed.items():
        if isinstance(item, (dict, list)):
            item = json.dumps(item, sort_keys=True, ensure_ascii=False)
        label = f"{key}: {item}" if key != "source" else str(item)
        parts.append(str(label))
    return parts or [text]


def row_kind(row):
    """Return the label that describes what one row is.

    A transform writes its entities with a `type` and its relations with a
    `relation` instead, so a relation row has no type at all. Labelling those
    rows by their empty type would print a dash in the filter chips and offer a
    `type=-` link that matches nothing, so they are named for what they are.
    """
    label = str(row.get("type") or "").strip().lower()
    if label:
        return label
    if str(row.get("relation") or "").strip():
        return "link"
    return "—"


def select_rows(columns, rows, query="", kind="", sort="", direction="asc", page=1, page_size=RESULT_PAGE_SIZE):
    """Filter, sort and slice the rows for one page of the viewer.

    The search matches every column at once, because an analyst looking for a
    name should not have to know which column the transform happened to put it
    in. The type counts are computed on the searched rows, so the chips describe
    what a click would actually return rather than the untouched file.
    """
    needle = str(query or "").strip().lower()
    wanted = str(kind or "").strip().lower()

    counts = {}
    matched = []
    for index, row in enumerate(rows):
        if needle and needle not in " ".join(str(row.get(column) or "") for column in columns).lower():
            continue
        matched.append(index)
        label = row_kind(row)
        counts[label] = counts.get(label, 0) + 1
    if wanted:
        matched = [index for index in matched if row_kind(rows[index]) == wanted]

    total = len(matched)
    if sort and sort in columns:
        reverse = str(direction or "asc").lower() == "desc"
        # A row with no value in the sorted column is not ordered by that
        # column, so it goes last in both directions. Sorting an empty string
        # first would open the page on rows that show nothing at all, which
        # reads as a broken table rather than as an ordering. The two groups are
        # sorted apart and then joined, because a single `reverse=True` would
        # flip the emptiness group along with the values.
        filled = [index for index in matched if str(rows[index].get(sort) or "").strip()]
        empty = [index for index in matched if not str(rows[index].get(sort) or "").strip()]
        filled.sort(key=lambda index: str(rows[index].get(sort)).strip().lower(), reverse=reverse)
        matched = filled + empty

    size = max(1, int(page_size or RESULT_PAGE_SIZE))
    pages = max(1, -(-total // size))
    number = max(1, min(int(page or 1), pages))
    start = (number - 1) * size
    window = matched[start:start + size]
    return {
        "rows": [rows[index] for index in window],
        "offset": start,
        # first and last are the numbers the "rows X–Y of Z" line shows. They are
        # computed here because a template cannot chain two filters over a list
        # length, and getting it wrong renders "1–0" on the first page.
        "first": start + 1 if total else 0,
        "last": start + len(window),
        "has_previous": number > 1,
        "has_next": number < pages,
        "previous_page": number - 1 if number > 1 else 1,
        "next_page": number + 1 if number < pages else number,
        "total": total,
        "page": number,
        "pages": pages,
        "page_size": size,
        "counts": sorted(counts.items(), key=lambda item: (-item[1], item[0])),
    }

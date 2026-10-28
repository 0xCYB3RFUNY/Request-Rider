"""Server-side rendering of the Scanner report, and the allow-lists it trusts.

The Scanner report used to be built in the browser: `scannerHtmlReport` in
`index.html` assembled the document out of live scan state and the browser wrote
it to a file. That is the wrong side of the boundary for two reasons, and this
module exists because of both of them rather than because of the first.

**The report is evidence.** A Scanner run carries a template name, a matcher
output and a response excerpt — all of it third-party text that came from a
target and from a corpus of YAML files the operator did not write. Rendering that
in the browser meant the escaping was the browser's job, and every value crossed
into `innerHTML`-adjacent string concatenation on the client.

The escaping is therefore done by the Django template layer, which escapes by
default, and the report template never marks a value `|safe`. That is the whole
mechanism, and it is worth being precise about why it is not this module: escaping
the same value here *and* in the template would double-escape it and render
`&amp;lt;` in the evidence, so exactly one layer owns it. The difference from the
browser version is not the function — it is that the escaping happens before the
document exists rather than in the code that assembles it, so a value that reaches
markup unescaped would have to be a deliberate `|safe` in the template, and there
is none.

**The evidence fields are a closed vocabulary, and it is measurable.** A severity,
a per-file status and a confidence are not free text: each one is drawn from a
set the engine itself defines, and a value outside that set is not a severity the
tool has ever produced. It is either a typo or something injected through a
template name. Both are refused here, loudly, instead of being printed as if the
tool had said them. The three lists below were read out of the code that produces
the values, not out of documentation:

- `SEVERITIES` is the set `scannerHtmlReport` styles as `sev-*` classes
  (`index.html`), plus `unknown`, which the scanner emits for a check with no
  severity and which the report must still be able to say out loud.
- `STATUSES` is every `Template*` constant in
  `engine/pkg/scanner/`, and the list is kept in step with them
  deliberately. A status the report has no word for is not rounded into a
  neighbouring one: `_status_word` returns `None` and the row is refused with
  `status is not one of …`, so an unlisted status drops a file from the report
  instead of misdescribing it. `duplicate` was added when content-addressed
  deduplication landed, `workflow` when orchestrators started producing no record
  of their own, and `flow` / `uncompiled` when the two document shapes the binary
  refuses to compile were named.
- `CONFIDENCE_LEVELS` is the WAF verdict ladder in `engine/main.go`. It is
  deliberately **not** the same shape as the other two: confidence here is a
  graded verdict ("none" when no vendor scored), while a severity is an ordering
  and a status is an outcome.

`confidence_percent` is a different thing entirely and is not run through this
list. It is a vendor score, and it is a number rather than a vocabulary; the WAF
detector writes it beside the ladder, and mixing the two would produce a
validator that rejects its own producer.

Refusal is a report row, not a crash. One malformed finding in a run of thousands
must not cost the analyst the other 999: `validate_findings` returns the accepted
findings plus the rejections, and the report shows both, because a rejected value
is itself evidence that something upstream produced a status nobody defined.
"""

import json
import re
from collections import Counter
from urllib.parse import quote

# SEVERITIES is every severity the report will print, in report order. The order
# is the display order of the chips, and `severity_rank` reads it as an ordering,
# so a list that is alphabetically sorted would sort findings wrongly.
SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")

# STATUSES is every per-file outcome the engine can report. Each one is a
# distinct claim about what happened to one file, so each one is a distinct word
# on the page. See the module docstring for why there are six.
# `workflow` is a `workflows:` orchestrator: the binary runs the subtemplates it
# names and requests the target, but emits no JSONL record of its own because it
# is not a matcher. It is neither `skipped` (its requests were on the wire) nor
# `not_matched` (it fires nothing of its own), and a report that has to name
# every status refuses a word the engine produces rather than rounding it into
# one that says something false. Measured on large template runs: `adminer-workflow.yaml`
# against a local fixture produced 9 HTTP connections and 0 JSONL records.
#
# `flow` is a document with a top-level `flow:` key. The binary compiles no
# runnable template out of it, so nothing in the file was checked: measured on
# v3.11.1, `directory-listing.yaml` alone under `-t` answers `[FTL] Could not run
# scanner: no templates provided for scan` with exit 1 and an empty report. 1 927
# of 14 072 corpus files have this shape. It is distinct from `workflow`, which
# the binary does run.
#
# `uncompiled` is a file the binary could not compile for the same reason as
# `flow` but with a different document shape: a `payloads:` block inside `http:`
# with no `fuzzing:` key beside it, which is the pre-v3 fuzzing spelling. On
# v3.11.1 that file is accepted by `-validate` and then compiles nothing, with or
# without `-dast`. 695 of 14 072 corpus files have it. It is separate from
# `invalid` because `-validate` passes it, and separate from `skipped` because
# no load-time clash stopped it — the batch that names it ran its other files.
STATUSES = (
    "matched",
    "not_matched",
    "no_request",
    "workflow",
    "flow",
    "uncompiled",
    "skipped",
    "invalid",
    "duplicate",
)

# CONFIDENCE_LEVELS is the WAF verdict ladder, ordered from no claim to a strong
# one. `unknown` is absent on purpose: "none" already means "no vendor scored",
# and a second word for it would let the report say two different things about the
# same absence.
CONFIDENCE_LEVELS = ("none", "low", "high")

# SEVERITY_ORDER is the unrecognised value the report substitutes for a severity
# it cannot accept. It is a member of SEVERITIES rather than a new word, so a
# filtered report is still filterable by severity.
UNKNOWN_SEVERITY = "unknown"

# UNKNOWN_STATUS is the same idea for a status. There is no honest default here:
# "the engine said a status I do not define" is a failure of the run, not an
# outcome, so it keeps its own word and never enters the per-status counters.
UNKNOWN_STATUS = "unknown_status"

# UNKNOWN_CONFIDENCE is the same idea for the WAF verdict.
UNKNOWN_CONFIDENCE = "unknown"

# REJECTED_LABEL is how a refused value is shown. It carries the raw value in the
# row so an operator can see what upstream produced, which is the only way to
# diagnose the producer.
REJECTED_LABEL = "rejected"

# _LEVEL_RE is the shape a vocabulary word may take on the way in. The lists
# above are lowercase and joined by underscores; the scanner writes them lowercase and
# hyphenated in some places and uppercase elsewhere, so normalisation has to
# accept "Not Matched", "not-matched" and "NOT_MATCHED" as the same word before
# it can refuse "not matched!".
_LEVEL_RE = re.compile(r"^[a-z0-9]+(?:[_-][a-z0-9]+)*$")

# _MAX_EVIDENCE_CHARS bounds one evidence block in the rendered document. The
# matcher output of a template can be tens of thousands of characters, and a run
# over a whole corpus produces thousands of rows; the report states the
# character count it actually wrote next to the truncated block rather than
# silently cutting a finding's evidence.
_MAX_EVIDENCE_CHARS = 4000


def normalize_severity(value):
    """Return the severity word for any input, or None when it is not one.

    None means "refuse it", and it is deliberately not the same as `unknown`:
    `unknown` is a severity the engine emits on purpose, so a report that showed
    a refusal as `unknown` would claim the tool had an opinion where it had none.
    """
    word = _normalize_token(value)
    if word is None:
        return None
    return word if word in SEVERITIES else None


def normalize_status(value):
    """Return the per-file status word for any input, or None when it is not one."""
    word = _normalize_token(value)
    if word is None:
        return None
    return word if word in STATUSES else None


def normalize_confidence(value):
    """Return the WAF verdict word for any input, or None when it is not one."""
    word = _normalize_token(value)
    if word is None:
        return None
    return word if word in CONFIDENCE_LEVELS else None


def normalize_severity_filter(value):
    """Normalise one requested severity filter, or return None to drop it.

    A filter is a request rather than evidence, so an unknown word here is dropped
    instead of refused: an analyst who types a severity that does not exist wants
    an empty table, and a report that refused to open would be a worse answer.
    """
    word = _normalize_token(value)
    if word is None:
        return None
    return word if word in SEVERITIES else None


def _normalize_token(value):
    """Fold one input to its vocabulary shape, or None when it cannot be one.

    Uppercase, surrounding whitespace and hyphen separators are the only
    differences between the ways these words arrive. Anything else — a space in
    the middle, a trailing character, an empty string, a non-string — cannot be
    folded into a known word, and is refused rather than trimmed until it fits.
    """
    if not isinstance(value, str):
        return None
    word = value.strip().lower().replace("-", "_")
    if not word or not _LEVEL_RE.match(word):
        return None
    return word


def severity_rank(value):
    """Return the display order of a severity, worst first.

    Unknown input sorts last. That is the safe direction for a findings list: a
    value nobody recognises must not appear above a real finding.
    """
    word = _normalize_token(value)
    if word is None or word not in SEVERITIES:
        return len(SEVERITIES)
    return SEVERITIES.index(word)


def validate_findings(findings, severities=None):
    """Split a raw findings list into accepted findings and refusals.

    The accepted finding keeps every key the engine sent, including the ones the
    report does not draw, because a finding is evidence and the report is only one
    view of it. What the report *draws* goes through the allow-lists, and a
    finding whose severity is outside them lands in `rejected` with its raw value
    intact.

    A row that is not a mapping is refused too, for the same reason: there is
    nothing to read a severity from, so there is nothing to trust about it.
    """
    accepted = []
    rejected = []
    wanted = None
    if severities:
        wanted = {normalize_severity_filter(level) for level in severities}
        wanted.discard(None)
    for index, item in enumerate(_as_list(findings)):
        if not isinstance(item, dict):
            rejected.append(_rejection(index, item, "finding is not an object"))
            continue
        level = normalize_severity(item.get("severity"))
        if level is None:
            rejected.append(_rejection(index, item, f"severity is not one of {', '.join(SEVERITIES)}"))
            continue
        if wanted and level not in wanted:
            continue
        accepted.append(_clean_finding(item, level))
    return accepted, rejected


def _clean_finding(item, severity):
    """Return one finding with its vocabulary fields already resolved.

    The two resolved fields are written back under the same keys, so the template
    never calls a normaliser itself: a template that normalises would be a second
    implementation of the rule, and the two would drift.
    """
    cleaned = dict(item)
    cleaned["severity"] = severity
    status = normalize_status(item.get("status"))
    if status is not None:
        cleaned["status"] = status
    return cleaned


def _rejection(index, item, reason):
    """Build the refusal record for one value the allow-lists did not accept."""
    raw = item.get("severity") if isinstance(item, dict) else item
    return {
        "index": index,
        "reason": reason,
        "raw": raw if isinstance(raw, str) else json.dumps(raw, default=str),
        "title": _text(item.get("title")) if isinstance(item, dict) else "",
        "template_id": _text(item.get("template_id")) if isinstance(item, dict) else "",
    }


def validate_templates(templates, statuses=None):
    """Split a raw per-file template list into accepted rows and refusals.

    This is the same rule applied to the other half of a scan report: the engine
    sends one row per file with its own status vocabulary, and a status outside
    `STATUSES` means the run produced something this report cannot describe.
    """
    accepted = []
    rejected = []
    wanted = None
    if statuses:
        wanted = {normalize_status(status) for status in statuses}
        wanted.discard(None)
    for index, item in enumerate(_as_list(templates)):
        if not isinstance(item, dict):
            rejected.append(_rejection(index, item, "template row is not an object"))
            continue
        status = normalize_status(item.get("status"))
        if status is None:
            rejected.append(_rejection(index, item, f"status is not one of {', '.join(STATUSES)}"))
            continue
        if wanted and status not in wanted:
            continue
        row = dict(item)
        row["status"] = status
        severity = normalize_severity(item.get("severity"))
        if severity is not None:
            row["severity"] = severity
        accepted.append(row)
    return accepted, rejected


def validate_filters(severities=None, statuses=None):
    """Drop requested filters that name a word outside the vocabulary.

    Both halves of a filter come back cleaned, and a half that survives is a real
    filter. An entirely empty result means "no filtering", which is the correct
    reading of a request that named nothing the tool knows.
    """
    levels = _clean_filter_list(severities, normalize_severity_filter)
    states = _clean_filter_list(statuses, normalize_status)
    return levels, states


def _clean_filter_list(values, normalizer):
    """Apply one normaliser to a possibly-absent filter list."""
    cleaned = []
    for value in _as_list(values):
        word = normalizer(value)
        if word is not None and word not in cleaned:
            cleaned.append(word)
    return cleaned


def _as_list(value):
    """Return a list for a JSON array, and an empty one for anything else.

    A run result that reached this point as an object instead of an array is a
    shape error, and rendering an empty table is better than raising: the export
    is a report about a run, and the rest of the run is still worth reading.
    """
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _text(value):
    """Return one value as text, with the empty string for nothing.

    A finding value is used to build a counter key, a file name and a table cell,
    and all three want a string. `str()` on a dict is not a value anybody reads,
    so a non-scalar is rendered as its JSON instead of its `repr`.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)


def evidence_text(finding, limit=_MAX_EVIDENCE_CHARS):
    """Return the evidence block of one finding, bounded and with its real size.

    The caller gets the character count that was actually written, because a
    report that silently truncated a matcher output and printed the same report
    as one that did not is a report that misstates its own evidence.
    """
    evidence = finding.get("evidence") if isinstance(finding, dict) else ""
    if isinstance(evidence, list):
        parts = []
        for entry in evidence:
            if isinstance(entry, dict):
                parts.append(_text(entry.get("matcher-data") or entry.get("data") or entry))
            else:
                parts.append(_text(entry))
        text = "\n".join(part for part in parts if part)
    else:
        text = _text(evidence)
    if not text:
        return "", 0, False
    total = len(text)
    truncated = total > limit
    return (text[:limit], total, truncated)


def status_counts(rows):
    """Count per-file rows by status.

    Counted per status rather than as "everything else", because deriving
    `not_matched` from the remainder folds `no_request`, `skipped` and `duplicate`
    into it, and a folder that contains files which never addressed the target
    then reads as a clean sweep.
    """
    counter = Counter(normalize_status(row.get("status")) or UNKNOWN_STATUS for row in rows)
    return {status: counter.get(status, 0) for status in STATUSES}


def severity_counts(rows):
    """Count findings by severity, across the whole vocabulary.

    Every severity in the list is present in the result even at zero, so the
    report's chip row has a fixed shape and a run that found nothing does not
    produce a shorter strip than a run that found a lot.
    """
    counter = Counter(normalize_severity(row.get("severity")) or UNKNOWN_SEVERITY for row in rows)
    return {level: counter.get(level, 0) for level in SEVERITIES}


def highest_severity(rows):
    """Return the worst severity present, or `info` for an empty or all-refused set.

    `info` is the floor rather than `unknown` because a run that found nothing
    has not produced an unknown severity; it has produced no severity, and the
    report says so with the same word it uses for a template that never declared
    one.
    """
    levels = [normalize_severity(row.get("severity")) for row in rows]
    levels = [level for level in levels if level is not None]
    if not levels:
        return "info"
    return min(levels, key=severity_rank)


def build_scanner_report(payload, view="active", severities=None, statuses=None, query=""):
    """Build everything the scanner report template needs from a raw run result.

    The whole contract of the report is decided here and nowhere else, so the
    template stays a layout. In particular the numbers the report shows are the
    numbers counted here: a report whose counters disagree with its own rows is
    the defect this module's allow-lists exist to make impossible.

    `payload` is whatever the browser or the engine sent. Every field is read
    defensively, because this is the one place a report is built from a document
    the server did not produce.
    """
    document = payload if isinstance(payload, dict) else {}
    engine = _text(document.get("engine")) or ("corpus" if view == "corpus" else ("active" if view == "active" else "builtin"))
    levels, states = validate_filters(severities, statuses)

    findings, rejected_findings = validate_findings(document.get("findings"), levels or None)
    templates, rejected_templates = validate_templates(document.get("templates"), states or None)

    if query:
        needle = str(query).strip().lower()
        if needle:
            findings = [row for row in findings if _matches(row, needle)]
            templates = [row for row in templates if _matches(row, needle)]

    findings.sort(key=lambda row: (severity_rank(row.get("severity")), _text(row.get("title"))))

    stats = document.get("stats") if isinstance(document.get("stats"), dict) else {}
    return {
        "view": view,
        "engine": engine,
        "url": _text(document.get("url")),
        "source_ip": _text(document.get("source_ip")),
        "findings": findings,
        "templates": templates,
        "rejected": rejected_findings + rejected_templates,
        "rejected_findings": len(rejected_findings),
        "rejected_templates": len(rejected_templates),
        "findings_total": len(findings),
        "templates_total": len(templates),
        "severity_counts": severity_counts(findings),
        "status_counts": status_counts(templates),
        "highest_severity": highest_severity(findings),
        "stats": stats,
        "stats_rows": _stats_rows(stats),
        "filters": {"severities": levels, "statuses": states},
        "query": str(query or ""),
    }


def _matches(row, needle):
    """Return whether a needle appears anywhere in a row's text."""
    return any(needle in value.lower() for value in _row_texts(row))


def _row_texts(row):
    """Yield every searchable text of one row, including its list fields."""
    for key, value in row.items():
        if isinstance(value, list):
            for entry in value:
                text = _text(entry)
                if text:
                    yield text
            continue
        text = _text(value)
        if text:
            yield text


def _stats_rows(stats):
    """Turn a free-form stats mapping into sorted, printable pairs.

    The engine's `stats` is a map whose keys depend on the run, including keys
    that carry whole arrays (`args`, `stdout`, `stderr` for a scanner
    invocation). Printing an array of every command-line argument as a stats row
    is unreadable, so a non-scalar is summarised by its length rather than
    dumped, and the report never claims to have shown it.
    """
    rows = []
    for key in sorted(stats):
        value = stats[key]
        if isinstance(value, (str, int, float, bool)) or value is None:
            rows.append((_text(key), _text(value) if value is not None else ""))
        elif isinstance(value, (list, tuple, dict)):
            size = len(value)
            noun = "item" if size == 1 else "items"
            rows.append((_text(key), f"[{size} {noun}]"))
        else:
            rows.append((_text(key), _text(value)))
    return rows


def slugify_filename(value):
    """Return a download file name that is safe to put in a Content-Disposition.

    Everything outside `[A-Za-z0-9._-]` becomes a dash. The name is built from
    operator-controlled text (a graph name, a URL fragment), and a quote or a
    newline in a header value is a response-splitting primitive, so the name is
    built from a fixed alphabet rather than by stripping characters that happen
    to be dangerous today.
    """
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", _text(value)).strip("-")
    return cleaned[:80] or "report"


def quoted_filename(name):
    """Return one file name in the form a Content-Disposition header accepts.

    RFC 6266 `filename*` carries a non-ASCII name correctly, and the plain
    `filename` stays ASCII so an older client still shows something.
    """
    return f"attachment; filename=\"{slugify_filename(name)}\"; filename*=UTF-8''{quote(str(name))}"


# EXPORT_REPORT_BRAND is the masthead every exported report carries: the same
# six-sided mark the application header draws, with `aria-hidden` because it
# carries no information the word beside it does not already carry. It is one
# constant for every report rather than a copy per generator, so a brand change
# is one edit.
EXPORT_REPORT_BRAND = (
    '<div class="rr-brand">'
    '<svg class="rr-logo" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" aria-hidden="true" focusable="false">'
    '<path d="M32 8 54 20v24L32 56 10 44V20z" fill="none" stroke="#43d9a3" stroke-width="5"/>'
    '<path d="m22 32 7 7 14-16" fill="none" stroke="#a970ff" stroke-width="5"/></svg>'
    "<span>RequestRider</span></div>"
)

# EXPORT_REPORT_CSS is the stylesheet every server-rendered report shares. The
# token values are the application's own `:root` block, and `EXPORT_REPORT_CSS`
# additionally declares the semantic colours the application still declares by
# hand (`--green`, `--danger`, `--warning`, `--info`), so no rule in a report has
# to name a hex value that is not a token.
EXPORT_REPORT_CSS = """
:root{color-scheme:dark;--bg:#080c12;--panel:#101722;--panel-2:#0d141e;--line:#263548;--text:#dbe7f5;--muted:#8294aa;--accent:#43d9a3;--accent-strong:#62e8b5;--purple:#a970ff;--purple-strong:#c79aff;--orange:#f06b38;--green:#34d399;--danger:#f87171;--warning:#f59e0b;--info:#60a5fa;--button:#182333;--button-hover:#22344b;--radius:7px}
*{box-sizing:border-box}
html{height:100%;background:linear-gradient(180deg,#244b68 0,#162d43 38%,#080c12 78%);background-attachment:scroll}
body{display:flex;flex-direction:column;height:100%;margin:0;padding:10px 14px 12px;color:var(--text);font:13px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
a{color:var(--info)}
.rr-head{flex:none;display:flex;align-items:center;flex-wrap:wrap;gap:8px 12px;padding-bottom:8px;border-bottom:1px solid var(--line)}
.rr-brand{display:inline-flex;align-items:center;gap:7px;font-weight:700;letter-spacing:.02em;flex:none}
.rr-subject{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rr-logo{width:20px;height:20px;flex:none}
.rr-title{padding:2px 9px;border:1px solid var(--line);border-radius:999px;background:#101b29;font-size:11px}
.rr-target{color:var(--muted);font:11px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}
.rr-back{margin-left:auto;display:inline-flex;align-items:center;gap:6px;padding:4px 9px;border:1px solid var(--line);border-radius:6px;background:var(--button);color:var(--text);font-size:11px;text-decoration:none;transition:border-color .15s ease,color .15s ease,background .15s ease}
.rr-back:hover{border-color:var(--purple);color:var(--purple);box-shadow:0 0 14px #a970ff55}
.rr-back:focus-visible{outline:2px solid var(--purple-strong);outline-offset:2px}
/* The counters are one strip rather than a row of tiles: a tile per number
   spends sixty vertical pixels to say something a strip says in twenty-two, and
   those pixels are rows of findings. */
.rr-stats{flex:none;display:flex;flex-wrap:wrap;gap:4px 16px;align-items:baseline;padding:7px 2px 8px}
.rr-stat{color:var(--muted);font-size:11px;white-space:nowrap}
.rr-stat b{margin-right:4px;color:var(--text);font:600 13px/1 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.rr-stat b.ok{color:var(--accent)}
.rr-stat + .rr-stat::before{content:"·";margin-right:12px;color:var(--line)}
main{flex:1 1 0;min-height:0;display:flex;flex-direction:column;gap:7px}
.rr-block{display:flex;flex-direction:column;gap:7px;min-height:0;margin:0}
.rr-block.grow{flex:1 1 0;min-height:0}
.rr-tools{display:flex;flex-wrap:wrap;gap:7px;align-items:center}
.rr-search{display:flex;flex-wrap:wrap;gap:7px;align-items:center;flex:1 1 300px;min-width:0}
.rr-search input[type=search]{flex:1 1 150px;min-width:130px}
.rr-tools input[type=search]{flex:1 1 220px;min-width:160px;min-height:30px;padding:5px 9px;border:1px solid var(--line);border-radius:6px;background:var(--panel-2);color:var(--text);font:12px system-ui,sans-serif}
.rr-tools input[type=search]:focus{outline:none;border-color:var(--purple);box-shadow:0 0 0 1px rgba(169,112,255,.2)}
.rr-tools input[type=search]:focus-visible{outline:2px solid var(--purple-strong);outline-offset:2px}
.rr-btn{display:inline-flex;align-items:center;gap:6px;min-height:30px;padding:4px 10px;border:1px solid var(--line);border-radius:6px;background:var(--button);color:var(--text);font:11px system-ui,sans-serif;text-decoration:none;cursor:pointer;transition:background .15s ease,border-color .15s ease,color .15s ease}
.rr-btn:hover{border-color:var(--purple);color:var(--purple);box-shadow:0 0 14px #a970ff55}
.rr-btn:active{background:var(--button-hover);border-color:var(--accent)}
.rr-btn:focus-visible{outline:2px solid var(--purple-strong);outline-offset:2px}
.rr-btn[aria-pressed=true]{background:#14634e;border-color:var(--accent);color:#f2fffa}
.rr-btn[aria-disabled=true]{opacity:.45;cursor:not-pointer;box-shadow:none}
.rr-btn[aria-disabled=true]:hover{border-color:var(--line);color:var(--text);box-shadow:none}
.rr-page-form{margin:0}
.rr-chips{display:flex;flex-wrap:wrap;gap:5px;align-items:center}
.rr-chip{display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border:1px solid var(--line);border-radius:999px;background:var(--panel-2);color:var(--muted);font-size:11px;text-decoration:none;cursor:pointer;transition:border-color .15s ease,color .15s ease,background .15s ease}
.rr-chip:hover{border-color:var(--purple);color:var(--purple)}
.rr-chip:focus-visible{outline:2px solid var(--purple-strong);outline-offset:2px}
.rr-chip[aria-pressed=true]{background:#14634e;border-color:var(--accent);color:#f2fffa}
.rr-chip b{color:var(--text);font-weight:600}
.rr-chip[aria-pressed=true] b{color:#f2fffa}
/* The word inside a chip is what names the filter. It is kept as text rather
   than a colour swatch for the same reason the severity chip is: a filter the
   analyst cannot name is a filter they will not trust to have run. */
.rr-chip-word{font-size:10px;letter-spacing:.04em;text-transform:uppercase;white-space:nowrap}
.rr-scroll{flex:1 1 0;min-height:0;overflow:auto;border:1px solid var(--line);border-radius:8px;background:var(--panel)}
.rr-table{width:100%;min-width:760px;border-collapse:collapse;table-layout:fixed;font-size:12px}
.rr-table th{position:sticky;top:0;z-index:1;padding:6px 9px;border-bottom:1px solid var(--line);background:#141e2b;color:var(--muted);font-size:10px;letter-spacing:.06em;text-align:left;text-transform:uppercase;white-space:nowrap}
.rr-table th a{display:inline-flex;align-items:center;gap:5px;color:inherit;text-decoration:none}
.rr-table th a:hover{color:var(--text)}
.rr-table th a:focus-visible{outline:2px solid var(--purple-strong);outline-offset:2px}
.rr-table th[aria-sort=ascending] a::after{content:" ↑";color:var(--accent)}
.rr-table th[aria-sort=descending] a::after{content:" ↓";color:var(--accent)}
/* No content-visibility on the rows. Size containment applies to an internal
   table element, so an intrinsic size of 0 x 30px also zeroes the width and the
   row collapses to a few pixels. */
.rr-table td{padding:5px 9px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}
.rr-table tbody tr:hover{background:#172536}
.rr-num{width:1%;color:var(--muted);font:11px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;text-align:right;white-space:nowrap}
.rr-id{font:12px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}
/* A severity chip is the report's only colour-coded cell, and it always carries
   its word as text. Colour alone would fail for a reader who cannot see it, and
   a severity is exactly the field that must never be ambiguous. */
.rr-sev{display:inline-block;padding:1px 7px;border:1px solid var(--line);border-radius:999px;font-size:10px;letter-spacing:.04em;text-transform:uppercase;white-space:nowrap}
.rr-sev-critical{background:rgba(244,63,94,.12);border-color:rgba(244,63,94,.4);color:#fb7185}
.rr-sev-high{background:rgba(240,107,56,.12);border-color:rgba(240,107,56,.4);color:#f6a07a}
.rr-sev-medium{background:rgba(245,158,11,.12);border-color:rgba(245,158,11,.36);color:#fbbf24}
.rr-sev-low{background:rgba(59,130,246,.12);border-color:rgba(59,130,246,.36);color:#60a5fa}
.rr-sev-info,.rr-sev-unknown{background:rgba(130,148,170,.12);border-color:rgba(130,148,170,.34);color:#a9b8ca}
.rr-status{display:inline-block;padding:1px 7px;border:1px solid var(--line);border-radius:999px;background:var(--panel-2);color:var(--muted);font-size:10px;letter-spacing:.04em;text-transform:uppercase;white-space:nowrap}
.rr-status-matched{color:var(--accent);border-color:#2c5c4c}
.rr-status-skipped{color:var(--warning)}
.rr-status-invalid{color:var(--danger);border-color:#5c2c3c}
.rr-status-duplicate{color:var(--purple-strong);border-color:#4a3a72}
.rr-status-no_request{color:var(--muted)}
.rr-status-not_matched{color:var(--muted)}
/* `workflow`, `flow` and `uncompiled` are the three statuses that say something
   about the file rather than about the target. They are styled apart from
   `matched` and from `not_matched` on purpose: a reader scanning the status
   counts must be able to tell "the check ran" from "no check was possible" at a
   glance, and the same three tones as the workspace keeps the exported document
   recognisably the same tool. */
.rr-status-workflow{color:#a9bcd8;border-color:#3d4a66;font-style:italic}
.rr-status-flow{color:#b79ce8;border-color:#4a3a6b;font-style:italic}
.rr-status-uncompiled{color:#8fa2bb;border-color:#3f4a5c;border-style:dashed;font-style:italic}
.rr-rejected{color:var(--danger)}
.rr-empty{padding:26px 12px;color:var(--muted);text-align:center}
.rr-foot{flex:none;display:flex;flex-wrap:wrap;gap:7px;align-items:center}
.rr-foot .rr-status-line{color:var(--muted);font-size:11px;margin-right:auto}
/* The count and the word it counts are separated by margin rather than by a
   space in the markup, because the label tag emits no leading space and a
   literal one collapses in the tag's own whitespace. The rule above
   `.rr-stat` does the same thing for the header strip. */
.rr-foot .rr-status-line b{color:var(--text);font-weight:600;margin-right:4px}
.rr-note{flex:none;margin:0;padding:6px 10px;border:1px solid var(--line);border-left:3px solid var(--accent);border-radius:6px;background:var(--panel-2);color:var(--muted);font-size:11px}
.rr-note.reject{border-left-color:var(--danger)}
.rr-note code{color:var(--text);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.rr-lang{margin-left:auto}
/* The evidence block is the bulky part of a scan report and it is bounded by the
   builder, which states the real size next to the truncated text. `pre-wrap`
   keeps a long matcher line inside the panel, so the evidence is scrolled
   sideways rather than cut off at the right edge. */
.rr-evidence{max-height:320px;margin:0;padding:8px 10px;border:1px solid var(--line);border-radius:6px;background:var(--panel-2);color:var(--text);font:11px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere;overflow:auto}
.rr-sr{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap;border:0}
@media (max-width:820px){
  body{height:auto;min-height:100%;padding:12px 10px}
  .rr-scroll{max-height:70vh}
  .rr-back{margin-left:0}
  .rr-subject-label{display:none}
  .rr-stats{gap:4px 12px}
}
"""

# EXPORT_REPORT_JS is the behaviour a rendered report needs: search, and the
# status and severity filters. It reads the rendered rows through `data-*`
# attributes and never from a JSON blob, so the document holds each value once
# and a hostile template name cannot become a script payload. The tag is assembled
# from parts rather than written literally, because a literal closing `script`
# inside this string would terminate the application page's own inline block.
EXPORT_REPORT_JS = """
(function () {
  var rows = Array.prototype.slice.call(document.querySelectorAll('.rr-row'));
  var search = document.querySelector('input[data-rr-search]');
  var status = document.getElementById('rr-search-status');
  var filters = Array.prototype.slice.call(document.querySelectorAll('[data-rr-filter]'));
  var counts = { shown: 0, total: rows.length };

  function readFilters() {
    var out = { severity: [], status: [] };
    filters.forEach(function (chip) {
      if (chip.getAttribute('aria-pressed') !== 'true') return;
      var value = chip.getAttribute('data-rr-value');
      if (out[value] === undefined) return;
      out[value].push(chip.getAttribute('data-rr-filter'));
    });
    return out;
  }

  function apply() {
    var needle = (search && search.value || '').trim().toLowerCase();
    var active = readFilters();
    var shown = 0;
    rows.forEach(function (row) {
      var haystack = (row.getAttribute('data-rr-search') || '').toLowerCase();
      var okSeverity = !active.severity.length || active.severity.indexOf(row.getAttribute('data-rr-severity')) !== -1;
      var okStatus = !active.status.length || active.status.indexOf(row.getAttribute('data-rr-status')) !== -1;
      var okSearch = !needle || haystack.indexOf(needle) !== -1;
      var visible = okSeverity && okStatus && okSearch;
      row.hidden = !visible;
      if (visible) shown += 1;
    });
    counts.shown = shown;
    if (status) {
      status.textContent = shown === counts.total
        ? String(counts.total)
        : shown + ' / ' + counts.total;
    }
  }

  var searchTimer = null;
  function applyDebounced() {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(apply, 150);
  }

  if (search) {
    search.addEventListener('input', applyDebounced);
    search.addEventListener('search', apply);
  }
  filters.forEach(function (chip) {
    chip.addEventListener('click', function (event) {
      event.preventDefault();
      chip.setAttribute('aria-pressed', chip.getAttribute('aria-pressed') === 'true' ? 'false' : 'true');
      apply();
    });
    chip.addEventListener('keydown', function (event) {
      if (event.key !== 'Enter' && event.key !== ' ') return;
      event.preventDefault();
      chip.click();
    });
  });
  var reset = document.getElementById('rr-reset');
  if (reset) {
    reset.addEventListener('click', function () {
      if (search) search.value = '';
      filters.forEach(function (chip) { chip.setAttribute('aria-pressed', 'false'); });
      apply();
    });
  }
  apply();
})();
"""
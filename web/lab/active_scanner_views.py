"""The gateway for the active scanner.

This lives in its own module rather than inside `views.py` for the reason the
Scanner report module gives for the same choice: `views.py` is shared, and two
sessions writing one file is how a change disappears. The wiring it needs from
`urls.py` is one import and three route lines.

Every rule it follows comes from the Nuclei job path, which is the existing
gateway contract for an asynchronous scan:

- the browser never holds a connection open for the run — it starts a job, polls
  it or subscribes to it, and the job outlives the request that created it;
- the job is bound to the route generation by the engine, not by this module, so
  `Apply route` still cancels a run that is in flight;
- a finished run is written to `ScannerRun` exactly once, and only on the poll
  that observes the terminal state, so a browser that polls every second cannot
  write the same evidence twice.

The one thing it does not reuse is the evidence shape. A Nuclei finding names a
template and a CVE; an active-scanner finding names a surface, the exact payload
that reached it, whether the impact was proven or only suspected, and a curl that
reproduces it. Writing it through the Nuclei ingest would silently drop four of
those five, and "dropped without a trace" is the one thing a findings journal must
not do — so the ingest is written for this shape instead of bent to fit the other.
"""

import json
import socket
import time

from django.http import JsonResponse, StreamingHttpResponse
from django.views.decorators.csrf import csrf_exempt

from lab.models import ActiveScanJob, Project, ScannerRun
from lab.outbound_runtime import OutboundOperationCancelled
from lab.views import (
    ENGINE_URL,
    SSE_MAX_LIFETIME,
    _outbound_runtime,
    _persist_tool_history,
    _route_switch_cancelled,
    call_engine,
    call_engine_get,
    open_engine_stream,
    tool_run_route,
)

# engine_active_jobs is the path segment the engine registers
# (`/proxy/scanner/active/jobs`). It is named here so the two sides of the bridge
# have one visible spelling, and a change to one that is not made in the other is
# a visible diff rather than a silent 404.
ENGINE_ACTIVE_JOBS_PATH = "/proxy/scanner/active/jobs"

# ACTIVE_SCAN_TERMINAL is the set of states a run can no longer leave.
#
# It is read from the engine's own answer rather than derived, and a run that is
# in it is settled exactly once: a report is written if there is one, and the row
# is marked either way so nothing re-reads it forever.
ACTIVE_SCAN_TERMINAL = frozenset({"completed", "cancelled", "failed"})

# _SEVERITY_RANK orders severities for the summary's `highest_severity`. It is the
# same ordering the project already uses for scanner runs, so a project that mixes
# Nuclei and active findings sorts both by one rule.
_SEVERITY_RANK = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


def _remember_active_scan_job(job_id, project, url):
    """Record which Project a run belongs to, durably.

    This used to be a dict in this module's memory, and the reason it cannot be
    one any more is measured: a scan that ran 65 minutes on one target was lost
    when the gateway restarted between the start and the poll, because the link
    that told the journal where to put the finished report went with the process.
    The run itself survived — the engine had never stopped — so the evidence was
    in memory for hours with nowhere to go.

    The write is an update-or-create rather than a plain create because a
    re-attach can legitimately reach this twice for one run: the browser
    re-reads its stored job id on reload, and a second start of the same id has
    to converge on one row instead of raising on the unique job_id.
    """
    job_id = str(job_id or "").strip()
    if not job_id:
        return None
    defaults = {
        "project": project,
        "url": str(url or ""),
        "status": "running",
        "ingested": False,
        "settled": False,
    }
    job, _ = ActiveScanJob.objects.update_or_create(job_id=job_id, defaults=defaults)
    return job


def _active_scan_job(job_id):
    """The durable record for one run, or None when the gateway never saw it start."""
    return ActiveScanJob.objects.filter(job_id=str(job_id or "")).first()


def _settle_active_scan_job(job_id, *, status, ingested):
    """Mark a run as needing no further reading.

    Both outcomes are recorded, not just the written one. A cancelled run has no
    report to store, so its `ingested` flag stays false forever — and if only
    that flag stopped the re-reading, every cancelled run in the table would be
    examined on every sweep for as long as the Project lives.
    """
    return ActiveScanJob.objects.filter(job_id=str(job_id or "")).update(
        status=str(status or "unknown"),
        ingested=bool(ingested),
        settled=True,
    )


def _active_scan_int(payload, key):
    """Read one optional integer bound, refusing a non-number outright.

    A value the engine cannot parse has to fail here rather than be forwarded: the
    engine answers `400 INVALID_TARGET_URL` for an unparseable body, which reads as
    a target problem and sends the operator looking at the wrong thing.
    """
    if key not in payload or payload[key] is None:
        return 0
    value = payload[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{key} must be a number")
    return int(value)


def _active_scan_words(payload, key, limit=200000):
    """Read one operator-supplied wordlist.

    Accepts a newline-separated string or a JSON array, because the thing the
    operator has is text: names out of a bundle, or the contents of a dictionary
    file. Both shapes are accepted so neither is a trap, and an absent key is an
    empty list rather than a refusal — a run without a wordlist is a run that
    spends nothing on those detectors, which the engine's own field documents.

    The `limit` is a transport bound and not a scan bound: it exists so a pasted
    megabyte cannot be turned into a request the engine has to hold in one JSON
    body. It is four times larger than any wordlist in ordinary use, and it is
    named here rather than hidden in the engine so that an operator who hits it is
    told which side of the bridge refused.
    """
    value = payload.get(key)
    if value is None:
        return []
    if isinstance(value, str):
        parts = value.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    elif isinstance(value, (list, tuple)):
        parts = [str(entry) for entry in value]
    else:
        raise ValueError(f"{key} must be text or a list of names")
    words = []
    for part in parts:
        # A wordlist pasted out of a file arrives with its indentation, and a name
        # with a leading space is a name that fires nothing.
        word = part.strip()
        if not word or word.startswith("#"):
            continue
        words.append(word)
        if len(words) > limit:
            raise ValueError(f"{key} holds more than {limit} entries")
    return words


def _active_scan_request(payload):
    """Turn the browser's body into the engine's request shape."""
    request = {
        "url": str(payload["url"]).strip(),
        "max_pages": _active_scan_int(payload, "max_pages"),
        "max_depth": _active_scan_int(payload, "max_depth"),
        "concurrency": _active_scan_int(payload, "concurrency"),
        "delay_ms": _active_scan_int(payload, "delay_ms"),
        # How long a blind technique may hold the target's connection. It is the
        # one field that makes somebody else's database slow, so it travels like
        # the rest of the operator's numbers rather than hiding in a detector's
        # default: a run that asks for eight seconds has to be an eight-second run.
        "blind_delay_ms": _active_scan_int(payload, "blind_delay_ms"),
        "timeout_ms": _active_scan_int(payload, "timeout_ms"),
        # Two operator-supplied wordlists, and neither has a default on the engine
        # side: `HiddenParams` fires parameter names the application's own
        # JavaScript binds, and `HiddenPaths` fires a dictionary. An absent list
        # means the detector runs and reports nothing, which is visible in the
        # report's module count — the arrangement `Redirect` was missing when its
        # marker was dropped on the floor.
        #
        # They travel as newline-separated text rather than as a JSON array because
        # the thing they are is text an operator pastes: a list of names out of a
        # bundle, or a file of paths. `_active_scan_words` accepts both shapes so
        # neither is a trap.
        "params": _active_scan_words(payload, "params"),
        "path_wordlist": _active_scan_words(payload, "path_wordlist"),
    }
    # `same_origin` is a tri-state on purpose: absent means the engine's own
    # default, and sending `None` would be indistinguishable from sending `false`,
    # which turns a crawl off-host. So the key is only present when the browser
    # actually sent the field.
    if "same_origin" in payload and payload["same_origin"] is not None:
        if not isinstance(payload["same_origin"], bool):
            raise ValueError("same_origin must be a boolean")
        request["same_origin"] = payload["same_origin"]
    request["follow_redirects"] = bool(payload.get("follow_redirects", False))
    # The blind delay is the one bound where a negative number cannot mean
    # "unbounded": there is no unbounded wait, and `-1` read as a default would
    # be a run that holds a stranger's connection open for a length nobody chose.
    # `max_depth` legitimately takes -1 for "no limit", which is why this check
    # lives here and not in `_active_scan_int`.
    if request["blind_delay_ms"] < 0:
        raise ValueError("blind_delay_ms must not be negative")
    return request


@csrf_exempt
def scanner_active_job_stream(request, job_id):
    """Proxy the engine's live scan stream without buffering individual lines.

    The bounded read and its keepalive comment are the same ones the passive
    traffic stream and the Nuclei stream use, for the same reason: a scan can go a
    long time between progress reports, and a stream that only wrote bytes on real
    events hit its own read deadline and looked like a transport failure for a job
    that was still running.
    """
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    cursor = request.headers.get("Last-Event-ID") or request.GET.get("last_event_id", "")
    stream_url = f"{ENGINE_URL}{ENGINE_ACTIVE_JOBS_PATH}/{job_id}/stream"
    if cursor:
        stream_url += f"?last_event_id={cursor}"
    # open_engine_stream already turns every connection-level failure into an
    # explicit 502, so nothing here has to be distinguished afterwards.
    response = open_engine_stream(stream_url, {"Last-Event-ID": cursor})
    if isinstance(response, JsonResponse):
        return response

    def stream():
        started = time.monotonic()
        try:
            while time.monotonic() - started < SSE_MAX_LIFETIME:
                try:
                    chunk = response.readline()
                except (TimeoutError, socket.timeout):
                    # The run is quiet between progress reports. Say so with a
                    # comment frame and keep waiting rather than letting the read
                    # deadline close a stream that is still worth listening to.
                    yield b": keepalive\n\n"
                    continue
                if not chunk:
                    break
                yield chunk
        except (OSError, ValueError):
            # The browser went away mid-stream; releasing the socket is the point.
            return
        finally:
            response.close()

    result = StreamingHttpResponse(stream(), content_type="text/event-stream")
    result["Cache-Control"] = "no-cache"
    result["X-Accel-Buffering"] = "no"
    return result


def _active_finding_row(item):
    """One finding, in the shape the journal stores.

    Every field the engine produced is kept, including the ones with no Nuclei
    equivalent: the surface, the payload, the tier and the curl. A tier is the
    difference between "this is proven" and "this is a pattern that looks like
    one", and a journal that dropped it would report both as the same row.
    """
    if not isinstance(item, dict):
        return None
    severity = str(item.get("severity") or "INFO").upper()
    return {
        "id": str(item.get("id", "")),
        "title": str(item.get("title", "")),
        "severity": severity,
        "tier": str(item.get("tier", "")),
        "module": str(item.get("module", "")),
        "endpoint": str(item.get("endpoint", "")),
        "method": str(item.get("method", "")),
        "param": str(item.get("param", "")),
        "payload": str(item.get("payload", "")),
        "evidence": str(item.get("evidence", "")),
        "poc_curl": str(item.get("poc_curl", "")),
        "description": str(item.get("description", "")),
        "recommendation": str(item.get("remediation", "")),
        "capped": bool(item.get("capped", False)),
        "chain_of": [str(value) for value in item.get("chain_of") or []],
        "version": str(item.get("version", "")),
        "version_source": str(item.get("version_source", "")),
        "patch_state": str(item.get("patch_state", "")),
    }


def _ingest_active_scan_run(project, url, report):
    """Write one finished run to the Project's journal.

    The evidence kept is the findings themselves plus the counters that make a run
    readable without opening it: which target, how many surfaces were tested, how
    many were proven, and how many were downgraded because the impact was not
    demonstrated. A run whose counters are all zero is a run that proved nothing,
    and that has to be visible in the summary rather than inferred from silence.
    """
    if not project or not isinstance(report, dict):
        return
    rows = [row for row in (_active_finding_row(item) for item in report.get("findings") or []) if row]
    severities = sorted(
        {row["severity"] for row in rows},
        key=lambda level: _SEVERITY_RANK.get(level, 9),
    )
    stats = report.get("stats") or {}
    ScannerRun.objects.create(
        project=project,
        engine="active",
        url=str(url or report.get("target") or ""),
        summary={
            "findings_count": len(rows),
            "highest_severity": severities[0] if severities else "INFO",
            "stats": {
                "requests": stats.get("requests", 0),
                "points": stats.get("points", 0),
                "modules": stats.get("modules", 0),
                "chains": stats.get("chains", 0),
                "verified": stats.get("verified", 0),
                "potential": stats.get("potential", 0),
                "capped": stats.get("capped", 0),
                "hosts": stats.get("hosts", 0),
                "pages": report.get("pages", 0),
                "workers": report.get("workers", 0),
                "duration": report.get("duration", ""),
            },
            "warnings": [str(value) for value in report.get("warnings") or []],
            "proofs": len(report.get("proofs") or []),
        },
        findings=rows,
    )


def _apply_active_scan_outcome(job_id, state, report):
    """Deal with one finished run, exactly once.

    This is the single place a finished active run becomes a journal row, and
    both callers come through it: the poll that observes the terminal state, and
    the sweep that finds a run nobody polled. Two callers need one implementation
    because the bug this fixes is precisely that a run whose browser went away had
    no second way in.

    The `settled` flag is the exactly-once guard, and it is checked before the
    write rather than trusted from the caller: the browser polls every second, so
    "only write when the state is terminal" is not enough on its own, and a second
    write would replace the first `ScannerRun`'s row with an identical one under
    a new id.
    """
    job = _active_scan_job(job_id)
    if job is None or job.settled:
        return False
    written = False
    project = job.project or Project.objects.filter(id=job.project_id).first()
    if state == "completed" and isinstance(report, dict):
        # A completed run always has a report; a cancelled or failed one carries
        # its partial report too, and that partial report is evidence — a scan
        # that proved four things before the fifth page timed out proved four
        # things. It is written on the same path, not thrown away with the state.
        _ingest_active_scan_run(project, job.url, report)
        written = True
    # Even a failed scan with no report may have made requests before it stopped.
    # Persist those exchanges independently from whether a findings report exists.
    _persist_tool_history(project)
    _settle_active_scan_job(job_id, status=state, ingested=written)
    return written


def sweep_active_scan_jobs(limit=50):
    """Re-read runs that finished while nobody was watching them.

    A run is started by a browser that may then close, and the engine keeps the
    run for `finished_job_retention_minutes` after it ends. Without this, a scan
    that finished into an abandoned tab had exactly one chance to be recorded and
    that chance was the poll that never came.

    Each unsettled row is asked about once per pass. The engine answers from its
    own job table, so a row whose run the engine has already dropped is settled as
    lost by the caller's 404 branch rather than retried indefinitely.
    """
    settled = 0
    jobs = ActiveScanJob.objects.filter(settled=False).order_by("created_at")[:limit]
    for job in jobs:
        status, result = call_engine_get(f"{ENGINE_ACTIVE_JOBS_PATH}/{job.job_id}")
        state = result.get("state") if isinstance(result, dict) else None
        if status == 200 and state in ACTIVE_SCAN_TERMINAL:
            _apply_active_scan_outcome(job.job_id, state, result.get("result"))
            settled += 1
        elif status == 404:
            _settle_active_scan_job(job.job_id, status="lost", ingested=False)
            settled += 1
    return settled


@csrf_exempt
def scanner_active_jobs(request, job_id=None, action=None):
    """Start an asynchronous active scan, or poll / control an existing one.

    `action` is cancel. There is no pause: a scan cannot be frozen between probes
    without holding its sockets and the target's attention, so the engine reports a
    stop as cancelled rather than as a state that looks like it is doing nothing.
    """
    if action:
        if action != "cancel":
            return JsonResponse({"error": f"unknown job action: {action}"}, status=400)
        if request.method not in {"POST", "DELETE"}:
            return JsonResponse({"error": "method not allowed"}, status=405)
        status, result = call_engine(f"{ENGINE_ACTIVE_JOBS_PATH}/{job_id}/cancel", {})
        return JsonResponse(result, status=status)

    if request.method == "GET":
        if not job_id:
            return JsonResponse({"error": "job_id is required"}, status=400)
        status, result = call_engine_get(f"{ENGINE_ACTIVE_JOBS_PATH}/{job_id}")
        # The record outlives every poll and is only settled once its outcome has
        # been dealt with, so a run that the browser stopped watching keeps its
        # Project instead of losing it with the last poll.
        if status == 200 and isinstance(result, dict) and result.get("state") in ACTIVE_SCAN_TERMINAL:
            _apply_active_scan_outcome(job_id, result.get("state"), result.get("result"))
        elif status == 404:
            # The engine no longer has this run. It forgot it — a restart of the
            # engine clears its job table — and nothing can ask it for the report
            # again, so the row is settled as lost rather than left unsettled and
            # re-read on every sweep forever.
            _settle_active_scan_job(job_id, status="lost", ingested=False)
        return JsonResponse(result, status=status)

    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = json.loads(request.body)
        if not isinstance(payload, dict) or not str(payload.get("url", "")).strip():
            raise ValueError("url is required")
        forwarded = _active_scan_request(payload)
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        return JsonResponse({"error": f"invalid active scanner job: {error}"}, status=400)
    project = getattr(request, "active_project", None)
    try:
        with _outbound_runtime().operation("active-scanner", project.id if project else None) as operation:
            status, result = call_engine(
                ENGINE_ACTIVE_JOBS_PATH,
                {
                    **forwarded,
                    # A job outlives the request, so the context is remembered with
                    # it and the run's exchanges are written when it finishes.
                    **tool_run_route(request, "active-scanner", forwarded["url"]),
                },
            )
            operation.raise_if_cancelled()
    except OutboundOperationCancelled:
        return _route_switch_cancelled("Active scanner")
    if status not in (200, 202) or not isinstance(result, dict):
        return JsonResponse(
            result if isinstance(result, dict) else {"error": "job did not start"},
            status=status,
        )
    _remember_active_scan_job(result.get("job_id", ""), project, forwarded["url"])
    return JsonResponse(result, status=status)
"""Request middleware for the validated server-side active Project context.

Two middlewares live here, and the reason for the split is that one protects the
**database view of the workspace** (which project the request belongs to) while the
other protects the **entry point of the control plane** (who is allowed to make this
request at all). They are independent problems and they fail differently.
"""

from .models import Project


ACTIVE_PROJECT_SESSION_KEY = "active_project_id"


class ActiveProjectMiddleware:
    """Attach a validated active Project without trusting request parameters."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        project = None
        raw_project_id = request.session.get(ACTIVE_PROJECT_SESSION_KEY)
        if raw_project_id not in (None, ""):
            try:
                project_id = int(raw_project_id)
            except (TypeError, ValueError):
                project_id = 0
            if project_id > 0:
                project = Project.objects.filter(id=project_id).first()
            if project is None:
                request.session.pop(ACTIVE_PROJECT_SESSION_KEY, None)
                request.session.modified = True
        request.active_project = project
        return self.get_response(request)


# --- Same-origin gate for state-changing requests -----------------------------
#
# WHY THIS EXISTS. The gateway has no login: it is a single-operator tool bound to
# loopback, and the whole UI runs on `http://127.0.0.1:<port>`. That design is fine
# for remote attackers and useless against the one threat that matters here — a web
# page the analyst happens to have open in the same browser.
#
# Every state-changing gateway view is `@csrf_exempt` because the UI's own fetch
# calls historically do not attach `X-CSRFToken`. The exemption is what made the
# tool remotely triggerable: `POST /api/execute` performed an arbitrary outbound
# HTTP request, `POST /api/intruder` started an attack, `POST /api/history/bulk`
# with `{"action":"clear"}` deleted the entire History. Measured, not theoretical:
# a request with no cookie, no CSRF token and `Origin: https://evil.example`
# produced a real outbound request (documented in the security audit).
#
# `SameSite=Lax` does not close this, and it is worth being precise about why: Lax
# withholds the **session cookie** on a cross-site POST, but these endpoints never
# read the session. They take `getattr(request, "active_project", None)` and run
# with `None`. There is nothing for the cookie policy to protect.
#
# WHAT THIS IS NOT. This is not a scope gate, not an allowlist of targets, and not
# a restriction on what the tool may scan. It constrains **who may make this HTTP
# request** — the tool's own address only. An operator pointing RequestRider at
# `192.168.0.0/24` or `169.254.169.254` is unaffected; a third-party web page
# posting to the analyst's localhost is exactly what it stops.
#
# WHY THE MIDDLEWARE AND NOT THE DECORATORS. Removing `@csrf_exempt` from ~39 views
# is the textbook fix, but it also requires every UI call site to send the token,
# which means editing one megabyte of hand-written JavaScript that other work is
# currently in the middle of. A gate at the boundary covers the endpoints that
# exist today *and* the ones added next month, in one auditable place, without
# touching a view.

# NOTE: `TRACE` used to be listed here as a safe method. It is not one, and it
# never needed to be: nothing in this tool issues it, and the gate below is about
# who may *change* state, not about which methods merely echo. `TRACE` is now
# refused outright by `ReflexiveMethodMiddleware` before it can reach a view.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Methods whose entire purpose is to send the request back to the client.
#
# WHY THIS REFUSAL IS NEEDED. Django's URL resolver does not filter by method — it
# resolves a view and calls it. A view written as `def index(request)` with no
# `require_GET` therefore answers **TRACE** with the full page, measured on a live
# stand: `TRACE /` returned `HTTP 200` and a 1 111 411-byte body, byte for byte the
# same as `GET /`. That is the cross-site tracing primitive: an attacker's page
# reads the analyst's own request — cookies and headers included — back out of the
# response body, and Same-Origin Policy does not stop it because the reading happens
# after the bytes have already crossed the network.
#
# The tool has no use for the echo. Selected exchanges are read from History and
# Traffic, and raw request/response pairs are already rendered into the inspector.
# Refusing is therefore not a restriction on what the analyst can do — it removes a
# capability nothing calls.
REFLEXIVE_METHODS = frozenset({"TRACE", "TRACK"})


class ReflexiveMethodMiddleware:
    """Refuse methods that echo the request back, before any view runs.

    Registered ahead of `SameOriginMutationMiddleware` so the refusal does not
    depend on an `Origin` header being present: a bare `curl -X TRACE` carries
    none, and a cross-site form/fetch would be judged by origin rules that answer a
    different question.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if (request.method or "").upper() in REFLEXIVE_METHODS:
            from django.http import JsonResponse

            return JsonResponse(
                {
                    "error": "request-echo methods are refused",
                    "reason": "REFLEXIVE_METHOD_REFUSED",
                    "hint": "read the exchange from History, Traffic or the inspector",
                },
                status=405,
                headers={"Allow": "GET, HEAD, OPTIONS"},
            )
        return self.get_response(request)

# Paths that are called by something other than a browser and therefore must not
# carry this app's `Origin`. `api/oast` is machine-to-machine: the listener calls
# back, so a cross-origin POST there is the product working, not an attack.
#
# `api/workflows/hooks/` used to be exempt as well, on the reasoning that a webhook is
# meant to be reached by a third party. That reasoning conflated two things: **not
# being a browser** is why the gate passes a request that carries no `Origin` at all,
# and a machine-to-machine caller still sends none. Removing the exemption therefore
# costs a server-to-server caller nothing, while stopping a hostile page from
# triggering the analyst's saved workflow graph cross-site — and the graph is
# exactly what makes that worth stopping, because the request body becomes
# `input_data` and `{{input.url}}` lets the caller choose where the saved payload
# goes.
ORIGIN_EXEMPT_PREFIXES = ("/api/oast",)


def _host_only(value: str) -> str:
    """Return `host` or `host:port`, dropping any scheme and path Django added."""
    value = (value or "").strip()
    if "://" in value:
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0]
    return value.lower()


class SameOriginMutationMiddleware:
    """Reject state-changing requests whose `Origin` is not this tool's own.

    A browser always sends `Origin` on a state-changing request, including a
    same-origin one, so a hostile page cannot omit it. A local command-line client
    (`curl`, a script) sends none, and that is allowed on purpose: a process that
    can already open a socket to loopback is not the threat model here, and the
    audit tooling relies on it.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.method not in SAFE_METHODS and not _origin_exempt(request):
            origin = request.META.get("HTTP_ORIGIN", "").strip()
            if origin and not _origin_allowed(origin, request):
                from django.http import JsonResponse

                return JsonResponse(
                    {
                        "error": "cross-origin request refused",
                        "reason": "CROSS_ORIGIN_REFUSED",
                        "hint": "open the workspace UI at the tool's own address",
                    },
                    status=403,
                )
        return self.get_response(request)


def _origin_exempt(request) -> bool:
    path = request.path or ""
    return path.startswith(ORIGIN_EXEMPT_PREFIXES)


def _origin_allowed(origin: str, request) -> bool:
    """Compare the request's `Origin` against the address it was actually sent to.

    Comparing against `request.get_host()` rather than a fixed allowlist means the
    gate follows the port the stack was started on instead of silently passing when
    the port differs from the default.
    """
    return _host_only(origin) == _host_only(request.get_host())
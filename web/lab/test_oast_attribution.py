"""A01-06 (MEDIUM) — an OAST callback could be attributed to any project.

`oast_callback` read `project_id` from the body or the query and resolved it with
`Project.objects.filter(id=…).first()`: whatever project the caller named got the event.
Attribution is the entire purpose of that endpoint, so an event nobody can attribute to
the workspace it came from is exactly the thing it must not be able to manufacture.

Nothing in this repository posts to `/api/oast` — the engine polls the OAST provider
itself and consumes the events — so the free-form `project_id` had no first-party caller to
begin with. These tests pin that a claim is now only honoured when it names the request's
own active project.
"""

import json
from unittest.mock import patch

from django.test import TestCase

from lab.middleware import ACTIVE_PROJECT_SESSION_KEY
from lab.models import Project


class OastAttributionTests(TestCase):
    def setUp(self):
        self.mine = Project.objects.create(name="Analyst workspace", target="https://shop.acme.test")
        self.foreign = Project.objects.create(name="Someone else workspace", target="https://other.test")
        self.addCleanup(Project.objects.filter(id__in=[self.mine.id, self.foreign.id]).delete)
        # Patched at the module the view looks it up in, so the assertion is on what the
        # endpoint actually published rather than on a copy of the logic.
        self.seen = []
        self._emit = patch("lab.views.emit_project_event")
        emitter = self._emit.start()
        emitter.side_effect = lambda project_id, event: self.seen.append((project_id, event))
        self.addCleanup(self._emit.stop)

    def _activate(self, project):
        session = self.client.session
        session[ACTIVE_PROJECT_SESSION_KEY] = project.id
        session.save()

    def _post(self, payload):
        return self.client.post("/api/oast", data=json.dumps(payload), content_type="application/json")

    def test_a_foreign_project_id_is_not_honoured(self) -> None:
        self._activate(self.mine)
        response = self._post({"source": "fixture", "project_id": self.foreign.id})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["project_id"], self.mine.id,
                         "a caller named a project it does not own and was believed")
        self.assertEqual([project_id for project_id, _ in self.seen], [self.mine.id])

    def test_the_own_project_id_is_still_honoured(self) -> None:
        """Not a blanket refusal: the analyst's own workspace keeps working."""
        self._activate(self.mine)
        response = self._post({"source": "fixture", "project_id": self.mine.id})
        self.assertEqual(response.json()["project_id"], self.mine.id)

    def test_no_project_claimed_and_none_active_stays_unattributed(self) -> None:
        """`None` is a correct answer and better than a wrong one."""
        response = self._post({"source": "fixture"})
        self.assertIsNone(response.json()["project_id"])
        self.assertEqual(self.seen[0][0], None)

    def test_a_nonsense_project_id_cannot_crash_or_widen(self) -> None:
        self._activate(self.mine)
        for junk in ("abc", -1, 0, "999999999", None, [], {"a": 1}):
            with self.subTest(junk=junk):
                response = self._post({"source": "fixture", "project_id": junk})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["project_id"], self.mine.id)

    def test_the_query_string_cannot_bypass_it_either(self) -> None:
        self._activate(self.mine)
        response = self.client.get(f"/api/oast?project_id={self.foreign.id}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["project_id"], self.mine.id)

    def test_the_callback_is_still_accepted(self) -> None:
        """The endpoint must keep working; refusing a claim is not refusing the event."""
        response = self._post({"source": "fixture-listener", "event": "dns-lookup"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["received"])
        self.assertEqual(len(self.seen), 1)

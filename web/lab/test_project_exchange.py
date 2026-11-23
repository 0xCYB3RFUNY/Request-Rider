"""The Project keeps its own copy of the evidence, and clearing Traffic does not
touch it.

Two rules meet in this file, and they pull in opposite directions:

- Clearing results deletes them, everywhere a clear exists. `Clear` in the
  Traffic tab empties the live snapshot *and* the durable capture archive, or it
  deletes nothing at all — a `Clear` that leaves the rows to come back through
  `Load more from database` is not a clear.
- What already landed in a Project must not depend on the capture rows. The
  bundle a Project exports is the workspace's own evidence, and it has to still
  be there after the Traffic tab has been cleared.

Satisfying both is why the Project reads `ProjectExchange` and not
`TrafficRecord`. These tests hold the second rule against the first, because
the failure mode is silent: a bundle that quietly comes back one section short is
not something a user notices.
"""

import json
from unittest import mock

from django.test import TestCase

from . import views
from .ingest import ingest_traffic_batch, project_exchange_key
from .models import Project, ProjectExchange, TrafficCaptureContext, TrafficRecord
from .project_transfer import export_bundle


def capture_row(project, event_id, url="http://target.test/wp-admin/", session=0):
    return TrafficRecord(
        project=project,
        source="proxy",
        method="GET",
        url=url,
        host="target.test",
        proxy_session=session,
        proxy_event_id=event_id,
        request_headers={"User-Agent": "RequestRider-Scanner/1.0"},
        response_headers={"Content-Type": "text/html"},
        response_body="<html>fixture</html>",
        response_content_type="text/html",
        status_code=200,
        response_size=21,
        latency_ms=7,
        scope_status="project_linked",
    )


class ProjectOwnsItsEvidenceTests(TestCase):
    def setUp(self):
        self.project = Project.objects.create(name="target project", target="http://target.test")
        self.context = TrafficCaptureContext.objects.create(
            name="Scanner · http://target.test", project=self.project
        )

    def store_and_ingest(self, event_id, **kwargs):
        row = capture_row(self.project, event_id, **kwargs)
        row.capture_context = self.context
        row.save()
        ingest_traffic_batch([row])
        return row

    def test_a_captured_exchange_is_copied_into_the_project(self):
        # The copy is written by the same ingestor that folds endpoints, so a
        # Project cannot end up with a known path and no record of the request
        # that revealed it.
        self.store_and_ingest(11)

        copy = ProjectExchange.objects.get(project=self.project)
        self.assertEqual(copy.method, "GET")
        self.assertEqual(copy.url, "http://target.test/wp-admin/")
        self.assertEqual(copy.status_code, 200)
        self.assertEqual(copy.response_body, "<html>fixture</html>")
        self.assertEqual(copy.response_headers, {"Content-Type": "text/html"})
        self.assertEqual(copy.request_headers, {"User-Agent": "RequestRider-Scanner/1.0"})
        self.assertEqual(copy.capture_context_id, self.context.id)

    def test_repeated_ingest_of_the_same_exchange_writes_one_copy(self):
        # Every Traffic poll re-reads the snapshot, and a nuclei job is polled
        # until the operator moves on. A second copy would be a second claim that
        # the workspace made a request it did not make.
        row = capture_row(self.project, 12)
        row.save()

        ingest_traffic_batch([row])
        ingest_traffic_batch([row])
        ingest_traffic_batch([row])

        self.assertEqual(ProjectExchange.objects.filter(project=self.project).count(), 1)

    def test_two_runs_of_the_same_target_keep_their_own_copies(self):
        # Distinct events are distinct evidence even when the URL is identical,
        # which is exactly what a scan repeats seventeen times.
        self.store_and_ingest(21)
        self.store_and_ingest(22, url="http://target.test/wp-login.php")
        self.store_and_ingest(23, url="http://target.test/.env")

        self.assertEqual(ProjectExchange.objects.filter(project=self.project).count(), 3)
        self.assertEqual(
            sorted(ProjectExchange.objects.values_list("url", flat=True)),
            [
                "http://target.test/.env",
                "http://target.test/wp-admin/",
                "http://target.test/wp-login.php",
            ],
        )

    def test_an_exchange_without_a_project_is_not_copied(self):
        # Ambient browser traffic belongs to the Traffic tab, not to a workspace.
        row = TrafficRecord(source="proxy", method="GET", url="http://elsewhere.test/")
        row.save()

        ingest_traffic_batch([row])

        self.assertEqual(ProjectExchange.objects.count(), 0)

    def test_the_bundle_keeps_the_exchange_after_the_capture_row_is_deleted(self):
        # This is the rule in one test: delete what `Clear` deletes, then export.
        self.store_and_ingest(31)
        self.store_and_ingest(32, url="http://target.test/.env")

        TrafficRecord.objects.filter(project=self.project).delete()
        self.assertEqual(TrafficRecord.objects.count(), 0)

        bundle = export_bundle(self.project)

        self.assertEqual(len(bundle["traffic"]), 2)
        exported = {item["url"] for item in bundle["traffic"]}
        self.assertEqual(exported, {"http://target.test/.env", "http://target.test/wp-admin/"})
        # The bodies are the point of a bundle: without them the evidence is a
        # claim, not a replayable exchange.
        self.assertTrue(
            all(item["response_body"] == "<html>fixture</html>" for item in bundle["traffic"])
        )

    def test_the_bundle_carries_the_session_and_event_pair(self):
        # An importer has always read `proxy_session` and `proxy_event_id`; the
        # copy stores them as one string, so the document has to take them apart
        # again rather than change shape.
        self.store_and_ingest(41, session=7)

        item = export_bundle(self.project)["traffic"][0]

        self.assertEqual(item["proxy_session"], 7)
        self.assertEqual(item["proxy_event_id"], 41)

    def test_clearing_traffic_leaves_the_bundle_untouched(self):
        # The operator's `Clear` and the Project's evidence are two different
        # things. This is the assertion that keeps them from being wired
        # together by accident.
        self.store_and_ingest(51)
        before = len(export_bundle(self.project)["traffic"])

        TrafficRecord.objects.filter(source="proxy").delete()
        after = export_bundle(self.project)

        self.assertEqual(before, 1)
        self.assertEqual(len(after["traffic"]), 1)
        self.assertEqual(after["traffic"][0]["url"], "http://target.test/wp-admin/")

    def test_the_hub_counts_the_project_copy(self):
        self.store_and_ingest(61)
        self.store_and_ingest(62, url="http://target.test/.env")

        response = self.client.get(f"/api/projects/{self.project.id}/hub")
        payload = json.loads(response.content)

        self.assertEqual(payload["metrics"]["traffic"], 2)

    def test_the_hub_number_survives_the_capture_archive_being_cleared(self):
        # A project card that empties because a view was cleared would be a lie
        # about the workspace, which is the whole reason the copy exists.
        self.store_and_ingest(71)
        TrafficRecord.objects.filter(source="proxy").delete()

        response = self.client.get(f"/api/projects/{self.project.id}/hub")
        payload = json.loads(response.content)

        self.assertEqual(payload["metrics"]["traffic"], 1)


class ClearTrafficTests(TestCase):
    """`Clear` in the Traffic tab deletes from the database, and nowhere else."""

    def setUp(self):
        self.project = Project.objects.create(name="target project", target="http://target.test")
        self.context = TrafficCaptureContext.objects.create(name="run", project=self.project)
        self.engine = mock.Mock()
        self.engine.return_value = (200, {"ok": True})

    def capture(self, source="proxy", event_id=1, project=None):
        row = TrafficRecord(
            project=project or self.project,
            source=source,
            method="GET",
            url=f"http://target.test/{event_id}",
            host="target.test",
            proxy_session=0,
            proxy_event_id=event_id,
            response_body="<html>fixture</html>",
            status_code=200,
        )
        row.capture_context = self.context
        row.save()
        ingest_traffic_batch([row])
        return row

    def clear(self):
        with mock.patch.object(views, "call_engine_delete", self.engine):
            return self.client.delete("/api/traffic")

    def test_clear_empties_the_live_snapshot_and_the_archive(self):
        # A clear that only emptied the screen would hand the same rows straight
        # back through `Load more from database`, which is not what an operator
        # who pressed a button labelled `Clear` was told would happen.
        self.capture(event_id=1)
        self.capture(event_id=2)

        response = self.clear()

        self.assertEqual(response.status_code, 200)
        self.engine.assert_called_once_with("/events")
        self.assertEqual(response.json()["deleted"], 2)
        self.assertEqual(TrafficRecord.objects.filter(source="proxy").count(), 0)

    def test_clear_leaves_repeater_and_intruder_rows_alone(self):
        # Those are History's results, not Traffic's. Each tab clears what it
        # shows, and a Repeater request is not something the Traffic archive owns.
        self.capture(source="repeater", event_id=3)
        self.capture(source="intruder", event_id=4)

        self.clear()

        self.assertEqual(
            sorted(TrafficRecord.objects.values_list("source", flat=True)),
            ["intruder", "repeater"],
        )

    def test_clear_leaves_the_project_bundle_intact(self):
        # The two rules meet: the capture archive goes, the workspace keeps the
        # evidence it already received.
        self.capture(event_id=5)
        self.capture(event_id=6)
        before = export_bundle(self.project)["traffic"]

        self.clear()

        after = export_bundle(self.project)["traffic"]
        self.assertEqual(len(before), 2)
        self.assertEqual(len(after), 2)
        self.assertEqual(after, before)

    def test_an_unreachable_engine_clears_nothing(self):
        # The engine holds the live snapshot. If it could not be cleared, deleting
        # the durable rows would leave the operator with neither, and the failure
        # would look like a successful clear.
        self.capture(event_id=7)
        self.engine.return_value = (502, {"error": "engine unavailable"})

        with mock.patch.object(views, "call_engine_delete", self.engine):
            response = self.client.delete("/api/traffic")

        self.assertEqual(response.status_code, 502)
        self.assertEqual(TrafficRecord.objects.filter(source="proxy").count(), 1)
        self.assertEqual(export_bundle(self.project)["traffic"][0]["url"], "http://target.test/7")


class ExchangeKeyTests(TestCase):
    def test_the_key_is_the_capture_pair_when_there_is_one(self):
        row = TrafficRecord(
            project=Project.objects.create(name="p", target="http://t.test"),
            proxy_session=3,
            proxy_event_id=9,
        )

        self.assertEqual(project_exchange_key(row), (row.project_id, "3:9"))

    def test_a_row_without_a_pair_still_gets_a_stable_key(self):
        # A Repeater row and an imported bundle row have no capture pair, and a
        # poll would otherwise copy them again on every pass.
        project = Project.objects.create(name="p", target="http://t.test")
        row = TrafficRecord(
            project=project,
            source="repeater",
            method="GET",
            url="http://t.test/a",
            status_code=200,
            latency_ms=3,
        )

        first = project_exchange_key(row)
        second = project_exchange_key(row)

        self.assertEqual(first, second)
        self.assertTrue(first[1].startswith("derived:"))

    def test_two_different_exchanges_do_not_collide(self):
        # The derived key has to separate real evidence, or a Repeater run that
        # hit the same URL twice would keep only the first request.
        project = Project.objects.create(name="p", target="http://t.test")
        first = TrafficRecord(project=project, method="GET", url="http://t.test/a", status_code=200)
        second = TrafficRecord(project=project, method="GET", url="http://t.test/a", status_code=500)

        self.assertNotEqual(project_exchange_key(first), project_exchange_key(second))

    def test_a_row_without_a_project_has_no_key(self):
        row = TrafficRecord(source="proxy", method="GET", url="http://t.test/")

        self.assertIsNone(project_exchange_key(row))

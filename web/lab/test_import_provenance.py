"""A08-03 — a bundle could dictate its own provenance.

A project bundle is a plain JSON file the analyst can be handed, and it was written as
`metadata={**mapping(item["metadata"]), "imported": True}`. So the file chose every key in
`metadata`, and `imported` sat right beside them: a reader could not tell "the exporter
asserted this" from "the importer recorded this", which is the one question provenance
exists to answer. A bundle that also carried full `TrafficRecord` rows with headers and
bodies was therefore a portable credential-extraction container that landed invisibly in
the analyst's own workspace.

These tests pin the two halves that can be fixed without changing the bundle format:
server-owned provenance keys, and a recorded verdict on whether the imported graph can
run at all. Signing the bundle is a format change and stays an owner decision.
"""

import uuid

from django.test import TestCase

from lab.models import Project, Workflow
from lab.project_transfer import (
    IMPORTED_METADATA_KEY,
    _imported_workflow_metadata,
    import_bundle,
)


def _bundle(*, workflow_metadata=None, nodes=None, connections=None):
    graph_nodes = [{"id": "s", "type": "set", "params": {"values": {"ok": True}}}] if nodes is None else nodes
    return {
        "schema_version": 1,
        "name": f"imported-{uuid.uuid4().hex[:8]}",
        "target": "https://shop.acme.test",
        "metadata": {},
        "workflows": [
            {
                "name": "imported workflow",
                "nodes": graph_nodes,
                "connections": [] if connections is None else connections,
                "graph_schema_version": 1,
                "active": True,
                "metadata": workflow_metadata if workflow_metadata is not None else {},
            }
        ],
    }


class ImportedProvenanceTests(TestCase):
    def _import(self, **kwargs):
        project, report = import_bundle(_bundle(**kwargs))
        self.addCleanup(Project.objects.filter(id=project.id).delete)
        workflow = Workflow.objects.get(project=project)
        self.addCleanup(workflow.delete)
        return workflow

    def test_the_bundle_cannot_forge_the_provenance_keys(self) -> None:
        """The whole point: every key in `metadata` used to come from the file, and
        `imported` sat among them."""
        workflow = self._import(workflow_metadata={"imported": False, "imported_at": "1999-01-01",
                                                  "imported_source": "trusted_export"})

        self.assertIs(workflow.metadata["imported"], True)
        self.assertNotEqual(workflow.metadata["imported_at"], "1999-01-01")
        self.assertEqual(workflow.metadata["imported_source"], "project_bundle")

    def test_what_the_bundle_sent_is_kept_but_namespaced(self) -> None:
        """Evidence is not thrown away — losing it would also destroy the trace — it is
        moved somewhere it cannot pose as a fact about this installation."""
        workflow = self._import(workflow_metadata={"owner": "someone-else", "imported": False})

        self.assertEqual(
            workflow.metadata[IMPORTED_METADATA_KEY],
            {"owner": "someone-else", "imported": False},
            "the bundle's own metadata must survive, namespaced",
        )

    def test_provenance_carries_a_server_side_timestamp(self) -> None:
        workflow = self._import()
        self.assertIn("imported_at", workflow.metadata)
        self.assertTrue(str(workflow.metadata["imported_at"]).startswith("20"))

    def test_a_graph_that_cannot_run_is_recorded_as_such(self) -> None:
        """`validate_workflow` already runs before execution, so an unrunnable imported
        graph was never a code-execution hole — the operator simply had nothing on the
        record telling them until they activated it."""
        workflow = self._import(nodes=[{"id": "x", "type": "not-a-real-node", "params": {}}])

        self.assertIs(workflow.metadata["imported_graph_valid"], False)
        self.assertIn("imported_graph_error", workflow.metadata)

    def test_a_runnable_graph_is_recorded_as_valid(self) -> None:
        workflow = self._import()
        self.assertIs(workflow.metadata["imported_graph_valid"], True)
        self.assertNotIn("imported_graph_error", workflow.metadata)

    def test_a_broken_graph_does_not_discard_the_workspace(self) -> None:
        """This module's stated design is that a partly readable bundle produces a
        Project holding exactly the sections it did contain. One malformed graph must
        not throw away a workspace's traffic."""
        bundle = _bundle(nodes=[{"id": "x", "type": "not-a-real-node", "params": {}}])
        bundle["traffic"] = [{"url": "https://shop.acme.test/a", "method": "GET", "status": 200,
                              "request_headers": {}, "request_body": "", "response_headers": {},
                              "response_body": "ok", "source": "repeater"}]
        project, report = import_bundle(bundle)
        self.addCleanup(Project.objects.filter(id=project.id).delete)

        self.assertEqual(report.get("workflows"), 1)
        self.assertTrue(Project.objects.filter(id=project.id).exists())

    def test_an_imported_workflow_is_still_inert(self) -> None:
        """The record above changes nothing about what the graph can do: an imported
        workflow lands inactive whatever the bundle claims."""
        workflow = self._import(workflow_metadata={"active": True})
        self.assertFalse(workflow.active)


class ImportedMetadataHelperTests(TestCase):
    """The helper on its own, so the guarantees do not depend on an import running."""

    def test_a_file_cannot_overwrite_a_server_key(self) -> None:
        metadata = _imported_workflow_metadata(
            {"imported": False, "imported_at": "1999", "imported_graph_valid": True},
            imported_at="2026-10-01T00:00:00Z",
        )
        self.assertIs(metadata["imported"], True)
        self.assertEqual(metadata["imported_at"], "2026-10-01T00:00:00Z")
        self.assertIs(metadata["imported_graph_valid"], True)

    def test_a_non_object_from_the_file_is_ignored_rather_than_crashing(self) -> None:
        for junk in (None, [], "string", 42):
            metadata = _imported_workflow_metadata(junk, imported_at="2026-10-01T00:00:00Z")
            self.assertIs(metadata["imported"], True)
            self.assertNotIn(IMPORTED_METADATA_KEY, metadata)

    def test_an_empty_file_metadata_adds_no_noise(self) -> None:
        metadata = _imported_workflow_metadata({}, imported_at="2026-10-01T00:00:00Z")
        self.assertNotIn(IMPORTED_METADATA_KEY, metadata)

    def test_the_validation_error_is_bounded(self) -> None:
        """A graph error can quote the offending node parameter verbatim, and this value
        is displayed. It is cut rather than stored whole."""
        metadata = _imported_workflow_metadata({}, imported_at="2026-10-01T00:00:00Z",
                                               graph_error="x" * 5000)
        self.assertLessEqual(len(metadata["imported_graph_error"]), 200)

"""A06-07 (MEDIUM) — a replay was not bound to what the operator had seen.

A `repeater` node carries a templated URL, so a scheduled run goes wherever the upstream
node's result pointed **at the moment it ran** — not where the operator approved when they
drew the graph.

Both facts were already stored and neither was visible beside the other:

* `run.graph_nodes` is snapshotted at start → "the graph said X";
* `WorkflowNodeExecution.input_data` is what actually arrived from upstream → "the run
  received Y".

Storing both without comparing them means the reader has to do the comparison by hand across
two structures, and in practice nobody does. That is what the finding meant.

What this does NOT do: refuse the run. A node whose output legitimately changes between runs
is the normal case for a workflow, and refusing it would break the tool. For an evidence
product the obligation is that the difference be *visible*.
"""

from django.test import TestCase

from lab.models import Workflow, WorkflowNodeExecution, WorkflowRun
from lab.workflow_engine import replay_divergence, run_item


def _workflow(nodes):
    return Workflow.objects.create(
        name="Replay divergence",
        description="https://shop.acme.test",
        nodes=nodes,
        connections=[],
        active=False,
    )


class ReplayDivergenceTests(TestCase):
    def _run_with(self, nodes, node_id, input_data):
        workflow = _workflow(nodes)
        run = WorkflowRun.objects.create(
            workflow=workflow,
            status="completed",
            mode="manual",
            graph_nodes=nodes,
        )
        WorkflowNodeExecution.objects.create(
            workflow_run=run, node_id=node_id, status="completed", input_data=input_data,
        )
        return run

    def test_a_literal_target_is_not_reported(self) -> None:
        """It can never diverge, so listing it would bury the rows that matter."""
        run = self._run_with(
            [{"id": "n1", "type": "repeater", "parameters": {"url": "https://shop.acme.test/a"}}],
            "n1", [{"url": "https://shop.acme.test/a"}],
        )
        self.assertEqual(replay_divergence(run), [])

    def test_a_templated_target_that_resolved_differently_is_reported(self) -> None:
        run = self._run_with(
            [{"id": "n1", "type": "repeater",
              "parameters": {"url": "https://shop.acme.test/item/{{ item_id }}"}}],
            "n1", [{"url": "https://shop.acme.test/item/9999-admin"}],
        )
        rows = replay_divergence(run)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertTrue(row["templated"])
        self.assertTrue(row["diverged"])
        self.assertEqual(row["approved"][0]["value"], "https://shop.acme.test/item/{{ item_id }}")
        self.assertEqual(row["received"][0]["value"], "https://shop.acme.test/item/9999-admin")

    def test_a_templated_target_that_resolved_to_the_same_thing_is_not_a_divergence(self) -> None:
        run = self._run_with(
            [{"id": "n1", "type": "repeater", "parameters": {"url": "https://a.test/x"}}],
            "n1", [{"url": "https://a.test/x"}],
        )
        self.assertEqual(replay_divergence(run), [])

    def test_a_node_absent_from_the_approved_graph_is_named(self) -> None:
        """The snapshot is the only record of what was approved, so its absence has to be
        said rather than rendering as "nothing to report"."""
        run = self._run_with(
            [{"id": "n1", "type": "set", "parameters": {"value": "x"}}], "n2", {"value": "y"},
        )
        rows = replay_divergence(run)
        self.assertEqual(len(rows), 1)
        self.assertIn("no longer contains this node", rows[0]["note"])

    def test_a_non_string_template_marker_is_still_a_template(self) -> None:
        run = self._run_with(
            [{"id": "n1", "type": "repeater", "parameters": {"url": "https://a.test/{% raw %}{{u}}{% endraw %}"}}],
            "n1", [{"url": "https://other.test/z"}],
        )
        self.assertEqual(len(replay_divergence(run)), 1)

    def test_parameters_given_as_a_json_string_are_read(self) -> None:
        """The graph stores parameters either as an object or as a JSON string depending on
        which editor wrote them; reading only one form would miss real graphs."""
        run = self._run_with(
            [{"id": "n1", "type": "repeater", "parameters": '{"url": "https://a.test/{{ id }}"}'}],
            "n1", [{"url": "https://a.test/7"}],
        )
        rows = replay_divergence(run)
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["diverged"])

    def test_a_deep_nested_received_value_is_found(self) -> None:
        run = self._run_with(
            [{"id": "n1", "type": "repeater", "parameters": {"url": "https://a.test/{{ x }}"}}],
            "n1", {"results": [{"detail": {"url": "https://elsewhere.test/y"}}]},
        )
        rows = replay_divergence(run)
        self.assertEqual(rows[0]["received"][0]["value"], "https://elsewhere.test/y")

    def test_nothing_is_invented_when_nothing_arrived(self) -> None:
        run = self._run_with(
            [{"id": "n1", "type": "repeater", "parameters": {"url": "https://a.test/{{ x }}"}}],
            "n1", {},
        )
        rows = replay_divergence(run)
        self.assertEqual(rows[0]["received"], [])
        self.assertFalse(rows[0]["diverged"], "an empty input is not evidence of a change")


class RunItemExposesItTests(TestCase):
    def test_the_run_payload_carries_the_divergence(self) -> None:
        """A comparison nobody can reach is not a comparison."""
        nodes = [{"id": "n1", "type": "repeater", "parameters": {"url": "https://a.test/{{ x }}"}}]
        workflow = _workflow(nodes)
        run = WorkflowRun.objects.create(
            workflow=workflow, status="completed", mode="manual", graph_nodes=nodes)
        WorkflowNodeExecution.objects.create(
            workflow_run=run, node_id="n1", status="completed",
            input_data=[{"url": "https://elsewhere.test/z"}])

        payload = run_item(run)
        self.assertIn("replay_divergence", payload)
        self.assertEqual(len(payload["replay_divergence"]), 1)
        self.assertTrue(payload["replay_divergence"][0]["diverged"])

    def test_a_clean_run_reports_nothing_and_is_still_readable(self) -> None:
        nodes = [{"id": "n1", "type": "repeater", "parameters": {"url": "https://a.test/x"}}]
        workflow = _workflow(nodes)
        run = WorkflowRun.objects.create(
            workflow=workflow, status="completed", mode="manual", graph_nodes=nodes)
        WorkflowNodeExecution.objects.create(
            workflow_run=run, node_id="n1", status="completed",
            input_data=[{"url": "https://a.test/x"}])
        payload = run_item(run)
        self.assertEqual(payload["replay_divergence"], [])
        self.assertEqual(payload["node_executions"][0]["node_id"], "n1")


class SensitiveValueTests(TestCase):
    def test_a_secret_in_the_received_target_is_redacted(self) -> None:
        """The divergence row goes into an exported report, so it inherits the project's
        rule that payloads and secrets do not travel unredacted."""
        nodes = [{"id": "n1", "type": "repeater",
                  "parameters": {"url": "https://a.test/{{ token }}"}}]
        workflow = _workflow(nodes)
        run = WorkflowRun.objects.create(
            workflow=workflow, status="completed", mode="manual", graph_nodes=nodes)
        WorkflowNodeExecution.objects.create(
            workflow_run=run, node_id="n1", status="completed",
            input_data=[{"url": "https://a.test/?token=SUPERSECRETVALUE"}])

        row = replay_divergence(run)[0]
        self.assertNotIn("SUPERSECRETVALUE", str(row))
        self.assertEqual(row["approved"][0]["value"], "https://a.test/{{ token }}")
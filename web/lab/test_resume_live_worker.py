"""Регресія: `resume` не піднімає друге виконання поверх живого воркера.

Коли `WORKFLOW_CELERY_ENABLED` увімкнено, граф виконується у Celery-воркері,
тож у процесі, який обробляє запит на resume, контролу рани немає. Старий код
на це відповідав «немає воркера — підніму нового», і новий воркер одразу
наштовхувався на `running`-чекпойнт живого попереднього вузла та відхиляв рану
з `node ... has an incomplete checkpoint; manual review is required before
retry`.

Виміряно на стенді: пауза через 1.2 с під час `delay` на 3 с, resume через
1.0 с → `failed`, `d1` лишався `running`. Той самий сценарій із resume через
4.0 с проходив, бо вузол доти встигав завершитися - саме тому це читалося як
флейк.

Тест імітує саме цю розстановку: воркер живе в іншому процесі (контролу тут
немає), але його вузол має `running`-чекпойнт.
"""

from django.test import TestCase

from .models import Workflow, WorkflowNodeExecution, WorkflowRun
from .workflow_engine import get_runtime


class ResumeMustNotRaceALiveWorkerTests(TestCase):
    def _paused_run_with_an_in_flight_node(self):
        workflow = Workflow.objects.create(name="Resume with live worker")
        run = WorkflowRun.objects.create(workflow=workflow, status="paused")
        WorkflowNodeExecution.objects.create(
            workflow_run=run,
            node_id="d1",
            status="running",
        )
        return run

    def test_resume_hands_the_run_back_instead_of_starting_a_second_worker(self):
        run = self._paused_run_with_an_in_flight_node()

        resumed = get_runtime().resume(run.pk)

        self.assertTrue(resumed, "a paused run with a live worker must resume")
        self.assertEqual(
            WorkflowRun.objects.get(pk=run.pk).status,
            "running",
            "the live worker continues once the run is marked running again",
        )
        node = WorkflowNodeExecution.objects.get(workflow_run=run, node_id="d1")
        self.assertEqual(
            node.status,
            "running",
            "the in-flight node keeps its checkpoint: a second worker would have "
            "rejected exactly this row as incomplete",
        )

    def test_resume_still_starts_a_worker_for_a_run_that_has_none(self):
        """The guard must not become a pause that never ends.

        With no in-flight node there is nobody to hand the run back to, so the
        run has to be queued for a worker - that is the case the original code
        existed for.
        """
        workflow = Workflow.objects.create(name="Resume without worker")
        run = WorkflowRun.objects.create(workflow=workflow, status="paused")
        started = []
        runtime = get_runtime()
        original = runtime.start_recovered
        runtime.start_recovered = lambda run_id: started.append(run_id)
        try:
            resumed = runtime.resume(run.pk)
        finally:
            runtime.start_recovered = original

        self.assertTrue(resumed)
        self.assertEqual(started, [run.pk], "a run with no live worker must be re-dispatched")

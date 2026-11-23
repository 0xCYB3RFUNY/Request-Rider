from __future__ import annotations

"""A status poll of a running Intruder attack must not drag the Traffic store.

The Intruder UI polls its attack continuously, and each poll used to call
`_persist_tool_history`, which reads the engine's whole in-memory Traffic store and
writes whatever is not stored yet. On a stand with a populated store that is a
7 142 866-byte response per poll, feeding a batched writer whose deduplication
throws all of it away — the exchanges of a *running* attack are still being made.

The attack's own results are carried incrementally by `persist_intruder_history`;
the store read is for the proxy exchanges, and those are complete only once the
attack has stopped. So the store read belongs to the terminal state, and both
halves of that are asserted here.
"""

from unittest.mock import patch

from django.test import TestCase


class IntruderTerminalPersistTests(TestCase):
    def _poll(self, state):
        with patch("lab.views.call_engine_get") as call_engine_get, \
                patch("lab.views.persist_intruder_history"), \
                patch("lab.views._persist_tool_history") as persist_tool_history:
            call_engine_get.return_value = (
                200, {"attack_id": 7, "status": state, "results": [], "result_offset": 0})
            response = self.client.get("/api/intruder?attack_id=7")
        return response, call_engine_get, persist_tool_history

    def test_a_running_attack_is_polled_without_reading_the_store(self):
        response, _, persist_tool_history = self._poll("running")
        self.assertEqual(response.status_code, 200)
        persist_tool_history.assert_not_called()

    def test_a_finished_attack_writes_its_exchanges(self):
        for state in ("completed", "cancelled", "failed"):
            with self.subTest(state=state):
                response, _, persist_tool_history = self._poll(state)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(persist_tool_history.call_count, 1)

    def test_the_poll_itself_is_still_just_the_attack(self):
        """No hidden second engine call on a running attack."""
        response, call_engine_get, _ = self._poll("running")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [call.args[0] for call in call_engine_get.call_args_list],
            ["/proxy/intruder/7"],
            "a status poll must not make an extra engine call for its own sake",
        )
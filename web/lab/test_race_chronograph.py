"""Tests for F3 Race Condition Chronograph & Multi-Endpoint Last-Byte Barrier."""
import json
from unittest.mock import patch

from django.test import Client, TestCase


class RaceChronographTests(TestCase):
    def setUp(self):
        self.client = Client()

    @patch("lab.views.call_engine")
    def test_repeater_last_byte_multi_endpoint_dispatch(self, mock_call_engine):
        mock_call_engine.return_value = (
            202,
            {
                "last_byte_id": 42,
                "status": "running",
                "total": 2,
            },
        )
        resp = self.client.post(
            "/api/repeater/last-byte",
            data=json.dumps({
                "hold_ms": 30,
                "requests": [
                    {
                        "method": "POST",
                        "url": "https://target.local/api/coupon/apply",
                        "headers": {"Content-Type": "application/json"},
                        "body": '{"code":"SAVE50"}',
                    },
                    {
                        "method": "POST",
                        "url": "https://target.local/api/order/checkout",
                        "headers": {"Content-Type": "application/json"},
                        "body": '{"cart_id":7}',
                    },
                ],
            }),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 202)
        self.assertEqual(resp.json()["last_byte_id"], 42)
        mock_call_engine.assert_called_once()
        called_path, called_payload = mock_call_engine.call_args[0]
        self.assertEqual(called_path, "/proxy/last-byte")
        self.assertEqual(len(called_payload["requests"]), 2)
        self.assertEqual(called_payload["iterations"], 2)
        self.assertEqual(called_payload["hold_ms"], 30)

    @patch("lab.views.call_engine_get")
    @patch("lab.views.call_engine_delete")
    def test_repeater_last_byte_poll_and_cancel(self, mock_delete, mock_get):
        mock_get.return_value = (
            200,
            {
                "last_byte_id": 42,
                "status": "completed",
                "race_window_spread_us": 145,
                "results": [
                    {"iteration": 0, "status": 200, "t_last_byte_sent_us": 1100, "t_done_us": 3200},
                    {"iteration": 1, "status": 200, "t_last_byte_sent_us": 1245, "t_done_us": 3400},
                ],
            },
        )
        get_resp = self.client.get("/api/repeater/last-byte/42")
        self.assertEqual(get_resp.status_code, 200)
        self.assertEqual(get_resp.json()["race_window_spread_us"], 145)
        mock_get.assert_called_once_with("/proxy/last-byte/42")

        mock_delete.return_value = (202, {"last_byte_id": 42, "status": "cancelling"})
        del_resp = self.client.delete("/api/repeater/last-byte/42")
        self.assertEqual(del_resp.status_code, 202)
        mock_delete.assert_called_once_with("/proxy/last-byte/42")

    def test_repeater_template_contains_race_chronograph_ui(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.content.decode("utf-8")
        self.assertIn("repeater-race-btn", html)
        self.assertIn("race-sync-wrap", html)
        self.assertIn("rs-svg-chronograph", html)
        self.assertIn("rs-fire-btn", html)

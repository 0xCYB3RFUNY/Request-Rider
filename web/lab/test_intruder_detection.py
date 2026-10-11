"""Gateway tests for the Intruder login-detection config.

The engine decides which rows of the Intruder table are a successful login, so
the config that drives it is checked here rather than trusted from the browser.
The failure this guards is specific and was measured on the engine side: an
unknown signal name is dropped there instead of failing, so a run would keep
reporting verdicts while comparing less than the operator asked for, and a login
that matched nothing would look like a page with no signal.

The tests are written against the validator rather than against a live engine so
they say what they check. The end-to-end behaviour against raised CMS containers
is a separate live test, because a green unit test only proves the gateway
accepts the field, not that the run flags the right credential.
"""

from django.test import SimpleTestCase
from unittest.mock import patch

from lab.views import _validate_detection_config


class DetectionConfigValidationTests(SimpleTestCase):
    def test_absent_config_stays_absent(self):
        # An attack that never mentions detection must reach the engine exactly
        # as it did before the feature existed.
        self.assertIsNone(_validate_detection_config(None))

    def test_minimal_enabled_config(self):
        validated = _validate_detection_config({"enabled": True})
        self.assertEqual(validated["enabled"], True)
        self.assertEqual(validated["signals"], [])
        self.assertEqual(validated["tolerance"], 0)
        self.assertEqual(validated["rules"], [])
        # The calibration count is left out when it is the default, so a saved
        # attack stays comparable with an older one.
        self.assertNotIn("calibration_requests", validated)

    def test_full_config_round_trip(self):
        validated = _validate_detection_config(
            {
                "enabled": True,
                "signals": ["status", "length", "body"],
                "tolerance": 48,
                "calibration_requests": 5,
                "rules": [
                    {"type": "body_contains", "value": "Welcome back"},
                    {"type": "header_contains", "name": "Location", "value": "/wp-admin/"},
                    {"type": "body_not_contains", "value": "Invalid username"},
                    {"type": "status_equals", "value": "302"},
                    {"type": "body_contains", "value": "id=\\d+", "regex": True},
                ],
            }
        )
        self.assertEqual(validated["signals"], ["status", "length", "body"])
        self.assertEqual(validated["tolerance"], 48)
        self.assertEqual(validated["calibration_requests"], 5)
        self.assertEqual(len(validated["rules"]), 5)
        header_rule = validated["rules"][1]
        self.assertEqual(header_rule["name"], "Location")

    def test_unknown_top_level_field_is_rejected(self):
        with self.assertRaisesMessage(ValueError, "unknown fields"):
            _validate_detection_config({"enabled": True, "silently_ignored": 1})

    def test_unknown_signal_is_rejected(self):
        # The engine drops an unknown signal name rather than failing. The
        # gateway is the place that must not let it through, or the operator sees
        # a comparison that is narrower than the one they configured.
        with self.assertRaisesMessage(ValueError, "detection.signals must only contain"):
            _validate_detection_config({"enabled": True, "signals": ["status", "made_up"]})

    def test_unknown_rule_type_is_rejected(self):
        with self.assertRaisesMessage(ValueError, "detection.rules[0].type must be one of"):
            _validate_detection_config(
                {"enabled": True, "rules": [{"type": "run_command", "value": "id"}]}
            )

    def test_rule_without_value_is_rejected(self):
        # An empty needle would match every row, which is the same as saying the
        # run found a successful login.
        with self.assertRaisesMessage(ValueError, "must be a non-empty string"):
            _validate_detection_config({"enabled": True, "rules": [{"type": "body_contains", "value": "  "}]})

    def test_header_rule_requires_a_header_name(self):
        with self.assertRaisesMessage(ValueError, "name is required for header_contains"):
            _validate_detection_config(
                {"enabled": True, "rules": [{"type": "header_contains", "value": "/wp-admin/"}]}
            )

    def test_negative_tolerance_is_rejected(self):
        with self.assertRaisesMessage(ValueError, "detection.tolerance must be at least 0"):
            _validate_detection_config({"enabled": True, "tolerance": -1})

    def test_calibration_below_one_is_rejected(self):
        with self.assertRaisesMessage(ValueError, "detection.calibration_requests must be at least 1"):
            _validate_detection_config({"enabled": True, "calibration_requests": -1})

    def test_zero_calibration_means_the_engine_default(self):
        # Zero is not "take no samples" — a run with no baseline can only use the
        # rules, and the operator would not learn that from the result. It means
        # the engine default, so the field is simply left out.
        validated = _validate_detection_config({"enabled": True, "calibration_requests": 0})
        self.assertNotIn("calibration_requests", validated)

    def test_calibration_ceiling_is_named_in_the_error(self):
        # The ceiling exists, so the error has to say what it is and where it
        # comes from rather than failing with a bare rejection.
        with self.assertRaisesMessage(ValueError, "must not exceed 100"):
            _validate_detection_config({"enabled": True, "calibration_requests": 101})

    def test_booleans_are_not_accepted_as_numbers(self):
        # `True` is an int in Python, and `calibration_requests: true` would
        # otherwise mean one calibration request.
        with self.assertRaisesMessage(ValueError, "detection.tolerance must be an integer"):
            _validate_detection_config({"enabled": True, "tolerance": True})

    def test_wrong_container_types_are_rejected(self):
        with self.assertRaisesMessage(ValueError, "detection must be an object"):
            _validate_detection_config(["enabled"])
        with self.assertRaisesMessage(ValueError, "detection.signals must be a list of strings"):
            _validate_detection_config({"enabled": True, "signals": "status"})
        with self.assertRaisesMessage(ValueError, "detection.rules must be a list"):
            _validate_detection_config({"enabled": True, "rules": {"type": "body_contains"}})

    def test_extra_rule_keys_are_not_carried_forward(self):
        validated = _validate_detection_config(
            {
                "enabled": True,
                "rules": [
                    {
                        "type": "body_contains",
                        "value": "Dashboard",
                        "regex": False,
                        "note": "kept out of the stored definition",
                    }
                ],
            }
        )
        self.assertNotIn("note", validated["rules"][0])


class DetectionReachesTheEngineTests(SimpleTestCase):
    def test_invalid_config_stops_the_start_request(self):
        # A config that never validates must not produce a half-started run: the
        # operator would see an attack id for an attack that never compared
        # anything.
        from django.test import RequestFactory

        from lab.views import intruder

        request = RequestFactory().post(
            "/api/intruder",
            data={
                "base_request": {},
                "mode": "sniper",
                "payloads": [["a"]],
                "detection": {"enabled": True, "signals": ["nope"]},
            },
            content_type="application/json",
        )
        response = intruder(request)
        self.assertEqual(response.status_code, 400)
        self.assertIn("detection.signals", response.content.decode())

    def test_valid_config_is_forwarded_to_the_engine(self):
        from django.test import RequestFactory

        from lab.views import intruder

        request = RequestFactory().post(
            "/api/intruder",
            data={
                "base_request": {"url": "http://127.0.0.1/login"},
                "mode": "sniper",
                "payloads": [["admin"]],
                "detection": {
                    "enabled": True,
                    "signals": ["length"],
                    "rules": [{"type": "body_contains", "value": "Dashboard"}],
                },
            },
            content_type="application/json",
        )
        with patch("lab.views.call_engine", return_value=(202, {"attack_id": 7})) as call_engine:
            with patch("lab.views.IntruderAttack.objects.create"):
                response = intruder(request)
        self.assertEqual(response.status_code, 202)
        forwarded = call_engine.call_args[0][1]
        self.assertTrue(forwarded["detection"]["enabled"])
        self.assertEqual(forwarded["detection"]["signals"], ["length"])
        self.assertEqual(forwarded["detection"]["rules"][0]["type"], "body_contains")

    def test_attack_without_detection_sends_no_field(self):
        # An attack that never mentions detection must reach the engine exactly
        # as it did before the feature existed.
        from django.test import RequestFactory

        from lab.views import intruder

        request = RequestFactory().post(
            "/api/intruder",
            data={"base_request": {"url": "http://127.0.0.1/"}, "mode": "sniper", "payloads": [["a"]]},
            content_type="application/json",
        )
        with patch("lab.views.call_engine", return_value=(202, {"attack_id": 8})) as call_engine:
            with patch("lab.views.IntruderAttack.objects.create"):
                response = intruder(request)
        self.assertEqual(response.status_code, 202)
        self.assertNotIn("detection", call_engine.call_args[0][1])

"""Tests for the three-gate finding verification state machine."""

import json
import unittest

from django.test import TestCase

from . import agent_verification as gate
from .models import FindingVerification, Project


class VerificationRulesTests(TestCase):
    def setUp(self):
        self.project = Project.objects.create(name="verification-tests")

    def test_full_happy_path_confirms_with_named_difference(self):
        gate.start_verification(
            project=self.project,
            finding_key="SQLI-1",
            title="UNION injection",
            baseline={"status": 200, "body": "Welcome"},
        )
        self.assertEqual(
            gate.get_verification(project=self.project, finding_key="SQLI-1")["status"],
            "baseline",
        )
        gate.record_attack(
            project=self.project,
            finding_key="SQLI-1",
            attack={"status": 200, "body": "version():8.0"},
        )
        row = gate.conclude_verification(
            project=self.project,
            finding_key="SQLI-1",
            diff={"changed": True, "what": "body contains DBMS version"},
            verified_by="operator-a",
        )
        self.assertEqual(row["status"], "confirmed")
        self.assertEqual(row["verified_by"], "operator-a")
        self.assertEqual(row["evidence"]["concluded_at"][:4], "2026")

    def test_confirmed_requires_named_change(self):
        gate.start_verification(
            project=self.project, finding_key="XSS-1", baseline={"status": 200}
        )
        gate.record_attack(project=self.project, finding_key="XSS-1", attack={"status": 201})
        with self.assertRaises(ValueError):
            gate.conclude_verification(
                project=self.project,
                finding_key="XSS-1",
                diff={"changed": True},
                decision="confirmed",
            )

    def test_attack_before_baseline_is_rejected(self):
        with self.assertRaises(ValueError):
            gate.record_attack(project=self.project, finding_key="NO-BASE", attack={"status": 200})

    def test_conclude_before_attack_is_rejected(self):
        gate.start_verification(project=self.project, finding_key="NO-ATK", baseline={"status": 200})
        with self.assertRaises(ValueError):
            gate.conclude_verification(
                project=self.project, finding_key="NO-ATK", diff={"changed": True, "what": "x"}
            )

    def test_no_difference_refutes(self):
        gate.start_verification(project=self.project, finding_key="SAFE", baseline={"status": 200})
        gate.record_attack(project=self.project, finding_key="SAFE", attack={"status": 200})
        row = gate.conclude_verification(project=self.project, finding_key="SAFE", diff={})
        self.assertEqual(row["status"], "refuted")

    def test_reset_reopens_all_three_gates(self):
        gate.start_verification(project=self.project, finding_key="RESET", baseline={"status": 200})
        gate.record_attack(project=self.project, finding_key="RESET", attack={"status": 500})
        gate.conclude_verification(
            project=self.project, finding_key="RESET",
            diff={"changed": True, "what": "status changed"},
        )
        row = gate.reset_verification(project=self.project, finding_key="RESET")
        self.assertEqual(row["status"], "suspected")
        self.assertEqual(row["baseline"], {})
        self.assertEqual(row["attack"], {})
        gate.start_verification(project=self.project, finding_key="RESET", baseline={"status": 200})
        self.assertEqual(
            gate.get_verification(project=self.project, finding_key="RESET")["status"],
            "baseline",
        )

    def test_scopes_are_isolated(self):
        other = Project.objects.create(name="other-verification-project")
        gate.start_verification(project=self.project, finding_key="SAME", baseline={"status": 200})
        self.assertIsNone(gate.get_verification(project=other, finding_key="SAME"))
        self.assertEqual(len(gate.list_verifications(project=other)), 0)


class VerificationApiTests(TestCase):
    def test_endpoints_drive_all_three_gates(self):
        base = {"finding_key": "API-1", "baseline": {"status": 200, "body": "ok"}}
        response = self.client.post(
            "/api/agent/verification",
            data=json.dumps({"action": "start", **base}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["verification"]["status"], "baseline")

        response = self.client.post(
            "/api/agent/verification",
            data=json.dumps({"action": "attack", "finding_key": "API-1", "attack": {"status": 200}}),
            content_type="application/json",
        )
        self.assertEqual(response.json()["verification"]["status"], "attack")

        response = self.client.post(
            "/api/agent/verification",
            data=json.dumps({
                "action": "conclude",
                "finding_key": "API-1",
                "diff": {"changed": True, "what": "body differs"},
                "verified_by": "tester",
            }),
            content_type="application/json",
        )
        self.assertEqual(response.json()["verification"]["status"], "confirmed")

        listed = self.client.get("/api/agent/verification")
        self.assertEqual(listed.json()["count"], 1)
        self.assertEqual(FindingVerification.objects.count(), 1)

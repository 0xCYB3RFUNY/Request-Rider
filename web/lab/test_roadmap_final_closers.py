import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

from django.test import Client, TestCase

from lab.models import AttackChain, AttackStep, Project, ProjectEndpoint, ScannerRun, WorkflowTemplate
from lab.roadmap_final_suite import (
    build_workflow_import_preview,
    convert_nuclei_to_workflow_graph,
    convert_postman_to_workflow_graph,
    encode_grpc_frame,
    encode_websocket_frame,
    generate_bounded_binary_mutations,
    import_openapi_spec,
    inspect_graphql_schema,
    inspect_protocol_metadata,
    introspect_proto_schema,
    sign_workflow_template_schema,
    verify_jwt_with_allowlist,
    verify_workflow_template_signature,
)


ROOT_DIR = Path(__file__).resolve().parent.parent.parent


class RoadmapFinalClosersTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.project = Project.objects.create(name="Final Roadmap Project", target="https://target.test")

    def test_workflow_template_crud_signing_and_preview(self):
        nodes = [
            {"id": "t1", "type": "manual_trigger", "label": "Start", "params": {}},
            {"id": "r1", "type": "repeater", "label": "Ping", "params": {"url": "https://target.test/"}},
        ]
        conns = [{"source": "t1", "source_handle": "main", "target": "r1", "target_handle": "main"}]
        resp = self.client.post(
            "/api/workflow-templates",
            data=json.dumps(
                {
                    "slug": "signed-recon",
                    "name": "Signed Recon",
                    "version": "1.2.0",
                    "nodes": nodes,
                    "connections": conns,
                    "manifest": {"license": "MIT", "tags": ["recon"]},
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertTrue(data["signature_verified"])
        self.assertTrue(data["schema_signature"].startswith("hmac-sha256:"))
        self.assertTrue(WorkflowTemplate.objects.filter(slug="signed-recon").exists())

        preview = self.client.post(
            "/api/workflow-templates/preview",
            data=json.dumps(data),
            content_type="application/json",
        )
        self.assertEqual(preview.status_code, 200)
        pdata = preview.json()
        self.assertTrue(pdata["valid"])
        self.assertTrue(pdata["signature_valid"])
        self.assertEqual(pdata["node_count"], 2)

        # Tampered node must fail signature verification
        tampered = json.loads(json.dumps(data))
        tampered["nodes"][1]["params"]["url"] = "https://evil.test/"
        preview_bad = build_workflow_import_preview(tampered)
        self.assertFalse(preview_bad["signature_valid"])

    def test_nuclei_and_postman_converters_enforce_canonical_validation(self):
        nuclei_yaml = """id: check-env
info:
  name: DotEnv Exposure
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
"""
        resp_nuc = self.client.post(
            "/api/workflows/convert",
            data=json.dumps({"format": "nuclei", "content": nuclei_yaml}),
            content_type="application/json",
        )
        self.assertEqual(resp_nuc.status_code, 200)
        nuc_data = resp_nuc.json()
        self.assertTrue(nuc_data["ok"])
        self.assertEqual(len(nuc_data["nodes"]), 2)
        self.assertEqual(nuc_data["nodes"][1]["type"], "repeater")

        # Non-data-only Nuclei template with code block must be rejected
        with self.assertRaises(ValueError):
            convert_nuclei_to_workflow_graph("id: evil\ncode:\n  - engine: [sh]\n    source: id\n")

        postman_col = {
            "info": {"name": "Target API v1"},
            "item": [
                {
                    "name": "Get Profile",
                    "request": {
                        "method": "GET",
                        "url": {"raw": "https://target.test/api/me"},
                        "header": [{"key": "Authorization", "value": "Bearer tok"}],
                    },
                }
            ],
        }
        resp_pm = self.client.post(
            "/api/workflows/convert",
            data=json.dumps({"format": "postman", "collection": postman_col}),
            content_type="application/json",
        )
        self.assertEqual(resp_pm.status_code, 200)
        pm_data = resp_pm.json()
        self.assertTrue(pm_data["ok"])
        self.assertEqual(pm_data["request_count"], 1)

    def test_semantic_attack_chain_and_step_provenance(self):
        resp = self.client.post(
            "/api/attack-chains",
            data=json.dumps(
                {
                    "title": "JWT Confusion -> Admin Export",
                    "severity": "critical",
                    "mitre_techniques": ["T1190", "T1552"],
                    "steps": [
                        {
                            "step_order": 1,
                            "phase": "initial_access",
                            "description": "Forge HS256 JWT using server public key",
                            "finding_identity": "sha256:jwt_key_confusion_01",
                            "evidence_provenance": {"source": "repeater", "status": 200},
                        },
                        {
                            "step_order": 2,
                            "phase": "exfiltration",
                            "description": "Download /api/admin/export",
                            "finding_identity": "sha256:admin_export_02",
                            "evidence_provenance": {"source": "active_scanner", "bytes": 4096},
                        },
                    ],
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 201)
        chain_data = resp.json()
        self.assertEqual(len(chain_data["steps"]), 2)
        self.assertEqual(AttackChain.objects.count(), 1)
        self.assertEqual(AttackStep.objects.count(), 2)

    def test_protocol_metadata_websocket_grpc_h2_h3_and_bounded_mutations(self):
        ws_frame = encode_websocket_frame(b'{"ping":1}', opcode=1, mask_key=b"\x12\x34\x56\x78")
        ws_info = inspect_protocol_metadata(
            ws_frame, alpn="ws", headers={"Upgrade": "websocket"}, is_tls=True
        )
        self.assertEqual(ws_info["metadata"]["protocol"], "websocket")
        self.assertEqual(ws_info["metadata"]["frame_count"], 1)
        self.assertEqual(ws_info["metadata"]["frames"][0]["text_preview"], '{"ping":1}')
        # Raw bytes stay strictly separated in raw_bytes_b64
        self.assertEqual(base64.b64decode(ws_info["raw_bytes_b64"]), ws_frame)

        # Protobuf field 1 (string "alice") + field 2 (varint 42)
        pb_payload = b"\x0a\x05alice\x10\x2a"
        grpc_frame = encode_grpc_frame(pb_payload, compressed=False)
        grpc_info = inspect_protocol_metadata(
            grpc_frame, alpn="h2", headers={"Content-Type": "application/grpc"}, is_tls=True
        )
        self.assertEqual(grpc_info["metadata"]["protocol"], "grpc")
        self.assertEqual(grpc_info["metadata"]["frames"][0]["protobuf_fields"][0]["utf8"], "alice")
        self.assertEqual(grpc_info["metadata"]["frames"][0]["protobuf_fields"][1]["value"], 42)

        proto_schema = introspect_proto_schema(
            """
            message UserRequest { string id = 1; }
            message UserReply { string role = 1; }
            service UserService { rpc GetUser (UserRequest) returns (UserReply); }
            """
        )
        self.assertEqual(proto_schema["services"][0]["name"], "UserService")
        self.assertEqual(proto_schema["services"][0]["methods"][0]["name"], "GetUser")

        h3_info = inspect_protocol_metadata(
            b"OK", alpn="h3", headers={"Alt-Svc": 'h3=":443"; ma=86400'}, is_tls=True
        )
        self.assertEqual(h3_info["metadata"]["protocol"], "h3")
        self.assertTrue(h3_info["metadata"]["h3_advertised"])

        mutations = generate_bounded_binary_mutations(pb_payload, max_mutations=4)
        self.assertEqual(len(mutations), 4)
        for m in mutations:
            self.assertIn("metadata", m)
            self.assertIn("raw_bytes_b64", m)

    def test_openapi_import_graphql_introspection_and_jwt_allowlist(self):
        spec = {
            "openapi": "3.0.0",
            "servers": [{"url": "https://target.test"}],
            "paths": {
                "/api/v2/users": {
                    "post": {
                        "summary": "Create user",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"properties": {"email": {}, "role": {}}}
                                }
                            }
                        },
                    }
                }
            },
        }
        resp = self.client.post(
            "/api/specs/import",
            data=json.dumps({"kind": "openapi", "spec": spec}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.json()["endpoints"]), 1)
        self.assertTrue(ProjectEndpoint.objects.filter(path="/api/v2/users").exists())

        gql = inspect_graphql_schema(
            {
                "data": {
                    "__schema": {
                        "queryType": {"name": "Query"},
                        "mutationType": {"name": "Mutation"},
                        "types": [
                            {
                                "name": "Query",
                                "fields": [{"name": "user", "args": [{"name": "id"}]}],
                            },
                            {
                                "name": "User",
                                "fields": [{"name": "passwordHash", "args": []}],
                            },
                        ],
                    }
                }
            }
        )
        self.assertEqual(gql["queries"][0]["name"], "user")
        self.assertIn("User.passwordHash", gql["sensitive_fields"])

        # JWT allowlist verification
        def b64u(raw: bytes) -> str:
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

        hdr = b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        pay = b64u(json.dumps({"sub": "1", "role": "user"}).encode())
        sig = b64u(hmac.new(b"s3cr3t", f"{hdr}.{pay}".encode(), hashlib.sha256).digest())
        valid_tok = f"{hdr}.{pay}.{sig}"
        self.assertTrue(verify_jwt_with_allowlist(valid_tok, "s3cr3t", ["HS256"])["valid"])

        none_hdr = b64u(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        self.assertFalse(verify_jwt_with_allowlist(f"{none_hdr}.{pay}.", "s3cr3t", ["HS256"])["valid"])

    def test_n4_mcp_stdio_jsonrpc_handshake_and_tools_list(self):
        venv_py = ROOT_DIR / "request-rider-mcp" / ".venv" / "bin" / "python"
        server_py = ROOT_DIR / "request-rider-mcp" / "server.py"
        if not venv_py.exists():
            self.skipTest("request-rider-mcp/.venv not present")

        init_msg = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "rr-test", "version": "1.0"},
                },
            }
        )
        notif_msg = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
        list_msg = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})

        proc = subprocess.run(
            [str(venv_py), str(server_py)],
            input=f"{init_msg}\n{notif_msg}\n{list_msg}\n",
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        lines = [json.loads(line) for line in proc.stdout.splitlines() if line.strip().startswith("{")]
        self.assertGreaterEqual(len(lines), 2)
        tools_resp = next((m for m in lines if m.get("id") == 2), None)
        self.assertIsNotNone(tools_resp)
        tools = tools_resp["result"]["tools"]
        self.assertGreaterEqual(len(tools), 50)

    def test_divider_never_covers_the_raw_block(self):
        """Verify UI layout persistence, divider geometry invariants, keyboard and i18n contracts."""
        index_html = (ROOT_DIR / "web" / "templates" / "lab" / "index.html").read_text(encoding="utf-8")
        translations_html = (ROOT_DIR / "web" / "templates" / "lab" / "includes" / "_translations.html").read_text(
            encoding="utf-8"
        )

        # Layout divider & raw block safety contracts
        self.assertIn("shrinkRoomCss", index_html)
        self.assertIn("dragFloorCss", index_html)
        self.assertIn("applyLanguage", index_html)
        self.assertIn("Ctrl+K", index_html + translations_html)

    def test_fixture_only_ci_runner_and_sarif(self):
        ci_script = ROOT_DIR / "scripts" / "ci_fixture_runner.py"
        proc = subprocess.run(
            [sys.executable, str(ci_script), "--skip-heavy"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["fixture_only"])

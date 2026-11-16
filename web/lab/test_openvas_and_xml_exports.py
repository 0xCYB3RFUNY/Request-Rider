import json
import xml.etree.ElementTree as ET
from unittest.mock import MagicMock, patch

from django.test import Client, TestCase

from lab import openvas_client, xml_exports
from lab.models import (
    OsintEntity,
    OsintGraph,
    Project,
    ProjectEndpoint,
    ScannerRun,
    TrafficRecord,
    Workflow,
    WorkflowRun,
)

SAMPLE_OPENVAS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<get_reports_response status="200" status_text="OK">
  <report id="rep-1">
    <results>
      <result id="res-1">
        <name>Apache HTTP Server Path Traversal</name>
        <host>192.168.1.50</host>
        <port>443/tcp</port>
        <threat>High</threat>
        <severity>7.5</severity>
        <description>Path traversal vulnerability detected.</description>
        <nvt oid="1.3.6.1.4.1.25623.1.0.146850">
          <name>Apache HTTP Server Path Traversal</name>
          <cvss_base>7.5</cvss_base>
          <cve>CVE-2021-41773</cve>
          <solution>Upgrade Apache HTTP Server to 2.4.51 or later.</solution>
        </nvt>
      </result>
    </results>
  </report>
</get_reports_response>
"""


class OpenVASClientTests(TestCase):
    def test_parse_openvas_report_xml(self):
        findings = openvas_client.parse_openvas_report_xml(SAMPLE_OPENVAS_XML)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["engine"], "openvas")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["cvss"], 7.5)
        self.assertEqual(f["host"], "192.168.1.50")
        self.assertEqual(f["port"], "443/tcp")
        self.assertEqual(f["nvt_oid"], "1.3.6.1.4.1.25623.1.0.146850")
        self.assertIn("CVE-2021-41773", f["cve"])

    def test_xxe_rejected(self):
        xxe = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><report>&xxe;</report>'
        with self.assertRaises(openvas_client.GVMError):
            openvas_client.parse_openvas_report_xml(xxe)

    def test_unix_socket_permission_denied_raises_gvm_error_and_returns_502(self):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = PermissionError(13, "Permission denied")
        cfg = openvas_client.GVMConnectionConfig(socket_path="/run/gvmd/gvmd.sock")
        with (
            patch("lab.openvas_client.os.path.exists", return_value=True),
            patch("lab.openvas_client.socket.socket", return_value=mock_sock),
        ):
            with self.assertRaises(openvas_client.GVMError) as ctx:
                openvas_client.GMPClient(cfg).connect()
            self.assertIn("permission denied", str(ctx.exception).lower())
            mock_sock.close.assert_called_once()

            resp = Client().post(
                "/api/scanner/openvas/sync",
                data=json.dumps({"socket_path": "/run/gvmd/gvmd.sock"}),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 502)
            body = resp.json()
            self.assertFalse(body["ok"])
            self.assertIn("permission denied", body["error"].lower())


class XMLExportAndMetasploitTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.project = Project.objects.create(
            name="Test <Project> & Co",
            target="https://app.example.test:8443",
        )
        self.run = ScannerRun.objects.create(
            project=self.project,
            engine="openvas",
            url="https://app.example.test:8443/login",
            findings=[
                {
                    "title": "SQL Injection <test>",
                    "severity": "critical",
                    "endpoint": "https://app.example.test:8443/login?id=1",
                    "method": "POST",
                    "param": "id",
                    "cve": ["CVE-2024-0001"],
                    "nvt_oid": "1.3.6.1.4.1.25623.1.0.999999",
                    "description": "Injected & verified",
                }
            ],
        )
        self.graph = OsintGraph.objects.create(project=self.project, name="OSINT")
        OsintEntity.objects.create(
            graph=self.graph,
            project=self.project,
            entity_type="ip",
            identity="10.0.0.5",
            display_value="10.0.0.5",
        )
        ProjectEndpoint.objects.create(
            project=self.project,
            method="GET",
            path="/api",
            sample_url="https://app.example.test:8443/api",
        )
        TrafficRecord.objects.create(
            project=self.project,
            source="proxy",
            method="GET",
            url="https://app.example.test:8443/health",
        )

    def test_metasploit_xml_structure_and_escaping(self):
        xml_str = xml_exports.export_metasploit_xml(
            self.project,
            scanner_runs=[self.run],
            osint_entities=list(OsintEntity.objects.filter(graph=self.graph)),
            endpoints=list(ProjectEndpoint.objects.filter(project=self.project)),
            traffic_records=list(TrafficRecord.objects.filter(project=self.project)),
        )
        root = ET.fromstring(xml_str)
        self.assertEqual(root.tag, "MetasploitV4")
        addresses = [el.text for el in root.findall("./hosts/host/address")]
        self.assertIn("app.example.test", addresses)
        self.assertIn("10.0.0.5", addresses)
        vuln_names = [el.text for el in root.findall("./hosts/host/vulns/vuln/name")]
        self.assertIn("SQL Injection <test>", vuln_names)
        refs = [el.text for el in root.findall("./hosts/host/vulns/vuln/refs/ref")]
        self.assertIn("CVE-2024-0001", refs)
        self.assertIn("OID-1.3.6.1.4.1.25623.1.0.999999", refs)
        web_vulns = root.findall("./web_vulns/web_vuln")
        self.assertGreaterEqual(len(web_vulns), 1)
        host_el = root.find("./hosts/host")
        self.assertIsNotNone(host_el)
        for tag in ("mac", "comm", "created-at", "updated-at", "os-name", "os-flavor", "os-sp", "os-lang", "purpose", "state"):
            self.assertIsNotNone(host_el.find(tag), f"Missing <{tag}> in <host>")
        svc_el = host_el.find("./services/service")
        if svc_el is not None:
            for tag in ("created-at", "updated-at", "port", "proto", "state", "name", "info"):
                self.assertIsNotNone(svc_el.find(tag), f"Missing <{tag}> in <service>")
        note_el = host_el.find("./notes/note")
        if note_el is not None:
            for tag in ("created-at", "updated-at", "ntype", "critical", "seen", "data"):
                self.assertIsNotNone(note_el.find(tag), f"Missing <{tag}> in <note>")

    def test_project_export_xml_and_msf_xml_endpoints(self):
        res_xml = self.client.get(f"/api/projects/{self.project.id}/export?format=xml")
        self.assertEqual(res_xml.status_code, 200)
        self.assertIn("application/xml", res_xml["Content-Type"])
        root = ET.fromstring(res_xml.content.decode("utf-8"))
        self.assertEqual(root.tag, "project_bundle")

        res_msf = self.client.get(f"/api/projects/{self.project.id}/export?format=msf-xml")
        self.assertEqual(res_msf.status_code, 200)
        self.assertIn("application/xml", res_msf["Content-Type"])
        msf_root = ET.fromstring(res_msf.content.decode("utf-8"))
        self.assertEqual(msf_root.tag, "MetasploitV4")

    @patch("lab.xml_exports.subprocess.run")
    def test_project_metasploit_import_endpoint_uses_no_shell(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="Imported", stderr="")
        res = self.client.post(
            f"/api/projects/{self.project.id}/metasploit-import",
            data=json.dumps({"workspace": "pentest_ws"}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["workspace"], "pentest_ws")
        mock_run.assert_called_once()
        _, kwargs = mock_run.call_args
        self.assertFalse(kwargs.get("shell"))

    @patch("lab.xml_exports.subprocess.run")
    def test_project_metasploit_import_detects_disconnected_db(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="[-] Database not connected\n[-] Failed to connect to the database\n",
            stderr="",
        )
        res = self.client.post(
            f"/api/projects/{self.project.id}/metasploit-import",
            data=json.dumps({"workspace": "pentest_ws"}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 502)
        data = res.json()
        self.assertFalse(data["ok"])
        self.assertIn("sudo msfdb init", data.get("error", ""))

    def test_history_and_workflow_and_scanner_xml_exports(self):
        res_hist = self.client.get("/api/history/export?format=xml")
        self.assertEqual(res_hist.status_code, 200)
        self.assertEqual(ET.fromstring(res_hist.content.decode("utf-8")).tag, "history_export")

        wf = Workflow.objects.create(project=self.project, name="WF1", nodes=[], connections=[])
        res_wf = self.client.get(f"/api/workflows/{wf.id}/export?format=xml")
        self.assertEqual(res_wf.status_code, 200)
        self.assertEqual(ET.fromstring(res_wf.content.decode("utf-8")).tag, "workflow_export")

        wf_run = WorkflowRun.objects.create(workflow=wf, status="completed", mode="manual", output_data={"ok": True})
        res_wfr = self.client.get(f"/api/workflows/runs/{wf_run.id}/export?format=xml")
        self.assertEqual(res_wfr.status_code, 200)
        self.assertEqual(ET.fromstring(res_wfr.content.decode("utf-8")).tag, "workflow_run_export")

        res_scan_xml = self.client.post(
            "/api/scanner/report?view=openvas&format=xml",
            data=json.dumps({"view": "openvas", "findings": self.run.findings}),
            content_type="application/json",
        )
        self.assertEqual(res_scan_xml.status_code, 200)
        self.assertEqual(ET.fromstring(res_scan_xml.content.decode("utf-8")).tag, "scanner_report")

        res_scan_msf = self.client.post(
            "/api/scanner/report?view=openvas&format=msf-xml",
            data=json.dumps({"view": "openvas", "url": self.run.url, "findings": self.run.findings}),
            content_type="application/json",
        )
        self.assertEqual(res_scan_msf.status_code, 200)
        self.assertEqual(ET.fromstring(res_scan_msf.content.decode("utf-8")).tag, "MetasploitV4")

    def test_openvas_import_xml_endpoint(self):
        res = self.client.post(
            "/api/scanner/openvas/import-xml",
            data=json.dumps({"xml": SAMPLE_OPENVAS_XML, "project_id": self.project.id}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["findings_count"], 1)
        run = ScannerRun.objects.get(id=data["run_id"])
        self.assertEqual(run.engine, "openvas")
        self.assertEqual(len(run.findings), 1)

    def test_openvas_status_includes_web_url(self):
        res = self.client.get("/api/scanner/openvas/status")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("web_url", data)
        self.assertIn("web_reachable", data)
        self.assertTrue(str(data["web_url"]).startswith("http"))

    def test_openvas_sync_endpoint_imports_gvm_report(self):
        from unittest.mock import patch

        class _FakeGMPClient:
            def __init__(self, cfg):
                self.cfg = cfg

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def authenticate(self):
                return None

            def get_tasks(self):
                return [{
                    "task_id": "t-1",
                    "name": "Juice Shop GVM Scan",
                    "status": "Done",
                    "progress": 100,
                    "report_id": "r-1",
                    "target": "127.0.0.1",
                    "timestamp": "2026-11-15T17:00:00Z",
                }]

            def get_report_xml(self, report_id):
                self.last_report_id = report_id
                return SAMPLE_OPENVAS_XML

        with patch("lab.openvas_client.GMPClient", _FakeGMPClient):
            res = self.client.post(
                "/api/scanner/openvas/sync",
                data=json.dumps({"project_id": self.project.id}),
                content_type="application/json",
            )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["report_id"], "r-1")
        self.assertEqual(data["findings_count"], 1)
        run = ScannerRun.objects.get(id=data["run_id"])
        self.assertEqual(run.engine, "openvas")
        self.assertEqual(run.findings[0]["title"], "Apache HTTP Server Path Traversal")

    def test_project_import_metasploit_xml_roundtrip(self):
        exp = self.client.get(f"/api/projects/{self.project.id}/export?format=msf-xml")
        self.assertEqual(exp.status_code, 200)
        msf_xml = exp.content.decode("utf-8")

        imp = self.client.post(
            "/api/projects/import-metasploit-xml",
            data=json.dumps({"xml": msf_xml, "project_name": "From Metasploit"}),
            content_type="application/json",
        )
        self.assertEqual(imp.status_code, 200)
        data = imp.json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["project_name"], "From Metasploit")
        self.assertGreaterEqual(data["findings_count"], 1)
        self.assertGreaterEqual(data["hosts_count"], 1)

        bad = self.client.post(
            f"/api/projects/{self.project.id}/import-metasploit-xml",
            data=json.dumps({"xml": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><MetasploitV4/>"}),
            content_type="application/json",
        )
        self.assertEqual(bad.status_code, 400)

    def test_openvas_scan_passes_credentials_and_authenticates(self):
        from unittest.mock import patch

        calls = {"authenticated": False, "username": None, "password": None}

        class _FakeGMPClient:
            def __init__(self, cfg):
                self.cfg = cfg

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def authenticate(self):
                calls["authenticated"] = True
                calls["username"] = self.cfg.username
                calls["password"] = self.cfg.password

            def find_config_id(self, name):
                if not calls["authenticated"]:
                    raise openvas_client.GVMError(
                        "GMP get_configs failed (400): Only command GET_VERSION is allowed before AUTHENTICATE"
                    )
                return "cfg-1"

            def find_scanner_id(self):
                return "scn-1"

            def create_target(self, name, hosts):
                return "tgt-1"

            def create_task(self, name, config_id, target_id, scanner_id):
                return "tsk-1"

            def start_task(self, task_id):
                return "rep-1"

        with patch("lab.openvas_client.GMPClient", _FakeGMPClient):
            res = self.client.post(
                "/api/scanner/openvas/scan",
                data=json.dumps({
                    "project_id": self.project.id,
                    "target": "http://127.0.0.1:3000",
                    "username": "gvm_admin",
                    "password": "secret-password",
                }),
                content_type="application/json",
            )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["task_id"], "tsk-1")
        self.assertTrue(calls["authenticated"])
        self.assertEqual(calls["username"], "gvm_admin")
        self.assertEqual(calls["password"], "secret-password")

    def test_openvas_scan_returns_401_auth_required_on_unauthenticated_gmp(self):
        import os
        from unittest.mock import patch

        class _FakeGMPClient:
            def __init__(self, cfg):
                self.cfg = cfg

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def authenticate(self):
                return None

            def find_config_id(self, name):
                raise openvas_client.GVMError(
                    "GMP get_configs failed (400): Only command GET_VERSION is allowed before AUTHENTICATE"
                )

        with patch.dict(os.environ, {"GVM_PASSWORD": ""}), patch("lab.openvas_client.GMPClient", _FakeGMPClient):
            res = self.client.post(
                "/api/scanner/openvas/scan",
                data=json.dumps({"project_id": self.project.id, "target": "http://127.0.0.1:3000"}),
                content_type="application/json",
            )
        self.assertEqual(res.status_code, 401)
        data = res.json()
        self.assertFalse(data["ok"])
        self.assertTrue(data["auth_required"])
        self.assertIn("GVM", data["error"])

    def test_openvas_sync_post_action_list_with_credentials(self):
        from unittest.mock import patch

        calls = {"authenticated": False, "password": None}

        class _FakeGMPClient:
            def __init__(self, cfg):
                self.cfg = cfg

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def authenticate(self):
                calls["authenticated"] = True
                calls["password"] = self.cfg.password

            def get_tasks(self):
                return [{"task_id": "t-2", "name": "Task 2", "status": "Done", "progress": 100, "report_id": "r-2"}]

        with patch("lab.openvas_client.GMPClient", _FakeGMPClient):
            res = self.client.post(
                "/api/scanner/openvas/sync",
                data=json.dumps({"action": "list", "username": "admin", "password": "pw"}),
                content_type="application/json",
            )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["ok"])
        self.assertTrue(calls["authenticated"])
        self.assertEqual(calls["password"], "pw")
        self.assertEqual(len(data["tasks"]), 1)

    def test_gvm_credentials_save_and_load_from_env_file(self):
        import os
        import tempfile
        from pathlib import Path
        from lab import openvas_client

        with tempfile.TemporaryDirectory() as tmpdir:
            cred_file = Path(tmpdir) / "gvm.env"
            with patch.dict(
                os.environ,
                {"GVM_CREDENTIALS_FILE": str(cred_file), "GVM_USER": "", "GVM_PASSWORD": ""},
                clear=False,
            ):
                openvas_client.save_gvm_credentials("secadmin", "s3cr3t!")
                self.assertTrue(cred_file.is_file())
                os.environ.pop("GVM_USER", None)
                os.environ.pop("GVM_PASSWORD", None)
                cfg = openvas_client.GVMConnectionConfig.from_env_and_payload({})
                self.assertEqual(cfg.username, "secadmin")
                self.assertEqual(cfg.password, "s3cr3t!")

    def test_openvas_options_endpoint(self):
        from unittest.mock import patch

        class _FakeGMPClient:
            def __init__(self, cfg):
                self.cfg = cfg

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def authenticate(self):
                return None

            def get_options(self):
                return {
                    "configs": [{"id": "c1", "name": "Full and fast"}],
                    "scanners": [{"id": "s1", "name": "OpenVAS Default"}],
                    "port_lists": [{"id": "p1", "name": "All IANA assigned TCP"}],
                    "credentials": [{"id": "cr1", "name": "SSH Key"}],
                    "schedules": [],
                    "alerts": [],
                    "alive_tests": openvas_client.ALIVE_TESTS_OPTIONS,
                    "hosts_ordering": openvas_client.HOSTS_ORDERING_OPTIONS,
                }

        with patch("lab.openvas_client.GMPClient", _FakeGMPClient):
            res = self.client.get("/api/scanner/openvas/options")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["configs"][0]["name"], "Full and fast")
        self.assertEqual(data["port_lists"][0]["id"], "p1")
        self.assertIn("Consider Alive", data["alive_tests"])

    def test_openvas_scan_passes_full_target_and_task_settings(self):
        from unittest.mock import patch

        captured = {}

        class _FakeGMPClient:
            def __init__(self, cfg):
                self.cfg = cfg

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def authenticate(self):
                return None

            def create_target(self, name, hosts, **kwargs):
                captured["target"] = {"name": name, "hosts": hosts, **kwargs}
                return "tgt-full"

            def create_task(self, name, config_id, target_id, scanner_id, **kwargs):
                captured["task"] = {
                    "name": name,
                    "config_id": config_id,
                    "target_id": target_id,
                    "scanner_id": scanner_id,
                    **kwargs,
                }
                return "tsk-full"

            def start_task(self, task_id):
                captured["started"] = task_id
                return "rep-full"

        with patch("lab.openvas_client.GMPClient", _FakeGMPClient):
            res = self.client.post(
                "/api/scanner/openvas/scan",
                data=json.dumps({
                    "project_id": self.project.id,
                    "target_name": "JuiceShop Target",
                    "hosts": "127.0.0.1, 10.0.0.0/24",
                    "exclude_hosts": "10.0.0.1",
                    "port_list_id": "pl-1",
                    "alive_tests": "Consider Alive",
                    "reverse_lookup_only": True,
                    "ssh_credential_id": "cred-ssh",
                    "ssh_port": 2222,
                    "task_name": "JuiceShop Full Audit",
                    "config_id": "cfg-1",
                    "scanner_id": "scn-1",
                    "hosts_ordering": "random",
                    "max_checks": 8,
                    "max_hosts": 10,
                    "source_iface": "eth0",
                    "min_qod": 80,
                    "add_to_assets": True,
                    "apply_overrides": False,
                    "alterable": True,
                    "auto_delete": "keep",
                    "auto_delete_data": 3,
                    "comment": "GSA parity test",
                    "start_immediately": False,
                }),
                content_type="application/json",
            )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["ok"])
        self.assertFalse(data["started"])
        self.assertNotIn("started", captured)
        self.assertEqual(captured["target"]["name"], "JuiceShop Target")
        self.assertEqual(captured["target"]["port_list_id"], "pl-1")
        self.assertEqual(captured["target"]["alive_tests"], "Consider Alive")
        self.assertEqual(captured["target"]["ssh_port"], 2222)
        self.assertEqual(captured["task"]["config_id"], "cfg-1")
        self.assertEqual(captured["task"]["hosts_ordering"], "random")
        self.assertEqual(captured["task"]["max_checks"], 8)
        self.assertEqual(captured["task"]["min_qod"], 80)
        self.assertEqual(captured["task"]["auto_delete"], "keep")

    def test_openvas_task_action_endpoint(self):
        from unittest.mock import patch

        actions = []

        class _FakeGMPClient:
            def __init__(self, cfg):
                self.cfg = cfg

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def authenticate(self):
                return None

            def start_task(self, task_id):
                actions.append(("start", task_id))
                return "rep-1"

            def stop_task(self, task_id):
                actions.append(("stop", task_id))

            def resume_task(self, task_id):
                actions.append(("resume", task_id))
                return "rep-2"

            def delete_task(self, task_id):
                actions.append(("delete", task_id))

            def get_task_status(self, task_id):
                return {"task_id": task_id, "status": "Running", "progress": 10, "report_id": "rep-1"}

            def get_tasks(self):
                return []

        with patch("lab.openvas_client.GMPClient", _FakeGMPClient):
            for act in ("start", "stop", "resume", "delete"):
                res = self.client.post(
                    "/api/scanner/openvas/task-action",
                    data=json.dumps({"task_id": "t-99", "action": act}),
                    content_type="application/json",
                )
                self.assertEqual(res.status_code, 200)
                self.assertTrue(res.json()["ok"])
        self.assertEqual(actions, [("start", "t-99"), ("stop", "t-99"), ("resume", "t-99"), ("delete", "t-99")])

    def test_openvas_create_port_list_and_credential_endpoints(self):
        from unittest.mock import patch

        created = {}

        class _FakeGMPClient:
            def __init__(self, cfg):
                self.cfg = cfg

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def authenticate(self):
                return None

            def create_port_list(self, name, port_range, comment=""):
                created["port_list"] = (name, port_range)
                return "pl-new"

            def create_credential(self, name, username="", password="", credential_type="up", comment="", **kwargs):
                created["credential"] = (name, username, password, credential_type)
                created["credential_kwargs"] = kwargs
                return "cred-new"

            def get_options(self):
                return {
                    "configs": [],
                    "scanners": [],
                    "port_lists": [{"id": "pl-new", "name": "Web Ports"}],
                    "credentials": [{"id": "cred-new", "name": "SSH User"}],
                    "schedules": [],
                    "alerts": [],
                    "alive_tests": openvas_client.ALIVE_TESTS_OPTIONS,
                    "hosts_ordering": openvas_client.HOSTS_ORDERING_OPTIONS,
                }

        with patch("lab.openvas_client.GMPClient", _FakeGMPClient):
            res_pl = self.client.post(
                "/api/scanner/openvas/create-port-list",
                data=json.dumps({"name": "Web Ports", "port_range": "T:80,443,3000"}),
                content_type="application/json",
            )
            self.assertEqual(res_pl.status_code, 200)
            self.assertEqual(res_pl.json()["id"], "pl-new")
            self.assertEqual(created["port_list"], ("Web Ports", "T:80,443,3000"))

            res_cr = self.client.post(
                "/api/scanner/openvas/create-credential",
                data=json.dumps({"name": "SSH User", "cred_username": "kali", "cred_password": "pw", "credential_type": "up"}),
                content_type="application/json",
            )
            self.assertEqual(res_cr.status_code, 200)
            self.assertEqual(res_cr.json()["id"], "cred-new")
            self.assertEqual(created["credential"], ("SSH User", "kali", "pw", "up"))

    def test_openvas_create_credential_usk_snmp_pw_xml_and_validation(self):
        import xml.etree.ElementTree as ET
        from unittest.mock import patch

        sent_xml = []

        class _FakeTransportClient(openvas_client.GMPClient):
            def __init__(self):
                super().__init__(openvas_client.GVMConnectionConfig())

            def send_xml(self, xml_cmd: str):
                sent_xml.append(xml_cmd)
                return ET.fromstring('<create_credential_response status="201" status_text="OK, resource created" id="cred-xyz"/>')

        fake = _FakeTransportClient()
        cid_usk = fake.create_credential("SSH Key", username="root", credential_type="usk", private_key="KEYDATA", passphrase="p1")
        self.assertEqual(cid_usk, "cred-xyz")
        self.assertIn("<type>usk</type>", sent_xml[-1])
        self.assertIn("<private>KEYDATA</private>", sent_xml[-1])
        self.assertIn("<phrase>p1</phrase>", sent_xml[-1])

        cid_snmp = fake.create_credential(
            "SNMP v3", username="snmpu", password="apw", credential_type="snmp",
            auth_algorithm="sha256", privacy_password="ppw", privacy_algorithm="aes"
        )
        self.assertEqual(cid_snmp, "cred-xyz")
        self.assertIn("<auth_algorithm>sha256</auth_algorithm>", sent_xml[-1])
        self.assertIn("<algorithm>aes</algorithm>", sent_xml[-1])

        with patch("lab.openvas_client.GMPClient") as mock_cls:
            res_bad_usk = self.client.post(
                "/api/scanner/openvas/create-credential",
                data=json.dumps({"name": "SSH Key", "cred_username": "root", "credential_type": "usk"}),
                content_type="application/json",
            )
            self.assertEqual(res_bad_usk.status_code, 400)
            mock_cls.assert_not_called()

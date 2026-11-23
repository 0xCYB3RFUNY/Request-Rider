"""Tests for F10 One-Click Reproducible PoC & Regression Packager."""
import ast
import json
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from django.test import Client, TestCase

from lab.poc_generator import generate_poc


class _FixtureHandler(BaseHTTPRequestHandler):
    vulnerable = True

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        if _FixtureHandler.vulnerable and "admin" in body:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"leak":"SECRET_LEAK_TOKEN"}')
        else:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'{"error":"forbidden"}')

    def log_message(self, format, *args):
        return


class PoCGeneratorTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_python_poc_is_valid_ast_and_executes_against_vulnerable_and_patched_fixture(self):
        srv = HTTPServer(("127.0.0.1", 0), _FixtureHandler)
        port = srv.server_address[1]
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        try:
            poc = generate_poc({
                "format": "python",
                "finding": {
                    "title": "Admin BOLA Leak",
                    "method": "POST",
                    "url": f"http://127.0.0.1:{port}/api/profile",
                    "evidence": "SECRET_LEAK_TOKEN",
                },
                "headers": {"Content-Type": "application/json"},
                "body": '{"role":"admin"}',
                "expected_status": 200,
            })
            ast.parse(poc["code"])

            with tempfile.NamedTemporaryFile("w", suffix=".py", delete=True) as tmp:
                tmp.write(poc["code"])
                tmp.flush()

                _FixtureHandler.vulnerable = True
                res_vuln = subprocess.run(
                    [sys.executable, tmp.name],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(res_vuln.returncode, 0, res_vuln.stdout + res_vuln.stderr)
                self.assertIn("[+] VULNERABLE", res_vuln.stdout)

                _FixtureHandler.vulnerable = False
                res_patched = subprocess.run(
                    [sys.executable, tmp.name],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(res_patched.returncode, 1, res_patched.stdout + res_patched.stderr)
                self.assertIn("[-] NOT REPRODUCED / PATCHED", res_patched.stdout)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_playwright_go_and_curl_formats(self):
        pw = generate_poc({
            "format": "playwright",
            "url": "https://target.local/xss?q=1",
            "evidence_marker": "<svg onload=alert(1)>",
        })
        ast.parse(pw["code"])
        self.assertIn("browser.close()", pw["code"])

        go_poc = generate_poc({
            "format": "go",
            "method": "POST",
            "url": "https://target.local/api/redeem",
            "headers": {"Authorization": "Bearer abc"},
            "body": '{"code":"SAVE"}',
        })
        self.assertIn("sync.WaitGroup", go_poc["code"])
        self.assertIn("package main", go_poc["code"])

        curl_poc = generate_poc({
            "format": "curl",
            "method": "POST",
            "url": "https://target.local/api/redeem",
            "headers": {"X-Test": "1"},
            "body": "a=1",
        })
        self.assertIn("curl", curl_poc["code"])
        self.assertIn("POST", curl_poc["code"])
        self.assertIn("'X-Test: 1'", curl_poc["code"])

    def test_api_poc_generate_and_ui_elements(self):
        resp = self.client.post(
            "/api/poc/generate",
            data=json.dumps({
                "format": "python",
                "exchange": {"method": "GET", "url": "https://target.local/admin"},
            }),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["filename"], "reproduce_poc.py")
        ast.parse(data["code"])

        html = self.client.get("/").content.decode("utf-8")
        self.assertIn("repeater-export-poc-btn", html)
        self.assertIn("repeater-poc-format", html)

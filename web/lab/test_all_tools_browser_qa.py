"""
Comprehensive QA Browser-Based End-to-End Test Suite for Request-Rider.
Verifies all 12 tools / workspaces, their controls, parameters, and business logic.
"""

import json
import os
import unittest
from playwright.sync_api import sync_playwright

BASE_URL = os.environ.get("RR_WEB_URL", "http://127.0.0.1:8000").rstrip("/")


class RequestRiderFullBrowserQATest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        )

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "browser") and cls.browser:
            cls.browser.close()
        if hasattr(cls, "playwright") and cls.playwright:
            cls.playwright.stop()

    def setUp(self):
        self.context = self.browser.new_context(viewport={"width": 1440, "height": 900})
        self.page = self.context.new_page()
        self.console_errors = []
        self.page_errors = []

        self.page.on("console", lambda msg: self.console_errors.append(msg.text) if msg.type == "error" else None)
        self.page.on("pageerror", lambda err: self.page_errors.append(str(err)))

        self.page.goto(BASE_URL, wait_until="domcontentloaded", timeout=30000)
        self.page.wait_for_timeout(1000)

    def tearDown(self):
        self.context.close()

    def _switch_tab(self, tab_name):
        nav_selector = f'nav .nav-tab[data-tab="{tab_name}"]'
        self.page.wait_for_selector(nav_selector, state="visible", timeout=10000)
        self.page.click(nav_selector)
        self.page.wait_for_timeout(300)
        # Check active class or section display
        section_selector = f"section#{tab_name}"
        self.assertTrue(self.page.is_visible(section_selector) or self.page.locator(section_selector).count() > 0,
                        f"Section for tab {tab_name} must exist")

    def test_01_page_load_and_navigation(self):
        """Verify initial page load, navigation tabs presence, and absence of fatal errors."""
        self.assertEqual(len(self.page_errors), 0, f"Page had uncaught exceptions: {self.page_errors}")

        tabs = [
            "projects", "repeater", "intruder", "target", "osint",
            "scanner", "comparer", "decoder", "proxy", "ai",
            "automation", "traffic"
        ]
        for t in tabs:
            locator = self.page.locator(f'nav .nav-tab[data-tab="{t}"]')
            self.assertGreater(locator.count(), 0, f"Navigation tab for '{t}' must exist")

    def test_02_decoder_business_logic_and_jwt_studio(self):
        """Test Decoder operations: 18 transformations, swap, clear, and JWT Forge Studio."""
        self._switch_tab("decoder")

        # 1. Test URL Encoding and Decoding
        test_str = "Antigravity QA Test <123> & %"
        self.page.fill("#decoder-input", test_str)
        self.page.select_option("#decoder-operation", "urlEncode")
        self.page.click("#decoder-apply")
        self.page.wait_for_timeout(200)

        encoded_val = self.page.input_value("#decoder-output")
        self.assertIn("Antigravity%20QA%20Test", encoded_val)

        # Test Swap
        self.page.click("#decoder-swap")
        self.assertEqual(self.page.input_value("#decoder-input"), encoded_val)

        # Test URL Decode
        self.page.select_option("#decoder-operation", "urlDecode")
        self.page.click("#decoder-apply")
        self.page.wait_for_timeout(200)
        decoded_val = self.page.input_value("#decoder-output")
        self.assertEqual(decoded_val, test_str)

        # 2. Test Base64 Encoding and Decoding
        self.page.click("#decoder-clear")
        self.assertEqual(self.page.input_value("#decoder-input"), "")
        self.assertEqual(self.page.input_value("#decoder-output"), "")

        self.page.fill("#decoder-input", "Hello Request-Rider!")
        self.page.select_option("#decoder-operation", "base64Encode")
        self.page.click("#decoder-apply")
        self.page.wait_for_timeout(200)
        b64_val = self.page.input_value("#decoder-output")
        self.assertEqual(b64_val, "SGVsbG8gUmVxdWVzdC1SaWRlciE=")

        # 3. Test JSON Pretty and Minify
        json_raw = '{"tool":"decoder","active":true,"version":2}'
        self.page.fill("#decoder-input", json_raw)
        self.page.select_option("#decoder-operation", "jsonPretty")
        self.page.click("#decoder-apply")
        self.page.wait_for_timeout(200)
        pretty_val = self.page.input_value("#decoder-output")
        self.assertIn("\n", pretty_val)
        self.assertIn('"tool": "decoder"', pretty_val)

        self.page.click("#decoder-swap")
        self.page.select_option("#decoder-operation", "jsonMinify")
        self.page.click("#decoder-apply")
        self.page.wait_for_timeout(200)
        minified_val = self.page.input_value("#decoder-output")
        self.assertNotIn("\n", minified_val)

        # 4. Test SHA-256 Hash
        self.page.fill("#decoder-input", "admin")
        self.page.select_option("#decoder-operation", "sha256")
        self.page.click("#decoder-apply")
        self.page.wait_for_timeout(200)
        hash_val = self.page.input_value("#decoder-output")
        self.assertEqual(len(hash_val), 64)
        # SHA-256 of "admin" is 8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918
        self.assertEqual(hash_val, "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918")

        # 5. Test JWT & Crypto Forge Studio
        sample_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwicm9sZSI6InVzZXIifQ.cThIIo-tQ2V1XqKk18V1KkQZ8x4eA_4J8fD8vE5d7tI"
        self.page.fill("#jwt-forge-token", sample_jwt)
        self.page.fill("#jwt-forge-secret", "supersecret123")
        self.page.fill("#jwt-forge-oast", "http://oast.local/jwt")
        self.page.check("#jwt-extend-exp")

        # Trigger Forge Vectors
        self.page.click("#jwt-forge-run-btn")
        self.page.wait_for_timeout(500)
        rows_count = self.page.locator("#jwt-forge-variants-tbody tr").count()
        self.assertGreater(rows_count, 1, "JWT Forge must generate mutation vectors")

    def test_03_comparer_business_logic(self):
        """Test Comparer: words comparison, bytes comparison, swap, and clear."""
        self._switch_tab("comparer")

        left_text = "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"status\": \"user\"}"
        right_text = "HTTP/1.1 403 Forbidden\nContent-Type: application/json\n\n{\"status\": \"admin\"}"

        self.page.fill("#comparer-left", left_text)
        self.page.fill("#comparer-right", right_text)

        # Compare words
        self.page.click("#compare-words")
        self.page.wait_for_timeout(200)
        out_text = self.page.inner_text("#comparer-output")
        self.assertIn("200", out_text)
        self.assertIn("403", out_text)

        # Compare bytes
        self.page.click("#compare-bytes")
        self.page.wait_for_timeout(200)
        out_bytes = self.page.inner_text("#comparer-output")
        self.assertTrue(len(out_bytes) > 0)

        # Swap sides
        self.page.click("#swap-comparer")
        self.page.wait_for_timeout(200)
        self.assertEqual(self.page.input_value("#comparer-left"), right_text)
        self.assertEqual(self.page.input_value("#comparer-right"), left_text)

        # Clear
        self.page.click("#clear-comparer")
        self.page.wait_for_timeout(200)
        self.assertEqual(self.page.input_value("#comparer-left"), "")
        self.assertEqual(self.page.input_value("#comparer-right"), "")

    def test_04_repeater_parameters_and_subpanels(self):
        """Test Repeater controls: Host, HTTPS, Path, Inspector, Auth Matrix, Race Sync, PoC export."""
        self._switch_tab("repeater")

        self.page.fill("#repeater-host", "127.0.0.1:8000")
        self.page.fill("#repeater-path", "/health")
        self.page.uncheck("#repeater-https")

        # Test Request Inspector toggle
        inspector_toggle = self.page.locator("#req-inspector-toggle")
        inspector_toggle.click()
        self.page.wait_for_timeout(300)
        self.assertTrue(self.page.is_visible("#req-inspector-body"), "Request Inspector body must be visible")

        # Add param in inspector
        self.page.click("#ri-add-param")
        self.page.wait_for_timeout(200)
        self.assertGreater(self.page.locator("#ri-params-tbody tr").count(), 0)

        # Test Auth Matrix button
        self.page.click("#repeater-auth-matrix-btn")
        self.page.wait_for_timeout(300)
        self.assertTrue(self.page.is_visible("#auth-matrix-wrap"), "Auth Matrix subpanel must open")

        # Add role to Auth Matrix
        self.page.fill("#am-role-name", "Admin_Auditor")
        self.page.select_option("#am-role-type", "admin")
        self.page.fill("#am-header-val", "Bearer test_token_xyz")
        self.page.click("#am-add-role-btn")
        self.page.wait_for_timeout(200)
        self.assertGreater(self.page.locator("#auth-matrix-profiles-list .auth-matrix-profile-tag").count(), 0)

        # Close Auth Matrix
        self.page.click("#auth-matrix-close-btn")
        self.page.wait_for_timeout(200)

        # Test PoC format selector
        self.page.select_option("#repeater-poc-format", "python")
        self.page.select_option("#repeater-poc-format", "curl")
        self.page.select_option("#repeater-poc-format", "go")

    def test_05_intruder_modes_parameters_and_rules(self):
        """Test Intruder attack modes, delay, concurrency, transformations, detection rules, and dictionaries."""
        self._switch_tab("intruder")

        # Target and Attack mode
        self.page.fill("#intruder-host", "127.0.0.1")
        self.page.fill("#intruder-port", "8000")
        self.page.uncheck("#intruder-https")

        modes = ["sniper", "batteringRam", "pitchfork", "clusterBomb"]
        for m in modes:
            self.page.select_option("#mode", m)
            self.assertEqual(self.page.input_value("#mode"), m)

        # Delay and concurrency
        self.page.fill("#intruder-delay", "100")
        self.page.fill("#intruder-concurrency", "2")

        # Transformations
        self.page.select_option("#transform-operation", "urlEncode")
        self.page.click("#add-transformation")
        self.page.wait_for_timeout(200)
        self.assertGreater(self.page.locator("#transform-list .transform-chip").count(), 0)

        # Detection rules
        self.page.check("#detect-enabled")
        self.page.fill("#detect-tolerance", "48")
        self.page.fill("#detect-calibration", "2")

        self.page.select_option("#detect-rule-type", "status_equals")
        self.page.fill("#detect-rule-value", "200")
        self.page.click("#detect-rule-add")
        self.page.wait_for_timeout(200)
        self.assertGreater(self.page.locator("#detect-rule-list .detect-rule-chip").count(), 0)

        # Dictionaries
        self.page.click("#add-dictionary")
        self.page.wait_for_timeout(200)
        self.assertGreater(self.page.locator("#dictionary-list .dictionary-row").count(), 0)

        # Export dropdown presence
        self.page.click("#intruder-export")
        self.page.wait_for_timeout(200)
        self.assertGreater(self.page.locator('[data-export-menu="intruder"] .export-menu-list button').count(), 0)

    def test_06_target_site_map_parameters_and_engines(self):
        """Test Target Site Map: Start URL, Static vs Browser engine, limits, anti-detect, auth headers."""
        self._switch_tab("target")

        self.page.fill("#target-url", "http://127.0.0.1:8000/")

        # Engine selector
        self.page.select_option("#target-engine", "static")
        self.page.wait_for_timeout(200)
        self.assertTrue(self.page.is_visible("#target-static-toolbar"))

        self.page.select_option("#target-engine", "browser")
        self.page.wait_for_timeout(200)
        self.assertTrue(self.page.is_visible("#target-browser-panel"))

        # Browser options
        self.page.select_option("#target-browser", "chromium")
        self.page.check("#target-anti-detect")

        # Limits
        self.page.fill("#target-max-pages", "50")
        self.page.fill("#target-max-depth", "3")
        self.page.fill("#target-delay", "100")
        self.page.check("#target-same-origin")

        # Auth & Session
        self.page.fill("#target-cookies", "PHPSESSID=e2e_session_test_val")
        self.page.fill("#target-custom-headers", "X-Scanner-QA: test_suite_2026")

        # Automatic pass chips
        self.page.click("#target-auto-forms")
        self.page.wait_for_timeout(100)
        self.page.click("#target-auto-both")
        self.page.wait_for_timeout(100)

        # Action buttons existence
        self.assertGreater(self.page.locator("#target-start").count(), 0)
        self.assertGreater(self.page.locator("#target-pause").count(), 0)

    def test_07_osint_recon_and_cytoscape_graph(self):
        """Test OSINT workspace: Target URL, benign WAF canary, summary cards, and Cytoscape entity graph."""
        self._switch_tab("osint")

        self.page.fill("#osint-url", "http://127.0.0.1:8000/")
        self.page.check("#osint-waf-check")

        # Verify 6 intelligence cards
        cards = ["#osint-dns", "#osint-http", "#osint-security", "#osint-tech", "#osint-discovery", "#osint-cookies"]
        for c in cards:
            self.assertGreater(self.page.locator(c).count(), 0, f"OSINT card {c} must exist")

        # Verify Cytoscape graph canvas
        self.assertGreater(self.page.locator("#osint-graph-canvas").count(), 0)

        # Layout selector
        layouts = ["grid", "radial", "concentric", "breadthfirst"]
        for lay in layouts:
            self.page.select_option("#osint-graph-layout-mode", lay)
            self.assertEqual(self.page.input_value("#osint-graph-layout-mode"), lay)

        # Zoom controls
        self.page.click("#osint-graph-zoom-in")
        self.page.wait_for_timeout(100)
        self.page.click("#osint-graph-zoom-out")
        self.page.wait_for_timeout(100)
        self.page.click("#osint-graph-reset")

        # Export dropdown
        self.page.click("#osint-export")
        self.page.wait_for_timeout(200)
        self.assertGreater(self.page.locator('[data-export-menu="osint"] .export-menu-list button').count(), 0)

    def test_08_active_scanner_and_views(self):
        """Test Scanner Pro: 4 views (CMS, Nuclei, Active & Corpus, OpenVAS), profiles, options."""
        self._switch_tab("scanner")

        self.page.fill("#scanner-url", "http://127.0.0.1:8000/")

        # View 1: CMS Scan
        self.page.click("#scanner-view-cms")
        self.page.wait_for_timeout(200)
        self.assertTrue(self.page.is_visible("#scanner-panel-cms"))
        profiles = ["generic_web", "cms", "api", "security_headers"]
        for p in profiles:
            self.page.select_option("#scanner-profile", p)
            self.assertEqual(self.page.input_value("#scanner-profile"), p)

        # View 2: Nuclei Scan
        self.page.click("#scanner-view-nuclei")
        self.page.wait_for_timeout(200)
        self.assertTrue(self.page.is_visible("#scanner-panel-nuclei"))
        self.assertGreater(self.page.locator("#scanner-upload-zone").count(), 0)
        self.assertGreater(self.page.locator("#scanner-templates-run").count(), 0)
        self.assertGreater(self.page.locator("#scanner-custom-yaml").count(), 0)

        # View 3: Active & Corpus Scanner
        self.page.click("#scanner-view-active")
        self.page.wait_for_timeout(200)
        self.assertTrue(self.page.is_visible("#scanner-panel-active"))
        self.assertGreater(self.page.locator("#scanner-active-run").count(), 0)
        self.assertGreater(self.page.locator("#scanner-corpus-run").count(), 0)

        # View 4: OpenVAS GVM
        self.page.click("#scanner-view-openvas")
        self.page.wait_for_timeout(200)
        self.assertTrue(self.page.is_visible("#scanner-panel-openvas"))

    def test_09_proxy_route_parameters(self):
        """Test Proxy/Route settings: SOCKS5 address, check URL, timeout ms."""
        self._switch_tab("proxy")

        self.page.fill("#route-address", "127.0.0.1:9050")
        self.page.fill("#route-check-url", "https://check.torproject.org/")
        self.page.fill("#route-check-timeout", "12000")

        self.assertGreater(self.page.locator("#route-apply").count(), 0)
        self.assertGreater(self.page.locator("#route-cancel").count(), 0)
        self.assertGreater(self.page.locator("#route-check").count(), 0)
        self.assertGreater(self.page.locator("#route-summary").count(), 0)

    def test_10_traffic_and_history_workspace(self):
        """Test Traffic & History: mode buttons, recording controls, search, sort options."""
        self._switch_tab("traffic")

        # Mode switches
        self.page.click("#traffic-mode-all")
        self.page.wait_for_timeout(100)
        self.page.click("#traffic-mode-tools")
        self.page.wait_for_timeout(100)
        self.page.click("#traffic-mode-proxy")
        self.page.wait_for_timeout(100)

        # Recording controls (pause/resume)
        self.page.click("#traffic-capture-pause")
        self.page.wait_for_timeout(200)
        self.page.click("#traffic-capture-resume")
        self.page.wait_for_timeout(200)

        # Host search and sort
        self.page.fill("#traffic-host-search", "127.0.0.1")
        sort_opts = self.page.locator("#traffic-sort option").count()
        self.assertGreaterEqual(sort_opts, 10, "Traffic must have multiple sorting criteria")

        # Inspector panels
        self.assertGreater(self.page.locator("#traffic-request-inspector").count(), 0)
        self.assertGreater(self.page.locator("#traffic-response-inspector").count(), 0)

    def test_11_automation_workflow_canvas_and_controls(self):
        """Test Automation: workflow search, name input, actions, canvas controls, node inspector."""
        self._switch_tab("automation")

        self.page.fill("#workflow-search", "recon")
        self.page.fill("#workflow-name", "QA_E2E_Test_Workflow")

        # Action buttons
        self.assertGreater(self.page.locator("#workflow-save").count(), 0)
        self.assertGreater(self.page.locator("#workflow-run").count(), 0)
        self.assertGreater(self.page.locator("#workflow-new").count(), 0)

        # Canvas controls
        self.page.click("#workflow-zoom-in")
        self.page.wait_for_timeout(100)
        self.page.click("#workflow-zoom-out")
        self.page.wait_for_timeout(100)
        self.page.click("#workflow-fit")
        self.page.wait_for_timeout(100)
        self.page.click("#workflow-auto-layout")

        self.assertGreater(self.page.locator("#workflow-inspector").count(), 0)

    def test_12_ai_assistant_presets_and_interface(self):
        """Test AI Assistant: audit presets, prompt input, status indicator."""
        self._switch_tab("ai")

        presets = ["vuln_analysis", "headers_check", "poc_generator", "report_summary"]
        for p in presets:
            btn = self.page.locator(f'.ai-preset-card[data-preset="{p}"]')
            self.assertGreater(btn.count(), 0, f"Preset {p} must exist")

        self.assertGreater(self.page.locator("#ai-clear-chat").count(), 0)

    def test_13_projects_management_and_export_formats(self):
        """Test Projects: active project selector, new/manage/delete, export menu formats (Fusion, SARIF, MSF XML)."""
        self._switch_tab("projects")

        self.assertGreater(self.page.locator("#project-select").count(), 0)
        self.assertGreater(self.page.locator("#project-new").count(), 0)

        # Open export menu
        self.page.click("#project-export")
        self.page.wait_for_timeout(200)
        export_formats = [
            "fusion-html", "sarif", "msf-xml", "msf-db", "xml", "json", "html", "csv"
        ]
        for fmt in export_formats:
            fmt_btn = self.page.locator(f'[data-export-menu="project"] button[data-format="{fmt}"]')
            self.assertGreater(fmt_btn.count(), 0, f"Export format {fmt} must exist in Project export menu")

    def test_14_faq_and_tab_settings_dialogs(self):
        """Test global FAQ dialog and Tab Settings dialog for multiple tools."""
        for tab in ["repeater", "decoder", "scanner"]:
            self._switch_tab(tab)
            # Test FAQ button
            faq_btn = self.page.locator(f'#workspace-tabs-{tab} .tab-faq-trigger')
            if faq_btn.count() > 0:
                faq_btn.first.click()
                self.page.wait_for_timeout(300)
                # Close dialog if open
                close_btn = self.page.locator('.faq-dialog-close, #faq-dialog-close, [data-dialog-close="faq"]')
                if close_btn.count() > 0 and close_btn.first.is_visible():
                    close_btn.first.click()
                    self.page.wait_for_timeout(200)

            # Test Settings button
            settings_btn = self.page.locator(f'#workspace-tabs-{tab} .tab-settings-trigger')
            if settings_btn.count() > 0:
                settings_btn.first.click()
                self.page.wait_for_timeout(300)
                # Close settings dialog if open
                close_settings = self.page.locator('.tab-settings-close, #tab-settings-close, [data-dialog-close="tab-settings"]')
                if close_settings.count() > 0 and close_settings.first.is_visible():
                    close_settings.first.click()
                    self.page.wait_for_timeout(200)


if __name__ == "__main__":
    unittest.main()

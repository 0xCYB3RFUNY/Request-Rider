import http.server
import json
import os
import threading
import unittest
import urllib.request

from playwright.sync_api import sync_playwright

BASE_URL = os.environ.get("RR_WEB_URL", "http://127.0.0.1:8000").rstrip("/")


class JuiceShopFixtureHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/rest/products/search"):
            body = json.dumps({
                "status": "success",
                "data": [
                    {"id": 1, "name": "Apple Juice (1000ml)", "price": 1.99},
                    {"id": 2, "name": "Orange Juice (1000ml)", "price": 2.99},
                ],
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path.startswith("/api/Challenges"):
            body = json.dumps({"status": "success", "data": [{"key": "scoreBoardChallenge", "solved": False}]}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
            return

        html = b"<!doctype html><html><head><title>OWASP Juice Shop</title></head><body><h1>OWASP Juice Shop</h1></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Powered-By", "Express")
        self.end_headers()
        self.wfile.write(html)

    def log_message(self, format, *args):
        return


def _web_is_up():
    try:
        with urllib.request.urlopen(BASE_URL + "/", timeout=2) as resp:
            return resp.status == 200
    except Exception:
        return False


@unittest.skipUnless(_web_is_up(), f"Web UI at {BASE_URL} is not running")
class JuiceShopBrowserE2ETest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), JuiceShopFixtureHandler)
        cls.fixture_port = cls.fixture_server.server_address[1]
        cls.fixture_url = f"http://127.0.0.1:{cls.fixture_port}"
        cls.fixture_thread = threading.Thread(target=cls.fixture_server.serve_forever, daemon=True)
        cls.fixture_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.fixture_server.shutdown()
        cls.fixture_server.server_close()

    def test_ui_renders_vulnx_vulncov_tlsx_subfinder_with_juice_shop_fixture(self):
        console_errors = []
        page_errors = []

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
            page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
            page.on("pageerror", lambda err: page_errors.append(str(err)))

            page.goto(BASE_URL + "/", wait_until="domcontentloaded")
            page.wait_for_function("typeof renderScannerTemplateStats === 'function' && typeof scannerTemplateRow === 'function'")

            # 1. Verify Juice Shop fixture endpoint is reachable
            with urllib.request.urlopen(f"{self.fixture_url}/rest/products/search?q=apple", timeout=2) as resp:
                fixture_payload = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(fixture_payload["status"], "success")

            # 2. Verify FAQ (subfinder + scanner badges) updated descriptions in DOM
            faq_text = page.locator(".faq-card", has_text="subdomains").inner_text()
            self.assertIn("anubis", faq_text)
            self.assertIn("hackertarget", faq_text)
            self.assertIn("threatcrowd", faq_text)

            badges_faq_text = page.locator(".faq-card", has_text="KEV / EPSS / Coverage").inner_text()
            for token in ["[KEV]", "EPSS", "[RANSOMWARE]", "[PoC]", "Blind spots"]:
                self.assertIn(token, badges_faq_text)

            # 3. Verify vulncov (CoverageReport) + vulnx (KEV/EPSS/PoC/Ransomware/Patch) rendering in DOM
            scanner_dom = page.evaluate(
                """(fixtureUrl) => {
                    const statsPayload = {
                        templates: [
                            { status: 'matched' },
                            { status: 'not_matched' },
                            { status: 'not_matched' },
                            { status: 'skipped' }
                        ],
                        findings: [{ template_id: 'juice-shop-sqli' }],
                        stats: {
                            coverage_report: {
                                total_planned: 4,
                                executed: 3,
                                matched: 1,
                                not_matched: 2,
                                skipped_or_unverified: 1,
                                coverage_percent: 75.0,
                                hit_rate_percent: 33.33,
                                blind_spots: [{ id: 'juice-shop-timeout', status: 'skipped', reason: 'timeout' }]
                            }
                        }
                    };
                    renderScannerTemplateStats(statsPayload);
                    const statsText = document.getElementById('scanner-tpl-perfile-stats').textContent;

                    const row = scannerTemplateRow({
                        name: 'juice-shop-sqli.yaml',
                        path: 'http/cves/2024/juice-shop-sqli.yaml',
                        template_id: 'CVE-2024-5678',
                        title: 'OWASP Juice Shop SQL Injection',
                        severity: 'critical',
                        status: 'matched',
                        cve: ['CVE-2024-5678'],
                        findings: [{
                            matched_at: fixtureUrl + '/rest/products/search?q=apple',
                            matcher_name: 'sqlite-error',
                            evidence: 'SQLITE_ERROR near syntax',
                            is_kev: true,
                            epss_score: 0.942,
                            known_ransomware_campaign_use: 'Known',
                            is_poc: true,
                            age_in_days: 14,
                            patch_url: 'https://owasp.org/juice-shop/patch'
                        }]
                    });
                    return { statsText, rowText: row.textContent };
                }""",
                self.fixture_url,
            )
            self.assertIn("Coverage: 75.0% (3/4) · Blind spots: 1", scanner_dom["statsText"])
            for token in ["[KEV]", "EPSS 94.2%", "[RANSOMWARE]", "[PoC]", "14d", "patch: https://owasp.org/juice-shop/patch"]:
                self.assertIn(token, scanner_dom["rowText"])

            # 3b. Verify the 5 badges render in OpenVAS (GVM), and stay absent in CMS / Active & Corpus
            other_scanners_dom = page.evaluate(
                """(fixtureUrl) => {
                    const sampleFinding = {
                        id: 'js-1',
                        title: 'Juice Shop CVE Finding',
                        severity: 'critical',
                        module: 'sqli',
                        endpoint: fixtureUrl + '/rest/products/search',
                        evidence: 'SQLITE_ERROR',
                        recommendation: 'Upgrade dependency',
                        is_kev: true,
                        epss_score: 0.942,
                        known_ransomware_campaign_use: 'Known',
                        is_poc: true,
                        age_in_days: 14,
                        patch_url: 'https://owasp.org/juice-shop/patch',
                        cve: ['CVE-2024-5678']
                    };
                    renderCmsFindings({ url: fixtureUrl, findings: [sampleFinding] });
                    const cmsText = document.getElementById('scanner-cms-body').textContent;

                    renderActiveScanFindings({ url: fixtureUrl, findings: [sampleFinding] });
                    const activeText = document.getElementById('scanner-active-body').textContent;

                    renderOpenvasFindings([sampleFinding], fixtureUrl);
                    const openvasText = document.getElementById('scanner-openvas-body').textContent;

                    return { cmsText, activeText, openvasText };
                }""",
                self.fixture_url,
            )
            for token in ["[KEV]", "EPSS 94.2%", "[RANSOMWARE]", "[PoC]", "14d"]:
                self.assertIn(token, other_scanners_dom["openvasText"], f"Missing {token} in openvasText")
                self.assertNotIn(token, other_scanners_dom["cmsText"], f"Unexpected {token} in cmsText")
                self.assertNotIn(token, other_scanners_dom["activeText"], f"Unexpected {token} in activeText")

            # 3c. Verify interactive clickable VulnX badge links (KEV -> cisa.gov, EPSS -> first.org, PoC -> sploitus.com)
            vulnx_links = page.evaluate(
                """() => {
                    const row = scannerTemplateRow({
                        name: 'struts-rce.yaml',
                        path: 'http/cves/2017/CVE-2017-5638.yaml',
                        template_id: 'CVE-2017-5638',
                        title: 'Apache Struts2 S2-045 RCE',
                        severity: 'critical',
                        status: 'matched',
                        cve: ['CVE-2017-5638'],
                        findings: [{
                            matched_at: 'http://127.0.0.1:8089/showcase.action',
                            matcher_name: 'struts-header-injection',
                            evidence: 'root:x:0:0',
                            is_kev: true,
                            epss_score: 0.9712,
                            known_ransomware_campaign_use: 'Known',
                            references: [
                                'https://sploitus.com/exploit?id=PACKETSTORM:149008'
                            ],
                            age_in_days: 120
                        }]
                    });
                    const links = Array.from(row.querySelectorAll('.scanner-match a')).map(a => ({
                        text: a.textContent,
                        href: a.href,
                        target: a.target,
                        title: a.title
                    }));
                    return links;
                }"""
            )
            kev_link = next(l for l in vulnx_links if l["text"] == "[KEV]")
            self.assertEqual(kev_link["target"], "_blank")
            self.assertIn("cisa.gov", kev_link["href"])
            self.assertIn("CVE-2017-5638", kev_link["href"])

            epss_link = next(l for l in vulnx_links if "EPSS" in l["text"])
            self.assertEqual(epss_link["target"], "_blank")
            self.assertEqual(epss_link["href"], "https://www.first.org/epss/")

            poc_link = next(l for l in vulnx_links if l["text"] == "[PoC]")
            self.assertEqual(poc_link["target"], "_blank")
            self.assertEqual(poc_link["href"], "https://sploitus.com/exploit?id=PACKETSTORM:149008")

            # 4. Verify tlsx (REVOKED / UNTRUSTED / Serial / DN / Org / SHA-256) rendering in OSINT details DOM
            osint_details_text = page.evaluate(
                """() => {
                    osintGraphEntities.set('juice-1', {
                        id: 'juice-1',
                        type: 'domain',
                        identity: 'juice-shop.local',
                        risk_score: 85,
                        observed_at: '2026-11-18T06:00:00Z',
                        properties: {
                            tls_revoked: true,
                            tls_untrusted: true,
                            tls_serial: '0A:1B:2C:3D',
                            tls_subject_dn: 'CN=juice-shop.local,O=OWASP Juice Shop',
                            tls_issuer_dn: 'CN=Untrusted Test CA,O=Test Authority',
                            tls_subject_org: ['OWASP Juice Shop'],
                            tls_issuer_org: ['Test Authority'],
                            tls_fingerprint_hash: { sha256: 'e3b0c44298fc1c149afbf4c8996fb924' }
                        }
                    });
                    selectOsintGraphEntity('juice-1');
                    return document.getElementById('osint-graph-details-content').textContent;
                }"""
            )
            for token in [
                "TLS Alert: REVOKED certificate",
                "TLS Alert: UNTRUSTED certificate chain",
                "TLS Serial: 0A:1B:2C:3D",
                "TLS Subject DN: CN=juice-shop.local,O=OWASP Juice Shop",
                "TLS Issuer DN: CN=Untrusted Test CA,O=Test Authority",
                "TLS Subject Org: OWASP Juice Shop",
                "TLS Issuer Org: Test Authority",
                "TLS SHA-256: e3b0c44298fc1c149afbf4c8996fb924",
            ]:
                self.assertIn(token, osint_details_text)

            # 5. Verify WAF detection and canary in OSINT Security Card
            waf_panel_text = page.evaluate(
                """() => {
                    const osintResult = {
                        url: 'https://example.com',
                        security_headers: { 'server': 'cloudflare', 'cf-ray': '847291a9b-LAX' },
                        waf: {
                            detected: true,
                            vendors: ['Cloudflare'],
                            confidence: 'high',
                            confidence_percent: 60,
                            evidence: { 'Cloudflare': ['Header: cf-ray', 'Header: server'] }
                        },
                        waf_check: {
                            status: 'completed',
                            canary_blocked: false,
                            response_delta: 'none'
                        }
                    };
                    renderOSINT(osintResult);
                    const security = document.getElementById('osint-security').textContent;
                    const summary = document.getElementById('osint-summary').textContent;
                    return { security, summary };
                }"""
            )
            for token in ["Cloudflare", "high", "cf-ray", "waf_check"]:
                self.assertIn(token, waf_panel_text["security"])
            self.assertIn("WAF: Cloudflare (high confidence)", waf_panel_text["summary"])

            # 6. Verify OSINT Technology Stack node rendering with Wappalyzer categories and evidence
            tech_details_text = page.evaluate(
                """() => {
                    osintGraphEntities.set('tech-1', {
                        id: 'tech-1',
                        type: 'technology',
                        identity: 'express',
                        risk_score: 10,
                        observed_at: '2026-11-18T06:00:00Z',
                        properties: {
                            status: 'announced',
                            host: '127.0.0.1',
                            scheme: 'http',
                            evidence: 'wappalyzer:web frameworks, header:x-powered-by',
                            evidence_count: 2
                        },
                        provenance: { source: 'host_probe' }
                    });
                    selectOsintGraphEntity('tech-1');
                    return document.getElementById('osint-graph-details-content').textContent;
                }"""
            )
            for token in [
                "express",
                "announced",
                "wappalyzer:web frameworks",
                "host_probe"
            ]:
                self.assertIn(token, tech_details_text)

            # 7. Verify S3 Cloud Asset (creepyCrawler parity: permission & open_listing) in OSINT Graph Details
            s3_details_text = page.evaluate(
                """() => {
                    osintGraphEntities.set('s3-1', {
                        id: 's3-1',
                        type: 'cloud_asset',
                        identity: 'https://juice-shop-assets.s3.amazonaws.com',
                        risk_score: 90,
                        observed_at: '2026-11-18T06:00:00Z',
                        properties: {
                            provider: 'aws_s3',
                            status: 200,
                            permission: 'public_listable',
                            open_listing: true
                        },
                        provenance: { source: 'bucket_probe' }
                    });
                    selectOsintGraphEntity('s3-1');
                    return document.getElementById('osint-graph-details-content').textContent;
                }"""
            )
            for token in [
                "cloud_asset",
                "https://juice-shop-assets.s3.amazonaws.com",
                "Provider: aws_s3",
                "Permission: public_listable",
                "Open Listing: YES (Vulnerable)",
                "bucket_probe"
            ]:
                self.assertIn(token, s3_details_text)

            browser.close()

        self.assertEqual(page_errors, [], f"Uncaught page errors: {page_errors}")
        self.assertEqual(console_errors, [], f"Browser console errors: {console_errors}")

    def test_multi_cve_fixtures_badges_nuclei_and_gvm_uxui(self):
        """Full UX/UI verification of VulnX interactive badges across multi-CVE fixtures in Nuclei and GVM/OpenVAS."""
        from playwright.sync_api import sync_playwright

        page_errors = []
        console_errors = []

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(viewport={"width": 1440, "height": 900})
            context.grant_permissions(["clipboard-read", "clipboard-write"])
            page = context.new_page()

            page.on("pageerror", lambda exc: page_errors.append(str(exc)))
            page.on("console", lambda msg: console_errors.append(f"[{msg.type}] {msg.text}") if msg.type == "error" else None)

            page.route("**/api/scanner/openvas/**", lambda route: route.fulfill(status=200, content_type="application/json", body=json.dumps({"ok": True, "available": True, "authenticated": True, "tasks": []})))

            page.goto(BASE_URL + "/", wait_until="domcontentloaded", timeout=15000)
            page.wait_for_function("typeof renderScannerTemplateStats === 'function' && typeof scannerTemplateRow === 'function' && typeof renderOpenvasFindings === 'function'")

            # Switch UI to Scanner -> Nuclei scan tab
            page.click("nav .nav-tab[data-tab='scanner']")
            page.click("#scanner-view-nuclei")

            # 1. Multi-CVE Fixture Test in Nuclei UI
            nuclei_results = page.evaluate(
                """() => {
                    if (typeof setScannerView === 'function') setScannerView('nuclei');
                    const multiCveTemplates = [
                        {
                            name: 'struts-s2-045.yaml',
                            path: 'http/cves/2017/CVE-2017-5638.yaml',
                            template_id: 'CVE-2017-5638',
                            title: 'Apache Struts2 S2-045 OGNL RCE',
                            severity: 'critical',
                            status: 'matched',
                            cve: ['CVE-2017-5638'],
                            findings: [{
                                matched_at: 'http://127.0.0.1:8089/showcase.action',
                                matcher_name: 'content-type-rce',
                                is_kev: true,
                                epss_score: 0.9712,
                                known_ransomware_campaign_use: 'Known',
                                references: ['https://sploitus.com/exploit?id=PACKETSTORM:149008'],
                                age_in_days: 120
                            }]
                        },
                        {
                            name: 'weblogic-cve-2020-14882.yaml',
                            path: 'http/cves/2020/CVE-2020-14882.yaml',
                            template_id: 'CVE-2020-14882',
                            title: 'Oracle WebLogic Console Remote Code Execution',
                            severity: 'critical',
                            status: 'matched',
                            cve: ['CVE-2020-14882'],
                            findings: [{
                                matched_at: 'http://127.0.0.1:8089/console/css/%252e%252e%252fconsole.portal',
                                matcher_name: 'admin-bypass',
                                is_kev: true,
                                epss_score: 0.965,
                                known_ransomware_campaign_use: 'Known',
                                references: ['https://www.exploit-db.com/exploits/49067'],
                                age_in_days: 45
                            }]
                        },
                        {
                            name: 'log4j-rce.yaml',
                            path: 'http/cves/2021/CVE-2021-44228.yaml',
                            template_id: 'CVE-2021-44228',
                            title: 'Apache Log4j2 JNDI RCE',
                            severity: 'critical',
                            status: 'matched',
                            cve: ['CVE-2021-44228'],
                            findings: [{
                                matched_at: 'http://127.0.0.1:8089/login',
                                matcher_name: 'jndi-callback',
                                is_kev: true,
                                epss_score: 0.975,
                                known_ransomware_campaign_use: 'Known',
                                references: ['https://github.com/tangxiaofeng7/apache-log4j-poc'],
                                age_in_days: 300
                            }]
                        },
                        {
                            name: 'zero-day-poc-curl.yaml',
                            path: 'http/cves/2023/CVE-2023-38606.yaml',
                            template_id: 'CVE-2023-38606',
                            title: 'Apple WebKit Zero-Day Memory Corruption',
                            severity: 'critical',
                            status: 'matched',
                            cve: ['CVE-2023-38606'],
                            findings: [{
                                matched_at: 'http://127.0.0.1:8089/webkit',
                                matcher_name: 'memory-read',
                                is_kev: true,
                                epss_score: 0.880,
                                curl_command: 'curl -X POST http://127.0.0.1:8089/webkit -d "payload=1"',
                                age_in_days: 60
                            }]
                        },
                        {
                            name: 'moniker-rce.yaml',
                            path: 'http/cves/2024/CVE-2024-21413.yaml',
                            template_id: 'CVE-2024-21413',
                            title: 'Microsoft Outlook Moniker RCE',
                            severity: 'high',
                            status: 'matched',
                            cve: ['CVE-2024-21413'],
                            findings: [{
                                matched_at: 'http://127.0.0.1:8089/outlook',
                                matcher_name: 'moniker-leak',
                                is_kev: false,
                                epss_score: 0.720,
                                is_poc: true,
                                age_in_days: 90
                            }]
                        }
                    ];

                    const resultsWrap = document.getElementById('scanner-tpl-results');
                    if (resultsWrap) resultsWrap.hidden = false;
                    const tplContainer = document.getElementById('scanner-tpl-body') || document.body;
                    tplContainer.innerHTML = '';
                    const parsedRows = [];
                    for (const tpl of multiCveTemplates) {
                        const row = scannerTemplateRow(tpl);
                        tplContainer.appendChild(row);
                        const links = Array.from(row.querySelectorAll('.scanner-match a')).map(a => ({
                            text: a.textContent,
                            href: a.href,
                            target: a.target,
                            title: a.title
                        }));
                        const spans = Array.from(row.querySelectorAll('.scanner-match span')).map(s => ({
                            text: s.textContent,
                            className: s.className,
                            title: s.title
                        }));
                        parsedRows.push({
                            title: tpl.title,
                            rowText: row.textContent,
                            links,
                            spans
                        });
                    }
                    return parsedRows;
                }"""
            )

            self.assertEqual(len(nuclei_results), 5)

            # Check Struts2 (Sploitus PoC link)
            struts_row = nuclei_results[0]
            self.assertIn("[KEV]", struts_row["rowText"])
            self.assertIn("EPSS 97.1%", struts_row["rowText"])
            self.assertIn("[RANSOMWARE]", struts_row["rowText"])
            self.assertIn("[PoC]", struts_row["rowText"])
            self.assertIn("120d", struts_row["rowText"])
            struts_kev = next(l for l in struts_row["links"] if l["text"] == "[KEV]")
            self.assertIn("cisa.gov", struts_kev["href"])
            self.assertIn("CVE-2017-5638", struts_kev["href"])
            struts_poc = next(l for l in struts_row["links"] if l["text"] == "[PoC]")
            self.assertEqual(struts_poc["href"], "https://sploitus.com/exploit?id=PACKETSTORM:149008")

            # Check WebLogic (Exploit-DB PoC link)
            wl_row = nuclei_results[1]
            wl_poc = next(l for l in wl_row["links"] if l["text"] == "[PoC]")
            self.assertEqual(wl_poc["href"], "https://www.exploit-db.com/exploits/49067")

            # Check Log4j (GitHub PoC link)
            log4j_row = nuclei_results[2]
            log4j_poc = next(l for l in log4j_row["links"] if l["text"] == "[PoC]")
            self.assertEqual(log4j_poc["href"], "https://github.com/tangxiaofeng7/apache-log4j-poc")

            # Check Moniker (Sploitus search fallback)
            moniker_row = nuclei_results[4]
            moniker_poc = next(l for l in moniker_row["links"] if l["text"] == "[PoC]")
            self.assertIn("sploitus.com", moniker_poc["href"])
            self.assertIn("CVE-2024-21413", moniker_poc["href"])

            # Test curl_command copy interaction via Playwright UI click
            poc_copy_btn = page.locator("#scanner-tpl-body .vulnx-poc-copy").first
            self.assertEqual(poc_copy_btn.text_content(), "[PoC]")
            poc_copy_btn.click()
            self.assertEqual(poc_copy_btn.text_content(), "[PoC Copied!]")

            # 2. Multi-CVE Fixture Test in GVM / OpenVAS UI
            page.click("#scanner-view-openvas")
            openvas_results = page.evaluate(
                """() => {
                    if (typeof setScannerView === 'function') setScannerView('openvas');
                    const multiCveOpenvas = [
                        {
                            id: 'ov-1',
                            title: 'OpenVAS: Apache Struts2 Showcase RCE',
                            severity: 'critical',
                            endpoint: 'http://127.0.0.1:8089/showcase.action',
                            cve: ['CVE-2017-5638'],
                            is_kev: true,
                            epss_score: 0.9712,
                            known_ransomware_campaign_use: 'Known',
                            references: ['https://sploitus.com/exploit?id=PACKETSTORM:149008'],
                            age_in_days: 120
                        },
                        {
                            id: 'ov-2',
                            title: 'OpenVAS: Oracle WebLogic Server Unauthenticated RCE',
                            severity: 'critical',
                            endpoint: 'http://127.0.0.1:8089/console.portal',
                            cve: ['CVE-2020-14882'],
                            is_kev: true,
                            epss_score: 0.965,
                            known_ransomware_campaign_use: 'Known',
                            references: ['https://www.exploit-db.com/exploits/49067'],
                            age_in_days: 45
                        },
                        {
                            id: 'ov-3',
                            title: 'OpenVAS: Zero-Day PoC with Curl',
                            severity: 'high',
                            endpoint: 'http://127.0.0.1:8089/zero',
                            cve: ['CVE-2023-38606'],
                            is_kev: true,
                            epss_score: 0.880,
                            curl_command: 'curl -s http://127.0.0.1:8089/zero',
                            age_in_days: 60
                        }
                    ];

                    renderOpenvasFindings(multiCveOpenvas, 'http://127.0.0.1:8089');
                    const rows = Array.from(document.querySelectorAll('#scanner-openvas-body tr')).filter(r => r.querySelector('.scanner-vulnx-badges'));
                    return rows.map(r => {
                        const links = Array.from(r.querySelectorAll('.scanner-vulnx-badges a')).map(a => ({
                            text: a.textContent,
                            href: a.href,
                            target: a.target
                        }));
                        const hasCopyBtn = !!r.querySelector('.vulnx-poc-copy');
                        return {
                            rowText: r.textContent,
                            links,
                            hasCopyBtn
                        };
                    });
                }"""
            )

            self.assertEqual(len(openvas_results), 3)

            # OpenVAS Row 1 (Struts2 Sploitus)
            ov1 = openvas_results[0]
            self.assertIn("[KEV]", ov1["rowText"])
            self.assertIn("EPSS 97.1%", ov1["rowText"])
            self.assertIn("[RANSOMWARE]", ov1["rowText"])
            self.assertIn("[PoC]", ov1["rowText"])
            self.assertIn("120d", ov1["rowText"])
            ov1_kev = next(l for l in ov1["links"] if l["text"] == "[KEV]")
            self.assertIn("cisa.gov", ov1_kev["href"])
            self.assertIn("CVE-2017-5638", ov1_kev["href"])
            ov1_poc = next(l for l in ov1["links"] if l["text"] == "[PoC]")
            self.assertEqual(ov1_poc["href"], "https://sploitus.com/exploit?id=PACKETSTORM:149008")

            # OpenVAS Row 2 (WebLogic Exploit-DB)
            ov2 = openvas_results[1]
            ov2_poc = next(l for l in ov2["links"] if l["text"] == "[PoC]")
            self.assertEqual(ov2_poc["href"], "https://www.exploit-db.com/exploits/49067")

            # OpenVAS Row 3 (Copy button)
            ov3 = openvas_results[2]
            self.assertTrue(ov3["hasCopyBtn"])
            ov_copy_btn = page.locator("#scanner-openvas-body .vulnx-poc-copy").first
            self.assertEqual(ov_copy_btn.text_content(), "[PoC]")
            ov_copy_btn.click()
            self.assertEqual(ov_copy_btn.text_content(), "[PoC Copied!]")

            browser.close()

        self.assertEqual(page_errors, [], f"Uncaught page errors: {page_errors}")
        self.assertEqual(console_errors, [], f"Browser console errors: {console_errors}")


if __name__ == "__main__":
    unittest.main()

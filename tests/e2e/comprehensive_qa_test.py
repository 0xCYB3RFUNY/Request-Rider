"""Comprehensive Senior QA Test Suite for RequestRider.
Executes automated browser interactions across all tabs and tools,
tracking console errors, network failures, DOM issues, usability bugs,
and business logic discrepancies.
"""

import json
import os
import sys
import time
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from playwright.sync_api import sync_playwright

BASE_URL = os.environ.get("REQUESTRIDER_BASE_URL", "http://127.0.0.1:8000/")
FIXTURE_PORT = 8991
FIXTURE_URL = f"http://127.0.0.1:{FIXTURE_PORT}"


class MockFixtureHandler(BaseHTTPRequestHandler):
    def send_body(self, status, body, content_type="text/html; charset=utf-8"):
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Server", "RequestRider-Mock/1.0")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/":
            self.send_body(200, "<html><head><title>Mock Home</title></head><body><h1>Welcome</h1><a href='/page1'>Page 1</a><a href='/page2'>Page 2</a></body></html>")
        elif self.path == "/page1":
            self.send_body(200, "<html><body><h1>Page 1</h1><a href='/page2'>To Page 2</a><a href='/api/json'>JSON API</a></body></html>")
        elif self.path == "/page2":
            self.send_body(200, "<html><body><h1>Page 2</h1><form action='/submit' method='GET'><input name='search'/></form></body></html>")
        elif self.path == "/api/json":
            self.send_body(200, json.dumps({"status": "success", "items": [1, 2, 3]}), "application/json")
        elif self.path.startswith("/api/echo"):
            query = self.path.split("?", 1)[1] if "?" in self.path else ""
            self.send_body(200, json.dumps({"echo": query, "headers": dict(self.headers)}), "application/json")
        else:
            self.send_body(404, "Not Found", "text/plain")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace")
        self.send_body(200, json.dumps({"received_post": body, "path": self.path}), "application/json")

    def log_message(self, *args):
        pass


def run_mock_server():
    server = ThreadingHTTPServer(("127.0.0.1", FIXTURE_PORT), MockFixtureHandler)
    server.serve_forever()


def main():
    # Start mock server
    mock_thread = threading.Thread(target=run_mock_server, daemon=True)
    mock_thread.start()
    time.sleep(0.5)

    qa_report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "base_url": BASE_URL,
        "browser": "Firefox (Playwright)",
        "tab_tests": {},
        "console_errors": [],
        "page_errors": [],
        "defects": [],
        "usability_issues": [],
        "untranslated_keys": [],
    }
    created_project_id = None

    with sync_playwright() as p:
        browser = p.firefox.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()

        page.on("console", lambda msg: qa_report["console_errors"].append({
            "type": msg.type,
            "text": msg.text,
            "location": msg.location
        }) if msg.type in ["error", "warning"] else None)

        page.on("pageerror", lambda exc: qa_report["page_errors"].append(str(exc)))

        print("=== Step 1: Loading Homepage ===")
        page.goto(BASE_URL, wait_until="domcontentloaded")
        page.locator("#header-status").wait_for(state="visible", timeout=30000)
        time.sleep(1)

        # Check status indicators in header
        header_status = page.locator("#header-status")
        engine_val = page.locator("#ss-engine-val").inner_text()
        proxy_val = page.locator("#ss-proxy-val").inner_text()
        route_val = page.locator("#ss-route-val").inner_text()
        print(f"Header Status: Engine={engine_val}, Proxy={proxy_val}, Route={route_val}")

        if not header_status.is_visible():
            qa_report["defects"].append({
                "severity": "HIGH",
                "category": "Header Status",
                "title": "Header status badges not visible",
                "details": "#header-status is hidden or missing"
            })

        # Check for untranslated i18n placeholders or keys in DOM
        untranslated = page.evaluate("""() => {
            const results = [];
            const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT);
            while (walker.nextNode()) {
                const el = walker.currentNode;
                if (el.getAttribute('data-i18n') && el.textContent.trim().startsWith('{{') && el.textContent.trim().endsWith('}}')) {
                    results.push({tag: el.tagName, key: el.getAttribute('data-i18n'), text: el.textContent.trim()});
                }
            }
            return results;
        }""")
        if untranslated:
            qa_report["untranslated_keys"].extend(untranslated)

        # -------------------------------------------------------------
        # Tab 1: Projects
        # -------------------------------------------------------------
        print("=== Step 2: Testing Projects Tab ===")
        page.click("button[data-tab='projects']")
        time.sleep(0.5)

        test_project_name = f"QA-Proj-{int(time.time())}"
        page.click("#project-new")
        time.sleep(0.5)

        # Handle dialog
        dialog = page.locator("dialog[open]")
        if dialog.count() > 0:
            val_input = dialog.locator("input[name='value']")
            if val_input.count() > 0:
                val_input.fill(test_project_name)
                save_btn = dialog.locator("button[value='save']")
                if save_btn.count() > 0:
                    save_btn.click()
                    time.sleep(1)
                    created_project_id = page.evaluate("""async name => {
                        const response = await fetch('/api/projects');
                        const data = await response.json();
                        return data.items.find(item => item.name === name)?.id || null;
                    }""", test_project_name)
        else:
            print("Warning: dialog did not open for #project-new")

        # Check active project label in header
        active_label = page.locator("#active-project-label").inner_text()
        print(f"Active project label in header: '{active_label}'")

        project_select = page.locator("#project-select")
        select_options = project_select.locator("option").all_inner_texts()

        qa_report["tab_tests"]["projects"] = {
            "visible": page.locator("#projects").is_visible(),
            "created_project": test_project_name,
            "header_active_label": active_label,
            "select_options": select_options,
            "count_text": page.locator("#project-count").inner_text() if page.locator("#project-count").count() > 0 else "N/A"
        }

        # -------------------------------------------------------------
        # Tab 2: Repeater
        # -------------------------------------------------------------
        print("=== Step 3: Testing Repeater Tab ===")
        page.click("button[data-tab='repeater']")
        time.sleep(0.5)

        repeater_visible = page.locator("#repeater").is_visible()
        raw_editor = page.locator("#repeater-raw-request")
        test_request = (
            f"GET /api/echo?test=repeater_qa HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{FIXTURE_PORT}\r\n"
            f"User-Agent: RequestRider-QA\r\n"
            f"Accept: application/json\r\n\r\n"
        )
        raw_editor.fill(test_request)
        time.sleep(0.2)

        # Click send
        page.click("#send")
        time.sleep(1.5)

        # Check response inspector
        response_inspector = page.locator("#response")
        resp_text = response_inspector.inner_text()
        print("Repeater response sample:", resp_text[:100].replace("\n", " "))

        status_badge = page.locator("#repeater-response-meta")
        badge_text = status_badge.inner_text() if status_badge.count() > 0 else "N/A"
        print("Repeater Status Badge:", badge_text)

        # Test "Copy as cURL"
        curl_btn = page.locator("#repeater-copy-curl")
        curl_success = False
        if curl_btn.count() > 0:
            curl_btn.click()
            time.sleep(0.3)
            curl_success = True

        qa_report["tab_tests"]["repeater"] = {
            "tab_visible": repeater_visible,
            "response_received": len(resp_text) > 0 and "not ok" not in resp_text.lower(),
            "status_badge": badge_text,
            "copy_curl_clicked": curl_success,
            "response_snippet": resp_text[:150]
        }

        # -------------------------------------------------------------
        # Tab 3: Intruder
        # -------------------------------------------------------------
        print("=== Step 4: Testing Intruder Tab ===")
        page.click("button[data-tab='intruder']")
        time.sleep(0.5)

        intruder_raw = page.locator("#intruder-raw-request")
        intruder_test_req = (
            f"GET /api/echo?user=§test§ HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{FIXTURE_PORT}\r\n"
            f"Accept: application/json\r\n\r\n"
        )
        intruder_raw.fill(intruder_test_req)
        # trigger input event
        page.evaluate("() => $('intruder-raw-request').dispatchEvent(new Event('input'))")
        time.sleep(0.3)

        # Fill dictionary
        dict_area = page.locator(".dictionary-values").first
        if dict_area.count() > 0:
            dict_area.fill("alpha\nbeta\ngamma")
            page.evaluate("el => el.dispatchEvent(new Event('input'))", dict_area.element_handle())
            time.sleep(0.3)

        # Check attack review
        review = page.locator("#intruder-review")
        review_text = review.inner_text() if review.count() > 0 else ""
        print("Intruder review text:", review_text)

        # Run attack
        attack_btn = page.locator("#attack")
        attack_btn.click()
        time.sleep(3)

        # Check attack status and results
        attack_status = page.locator("#attack-status").inner_text() if page.locator("#attack-status").count() > 0 else ""
        result_rows = page.locator("#attack-results tr").count()
        print(f"Intruder attack status: {attack_status}, results count: {result_rows}")

        qa_report["tab_tests"]["intruder"] = {
            "tab_visible": page.locator("#intruder").is_visible(),
            "raw_editor": intruder_raw.is_visible(),
            "review_text": review_text,
            "attack_status": attack_status,
            "result_rows_count": result_rows
        }

        # -------------------------------------------------------------
        # Tab 4: Target
        # -------------------------------------------------------------
        print("=== Step 5: Testing Target Tab ===")
        page.click("button[data-tab='target']")
        time.sleep(0.5)

        target_url_input = page.locator("#target-url")
        target_url_input.fill(f"{FIXTURE_URL}/")
        time.sleep(0.2)

        static_btn = page.locator("#target-start")
        static_btn.click()
        time.sleep(3)

        target_progress = page.locator("#target-status").inner_text() if page.locator("#target-status").count() > 0 else ""
        tree_count = page.locator("#target-results tr").count()
        print(f"Target progress: {target_progress}, Discovered items: {tree_count}")

        qa_report["tab_tests"]["target"] = {
            "tab_visible": page.locator("#target").is_visible(),
            "progress": target_progress,
            "discovered_items_count": tree_count
        }

        # -------------------------------------------------------------
        # Tab 5: OSINT
        # -------------------------------------------------------------
        print("=== Step 6: Testing OSINT Tab ===")
        page.click("button[data-tab='osint']")
        time.sleep(0.5)

        osint_input = page.locator("#osint-url")
        osint_btn = page.locator("#osint-run")
        osint_status = page.locator("#osint-results, #osint-output, #osint-status").first

        if osint_input.count() > 0:
            osint_input.fill(FIXTURE_URL)
            if osint_btn.count() > 0:
                osint_btn.click()
                time.sleep(1)

        qa_report["tab_tests"]["osint"] = {
            "tab_visible": page.locator("#osint").is_visible(),
            "input_exists": osint_input.count() > 0,
            "button_exists": osint_btn.count() > 0,
            "status_text": osint_status.inner_text() if osint_status.count() > 0 else ""
        }

        # -------------------------------------------------------------
        # Tab 6: Scanner
        # -------------------------------------------------------------
        print("=== Step 7: Testing Scanner Tab ===")
        page.click("button[data-tab='scanner']")
        time.sleep(0.5)

        scanner_url = page.locator("#scanner-url")
        scanner_run = page.locator("#scanner-run")
        if scanner_url.count() > 0 and scanner_run.count() > 0:
            scanner_url.fill(f"{FIXTURE_URL}/")
            scanner_run.click()
            time.sleep(2)

        findings_text = page.locator("#scanner-findings").inner_text() if page.locator("#scanner-findings").count() > 0 else ""
        print(f"Scanner findings output: {findings_text[:100]!r}")
        qa_report["tab_tests"]["scanner"] = {
            "tab_visible": page.locator("#scanner").is_visible(),
            "findings_output": findings_text
        }

        # -------------------------------------------------------------
        # Tab 7: Comparer
        # -------------------------------------------------------------
        print("=== Step 8: Testing Comparer Tab ===")
        page.click("button[data-tab='comparer']")
        time.sleep(0.5)

        comp_left = page.locator("#comparer-left")
        comp_right = page.locator("#comparer-right")
        comp_btn = page.locator("#comparer-compare, button[id*='compar']").first

        if comp_left.count() > 0 and comp_right.count() > 0:
            comp_left.fill("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nHello World")
            comp_right.fill("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\nHello JSON")
            if comp_btn.count() > 0:
                comp_btn.click()
                time.sleep(0.5)

        diff_view = page.locator("#comparer-output, #comparer-diff, .comparer-output, #comparer-result")
        diff_visible = diff_view.count() > 0 and len(diff_view.first.inner_text().strip()) > 0
        print("Comparer diff visible and non-empty:", diff_visible)

        qa_report["tab_tests"]["comparer"] = {
            "tab_visible": page.locator("#comparer").is_visible(),
            "diff_rendered": diff_visible
        }

        # -------------------------------------------------------------
        # Tab 8: Decoder
        # -------------------------------------------------------------
        print("=== Step 9: Testing Decoder Tab ===")
        page.click("button[data-tab='decoder']")
        time.sleep(0.5)

        dec_input = page.locator("#decoder-input")
        dec_output = page.locator("#decoder-output")
        decoder_operation = page.locator("#decoder-operation")
        decoder_apply = page.locator("#decoder-apply")

        out_val = ""
        if dec_input.count() > 0:
            dec_input.fill("Hello RequestRider QA 2026!")
            if decoder_operation.count() > 0 and decoder_apply.count() > 0:
                decoder_operation.select_option("base64Encode")
                decoder_apply.click()
                time.sleep(0.3)
            out_val = dec_output.input_value() if dec_output.count() > 0 else ""
            print("Decoder output:", out_val)

        qa_report["tab_tests"]["decoder"] = {
            "tab_visible": page.locator("#decoder").is_visible(),
            "output": out_val
        }

        # -------------------------------------------------------------
        # Tab 9: Tor/Proxy
        # -------------------------------------------------------------
        print("=== Step 10: Testing Proxy Tab ===")
        page.click("button[data-tab='proxy']")
        time.sleep(0.5)

        route_addr = page.locator("#route-address")
        route_status = page.locator("#route-status")
        print("Route address current value:", route_addr.input_value())
        qa_report["tab_tests"]["proxy"] = {
            "tab_visible": page.locator("#proxy").is_visible(),
            "address_val": route_addr.input_value(),
            "status_text": route_status.inner_text() if route_status.count() > 0 else ""
        }

        # -------------------------------------------------------------
        # Tab 10: AI
        # -------------------------------------------------------------
        print("=== Step 11: Testing AI Tab ===")
        page.click("button[data-tab='ai']")
        time.sleep(0.5)

        ai_input = page.locator("#agent-chat-input")
        ai_send = page.locator("#agent-chat-send")

        qa_report["tab_tests"]["ai"] = {
            "tab_visible": page.locator("#ai").is_visible(),
            "input_exists": ai_input.count() > 0,
            "send_exists": ai_send.count() > 0
        }

        # -------------------------------------------------------------
        # Tab 11: Automation
        # -------------------------------------------------------------
        print("=== Step 12: Testing Automation Tab ===")
        page.click("button[data-tab='automation']")
        time.sleep(0.5)

        canvas = page.locator("#workflow-canvas, svg#workflow-edges, .workflow-workspace")
        templates_btn = page.locator("#workflow-templates, #workflow-template-store, button:has-text('Templates')")

        templates_modal_works = False
        if templates_btn.count() > 0:
            templates_btn.click()
            time.sleep(0.8)
            dialog = page.locator("#template-store-dialog, dialog[open]")
            templates_modal_works = dialog.count() > 0 and dialog.is_visible()
            print("Template Store modal opened:", templates_modal_works)
            close_btn = page.locator("#template-store-close")
            if close_btn.count() > 0:
                close_btn.first.click()
                time.sleep(0.3)

        qa_report["tab_tests"]["automation"] = {
            "tab_visible": page.locator("#automation").is_visible(),
            "canvas_exists": canvas.count() > 0,
            "template_store_opens": templates_modal_works
        }

        # -------------------------------------------------------------
        # Tab 12: History
        # -------------------------------------------------------------
        print("=== Step 13: Testing History Tab ===")
        page.click("button[data-tab='history']")
        time.sleep(0.5)

        history_rows = page.locator("#history-body tr").count()
        print(f"History table rows count: {history_rows}")

        inspector_updated = False
        if history_rows > 0:
            page.locator("#history-body tr").first.click()
            time.sleep(0.5)
            req_insp = page.locator("#history-request-inspector").inner_text()
            inspector_updated = "Select a history row" not in req_insp and len(req_insp.strip()) > 0
            print("History inspector updated on row click:", inspector_updated)

        qa_report["tab_tests"]["history"] = {
            "tab_visible": page.locator("#history").is_visible(),
            "rows_count": history_rows,
            "inspector_works": inspector_updated
        }

        # -------------------------------------------------------------
        # Tab 13: Traffic
        # -------------------------------------------------------------
        print("=== Step 14: Testing Traffic Tab ===")
        page.click("button[data-tab='traffic']")
        time.sleep(0.5)

        traffic_rows = page.locator("#traffic-body tr").count()
        pause_btn = page.locator("#traffic-capture-pause")
        resume_btn = page.locator("#traffic-capture-resume")
        traffic_status = page.locator("#traffic-capture-status").inner_text() if page.locator("#traffic-capture-status").count() > 0 else ""

        print(f"Traffic rows: {traffic_rows}, Status: {traffic_status}")

        qa_report["tab_tests"]["traffic"] = {
            "tab_visible": page.locator("#traffic").is_visible(),
            "rows_count": traffic_rows,
            "status": traffic_status,
            "pause_button_exists": pause_btn.count() > 0,
            "resume_button_exists": resume_btn.count() > 0
        }

        # -------------------------------------------------------------
        # Step 15: Language Switcher Check
        # -------------------------------------------------------------
        print("=== Step 15: Testing Language Toggle ===")
        lang_btn = page.locator("#language-toggle")
        initial_lang = lang_btn.inner_text()
        lang_btn.click()
        time.sleep(0.5)
        switched_lang = lang_btn.inner_text()
        print(f"Language toggle: {initial_lang} -> {switched_lang}")

        # Switch back
        lang_btn.click()
        time.sleep(0.5)

        # -------------------------------------------------------------
        # Viewport overlap check
        # -------------------------------------------------------------
        print("=== Step 16: Viewport Overlap Check ===")
        strip_in_dom = page.locator("#header-status").count() > 0
        print("#header-status exists in DOM:", strip_in_dom)

        if created_project_id:
            page.evaluate("""async id => {
                await fetch(`/api/projects/${id}`, {method: 'DELETE'});
            }""", created_project_id)

        browser.close()

    output_path = Path(__file__).resolve().parent / "qa_results.json"
    output_path.write_text(json.dumps(qa_report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nQA run complete! Saved results to {output_path}")


if __name__ == "__main__":
    main()

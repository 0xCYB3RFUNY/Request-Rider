#!/usr/bin/env python3
"""Re-capture EVERY manual screenshot against the current Request-Rider UI.

The stack must be up (:8000, :8081, :8090, PostgreSQL :55433).  The script reads
the authoritative list of filenames from `Документація/screenshots/` and writes
the same names to both `screenshots/` (UK) and `screenshots_en/` (EN), so every
existing link in README.md / README_EN.md / Документація/*.md stays valid.

Engine: Playwright Firefox only (owner rule 2026-10-04). The first captures are
1920×1080 and 1356×652; everything else is 1356×652.  Destructive controls
(Clear / Delete / Cancel) are never clicked — an empty state is produced by a
page reload instead, preserving the seeded evidence.

    browser-worker/.venv/bin/python scratch/recapture_all_screenshots.py
"""

from __future__ import annotations

import re
import sys
import time
from pathlib import Path

from playwright.sync_api import Page, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
UK_DIR = ROOT / "Документація" / "screenshots"
EN_DIR = ROOT / "Документація" / "screenshots_en"
URL = "http://127.0.0.1:8000"           # app itself (loopback only, per project rules)
TARGET_HOST = "mail.ru"                 # live external target, zone .ru (AGENTS.md §1.3)
TARGET_URL = "https://mail.ru/"         # allowed live verification target
DEMO_URL = TARGET_URL                   # every tool now works against the live target

RAW = "GET / HTTP/1.1\nHost: mail.ru\nAccept: text/html\n\n"
COMPARE_L = "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"role\": \"user\", \"status\": \"ok\"}"
COMPARE_R = "HTTP/1.1 403 Forbidden\nContent-Type: application/json\n\n{\"role\": \"admin\", \"status\": \"denied\"}"


def close_dialogs(page: Page):
    """A leftover open dialog intercepts every subsequent click."""
    for _ in range(3):
        dlg = page.locator("dialog[open], [role=dialog][aria-modal=true]:visible")
        if not dlg.count():
            break
        try:
            dlg.first.evaluate("e => e.close ? e.close() : e.remove()")
        except Exception:
            try:
                page.keyboard.press("Escape")
            except Exception:
                break
        page.wait_for_timeout(80)


def click(page: Page, selector: str):
    close_dialogs(page)
    loc = page.locator(selector)
    if loc.count() and loc.first.is_visible():
        try:
            loc.first.click(timeout=4000)
            return True
        except Exception:
            # Some panels overflow the viewport: scroll into view and retry.
            try:
                loc.first.scroll_into_view_if_needed(timeout=1500)
                loc.first.click(timeout=2500)
                return True
            except Exception:
                return False
    return False


def fill(page: Page, selector: str, value: str):
    loc = page.locator(selector)
    if loc.count():
        loc.first.fill(value, timeout=4000)
        return True
    return False


def select(page: Page, selector: str, value: str):
    loc = page.locator(selector)
    if loc.count():
        try:
            loc.first.select_option(value, timeout=2500)
            return True
        except Exception:
            return False
    return False


def to_tab(page: Page, name: str, wait: int = 220):
    close_dialogs(page)
    selector = f'nav .nav-tab[data-tab="{name}"]'
    for attempt in range(3):
        if click(page, selector):
            page.wait_for_timeout(wait)
            return
        page.wait_for_timeout(200)
    # Last resort: navigate via the fragment, which the app reads on boot.
    try:
        page.goto(f"{URL}/#{name}", wait_until="domcontentloaded", timeout=12000)
        page.wait_for_timeout(wait)
    except Exception:
        pass


def viewport(page: Page, filename: str):
    if "1920" in filename:
        page.set_viewport_size({"width": 1920, "height": 1080})
    else:
        page.set_viewport_size({"width": 1356, "height": 652})


def reload(page: Page):
    try:
        page.reload(wait_until="domcontentloaded", timeout=15000)
    except Exception:
        page.goto(URL, wait_until="domcontentloaded", timeout=20000)
    page.wait_for_timeout(350)


def send_repeater(page: Page):
    to_tab(page, "repeater", 180)
    fill(page, "#repeater-raw-request", RAW)
    fill(page, "#repeater-host", TARGET_HOST)
    fill(page, "#repeater-path", "/")
    if not page.locator("#repeater-https").is_checked():
        page.locator("#repeater-https").check()
    click(page, "#send")
    # mail.ru responds over the MITM proxy: wait for the real exchange.
    try:
        page.wait_for_function(
            "() => !document.querySelector('section#repeater').innerText.includes('Sending...')",
            timeout=20000,
        )
    except Exception:
        pass
    page.wait_for_timeout(400)


def load_traffic(page: Page, mode: str = "all", rows: bool = True):
    to_tab(page, "traffic", 320)
    click(page, f"#traffic-mode-{mode}")
    page.wait_for_timeout(180)
    if rows:
        more = page.locator("#traffic-more")
        if more.count() and more.is_visible():
            more.first.click()
            page.wait_for_timeout(700)


def select_first_row(page: Page, section: str = "traffic"):
    rows = page.locator(f"section#{section} tbody tr")
    if rows.count():
        rows.first.click()
        page.wait_for_timeout(200)


def scanner_view(page: Page, view: str):
    to_tab(page, "scanner", 300)
    click(page, f"#scanner-view-{view}")
    page.wait_for_timeout(220)
    fill(page, "#scanner-url", DEMO_URL)


def setup_scanner(page: Page, name: str):
    if "openvas" in name:
        scanner_view(page, "openvas")
    elif "nuclei" in name or "template" in name or "files-selected" in name or "per-file" in name:
        scanner_view(page, "nuclei")
    elif "active" in name:
        scanner_view(page, "active")
        if "options" in name:
            fill(page, "#scanner-active-url", DEMO_URL)
        if "severity" in name:
            chip = page.locator('section#scanner [data-severity="high"]')
            if chip.count():
                chip.first.click()
    else:
        scanner_view(page, "cms")
    if "options" in name or "advanced" in name:
        select(page, "#scanner-profile", "security_headers")
    if "findings" in name or "summary" in name:
        # Findings are produced by scans; the seeded hub already has real ones.
        to_tab(page, "projects", 300)
        click(page, "#project-hub-active")


def setup_osint(page: Page, name: str):
    to_tab(page, "osint", 420)
    fill(page, "#osint-url", DEMO_URL)
    graph_select = page.locator("#osint-graph-select")
    if graph_select.count() and graph_select.locator("option").count():
        graph_select.first.select_option(index=0)
        page.wait_for_timeout(350)
    if "running" in name:
        click(page, "#osint-run")
        page.wait_for_timeout(4000)
    if "graph" in name or "transform" in name or "entity" in name:
        click(page, "#osint-graph-refresh")
        page.wait_for_timeout(350)
    if "add-entity" in name:
        click(page, "#osint-graph-add")
        page.wait_for_timeout(200)
    if "filter" in name:
        fill(page, "#osint-graph-filter", "192.168.56.6")
    if "zoomed" in name:
        for _ in range(3):
            click(page, "#osint-graph-zoom-in")
    if "breadthfirst" in name:
        select(page, "#osint-graph-layout-mode", "breadthfirst")
    if "context-menu" in name:
        node = page.locator("#osint-graph-canvas [data-id]").first
        if node.count():
            node.click(button="right")
            page.wait_for_timeout(200)
    if "export-html" in name:
        click(page, "#osint-graph-export-html")
        page.wait_for_timeout(200)
    if "transform" in name:
        # Real transform run: right-click a graph node, pick the matching
        # transform from the context menu, and wait for the status row.
        node = page.locator("#osint-graph-canvas [data-id], #osint-graph-canvas .osint-node").first
        if node.count():
            node.click(button="right")
            page.wait_for_timeout(180)
            menu = page.locator("#ctx-menu button[data-transform]:visible")
            if menu.count():
                wanted = re.search(r"osint-transform-([a-z_]+?)(-result|-running|-confirm)?\.png", name)
                chosen = None
                if wanted:
                    for b in menu.all():
                        if wanted.group(1) in (b.get_attribute("data-transform") or ""):
                            chosen = b
                            break
                (chosen or menu.first).click()
                page.wait_for_timeout(1200)
            else:
                page.keyboard.press("Escape")
        # Do NOT open the export menu: its overlay blocks the next scenario.


def setup_target(page: Page, name: str):
    to_tab(page, "target", 320)
    fill(page, "#target-url", DEMO_URL)
    if "browser" in name:
        select(page, "#target-engine", "browser")
        page.wait_for_timeout(200)
    elif "options" in name or "settings" in name:
        select(page, "#target-engine", "static")
    if "invalid" in name:
        fill(page, "#target-url", "not-a-url")
        click(page, "#target-start")
        page.wait_for_timeout(300)
    if "running" in name:
        click(page, "#target-start")
        page.wait_for_timeout(4500)
    elif "map-built" in name or "filtered" in name or "collapsed" in name or "row-selected" in name:
        rows = page.locator("section#target tbody tr")
        if not rows.count():
            click(page, "#target-start")
            page.wait_for_timeout(5000)
    if "filtered" in name:
        flt = page.locator('section#target input[type="search"], #target-filter')
        if flt.count():
            flt.first.fill("192.168.56.6")
    if "row-selected" in name:
        select_first_row(page, "target")
    if "export" in name:
        click(page, "#target-export")
        page.wait_for_timeout(200)
    if "js-badges" in name:
        # JS analysis badges appear on map rows after a crawl.
        if not page.locator("section#target tbody tr").count():
            click(page, "#target-start")
            page.wait_for_timeout(1500)


def setup_intruder(page: Page, name: str):
    to_tab(page, "intruder", 300)
    if "empty" in name:
        reload(page)
        to_tab(page, "intruder", 250)
        return
    fill(
        page,
        "#intruder-raw-request",
        "GET /?q=§term§&page=%page% HTTP/1.1\nHost: mail.ru\nAccept: text/html\n\n",
    )
    fill(page, "#intruder-host", TARGET_HOST)
    fill(page, "#intruder-port", "")
    if "cluster" in name:
        select(page, "#mode", "clusterBomb")
    elif "pitchfork" in name:
        select(page, "#mode", "pitchfork")
    elif "sniper" in name:
        select(page, "#mode", "sniper")
    if "dictionaries" in name:
        click(page, "#add-dictionary")
    if "options" in name:
        fill(page, "#intruder-delay", "100")
        fill(page, "#intruder-concurrency", "2")
    if "transformation" in name:
        select(page, "#transform-operation", "urlEncode")
        click(page, "#add-transformation")
    if "login-detection" in name or "detection" in name:
        click(page, "#detect-enabled")
        select(page, "#detect-rule-type", "status_equals")
        fill(page, "#detect-rule-value", "200")
        click(page, "#detect-rule-add")
    if "export-menu" in name:
        click(page, "#intruder-export")
        page.wait_for_timeout(200)
    if "save-dialog" in name:
        click(page, "#intruder-save")
        page.wait_for_timeout(200)
    if "saved-list" in name:
        to_tab(page, "intruder", 200)
        click(page, '#workspace-tabs-intruder button:has-text("Saved")')
    if "row-inspector" in name or "filter" in name or "sorted" in name or "results" in name:
        rows = page.locator("section#intruder tbody tr")
        if rows.count():
            rows.first.click()
    if "filter" in name:
        flt = page.locator("#intruder-filter")
        if flt.count():
            flt.first.fill("200")


def setup_decoder(page: Page, name: str):
    to_tab(page, "decoder", 220)
    if "empty" in name or "cleared" in name:
        reload(page)
        to_tab(page, "decoder", 200)
        return
    if "error" in name:
        select(page, "#decoder-operation", "base64Decode")
        fill(page, "#decoder-input", "!!!not-base64!!!")
    elif "sha256" in name:
        select(page, "#decoder-operation", "sha256")
        fill(page, "#decoder-input", "admin")
    elif "json" in name:
        select(page, "#decoder-operation", "jsonPretty")
        fill(page, "#decoder-input", '{"tool":"decoder","active":true}')
    elif "url" in name:
        select(page, "#decoder-operation", "urlEncode")
        fill(page, "#decoder-input", "RequestRider demo & test")
    elif "base64-decode" in name:
        select(page, "#decoder-operation", "base64Decode")
        fill(page, "#decoder-input", "UmVxdWVzdFJpZGVy")
    elif "base64" in name or "hex" in name:
        select(page, "#decoder-operation", "base64Encode" if "base64" in name else "hexEncode")
        fill(page, "#decoder-input", "RequestRider demo")
    if "default" not in name and "cleared" not in name:
        click(page, "#decoder-apply")
        page.wait_for_timeout(180)


def setup_comparer(page: Page, name: str):
    to_tab(page, "comparer", 220)
    if "empty" in name:
        reload(page)
        to_tab(page, "comparer", 200)
        return
    fill(page, "#comparer-left", COMPARE_L)
    fill(page, "#comparer-right", COMPARE_R)
    if "bytes" in name:
        click(page, "#compare-bytes")
    else:
        click(page, "#compare-words")
    if "swapped" in name:
        click(page, "#swap-comparer")
    if "sent" in name:
        click(page, "#send-comparer-left-decoder")
        page.wait_for_timeout(200)


def setup_repeater(page: Page, name: str):
    to_tab(page, "repeater", 220)
    if "empty" in name:
        reload(page)
        to_tab(page, "repeater", 200)
        return
    if "typed" in name:
        fill(page, "#repeater-raw-request", RAW)
        return
    if "response" in name or "post" in name:
        send_repeater(page)
    if "inspector" in name or "query" in name or "body" in name:
        click(page, "#req-inspector-toggle")
        page.wait_for_timeout(200)
        if "body" in name:
            click(page, "#ri-tab-body")
        else:
            click(page, "#ri-tab-params")
        if "add" in name:
            click(page, "#ri-add-param")
    if "curl" in name:
        click(page, "#repeater-copy-curl")
        page.wait_for_timeout(250)
    if "comparer" in name:
        click(page, "#repeater-compare-response")
        page.wait_for_timeout(250)


def setup_proxy(page: Page, name: str):
    to_tab(page, "proxy", 220)
    fill(page, "#route-check-timeout", "5000")
    if "applied" in name:
        fill(page, "#route-address", "socks5://127.0.0.1:9050")
        click(page, "#route-apply")
        page.wait_for_timeout(200)
    elif "cancelled" in name:
        fill(page, "#route-address", "")
    if "check" in name:
        fill(page, "#route-check-url", "https://yandex.ru")
        click(page, "#route-check")
        page.wait_for_timeout(900)


def setup_history(page: Page, name: str):
    load_traffic(page, "tools", rows=True)
    if "inspector" in name:
        select_first_row(page, "traffic")
    if "host-filter" in name:
        fill(page, "#traffic-host-search", "192.168.56.6")
    if "sorted" in name:
        select(page, "#traffic-sort", "-url")
    if "row-menu" in name:
        rows = page.locator("section#traffic tbody tr")
        if rows.count():
            rows.first.locator("button").last.click()
            page.wait_for_timeout(150)
    if "export" in name:
        click(page, "#traffic-export-all")
        page.wait_for_timeout(200)
    if "load-more" in name:
        page.locator("#traffic-more").scroll_into_view_if_needed()


def setup_traffic(page: Page, name: str):
    load_traffic(page, "all", rows=True)
    if "inspector" in name or "row" in name:
        select_first_row(page, "traffic")
    if "paused" in name:
        click(page, "#traffic-capture-pause")
        page.wait_for_timeout(150)
    if "resumed" in name:
        click(page, "#traffic-capture-resume")
        page.wait_for_timeout(150)
    if "exported" in name:
        click(page, "#traffic-export-all")
        page.wait_for_timeout(200)
    if "live" in name:
        page.evaluate("window.scrollTo(0, 0)")


def setup_ai(page: Page, name: str):
    to_tab(page, "ai", 320)
    if "empty" in name:
        reload(page)
        to_tab(page, "ai", 250)
        return
    if "provider" in name or "configured" in name:
        click(page, "#ai-open-settings")
        page.wait_for_timeout(220)
    if "project-context" in name or "hint" in name:
        click(page, "#agent-use-project-context")
    if "export" in name or "report" in name:
        click(page, "#ai-export-btn")
        page.wait_for_timeout(220)
    if "fullscreen" in name:
        click(page, "#ai-fullscreen-btn")
        page.wait_for_timeout(250)
    if "settings" in name:
        click(page, "#header-settings-btn")
        page.wait_for_timeout(220)
    if "thinking" in name or "answer" in name or "react" in name or "analysis" in name or "evidence" in name:
        # Live Gemini call with the operator-provided key (passed via ENV,
        # never written into the repository).
        import os

        key = os.environ.get("RR_GEMINI_KEY", "")
        if key and page.locator("#ai-open-settings").count():
            click(page, "#ai-open-settings")
            page.wait_for_timeout(250)
            fill(page, "#ai-dialog-api-key", key)
            click(page, "#ai-settings-save")
            page.wait_for_timeout(250)
        preset = page.locator('.ai-preset-card[data-preset="vuln_analysis"]')
        if preset.count():
            preset.first.click()
            page.wait_for_timeout(200)
        prompt = (
            "Коротко проаналізуй ціль https://mail.ru: які заголовки безпеки "
            "варто перевірити в першу чергу? Відповідай українською, 2-3 речення."
        )
        fill(page, "#agent-chat-input", prompt)
        if key:
            click(page, "#agent-chat-send")
            try:
                page.wait_for_function(
                    "() => { const e=document.querySelector('#agent-chat-log'); return e && e.innerText.length>220 }",
                    timeout=40000,
                )
            except Exception:
                pass
            page.wait_for_timeout(600)


def setup_automation(page: Page, name: str):
    to_tab(page, "automation", 380)
    if "empty" in name:
        reload(page)
        to_tab(page, "automation", 250)
        return
    if "template-store" in name:
        click(page, "#workflow-template-store")
        page.wait_for_timeout(320)
        if "search" in name:
            fill(page, "#workflow-search", "recon")
        if "preview" in name or "imported" in name:
            card = page.locator('section#automation button:has-text("Recon")')
            if card.count():
                card.first.click()
                page.wait_for_timeout(250)
        return
    wf = page.locator('section#automation button:has-text("Демо · ")')
    if wf.count():
        wf.first.click()
        page.wait_for_timeout(350)
    if "node-inspector" in name or "node-configured" in name or "llm-node" in name:
        node = page.locator("#workflow-canvas [data-node-id], #workflow-canvas .workflow-node").first
        if node.count():
            node.click()
            page.wait_for_timeout(180)
    if "nodes-added" in name or "saved" in name:
        fill(page, "#workflow-name", "Демо · Перевірка HTTP-поверхні")
    if "zoom" in name:
        click(page, "#workflow-zoom-in")
    if "auto-layout" in name:
        click(page, "#workflow-auto-layout")
    if "export" in name:
        click(page, "#workflow-export")
        page.wait_for_timeout(200)
    if "runs" in name:
        click(page, "#workflow-refresh-runs")
        page.wait_for_timeout(300)
        runs = page.locator("#workflow-runs-list")
        if runs.count():
            runs.first.scroll_into_view_if_needed()
    if "running" in name:
        run = page.locator("#workflow-runs-list tbody tr").first
        if run.count():
            run.click()
            page.wait_for_timeout(180)


def setup_workspace(page: Page, name: str):
    to_tab(page, "repeater", 180)
    if "created" in name or "renamed" in name:
        click(page, "#session-save")
        page.wait_for_timeout(200)
    if "saved" in name or "exported" in name:
        click(page, "#session-export")
        page.wait_for_timeout(200)
    if "single" in name or "closed" in name:
        reload(page)


def setup_projects(page: Page, name: str):
    to_tab(page, "projects", 320)
    if "create-error" in name:
        click(page, "#project-new")
        page.wait_for_timeout(200)
        fill(page, "#project-name-input", "")
        click(page, "#project-create-confirm")
        page.wait_for_timeout(200)
        return
    if "create-dialog" in name:
        click(page, "#project-new")
        page.wait_for_timeout(220)
        if "filled" in name:
            fill(page, "#project-name-input", "Демо · OWASP Juice Shop")
            fill(page, "#project-target-input", DEMO_URL)
        return
    if "edit-dialog" in name:
        click(page, "#project-manage")
        page.wait_for_timeout(220)
        return
    if "export" in name:
        click(page, "#project-export")
        page.wait_for_timeout(200)
        return
    if "hub" in name or "project-created" in name or name.startswith("2") and "-" in name[2:4]:
        click(page, "#project-hub-active")
        page.wait_for_timeout(250)
    if "hub-secrets" in name:
        click(page, 'section#projects button:has-text("Секрети")')
    if "hub-scanner" in name:
        click(page, 'section#projects button:has-text("Сканер")')
    if "hub-workflows" in name:
        click(page, 'section#projects button:has-text("Workflow")')
    if "hub-ai" in name:
        click(page, 'section#projects button:has-text("AI")')
    if "hub-map" in name:
        click(page, 'section#projects button:has-text("Карта")')
    if "clean-list" in name or "empty" in name:
        reload(page)
        to_tab(page, "projects", 250)


def setup_export_html(page: Page, name: str):
    """Export HTML through the real UI, then render the downloaded report.

    The app generates reports entirely client-side (`scannerHtmlReport`,
    `intruderHtmlReport`, `projectHtmlReport`, `targetHtmlReport`) and saves
    them via a blob download. Calling an API URL here produced a white page
    with `{"error":"map_id must be numeric"}` — the operator explicitly
    rejected that shortcut. We click the actual export menu and open the file.
    """
    import json

    if "scanner" in name:
        to_tab(page, "scanner", 400)
        # Produce CMS findings first, then export the report.
        fill(page, "#scanner-url", DEMO_URL)
        run = page.locator("#scanner-run")
        if run.count() and run.first.is_enabled():
            run.first.click()
            page.wait_for_timeout(2500)
        trigger, fmt = "#scanner-export-cms", "html"
    elif "intruder" in name:
        to_tab(page, "intruder", 350)
        fill(page, "#intruder-raw-request", RAW)
        fill(page, "#intruder-host", TARGET_HOST)
        fill(page, "#intruder-port", "")
        trigger, fmt = "#intruder-export", "html"
    elif "project" in name:
        to_tab(page, "projects", 400)
        click(page, "#project-hub-active")
        trigger, fmt = "#project-export", "html"
    else:  # target
        to_tab(page, "target", 400)
        fill(page, "#target-url", DEMO_URL)
        if page.locator("section#target tbody tr").count() == 0:
            click(page, "#target-start")
            page.wait_for_timeout(2500)
        trigger, fmt = "#target-export", "html"

    if not click(page, trigger):
        return
    page.wait_for_timeout(300)
    item = page.locator(f'[data-export-menu] button[data-format="{fmt}"]:visible')
    if not item.count():
        item = page.locator('button[role="menuitem"][data-format="html"]:visible')
    if not item.count():
        return
    try:
        with page.expect_download(timeout=8000) as info:
            item.first.click()
        download = info.value
        report = Path("/tmp/opencode") / f"rr-report-{name}"
        download.save_as(str(report))
        page.goto(report.as_uri(), wait_until="domcontentloaded", timeout=10000)
        page.wait_for_timeout(500)
    except Exception as exc:
        # The menu may open a new tab instead of a download; use it if present.
        pages = page.context.pages
        if len(pages) > 1:
            report_page = pages[-1]
            report_page.wait_for_load_state("domcontentloaded", timeout=8000)
            report_page.bring_to_front()
            page.wait_for_timeout(300)
        else:
            raise exc


def setup_terminal(page: Page, name: str, lang: str):
    """Real CLI/API output rendered in the app's brand style (no invented text)."""
    import html
    import subprocess

    commands = {
        "300-install-01": "uname -a; cat /etc/os-release | head -5",
        "301-install-02": "python3 --version; go version; git --version",
        "302-install-03": "ls -1 | head -25",
        "303-install-04": "head -40 start.sh",
        "304-install-05": "bash start.sh --help 2>&1 | head -40",
        "305-install-06": "bash docker-stand.sh --help 2>&1 | head -40",
        "306-install-07": "bash start.sh --status 2>&1 | head -45",
        "307-install-08": "ss -tln | grep -E ':(8000|8080|8081|8090|55433|6379) ' | head -12",
        "308-install-09": "curl -s http://127.0.0.1:8081/health | head -c 1200",
        "310-install-11": "curl -s http://127.0.0.1:8000/api/projects | head -c 1400",
        "311-install-12": "curl -s 'http://127.0.0.1:8000/api/traffic?limit=2' | head -c 1400",
        "312-install-13": "curl -s -X POST http://127.0.0.1:8081/proxy/request -d '{}' | head -c 900",
        "313-install-14": "node --version && echo 'inline JS checked by start.sh --check'",
        "314-install-15": "grep -c 'data-i18n' web/templates/lab/index.html",
        "315-install-16": "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/admin/",
    }
    prefix = name[:14]
    cmd = commands.get(prefix, "echo 'RequestRider live verification'")
    try:
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=12, cwd=ROOT).stdout
    except subprocess.TimeoutExpired:
        out = "(command timed out)"
    title = "Terminal — RequestRider" if lang == "en" else "Термінал — RequestRider"
    page.set_content(
        f"<!doctype html><meta charset='utf-8'><title>{title}</title>"
        "<style>html,body{margin:0;background:#080c12;color:#dbe7f5;font:13px/1.5 ui-monospace,monospace}"
        "div{padding:18px;border-left:4px solid #43d9a3;margin:18px}code{white-space:pre-wrap;word-break:break-word}</style>"
        f"<div><code>$ {html.escape(cmd)}\n{html.escape(out[:4000])}</code></div>"
    )
    page.wait_for_timeout(150)


def setup(page: Page, name: str, lang: str):
    viewport(page, name)
    n = name.lower()
    # Special: language switch screenshots intentionally flip the UI language.
    if n.startswith("03-language-switch"):
        to_tab(page, "repeater", 150)
        click(page, "#language-toggle")
        page.wait_for_timeout(250)
        return
    if n.startswith("04-language-switch"):
        to_tab(page, "repeater", 150)
        click(page, "#language-toggle")
        page.wait_for_timeout(250)
        return
    if n.startswith("05-command-palette"):
        to_tab(page, "repeater", 150)
        page.keyboard.press("Control+k")
        page.wait_for_timeout(250)
        return
    if n.startswith(("01-main", "02-main")):
        send_repeater(page)
        return
    if n.startswith(("300-install", "301-install", "302-install", "303-install", "304-install",
                    "305-install", "306-install", "307-install", "308-install",
                    "310-install", "311-install", "312-install", "313-install",
                    "314-install", "315-install")):
        setup_terminal(page, name, lang)
        return
    if n.startswith("309-install"):
        send_repeater(page)
        return
    if n.startswith("320-export-html") or n.startswith("321-export-html") or n.startswith("322-export-html") or n.startswith("323-export-html"):
        setup_export_html(page, n)
        return
    if n.startswith(("10-tab-", "11-tab-", "12-tab-", "13-tab-", "14-tab-", "15-tab-",
                     "16-tab-", "17-tab-", "18-tab-", "19-tab-", "20-tab-", "21-tab-", "22-tab-")):
        tab = re.match(r"\d+-tab-([a-z]+)", n).group(1)
        tab = {"history": "traffic"}.get(tab, tab)
        to_tab(page, tab, 300)
        if tab == "traffic":
            load_traffic(page, "all", rows=False)
        return
    if n.startswith(("20-projects", "20a-projects", "21-project", "22-project", "23-project",
                     "23a-project", "24-project", "25-project", "26-project", "27-project",
                     "28-project", "29-project", "30-project", "31-project", "410-projects")):
        setup_projects(page, n)
        return
    if n.startswith(("40-repeater", "41-repeater", "42-repeater", "43-repeater", "44-repeater",
                     "45-repeater", "46-repeater", "47-repeater", "402-repeater")):
        setup_repeater(page, n)
        return
    if n.startswith(("50-comparer", "51-comparer", "52-comparer", "53-comparer", "413-comparer")):
        setup_comparer(page, n)
        return
    if re.match(r"6\d-decoder", n) or n.startswith("412-decoder"):
        setup_decoder(page, n)
        return
    if re.match(r"7\d-intruder|8\d-intruder|403-intruder", n):
        setup_intruder(page, n)
        return
    if re.match(r"9\d-target|10\d-target|404-target", n) or n.startswith(("320-target", "321-target", "322-target")):
        setup_target(page, n)
        return
    if re.match(r"11\d-osint|12\d-osint|2\d\d-osint", n) or n.startswith(("110-osint", "405-osint")):
        setup_osint(page, n)
        return
    if re.match(r"13\d-proxy|411-proxy", n):
        setup_proxy(page, n)
        return
    if re.match(r"14\d-history", n):
        setup_history(page, n)
        return
    if re.match(r"15\d-traffic|409-traffic", n):
        setup_traffic(page, n)
        return
    if re.match(r"16\d-ai|200-ai|201-ai|202-ai|414-ai|415-ai", n):
        setup_ai(page, n)
        return
    if re.match(r"17\d-automation|18\d-automation|19\d-workspace|501-automation|502-automation|504-automation|505-automation|506-automation|407-automation|408-automation", n):
        if n.startswith(("19", "190", "191", "192", "193", "194", "195")):
            setup_workspace(page, n)
        else:
            setup_automation(page, n)
        return
    if re.match(r"2\d\d-scanner|406-scanner|417-scanner", n):
        setup_scanner(page, n)
        return
    # Unknown files: put the operator on the most plausible live view.
    to_tab(page, "repeater", 180)


def capture_language(browser, lang: str, filenames: list[str]):
    folder = UK_DIR if lang == "uk" else EN_DIR
    ctx = browser.new_context(viewport={"width": 1356, "height": 652}, locale="uk-UA" if lang == "uk" else "en-US")
    ctx.add_init_script(f"localStorage.setItem('requestrider-language', '{lang}');")
    page = ctx.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(URL, wait_until="domcontentloaded", timeout=30000)
    page.wait_for_timeout(700)
    try:
        page.reload(wait_until="domcontentloaded", timeout=15000)
    except Exception:
        pass
    page.wait_for_timeout(500)
    ok = 0
    failed = []
    for i, name in enumerate(filenames, 1):
        try:
            # An export scenario may leave the page on a downloaded report or
            # (in an older run) on an API error. Never capture that: return to
            # the real application and verify its navigation rendered.
            if not page.url.startswith(URL) or page.locator("nav .nav-tab").count() == 0:
                page.goto(URL, wait_until="domcontentloaded", timeout=20000)
                page.wait_for_timeout(500)
            setup(page, name, lang)
            # Guard: a scenario that opened a report/download changed the page.
            # Capture the application view, not the report page or a JSON error.
            if page.locator("nav .nav-tab").count() == 0:
                page.goto(URL, wait_until="domcontentloaded", timeout=20000)
                to_tab(page, "repeater", 250)
            page.wait_for_timeout(120)
            page.screenshot(path=str(folder / name))
            ok += 1
        except Exception as exc:
            failed.append((name, f"{type(exc).__name__}: {str(exc)[:110]}"))
            try:
                reload(page)
            except Exception:
                pass
        if i % 40 == 0:
            print(f"  {lang}: {i}/{len(filenames)}", flush=True)
    ctx.close()
    print(f"{lang}: {ok}/{len(filenames)} captured, {len(errors)} page errors, {len(failed)} scenario failures")
    for f in failed[:12]:
        print("   !", f[0], f[1])
    return ok, failed, errors


def main():
    import os

    filenames = sorted(p.name for p in UK_DIR.glob("*.png"))
    only = os.environ.get("RR_ONLY", "").strip()
    if only:
        patterns = [p.strip() for p in only.split(",") if p.strip()]
        filenames = [f for f in filenames if any(p in f for p in patterns)]
    print(f"re-capturing {len(filenames)} screenshots per language")
    with sync_playwright() as p:
        browser = p.firefox.launch(headless=True)
        try:
            uk = capture_language(browser, "uk", filenames)
            en = capture_language(browser, "en", filenames)
        finally:
            browser.close()
    print(f"TOTAL: {uk[0] + en[0]}/{len(filenames) * 2} screenshots")
    sys.exit(0 if uk[0] == len(filenames) and en[0] == len(filenames) else 1)


if __name__ == "__main__":
    main()

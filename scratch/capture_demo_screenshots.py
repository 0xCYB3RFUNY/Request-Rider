#!/usr/bin/env python3
"""Capture live, data-rich Firefox screenshots for the Request-Rider manual.

Run from the repository root while the stack is up (:8000, :8081, :8090):

    browser-worker/.venv/bin/python scratch/capture_demo_screenshots.py

Produces paired UK/EN screenshots named 4xx-* inside
`Документація/screenshots/` and `Документація/screenshots_en/`.
The first two captures are 1920×1080 and 1356×652 (owner rule 2026-09-28);
the remaining ones use 1356×652. Every browser is closed in `finally`.
"""

from __future__ import annotations

import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
BASE_URL = "http://127.0.0.1:8000"
OUT = {
    "uk": ROOT / "Документація" / "screenshots",
    "en": ROOT / "Документація" / "screenshots_en",
}
RAW_REQUEST = "GET /health HTTP/1.1\nHost: 127.0.0.1:8081\nAccept: application/json\n\n"


def tab(page, name: str, wait: int = 350) -> None:
    page.click(f'nav .nav-tab[data-tab="{name}"]')
    page.wait_for_timeout(wait)


def shot(page, number: str, slug: str, lang: str) -> str:
    path = OUT[lang] / f"{number}-{slug}.png"
    page.screenshot(path=str(path))
    return path.name


def safe(label: str):
    def decorate(fn):
        def wrapper(page, lang):
            try:
                fn(page, lang)
                return True
            except Exception as exc:  # keep the rest of the gallery alive
                print(f"  ! {label}: {type(exc).__name__}: {str(exc)[:160]}", file=sys.stderr)
                return False

        wrapper.__name__ = label
        return wrapper

    return decorate


@safe("400/401 main with live engine response")
def s_main(page, lang):
    tab(page, "repeater", 250)
    page.fill("#repeater-raw-request", RAW_REQUEST)
    page.fill("#repeater-host", "127.0.0.1:8081")
    page.fill("#repeater-path", "/health")
    page.click("#send")
    page.wait_for_timeout(900)
    shot(page, "400", "main-1920", lang)
    page.set_viewport_size({"width": 1356, "height": 652})
    page.wait_for_timeout(350)
    shot(page, "401", "main-1356", lang)


@safe("402 repeater inspector")
def s_repeater_inspector(page, lang):
    tab(page, "repeater")
    page.click("#repeater-inspector-btn")
    page.wait_for_timeout(350)
    shot(page, "402", "repeater-inspector", lang)


@safe("403 intruder configuration")
def s_intruder(page, lang):
    tab(page, "intruder")
    page.fill(
        "#intruder-raw-request",
        "GET /search?q=§term§&page=%page% HTTP/1.1\nHost: 127.0.0.1:8081\nAccept: application/json\n\n",
    )
    mode = page.locator("#mode")
    if mode.count():
        for value in ("pitchfork", "sniper", "cluster_bomb"):
            try:
                mode.select_option(value)
                break
            except Exception:
                continue
    page.wait_for_timeout(300)
    shot(page, "403", "intruder-config", lang)


@safe("404 target parameters")
def s_target(page, lang):
    tab(page, "target")
    page.fill("#target-url", "http://127.0.0.1:8000/")
    page.wait_for_timeout(300)
    shot(page, "404", "target-settings", lang)


@safe("405 osint graph with seeded relations")
def s_osint(page, lang):
    tab(page, "osint", 500)
    select = page.locator("#osint-graph-select")
    if select.count():
        options = select.locator("option")
        if options.count():
            select.select_option(index=0)
            page.wait_for_timeout(700)
    page.click("#osint-graph-refresh")
    page.wait_for_timeout(500)
    shot(page, "405", "osint-graph", lang)


@safe("406 scanner settings")
def s_scanner(page, lang):
    tab(page, "scanner", 500)
    page.fill("#scanner-url", "http://127.0.0.1:8000/")
    page.wait_for_timeout(300)
    shot(page, "406", "scanner-settings", lang)


@safe("407/408 automation graph and runs")
def s_automation(page, lang):
    tab(page, "automation", 500)
    wf = page.locator('section#automation button:has-text("Демо · ")')
    if wf.count():
        wf.first.click()
        page.wait_for_timeout(500)
    shot(page, "407", "automation-canvas", lang)
    refresh = page.locator("#workflow-refresh-runs")
    if refresh.count():
        refresh.click()
        page.wait_for_timeout(500)
    runs = page.locator('section#automation [id*="run"]').last
    if runs.count():
        runs.scroll_into_view_if_needed()
    page.wait_for_timeout(250)
    shot(page, "408", "automation-runs", lang)


@safe("409 traffic with durable archive rows")
def s_traffic(page, lang):
    tab(page, "traffic", 400)
    more = page.locator("#traffic-more")
    if more.count() and more.is_visible():
        more.click()
        page.wait_for_timeout(900)
    # Invariant 1: RAW takes the first full screen and the table lives on the
    # second one. Scroll to the archived rows so the capture proves real data.
    page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
    page.wait_for_timeout(450)
    shot(page, "409", "traffic-data", lang)


@safe("410 projects hub")
def s_projects(page, lang):
    tab(page, "projects", 500)
    shot(page, "410", "projects-hub", lang)


@safe("411 proxy route parameters")
def s_proxy(page, lang):
    tab(page, "proxy")
    page.fill("#route-check-timeout", "5000")
    page.wait_for_timeout(250)
    shot(page, "411", "proxy-route", lang)


@safe("412 decoder transformation")
def s_decoder(page, lang):
    tab(page, "decoder")
    page.fill("#decoder-input", "RequestRider demo · OWASP ZAP parity")
    op = page.locator("#decoder-operation")
    for value in ("base64Encode", "base64encode", "urlEncode"):
        try:
            op.select_option(value)
            break
        except Exception:
            continue
    page.click("#decoder-apply")
    page.wait_for_timeout(300)
    shot(page, "412", "decoder-transform", lang)


@safe("413 comparer diff")
def s_comparer(page, lang):
    tab(page, "comparer")
    page.fill("#comparer-left", "GET /api/users/1 HTTP/1.1\nHost: example.ru\n\n200 OK\n{\"role\":\"user\"}")
    page.fill("#comparer-right", "GET /api/users/2 HTTP/1.1\nHost: example.ru\n\n200 OK\n{\"role\":\"admin\"}")
    page.click("#compare-words")
    page.wait_for_timeout(350)
    shot(page, "413", "comparer-diff", lang)


@safe("414 AI chat")
def s_ai(page, lang):
    tab(page, "ai", 500)
    shot(page, "414", "ai-chat", lang)


@safe("415 AI fullscreen with font-size control")
def s_ai_fullscreen(page, lang):
    tab(page, "ai", 350)
    page.click("#ai-fullscreen-btn")
    page.wait_for_timeout(400)
    slider = page.locator("#ai-font-size")
    if slider.count():
        slider.fill("16")
        page.wait_for_timeout(200)
    shot(page, "415", "ai-fullscreen", lang)
    close = page.locator("#ai-fullscreen-close")
    if close.count():
        close.click()


@safe("416 project export formats")
def s_exports(page, lang):
    tab(page, "projects", 400)
    page.click("#project-export")
    page.wait_for_timeout(300)
    shot(page, "416", "export-formats", lang)
    page.keyboard.press("Escape")


@safe("417 scanner active view")
def s_scanner_active(page, lang):
    tab(page, "scanner", 350)
    page.click("#scanner-view-active")
    page.wait_for_timeout(400)
    shot(page, "417", "scanner-active", lang)


SCENARIOS = [
    s_main,
    s_repeater_inspector,
    s_intruder,
    s_target,
    s_osint,
    s_scanner,
    s_automation,
    s_traffic,
    s_projects,
    s_proxy,
    s_decoder,
    s_comparer,
    s_ai,
    s_ai_fullscreen,
    s_exports,
    s_scanner_active,
]


def capture_language(browser, lang: str):
    ctx = browser.new_context(viewport={"width": 1920, "height": 1080}, locale="uk-UA" if lang == "uk" else "en-US")
    ctx.add_init_script(f"localStorage.setItem('requestrider-language', '{lang}');")
    page = ctx.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("console", lambda m: errors.append(f"console:{m.text}") if m.type == "error" else None)
    page.goto(BASE_URL, wait_until="domcontentloaded", timeout=30000)
    page.wait_for_timeout(900)
    # A reload makes the injected language the authoritative one for all render* functions.
    page.reload(wait_until="domcontentloaded")
    page.wait_for_timeout(700)
    ok = 0
    for scenario in SCENARIOS:
        if scenario(page, lang):
            ok += 1
    print(f"{lang}: {ok}/{len(SCENARIOS)} scenarios OK, page errors: {len(errors)}")
    if errors:
        print("  first errors:", errors[:3])
    ctx.close()
    return ok, errors


def main():
    for folder in OUT.values():
        folder.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.firefox.launch(headless=True)
        try:
            results = {lang: capture_language(browser, lang) for lang in ("uk", "en")}
        finally:
            browser.close()
    total_ok = sum(v[0] for v in results.values())
    total_err = sum(len(v[1]) for v in results.values())
    print(f"TOTAL: {total_ok} scenarios, {total_err} page errors")
    if total_ok < len(SCENARIOS) * 2 or total_err:
        sys.exit(1)


if __name__ == "__main__":
    main()

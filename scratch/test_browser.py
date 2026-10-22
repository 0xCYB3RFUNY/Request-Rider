from playwright.sync_api import sync_playwright

def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page_errors = []
        page.on("pageerror", lambda err: page_errors.append(str(err)))
        console_msgs = []
        page.on("console", lambda msg: console_msgs.append(f"{msg.type}: {msg.text}"))

        print("Navigating to http://127.0.0.1:8000 ...")
        page.goto("http://127.0.0.1:8000", wait_until="networkidle", timeout=15000)
        page.wait_for_timeout(3000)

        print(f"PAGE ERRORS count: {len(page_errors)}")
        for err in page_errors:
            print(f"  ERROR: {err}")

        # Check status strip indicators
        engine_dot = page.locator("#ss-engine-dot")
        proxy_dot = page.locator("#ss-proxy-dot")
        cls_engine = engine_dot.get_attribute("class")
        cls_proxy = proxy_dot.get_attribute("class")
        print(f"ss-engine-dot class: {cls_engine}")
        print(f"ss-proxy-dot class: {cls_proxy}")

        # Check navigation tabs
        nav_tabs = page.locator("nav .nav-tab").all()
        print(f"Found {len(nav_tabs)} nav tabs")
        for tab in nav_tabs:
            tab_name = tab.get_attribute("data-tab")
            tab.click()
            page.wait_for_timeout(300)
            is_active = "active" in (tab.get_attribute("class") or "")
            print(f"Tab {tab_name}: active={is_active}")

        print(f"Final PAGE ERRORS count: {len(page_errors)}")
        for err in page_errors:
            print(f"  FINAL ERROR: {err}")
        browser.close()

if __name__ == "__main__":
    main()

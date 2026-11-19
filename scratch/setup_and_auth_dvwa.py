import asyncio
from playwright.async_api import async_playwright

async def setup_and_login():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        print("[1] Opening setup.php ...")
        await page.goto("http://127.0.0.1:8088/setup.php")
        await page.wait_for_timeout(1000)
        
        # Click "Create / Reset Database"
        print("[2] Clicking Create / Reset Database ...")
        await page.click("input[name='create_db']")
        await page.wait_for_timeout(2000)

        # Navigate to login.php
        print("[3] Opening login.php ...")
        await page.goto("http://127.0.0.1:8088/login.php")
        await page.fill("input[name='username']", "admin")
        await page.fill("input[name='password']", "password")
        await page.click("input[name='Login']")
        await page.wait_for_timeout(2000)

        current_url = page.url
        print(f"[4] Current URL after login: {current_url}")

        cookies = await context.cookies()
        cookie_parts = [f"{c['name']}={c['value']}" for c in cookies]
        cookie_header = "; ".join(cookie_parts)
        print(f"[5] Session Cookie Header: {cookie_header}")

        # Check content of index.php
        content = await page.content()
        has_vulnerabilities_nav = "vulnerabilities/" in content
        print(f"[6] Navigation contains vulnerabilities link: {has_vulnerabilities_nav}")

        await browser.close()
        return cookie_header

if __name__ == "__main__":
    asyncio.run(setup_and_login())

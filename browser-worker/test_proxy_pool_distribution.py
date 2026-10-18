#!/usr/bin/env python3
"""Test proxy pool distribution and deduplication across browser fleet."""
import asyncio
import unittest
from unittest.mock import MagicMock

import sys
from pathlib import Path

# Add browser-worker to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from proxy_pool import ProxyPool, pool_from_payload


class ProxyPoolDistributionTests(unittest.IsolatedAsyncioTestCase):
    async def test_fleet_deduplication_and_distribution(self):
        """Simulate crawl queue processing across multiple fleet workers with a proxy pool."""
        endpoints = [
            "http://proxy1.internal:8080",
            "http://proxy2.internal:8080",
            "http://proxy3.internal:8080",
        ]
        pool = ProxyPool(endpoints)
        self.assertEqual(pool.slots(3), endpoints)

        # Simulated link graph
        graph = {
            "http://target.local/": [
                "http://target.local/page1",
                "http://target.local/page2",
                "http://target.local/page3",
            ],
            "http://target.local/page1": [
                "http://target.local/sub1",
                "http://target.local/sub2",
                "http://target.local/page2", # Duplicate reference
            ],
            "http://target.local/page2": [
                "http://target.local/sub3",
                "http://target.local/page3", # Duplicate reference
            ],
            "http://target.local/page3": [
                "http://target.local/sub4",
            ],
            "http://target.local/sub1": [],
            "http://target.local/sub2": [],
            "http://target.local/sub3": [],
            "http://target.local/sub4": [],
        }

        # Shared queue and seen state, exactly as in worker.py
        queue = asyncio.Queue()
        start_url = "http://target.local/"
        seen = {start_url}
        state_lock = asyncio.Lock()
        await queue.put((start_url, 0))

        executed = []
        proxy_executions = {ep: 0 for ep in endpoints}

        async def simulate_browser_worker(endpoint):
            while True:
                try:
                    url, depth = await asyncio.wait_for(queue.get(), timeout=0.1)
                except asyncio.TimeoutError:
                    break

                try:
                    # Record execution
                    async with state_lock:
                        executed.append((url, endpoint))
                        proxy_executions[endpoint] += 1

                    # Discover links and add to seen / queue under lock
                    discovered = graph.get(url, [])
                    async with state_lock:
                        for link in discovered:
                            if link not in seen:
                                seen.add(link)
                                await queue.put((link, depth + 1))
                    await asyncio.sleep(0.005)
                finally:
                    queue.task_done()

        # Run 3 workers concurrently, one per endpoint
        tasks = [
            asyncio.create_task(simulate_browser_worker(ep))
            for ep in endpoints
        ]
        await queue.join()
        await asyncio.gather(*tasks)

        # Verify deduplication: every distinct URL in graph was crawled exactly once
        executed_urls = [url for url, ep in executed]
        self.assertEqual(len(executed_urls), len(set(executed_urls)), "Duplicate requests detected in worker queue!")
        self.assertEqual(len(executed_urls), 8, f"Expected 8 unique URLs crawled, got {len(executed_urls)}")

        # Verify proxy distribution: all endpoints were utilized
        for ep, count in proxy_executions.items():
            self.assertGreater(count, 0, f"Proxy endpoint {ep} was starved and never used!")

    async def test_fleet_replicate_distribution(self):
        """Simulate crawl in replicate mode: each proxy worker crawls the entire target list."""
        endpoints = [
            "http://proxy1.internal:8080",
            "http://proxy2.internal:8080",
            "http://proxy3.internal:8080",
        ]
        pool = ProxyPool(endpoints, mode="replicate")
        self.assertEqual(pool.mode, "replicate")
        report = pool.report()
        self.assertEqual(report["mode"], "replicate")

        # Simulated link graph
        graph = {
            "http://target.local/": [
                "http://target.local/page1",
                "http://target.local/page2",
            ],
            "http://target.local/page1": [],
            "http://target.local/page2": [],
        }

        executed_by_endpoint = {ep: [] for ep in endpoints}

        async def simulate_replicate_worker(endpoint):
            # In replicate mode, each worker has its own independent queue and seen set
            queue = asyncio.Queue()
            start_url = "http://target.local/"
            seen = {start_url}
            await queue.put((start_url, 0))

            while True:
                try:
                    url, depth = await asyncio.wait_for(queue.get(), timeout=0.1)
                except asyncio.TimeoutError:
                    break

                try:
                    executed_by_endpoint[endpoint].append(url)
                    discovered = graph.get(url, [])
                    for link in discovered:
                        if link not in seen:
                            seen.add(link)
                            await queue.put((link, depth + 1))
                    await asyncio.sleep(0.002)
                finally:
                    queue.task_done()

        tasks = [
            asyncio.create_task(simulate_replicate_worker(ep))
            for ep in endpoints
        ]
        await asyncio.gather(*tasks)

        # In replicate mode, EVERY endpoint must have independently visited all 3 URLs
        for ep, visited in executed_by_endpoint.items():
            self.assertEqual(len(visited), 3, f"Endpoint {ep} only visited {len(visited)} URLs, expected 3")
            self.assertEqual(set(visited), {"http://target.local/", "http://target.local/page1", "http://target.local/page2"})


class BrowserLaunchRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_launch_browser_chromium_passes_ignore_cert_errors_and_awaits_font_env(self):
        from unittest.mock import AsyncMock, patch
        import worker

        fake_browser = MagicMock()
        fake_playwright = MagicMock()
        fake_playwright.chromium.launch = AsyncMock(return_value=fake_browser)

        with patch("worker.chromium_fonts.launch_env", new=AsyncMock(return_value={"FONTCONFIG_FILE": "/tmp/fonts.conf"})) as mock_env:
            result = await worker.launch_browser(
                fake_playwright,
                "chromium",
                proxy={"server": "http://127.0.0.1:8080"},
            )

        self.assertIs(result, fake_browser)
        mock_env.assert_awaited_once_with(fake_playwright)
        fake_playwright.chromium.launch.assert_awaited_once()
        call_kwargs = fake_playwright.chromium.launch.await_args.kwargs
        self.assertEqual(call_kwargs["headless"], True)
        self.assertEqual(call_kwargs["proxy"], {"server": "http://127.0.0.1:8080"})
        self.assertIn("--ignore-certificate-errors", call_kwargs["args"])
        self.assertEqual(call_kwargs["env"], {"FONTCONFIG_FILE": "/tmp/fonts.conf"})

    async def test_launch_browser_camoufox_uses_async_new_browser_not_chromium(self):
        from unittest.mock import AsyncMock, patch
        import worker

        fake_camoufox_browser = MagicMock()
        fake_playwright = MagicMock()
        fake_playwright.chromium.launch = AsyncMock()
        fake_playwright.firefox.launch = AsyncMock()

        with patch("camoufox.async_api.AsyncNewBrowser", new=AsyncMock(return_value=fake_camoufox_browser)) as mock_camoufox:
            result = await worker.launch_browser(
                fake_playwright,
                "camoufox",
                proxy={"server": "http://127.0.0.1:8080"},
            )

        self.assertIs(result, fake_camoufox_browser)
        mock_camoufox.assert_awaited_once_with(
            fake_playwright,
            headless=True,
            proxy={"server": "http://127.0.0.1:8080"},
            i_know_what_im_doing=True,
        )
        fake_playwright.chromium.launch.assert_not_awaited()
        fake_playwright.firefox.launch.assert_not_awaited()

    async def test_chromium_fonts_system_config_draws_text_awaits_async_playwright(self):
        from unittest.mock import AsyncMock
        import chromium_fonts

        fake_page = MagicMock()
        fake_page.set_content = AsyncMock()
        fake_page.wait_for_timeout = AsyncMock()
        fake_page.screenshot = AsyncMock(return_value=b"x" * (chromium_fonts._PROBE_THRESHOLD_BYTES + 100))

        fake_browser = MagicMock()
        fake_browser.new_page = AsyncMock(return_value=fake_page)
        fake_browser.close = AsyncMock()

        fake_playwright = MagicMock()
        fake_playwright.chromium.launch = AsyncMock(return_value=fake_browser)

        draws = await chromium_fonts._system_config_draws_text(fake_playwright)
        self.assertTrue(draws)
        fake_playwright.chromium.launch.assert_awaited_once()
        fake_browser.new_page.assert_awaited_once()
        fake_page.set_content.assert_awaited_once()
        fake_page.wait_for_timeout.assert_awaited_once()
        fake_page.screenshot.assert_awaited_once()
        fake_browser.close.assert_awaited_once()

    async def test_extract_links_excludes_script_src_and_resolves_links(self):
        from unittest.mock import AsyncMock
        import worker

        fake_page = MagicMock()
        fake_page.eval_on_selector_all = AsyncMock(return_value=["/about", "/contact"])

        links = await worker.extract_links(fake_page, "http://127.0.0.1:18993/")
        self.assertEqual(links, ["http://127.0.0.1:18993/about", "http://127.0.0.1:18993/contact"])
        selector_arg = fake_page.eval_on_selector_all.await_args.args[0]
        self.assertNotIn("script[src]", selector_arg)

    async def test_perform_auto_interactions_skips_cross_origin_forms_when_same_origin_enabled(self):
        from unittest.mock import AsyncMock, patch
        import worker

        fake_page = MagicMock()
        fake_page.url = "http://127.0.0.1:18993/"
        fake_page.goto = AsyncMock()
        fake_page.wait_for_timeout = AsyncMock()

        fake_plan = {
            "forms": [
                {
                    "index": 0,
                    "method": "POST",
                    "action": "http://127.0.0.1:18994/ext-submit",
                    "fields": [{"selector": "#q", "kind": "text", "name": "q"}],
                    "submit_selector": "button[type='submit']",
                }
            ],
            "fields": [],
            "controls": [],
        }

        with patch("worker.await_auto_plan", new=AsyncMock(return_value=(fake_plan, {"status": "ready"}))):
            actions, wait_report = await worker.perform_auto_interactions(
                fake_page,
                {
                    "url": "http://127.0.0.1:18993/",
                    "same_origin": True,
                    "auto_fill": True,
                    "auto_click": False,
                    "auto_wait_timeout_ms": 100,
                    "navigation_timeout_ms": 1000,
                },
                "job-test",
                "http://127.0.0.1:18993/",
            )

        self.assertEqual(actions, [])
        self.assertEqual(wait_report["status"], "ready")


if __name__ == "__main__":
    unittest.main()



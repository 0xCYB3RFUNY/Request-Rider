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


if __name__ == "__main__":
    unittest.main()

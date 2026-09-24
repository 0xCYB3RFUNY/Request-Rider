import json
import threading
import unittest
import urllib.request

from tools.oast_fixture import OASTFixtureServer


class OASTFixtureTests(unittest.TestCase):
    def setUp(self):
        self.server = OASTFixtureServer(("127.0.0.1", 0))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, path, method="GET", payload=None):
        body = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(
            f"{self.base}{path}",
            data=body,
            method=method,
            headers={"Content-Type": "application/json"} if body else {},
        )
        with urllib.request.urlopen(request, timeout=2) as response:
            return response.status, json.loads(response.read())

    def test_register_poll_and_delete_listener(self):
        status, registration = self.request(
            "/register",
            method="POST",
            payload={"listener_id": "fixture-test", "protocols": ["http"]},
        )
        self.assertEqual(status, 200)
        self.assertEqual(registration["listener_id"], "fixture-test")
        status, result = self.request(f"/hit/{registration['listener_id']}?kind=canary")
        self.assertEqual(status, 200)
        status, result = self.request(f"/poll?listener_id={registration['listener_id']}")
        self.assertEqual(status, 200)
        self.assertTrue(result["triggered"])
        self.assertEqual(result["events"][0]["query"]["kind"], "canary")
        status, result = self.request(f"/listener/{registration['listener_id']}", method="DELETE")
        self.assertEqual(status, 200)
        self.assertTrue(result["deleted"])
        status, result = self.request(f"/listener/{registration['listener_id']}", method="DELETE")
        self.assertEqual(status, 200)
        self.assertFalse(result["deleted"])

    def test_poll_without_callback_is_explicitly_empty(self):
        status, registration = self.request(
            "/register",
            method="POST",
            payload={"listener_id": "empty-listener", "protocols": ["http"]},
        )
        self.assertEqual(status, 200)
        status, result = self.request(f"/poll?listener_id={registration['listener_id']}")
        self.assertEqual(status, 200)
        self.assertFalse(result["triggered"])
        self.assertEqual(result["events"], [])


if __name__ == "__main__":
    unittest.main()

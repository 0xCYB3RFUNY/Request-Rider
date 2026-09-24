import socket
import threading
import time
import unittest

from tools.last_byte_fixture import LastByteFixtureServer


class LastByteFixtureTests(unittest.TestCase):
    def setUp(self):
        self.server = LastByteFixtureServer(("127.0.0.1", 0))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_final_byte_is_required_before_fixture_responds(self):
        body = b"canary"
        wire = (
            b"POST /sync HTTP/1.1\r\n"
            + f"Host: {self.host}:{self.port}\r\n".encode("ascii")
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"Connection: close\r\n\r\n"
            + body
        )
        with socket.create_connection((self.host, self.port), timeout=2) as connection:
            connection.sendall(wire[:-1])
            time.sleep(0.04)
            connection.sendall(wire[-1:])
            response = b""
            while True:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                response += chunk
        self.assertIn(b"200 OK", response)
        self.assertIn(b'"fixture": "last-byte"', response)
        self.assertEqual(len(self.server.requests), 1)
        self.assertEqual(self.server.requests[0]["body_bytes"], len(body))


if __name__ == "__main__":
    unittest.main()

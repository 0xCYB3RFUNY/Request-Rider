"""The Redis transport, tested without a broker and again with one.

Two layers, because they answer different questions. The in-process RESP server
answers "does the transport speak the protocol it thinks it speaks" on any
machine, and the live class answers "does a real Redis agree", which is the only
way to know that a blocking move really is one command.
"""

import io
import json
import socketserver
import threading
import time
import unittest
from urllib.parse import quote

from django.test import SimpleTestCase, TestCase

from lab import broker_transport
from lab.broker_transport import (
    RESULT_QUEUE,
    TASK_QUEUE,
    BrokerTransportError,
    RedisConnection,
    RedisResultConsumer,
    dead_list,
    inflight_list,
    is_redis,
    parse_redis_url,
    publish_task,
    require_redis_broker,
)
from lab.engine_task_contract import validate_engine_task
from lab.tasks import publish_engine_task
from lab.models import EngineTask


def valid_task(task_id="6f0e8400-e29b-41d4-a716-446655440000"):
    return {
        "schema_version": 1,
        "task_id": task_id,
        "task_type": "target.crawl",
        "created_at": "2026-09-27T09:00:00+00:00",
        "payload": {"url": "http://127.0.0.1/fixture/§"},
    }


class FakeRedisHandler(socketserver.StreamRequestHandler):
    """A RESP2 server with exactly the commands this transport uses."""

    def handle(self):
        lists = self.server.lists
        values = self.server.values
        while True:
            command = self._read_command()
            if command is None:
                return
            name = command[0].upper()
            if name == "PING":
                self._write(b"+PONG\r\n")
            elif name == "AUTH":
                self._write(b"+OK\r\n")
            elif name == "SELECT":
                self._write(b"+OK\r\n")
            elif name == "LPUSH":
                key = command[1]
                for value in command[2:]:
                    lists.setdefault(key, []).insert(0, value)
                self._write(b":%d\r\n" % len(lists[key]))
            elif name == "LMOVE" or name == "BLMOVE":
                source, destination, src_pos, dest_pos = command[1:5]
                blocking = name == "BLMOVE"
                timeout = float(command[5]) if blocking and len(command) > 5 else 0.0
                deadline = time.monotonic() + timeout
                while True:
                    items = lists.get(source, [])
                    if items:
                        taken = items.pop() if src_pos.upper() == "RIGHT" else items.pop(0)
                        target = lists.setdefault(destination, [])
                        if dest_pos.upper() == "RIGHT":
                            target.append(taken)
                        else:
                            target.insert(0, taken)
                        self._write_bulk(taken)
                        break
                    if not blocking or time.monotonic() >= deadline:
                        self._write(b"$-1\r\n")
                        break
                    time.sleep(0.01)
            elif name == "BRPOP":
                key, timeout = command[1], float(command[2])
                deadline = time.monotonic() + timeout
                while True:
                    items = lists.get(key, [])
                    if items:
                        taken = items.pop()
                        self._write_bulk(taken)
                        break
                    if time.monotonic() >= deadline:
                        self._write(b"$-1\r\n")
                        break
                    time.sleep(0.01)
            elif name == "LREM":
                key, value = command[1], command[3]
                items = lists.get(key, [])
                if value in items:
                    items.remove(value)
                    self._write(b":1\r\n")
                else:
                    self._write(b":0\r\n")
            elif name == "LLEN":
                self._write(b":%d\r\n" % len(lists.get(command[1], [])))
            elif name == "LRANGE":
                items = lists.get(command[1], [])
                start, stop = int(command[2]), int(command[3])
                selected = items[start:] if stop == -1 else items[start : stop + 1]
                self._write(b"*%d\r\n" % len(selected))
                for item in selected:
                    self._write_bulk(item)
            elif name == "INFO":
                if command[1] == "server" and self.server.version:
                    self._write(
                        b"$%d\r\n" % len(self.server.version)
                        + self.server.version
                        + b"\r\n"
                    )
                else:
                    self._write(b"-ERR unknown command 'INFO'\r\n")
            elif name == "GET":
                if command[1] in values:
                    stored = values[command[1]].encode("utf-8")
                    self._write(b"$%d\r\n%s\r\n" % (len(stored), stored))
                else:
                    self._write(b"$-1\r\n")
            elif name == "SET":
                values[command[1]] = command[2]
                self._write(b"+OK\r\n")
            elif name == "DEL":
                for key in command[1:]:
                    lists.pop(key, None)
                    values.pop(key, None)
                self._write(b":%d\r\n" % len(command) - 1)
            else:
                self._write(b"-ERR unknown command " + name.encode() + b"\r\n")

    def _read_command(self):
        line = self.rfile.readline()
        if not line:
            return None
        if not line.startswith(b"*"):
            return None
        arguments = []
        for _ in range(int(line[1:-2])):
            header = self.rfile.readline()
            if not header.startswith(b"$"):
                return None
            payload = self.rfile.read(int(header[1:-2]) + 2)
            arguments.append(payload[:-2].decode("utf-8"))
        return arguments

    def _write_bulk(self, value: str):
        raw = value.encode("utf-8")
        self._write(b"$%d\r\n" % len(raw) + raw + b"\r\n")

    def _write(self, payload):
        self.wfile.write(payload)
        self.wfile.flush()


class FakeRedisServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), FakeRedisHandler)
        self.lists = {}
        self.values = {}
        self.version = b"# Server\r\nredis_version:8.0.6\r\n"
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc_info):
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=5)

    @property
    def url(self):
        return f"redis://127.0.0.1:{self.server_address[1]}/0"


class RedisURLTests(SimpleTestCase):
    def test_broker_schemes_are_recognised(self):
        self.assertTrue(is_redis("redis://127.0.0.1:6379/0"))
        self.assertTrue(is_redis("rediss://cache:6380/1"))
        self.assertTrue(is_redis("unix:///tmp/rr.sock"))
        self.assertFalse(is_redis("amqp://guest@127.0.0.1:5672//"))

    def test_a_removed_broker_url_names_its_replacement(self):
        # An old broker URL in the environment must fail here, loudly, and say
        # what to use instead — not publish nowhere and mark the task published.
        for broker_url in ["amqp://guest:guest@127.0.0.1:5672//", "amqps://broker/", ""]:
            with self.assertRaises(BrokerTransportError) as raised:
                require_redis_broker(broker_url)
            message = str(raised.exception)
            self.assertIn("redis://127.0.0.1:6379/0", message)
            self.assertIn("CELERY_BROKER_URL", message)
        self.assertEqual("redis://127.0.0.1:6379/2", require_redis_broker("redis://127.0.0.1:6379/2"))

    def test_a_plain_url_keeps_its_parts(self):
        target = parse_redis_url("redis://127.0.0.1:6379/0")
        self.assertEqual(("127.0.0.1", 6379, 0, False), (target.host, target.port, target.db, target.use_tls))

    def test_credentials_and_database_index_are_read(self):
        # safe="" because a password with a slash must be percent-encoded, or
        # the URL has two slashes where the parser expects one.
        target = parse_redis_url(
            f"redis://agent:{quote('p@ss/word', safe='')}@cache.example:6380/4"
        )
        self.assertEqual("cache.example", target.host)
        self.assertEqual(6380, target.port)
        self.assertEqual(4, target.db)
        self.assertEqual("p@ss/word", target.password)
        self.assertEqual("agent", target.username)

    def test_defaults_apply_when_the_url_is_bare(self):
        target = parse_redis_url("redis://")
        self.assertEqual(("127.0.0.1", 6379, 0), (target.host, target.port, target.db))

    def test_tls_and_unix_forms_are_parsed(self):
        self.assertTrue(parse_redis_url("rediss://cache:6380/2").use_tls)
        unix = parse_redis_url("unix:///tmp/rr.sock?db=2&password=s3cret")
        self.assertEqual("/tmp/rr.sock", unix.unix_path)
        self.assertEqual(2, unix.db)
        self.assertEqual("s3cret", unix.password)

    def test_a_broken_url_is_reported_with_its_own_text(self):
        with self.assertRaises(BrokerTransportError) as raised:
            parse_redis_url("amqp://guest@127.0.0.1:5672//")
        self.assertIn("not a Redis URL", str(raised.exception))
        with self.assertRaises(BrokerTransportError) as raised:
            parse_redis_url("redis://127.0.0.1:6379/not-a-number")
        self.assertIn("not-a-number", str(raised.exception))


class CommandEncodingTests(SimpleTestCase):
    def test_a_command_is_encoded_as_a_resp_array_of_bulk_strings(self):
        self.assertEqual(
            b"*2\r\n$4\r\nPING\r\n$5\r\nhello\r\n",
            broker_transport._encode_command(["PING", "hello"]),
        )

    def test_bytes_arguments_are_sent_verbatim(self):
        # A non-ASCII marker must reach the broker as the UTF-8 bytes of the
        # right length, because the length prefix is what Redis reads first.
        self.assertEqual(
            b"*1\r\n$3\r\n\xc2\xa7x\r\n",
            broker_transport._encode_command(["\u00a7x".encode("utf-8")]),
        )

    def test_replies_of_every_shape_are_decoded(self):
        stream = io.BytesIO(b"+OK\r\n:7\r\n$5\r\nhello\r\n$-1\r\n*2\r\n$1\r\na\r\n$1\r\nb\r\n*-1\r\n")
        self.assertEqual("OK", broker_transport._read_reply(stream))
        self.assertEqual(7, broker_transport._read_reply(stream))
        self.assertEqual(b"hello", broker_transport._read_reply(stream))
        self.assertIsNone(broker_transport._read_reply(stream))
        self.assertEqual([b"a", b"b"], broker_transport._read_reply(stream))
        self.assertIsNone(broker_transport._read_reply(stream))

    def test_an_error_reply_and_a_closed_connection_are_reported(self):
        with self.assertRaises(BrokerTransportError) as raised:
            broker_transport._read_reply(io.BytesIO(b"-ERR wrong number of arguments\r\n"))
        self.assertIn("wrong number of arguments", str(raised.exception))
        with self.assertRaises(BrokerTransportError):
            broker_transport._read_reply(io.BytesIO(b""))
        with self.assertRaises(BrokerTransportError):
            broker_transport._read_reply(io.BytesIO(b"?unexpected\r\n"))


class FakeBrokerTests(SimpleTestCase):
    """The protocol and the reliability rules, with no broker involved."""

    def setUp(self):
        self.server = FakeRedisServer()
        self.server.__enter__()
        self.addCleanup(self.server.__exit__, None, None, None)

    def test_a_published_task_is_the_contract_json_and_the_go_engine_can_read_it(self):
        envelope = valid_task()
        validate_engine_task(envelope)
        length = publish_task(self.server.url, envelope, queue="tasks")
        self.assertEqual(1, length)

        with RedisConnection(parse_redis_url(self.server.url)) as connection:
            taken = connection.command(
                "BLMOVE", "tasks", inflight_list("tasks"), "RIGHT", "LEFT", "1.000"
            )
        # Exactly what the Go transport does: one blocking move out of the queue
        # and into the in-flight list.
        self.assertEqual(json.loads(taken), envelope)

    def test_fifo_order_survives_both_sides(self):
        for index in range(3):
            publish_task(self.server.url, valid_task(), queue="tasks")
        with RedisConnection(parse_redis_url(self.server.url)) as connection:
            served = [
                connection.command(
                    "BLMOVE", "tasks", inflight_list("tasks"), "RIGHT", "LEFT", "1.000"
                )
                for _ in range(3)
            ]
        self.assertEqual(3, len(served))

    def test_ack_settles_a_delivery_exactly_once(self):
        publish_task(self.server.url, valid_task(), queue="results")
        with RedisResultConsumer(self.server.url, queue="results") as consumer:
            delivery = consumer.next_message(1)
            self.assertIsNotNone(delivery)
            delivery.ack()
            delivery.ack()
            self.assertIsNone(consumer.next_message(0.2))
            self.assertEqual(0, self._length(inflight_list("results")))

    def test_requeue_returns_the_message_and_reject_keeps_it_as_evidence(self):
        publish_task(self.server.url, valid_task(), queue="retry")
        with RedisResultConsumer(self.server.url, queue="retry") as consumer:
            consumer.next_message(1).requeue()
            self.assertEqual(1, self._length("retry"))
            self.assertEqual(0, self._length(inflight_list("retry")))

        publish_task(self.server.url, valid_task(), queue="poison")
        with RedisResultConsumer(self.server.url, queue="poison") as consumer:
            consumer.next_message(1).reject(requeue=False)
            self.assertEqual(0, self._length("poison"))
            self.assertEqual(1, self._length(dead_list("poison")))
            self.assertEqual(0, self._length(inflight_list("poison")))

    def test_a_consumer_recovers_what_a_dead_process_left_inflight(self):
        publish_task(self.server.url, valid_task(), queue="results")
        with RedisConnection(parse_redis_url(self.server.url)) as connection:
            connection.command("BLMOVE", "results", inflight_list("results"), "RIGHT", "LEFT", "1.000")
        # A second consumer starts while the message is still held by the first.
        with RedisResultConsumer(self.server.url, queue="results") as consumer:
            self.assertIsNotNone(consumer.next_message(1))
            consumer.recover_inflight()

    def test_ping_and_an_unreachable_broker_are_distinguished(self):
        with RedisConnection(parse_redis_url(self.server.url)) as connection:
            self.assertTrue(connection.ping())
        with self.assertRaises(BrokerTransportError) as raised:
            with RedisConnection(parse_redis_url("redis://127.0.0.1:1/0"), timeout=0.5) as connection:
                connection.ping()
        self.assertIn("cannot reach", str(raised.exception))

    def test_a_broker_without_blocking_moves_is_refused_by_name(self) -> None:
        self.server.version = b"# Server\r\nredis_version:6.0.9\r\n"
        with self.assertRaises(BrokerTransportError) as raised:
            RedisResultConsumer(self.server.url, queue="results").__enter__()
        self.assertIn("6.0.9", str(raised.exception))
        self.assertIn("6.2", str(raised.exception))

    def test_a_broker_that_hides_its_version_is_still_usable(self) -> None:
        # Managed brokers can disable INFO; refusing to start over a missing
        # version string would be worse than the risk being real.
        self.server.version = b""
        with RedisResultConsumer(self.server.url, queue="results") as consumer:
            self.assertIsNone(consumer.next_message(0.2))

    def test_the_queue_names_are_the_contract(self):
        self.assertEqual("rr.engine.tasks.v1", TASK_QUEUE)
        self.assertEqual("rr.engine.results.v1", RESULT_QUEUE)
        self.assertEqual("rr.engine.results.v1.inflight", inflight_list(RESULT_QUEUE))
        self.assertEqual("rr.engine.results.v1.dead", dead_list(RESULT_QUEUE))

    def _length(self, key):
        with RedisConnection(parse_redis_url(self.server.url)) as connection:
            return int(connection.command("LLEN", key))


class LiveRedisTests(SimpleTestCase):
    """The same rules against a real server, when one is listening."""

    URL = "redis://127.0.0.1:6379/15"

    def setUp(self):
        try:
            with RedisConnection(parse_redis_url(self.URL), timeout=1.0) as connection:
                if not connection.ping():
                    raise BrokerTransportError("no PING answer")
        except BrokerTransportError as error:
            self.skipTest(f"no Redis broker at {self.URL}: {error}")
        self.addCleanup(self._clear)

    def _clear(self):
        with RedisConnection(parse_redis_url(self.URL)) as connection:
            connection.command("DEL", RESULT_QUEUE, inflight_list(RESULT_QUEUE), dead_list(RESULT_QUEUE))

    def test_the_oldest_message_is_served_first_and_the_ack_is_durable(self):
        first_id = "6f0e8400-e29b-41d4-a716-446655440000"
        second_id = "7f0e8400-e29b-41d4-a716-446655440001"
        publish_task(self.URL, valid_task(first_id), queue=RESULT_QUEUE)
        publish_task(self.URL, valid_task(second_id), queue=RESULT_QUEUE)
        with RedisResultConsumer(self.URL, queue=RESULT_QUEUE) as consumer:
            first = consumer.next_message(2)
            self.assertIsNotNone(first)
            self.assertEqual(first_id, json.loads(first.body)["task_id"])
            first.ack()
            with RedisConnection(parse_redis_url(self.URL)) as connection:
                self.assertEqual(0, int(connection.command("LLEN", inflight_list(RESULT_QUEUE))))
                self.assertEqual(1, int(connection.command("LLEN", RESULT_QUEUE)))
            second = consumer.next_message(2)
            self.assertIsNotNone(second)
            self.assertEqual(second_id, json.loads(second.body)["task_id"])
            second.ack()

    def test_a_message_left_inflight_is_recovered_on_the_next_start(self):
        publish_task(self.URL, valid_task(), queue=RESULT_QUEUE)
        with RedisResultConsumer(self.URL, queue=RESULT_QUEUE) as consumer:
            body = consumer.next_message(2)
            self.assertIsNotNone(body)
            # The process "dies" here: the message stays in flight.
        with RedisResultConsumer(self.URL, queue=RESULT_QUEUE) as consumer:
            recovered = consumer.next_message(2)
            self.assertIsNotNone(recovered)
            self.assertEqual(body.body, recovered.body)


class PublisherRoutingTests(TestCase):
    """One broker, one hop: the routing decision is the only thing that moves."""

    def test_a_redis_broker_publishes_the_contract_json_directly(self):
        task = EngineTask.objects.create(
            task_type="target.crawl", payload={"url": "http://127.0.0.1/\u00a7"}
        )
        with unittest.mock.patch("lab.tasks.publish_task") as publish:
            publish_engine_task.run(str(task.task_id))

        publish.assert_called_once()
        broker_url, envelope = publish.call_args.args
        # Порівнюємо з налаштованим URL, а не з літералом: контракт
        # publisher-а — «передати наскрізь те, що налаштовано», а стенд
        # змінює порт через REDIS_PORT. Літерал робив тест зеленим лише на
        # дефолтному 6379 і падав на будь-якій іншій конфігурації, тобто
        # результат залежав від того, в якому режимі оператор запустив стенд.
        self.assertEqual(publish_engine_task.app.conf.broker_url, broker_url)
        self.assertEqual(str(task.task_id), envelope["task_id"])
        self.assertEqual({"url": "http://127.0.0.1/\u00a7"}, envelope["payload"])
        task.refresh_from_db()
        self.assertEqual("published", task.status)

    def test_a_removed_broker_url_does_not_mark_the_task_published(self):
        task = EngineTask.objects.create(task_type="target.crawl", payload={})
        with unittest.mock.patch(
            "lab.tasks.require_redis_broker", side_effect=BrokerTransportError("amqp")
        ):
            with self.assertRaises(Exception):
                publish_engine_task.run(str(task.task_id))
        task.refresh_from_db()
        self.assertEqual("queued", task.status)
        self.assertEqual({}, task.error)

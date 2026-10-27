"""The engine task transport: Redis, and the JSON contract it carries.

The wire format and the queue names are the contract in ``contracts/``.

Redis is the only broker, and this module is the whole transport. It speaks RESP
directly rather than going through kombu for two reasons. kombu's Redis transport
wraps every message in its own envelope: a base64 body plus kombu headers,
properties and a delivery tag, with unacked state in kombu's own bookkeeping
keys — measured on kombu 5.6, a published task arrives in Redis as exactly that
wrapper, so the Go engine would depend on a framing owned by another project and
versioned with it. And a task that reaches a Go consumer is better off as the
contract JSON of ``contracts/engine-task-v1.json`` than as somebody else's
envelope. Celery still uses kombu for its own queues; the ``redis`` Python
package is required for that and for nothing here.

**Reliability is explicit rather than borrowed.** A message moves to
``<queue>.inflight`` in the same blocking command that removes it from the
queue, ``ack`` deletes it from there, ``requeue`` returns it to the head of the
queue, and ``reject`` moves it to ``<queue>.dead`` so a malformed message
survives as evidence instead of vanishing. A consumer that finds entries
inflight on startup returns them to the queue, which is how the work of a
process that died mid-handling is recovered. A finished task's result is written
back under ``rr.engine.outcome.<task_id>`` by the engine, so a redelivery after a
restart replays that answer instead of sending the request again.

Ordering is what Redis gives for free and both sides rely on: producers push
with ``LPUSH`` and consumers pop from the tail, so the oldest message is served
next. A publish is one atomic command whose answer is the new length of the
queue, so a publisher can see that its message is in.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import ssl
from dataclasses import dataclass
from types import TracebackType
from typing import Iterator
from urllib.parse import unquote, urlparse

logger = logging.getLogger(__name__)

#: Queue names are the contract, identical on both brokers and on both sides.
TASK_QUEUE = "rr.engine.tasks.v1"
RESULT_QUEUE = "rr.engine.results.v1"

#: Suffixes for the in-flight and dead-letter lists, derived from the queue name
#: so a message cannot be acknowledged into a list that belongs to another queue.
INFLIGHT_SUFFIX = ".inflight"
DEAD_SUFFIX = ".dead"

#: Explicit technical bounds, overridable and visible. They exist so a dead
#: socket or a stopped broker produces a reconnect instead of a hung thread;
#: they say nothing about how much work may be published.
DEFAULT_TIMEOUT_SECONDS = 5.0
BLOCK_TIMEOUT_SECONDS = 1.0

#: ``LMOVE`` and its blocking form arrived in Redis 6.2; that is the version that
#: makes a message recoverable between the pop and the commit.
MINIMUM_REDIS_VERSION = (6, 2)

REDIS_SCHEMES = {"redis", "rediss", "unix"}


class BrokerTransportError(RuntimeError):
    """The broker could not be reached, or refused a command."""


def configured_timeout() -> float:
    try:
        value = float(
            os.environ.get("RR_BROKER_REDIS_TIMEOUT", "") or DEFAULT_TIMEOUT_SECONDS
        )
    except ValueError:
        return DEFAULT_TIMEOUT_SECONDS
    return value if value > 0 else DEFAULT_TIMEOUT_SECONDS


def is_redis(broker_url: str) -> bool:
    return urlparse(broker_url).scheme in REDIS_SCHEMES


def require_redis_broker(broker_url: str) -> str:
    """Return ``broker_url`` when Redis can serve it, and say what to do if not.

    This deployment has one broker. A URL left over from the previous one has to
    fail loudly and name the replacement, because a task queue that quietly
    consumes nothing is the worst possible state to discover later.
    """
    if is_redis(broker_url):
        return broker_url
    scheme = urlparse(broker_url).scheme or "(none)"
    raise BrokerTransportError(
        f"broker URL {broker_url!r} uses scheme {scheme!r}, which this "
        "deployment cannot serve. The engine task transport speaks Redis: set "
        "CELERY_BROKER_URL=redis://127.0.0.1:6379/0 (or rediss://, unix://) and "
        "run a Redis server — for example `redis-server --port 6379 --bind "
        "127.0.0.1 --appendonly yes`, or `docker compose up -d redis`."
    )


@dataclass(frozen=True)
class RedisTarget:
    host: str
    port: int
    db: int
    password: str = ""
    username: str = ""
    use_tls: bool = False
    unix_path: str = ""

    @property
    def label(self) -> str:
        if self.unix_path:
            return f"redis+unix:{self.unix_path}"
        scheme = "rediss" if self.use_tls else "redis"
        return f"{scheme}://{self.host}:{self.port}/{self.db}"


def parse_redis_url(broker_url: str) -> RedisTarget:
    parsed = urlparse(broker_url)
    if parsed.scheme not in REDIS_SCHEMES:
        raise BrokerTransportError(
            f"{broker_url!r} is not a Redis URL (expected redis://, rediss:// or unix://)"
        )
    if parsed.scheme == "unix":
        # A unix socket is spelled unix:///path/to.sock?db=0&password=secret
        return RedisTarget(
            host="",
            port=0,
            db=_query_int(parsed.query, "db", 0),
            password=_query_value(parsed.query, "password"),
            unix_path=parsed.path or "",
        )
    path = parsed.path.strip("/")
    try:
        db = int(path) if path else 0
    except ValueError as error:
        raise BrokerTransportError(
            f"the Redis database index {path!r} in {broker_url!r} is not a number"
        ) from error
    return RedisTarget(
        host=parsed.hostname or "127.0.0.1",
        port=int(parsed.port or 6379),
        db=db,
        password=unquote(parsed.password or ""),
        username=unquote(parsed.username or ""),
        use_tls=parsed.scheme == "rediss",
    )


def _query_value(query: str, key: str) -> str:
    for part in query.split("&"):
        name, _, value = part.partition("=")
        if name == key:
            return unquote(value)
    return ""


def _query_int(query: str, key: str, default: int) -> int:
    value = _query_value(query, key)
    try:
        return int(value) if value else default
    except ValueError:
        return default


def inflight_list(queue: str) -> str:
    return f"{queue}{INFLIGHT_SUFFIX}"


def dead_list(queue: str) -> str:
    return f"{queue}{DEAD_SUFFIX}"


class RedisConnection:
    """A minimal RESP2 client for the six commands this transport uses.

    ``PING``, ``LPUSH``, ``BLMOVE``, ``LREM`` and ``DEL`` are what publishing,
    consuming and recovering need. A general client would be a dependency and a
    version to track for a fixed, documented set of commands, and a broker
    client nobody can read in one screen is a broker client nobody can audit.
    """

    def __init__(self, target: RedisTarget, timeout: float | None = None) -> None:
        self.target = target
        self.timeout = configured_timeout() if timeout is None else timeout
        self._socket: socket.socket | None = None
        self._stream = None

    def __enter__(self) -> "RedisConnection":
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def connect(self) -> None:
        if self._socket is not None:
            return
        try:
            if self.target.unix_path:
                connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.settimeout(self.timeout)
                connection.connect(self.target.unix_path)
            else:
                connection = socket.create_connection(
                    (self.target.host, self.target.port), timeout=self.timeout
                )
                if self.target.use_tls:
                    context = ssl.create_default_context()
                    connection = context.wrap_socket(
                        connection, server_hostname=self.target.host
                    )
        except OSError as error:
            raise BrokerTransportError(
                f"cannot reach the Redis broker at {self.target.label}: {error}"
            ) from error
        self._socket = connection
        # RESP is strictly request/answer and nothing here pipelines, so one
        # buffered reader serves every reply on this connection. It is closed
        # together with the socket, because an abandoned reader swallows the
        # next answer.
        self._stream = connection.makefile("rb")
        if self.target.password:
            arguments = ["AUTH"]
            if self.target.username:
                arguments.append(self.target.username)
            arguments.append(self.target.password)
            self.command(*arguments)
        if self.target.db:
            self.command("SELECT", str(self.target.db))

    def close(self) -> None:
        stream, self._stream = self._stream, None
        if stream is not None:
            try:
                stream.close()
            except OSError:  # pragma: no cover - a closed stream is already closed
                pass
        if self._socket is None:
            return
        try:
            self._socket.close()
        except OSError:  # pragma: no cover - a closed socket is already closed
            pass
        self._socket = None

    def command(self, *arguments: str | bytes | int | float) -> object:
        self.connect()
        assert self._socket is not None
        try:
            self._socket.sendall(_encode_command(arguments))
            return _read_reply(self._stream)
        except socket.timeout as error:
            self.close()
            raise BrokerTransportError(
                f"the Redis broker at {self.target.label} did not answer in {self.timeout}s"
            ) from error
        except OSError as error:
            self.close()
            raise BrokerTransportError(
                f"the Redis connection to {self.target.label} failed: {error}"
            ) from error

    def ping(self) -> bool:
        return self.command("PING") in {"PONG", b"PONG"}


def _encode_command(arguments) -> bytes:
    parts = [b"*%d\r\n" % len(arguments)]
    for argument in arguments:
        if isinstance(argument, bytes):
            raw = argument
        elif isinstance(argument, bool):
            raw = b"1" if argument else b"0"
        elif isinstance(argument, float):
            raw = f"{argument:.3f}".encode("ascii")
        else:
            raw = str(argument).encode("utf-8")
        parts.append(b"$%d\r\n" % len(raw))
        parts.append(raw)
        parts.append(b"\r\n")
    return b"".join(parts)


def _read_reply(stream) -> object:
    line = stream.readline()
    if not line:
        raise BrokerTransportError("the Redis broker closed the connection")
    marker, payload = line[:1], line[1:-2]
    if marker == b"+":
        return payload.decode("utf-8", "replace")
    if marker == b"-":
        raise BrokerTransportError(payload.decode("utf-8", "replace"))
    if marker == b":":
        return int(payload)
    if marker == b"$":
        length = int(payload)
        if length == -1:
            return None
        return stream.read(length + 2)[:-2]
    if marker == b"*":
        count = int(payload)
        if count == -1:
            return None
        return [_read_reply(stream) for _ in range(count)]
    raise BrokerTransportError(f"unexpected Redis reply marker {marker!r}")


def publish_task(broker_url: str, envelope: dict, *, queue: str = TASK_QUEUE) -> int:
    """Push one task envelope and return the length the queue had afterwards."""
    body = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    with RedisConnection(parse_redis_url(broker_url)) as connection:
        length = connection.command("LPUSH", queue, body)
    logger.info(
        "engine_task_published transport=redis queue=%s queue_length=%s",
        queue,
        length,
    )
    return int(length or 0)


class ResultDelivery:
    """One result message with the three dispositions the consumer uses.

    ``ack``, ``requeue`` and ``reject`` are the dispositions a queue message has
    everywhere, so the consumer's handling of a result — persist, then ack; retry
    the database error; drop a message that can never be valid — is one code path
    and only the transport underneath it differs.
    """

    def __init__(self, connection: RedisConnection, body: bytes, queue: str) -> None:
        self._connection = connection
        self._body = body
        self._queue = queue
        self._settled = False

    @property
    def body(self) -> bytes:
        return self._body

    def ack(self) -> None:
        if self._settled:
            return
        self._settled = True
        self._connection.command("LREM", inflight_list(self._queue), "1", self._body)

    def requeue(self, body: bytes | None = None) -> None:
        """Return the message to the head of the queue, optionally with new bytes.

        `body` exists for the retry counter. Redis lists have no "update in place"
        and no delay, so a requeue that has to carry state has to re-push different
        bytes — and the caller has to be able to hand back a message that will read
        its own attempt number on redelivery. Passing None keeps the original bytes,
        so every existing caller behaves exactly as before.
        """
        if self._settled:
            return
        self._settled = True
        payload = self._body if body is None else body
        self._connection.command("LREM", inflight_list(self._queue), "1", self._body)
        self._connection.command("LPUSH", self._queue, payload)
        logger.warning(
            "engine_result_requeued transport=redis queue=%s bytes=%d rewritten=%s",
            self._queue,
            len(payload),
            "yes" if body is not None else "no",
        )

    def reject(self, requeue: bool = False) -> None:
        if self._settled:
            return
        self._settled = True
        self._connection.command("LREM", inflight_list(self._queue), "1", self._body)
        if requeue:
            self._connection.command("LPUSH", self._queue, self._body)
            return
        self._connection.command("LPUSH", dead_list(self._queue), self._body)
        logger.error(
            "engine_result_dead_lettered transport=redis queue=%s bytes=%d dead_list=%s",
            self._queue,
            len(self._body),
            dead_list(self._queue),
        )


class RedisResultConsumer:
    """Block for result messages, holding each one inflight until it is settled."""

    def __init__(self, broker_url: str, *, queue: str = RESULT_QUEUE) -> None:
        self.broker_url = broker_url
        self.queue = queue
        self._connection: RedisConnection | None = None

    def __enter__(self) -> "RedisResultConsumer":
        self._connection = RedisConnection(parse_redis_url(self.broker_url))
        self._connection.connect()
        if not self._connection.ping():
            raise BrokerTransportError(f"{self.broker_url} did not answer PING")
        self._require_blocking_move()
        recovered = self.recover_inflight()
        if recovered:
            logger.warning(
                "engine_result_inflight_recovered transport=redis queue=%s messages=%d",
                self.queue,
                recovered,
            )
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    @property
    def connection(self) -> RedisConnection:
        if self._connection is None:
            raise BrokerTransportError("the Redis result consumer is not connected")
        return self._connection

    def _require_blocking_move(self) -> None:
        """Refuse a server that cannot move a message while it blocks.

        Without ``LMOVE``/``BLMOVE`` a crash between the pop and the commit loses
        the message, and the failure would surface as an unknown-command error in
        the middle of a delivery. A server that hides ``INFO`` is left alone:
        some managed brokers disable it, and refusing to start over a missing
        version string would be worse than the risk being real.
        """
        try:
            answer = self.connection.command("INFO", "server")
        except BrokerTransportError:
            logger.debug("redis version is not readable; skipping the version check")
            return
        if not isinstance(answer, bytes):
            return
        version = ""
        for line in answer.decode("utf-8", "replace").splitlines():
            if line.startswith("redis_version:"):
                version = line.split(":", 1)[1].strip()
                break
        if not version:
            return
        parts = []
        for piece in version.split(".")[:3]:
            digits = "".join(character for character in piece if character.isdigit())
            parts.append(int(digits or 0))
        while len(parts) < 3:
            parts.append(0)
        if tuple(parts) < MINIMUM_REDIS_VERSION:
            raise BrokerTransportError(
                f"this Redis broker is {version}, and the recoverable move this "
                f"transport needs arrived in {MINIMUM_REDIS_VERSION[0]}.{MINIMUM_REDIS_VERSION[1]}; "
                "a message would be lost if the process died between the read "
                "and the acknowledgement"
            )
        logger.info("redis broker %s speaks the required protocol", version)

    def recover_inflight(self) -> int:
        """Return messages a previous process left inflight to the queue.

        Only valid at startup, when this consumer owns the queue: an inflight
        entry is by definition one that no live handler still holds. The oldest
        entry is the tail, and it is pushed to the head of the queue, so the
        recovered order is the order the messages were taken in.
        """
        recovered = 0
        while True:
            body = self.connection.command(
                "LMOVE", inflight_list(self.queue), self.queue, "RIGHT", "LEFT"
            )
            if not body:
                return recovered
            recovered += 1

    def next_message(
        self, block_timeout: float = BLOCK_TIMEOUT_SECONDS
    ) -> "ResultDelivery | None":
        """Return the next result message, or ``None`` when none arrived in time.

        ``None`` is the idle signal and the only one: a dropped connection
        raises, because reconnection belongs to the caller's loop and an
        in-flight message is recovered when the consumer starts again.
        """
        # One blocking command moves the message out of the queue and into the
        # in-flight list. A pop followed by a move would leave a window in which
        # a crash loses the message, which is the whole reason the in-flight
        # list exists.
        body = self.connection.command(
            "BLMOVE",
            self.queue,
            inflight_list(self.queue),
            "RIGHT",
            "LEFT",
            f"{block_timeout:.3f}",
        )
        if not body:
            return None
        return ResultDelivery(self.connection, bytes(body), self.queue)

    def messages(
        self, block_timeout: float = BLOCK_TIMEOUT_SECONDS
    ) -> Iterator[ResultDelivery]:
        while True:
            delivery = self.next_message(block_timeout)
            if delivery is not None:
                yield delivery

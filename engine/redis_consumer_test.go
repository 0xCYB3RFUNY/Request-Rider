package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"intruder/engine/pkg/taskcontract"
)

// fakeRedis is an in-memory stand-in for the commands the transport uses, so
// the reliability rules are testable without a broker. A test that needs a real
// Redis is in TestRedisBrokerTests, and it skips when none is listening.
type fakeRedis struct {
	mu       sync.Mutex
	lists    map[string][]string
	values   map[string]string
	closed   bool
	pingErr  error
	moveErr  error
	pushErr  error
	blocked  chan struct{}
	blockTTL time.Duration
}

// valueString is what a Redis list actually stores: the client encodes a []byte
// and a string as the same bulk string, so the fake must not tell them apart.
func valueString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	default:
		return fmt.Sprint(typed)
	}
}

func newFakeRedis() *fakeRedis {
	return &fakeRedis{
		lists:  map[string][]string{},
		values: map[string]string{},
	}
}

func (fake *fakeRedis) Close() error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.closed = true
	return nil
}

func (fake *fakeRedis) Ping(context.Context) *redis.StatusCmd {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.pingErr != nil {
		return redis.NewStatusResult("", fake.pingErr)
	}
	return redis.NewStatusResult("PONG", nil)
}

func (fake *fakeRedis) LPush(_ context.Context, key string, values ...any) *redis.IntCmd {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.pushErr != nil {
		return redis.NewIntResult(0, fake.pushErr)
	}
	for _, value := range values {
		fake.lists[key] = append([]string{valueString(value)}, fake.lists[key]...)
	}
	return redis.NewIntResult(int64(len(fake.lists[key])), nil)
}

func (fake *fakeRedis) LRem(_ context.Context, key string, _ int64, value any) *redis.IntCmd {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	items := fake.lists[key]
	removed := int64(0)
	for index, item := range items {
		if item == valueString(value) {
			fake.lists[key] = append(items[:index:index], items[index+1:]...)
			return redis.NewIntResult(1, nil)
		}
	}
	return redis.NewIntResult(removed, nil)
}

func (fake *fakeRedis) Del(_ context.Context, keys ...string) *redis.IntCmd {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for _, key := range keys {
		delete(fake.lists, key)
		delete(fake.values, key)
	}
	return redis.NewIntResult(1, nil)
}

func (fake *fakeRedis) LLen(_ context.Context, key string) *redis.IntCmd {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return redis.NewIntResult(int64(len(fake.lists[key])), nil)
}

func (fake *fakeRedis) Get(_ context.Context, key string) *redis.StringCmd {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	value, ok := fake.values[key]
	if !ok {
		return redis.NewStringResult("", redis.Nil)
	}
	return redis.NewStringResult(value, nil)
}

func (fake *fakeRedis) Set(_ context.Context, key string, value any, _ time.Duration) *redis.StatusCmd {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.values[key] = valueString(value)
	return redis.NewStatusResult("OK", nil)
}

// move implements both LMove and BLMove, which differ only in whether they wait
// for a message to arrive.
func (fake *fakeRedis) move(source, destination, srcPos, destPos string) (string, error) {
	items := fake.lists[source]
	if len(items) == 0 {
		return "", nil
	}
	var taken string
	if srcPos == "RIGHT" {
		taken = items[len(items)-1]
		fake.lists[source] = items[:len(items)-1]
	} else {
		taken = items[0]
		fake.lists[source] = items[1:]
	}
	if destPos == "RIGHT" {
		fake.lists[destination] = append(fake.lists[destination], taken)
	} else {
		fake.lists[destination] = append([]string{taken}, fake.lists[destination]...)
	}
	return taken, nil
}

func (fake *fakeRedis) LMove(_ context.Context, source, destination, srcPos, destPos string) *redis.StringCmd {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.moveErr != nil {
		return redis.NewStringResult("", fake.moveErr)
	}
	moved, err := fake.move(source, destination, srcPos, destPos)
	if moved == "" && err == nil {
		// go-redis reports a drained source as redis.Nil, and a fake that
		// returned "" would hide the difference between an idle queue and a
		// broken connection — which is exactly what the live E2E caught.
		return redis.NewStringResult("", redis.Nil)
	}
	return redis.NewStringResult(moved, err)
}

func (fake *fakeRedis) BLMove(_ context.Context, source, destination, srcPos, destPos string, timeout time.Duration) *redis.StringCmd {
	fake.mu.Lock()
	fake.blockTTL = timeout
	if fake.blocked != nil {
		close(fake.blocked)
		fake.blocked = nil
	}
	defer fake.mu.Unlock()
	if fake.moveErr != nil {
		return redis.NewStringResult("", fake.moveErr)
	}
	moved, err := fake.move(source, destination, srcPos, destPos)
	if moved == "" && err == nil {
		return redis.NewStringResult("", redis.Nil)
	}
	return redis.NewStringResult(moved, err)
}

func (fake *fakeRedis) snapshot(key string) []string {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return append([]string{}, fake.lists[key]...)
}

func taskBody(t *testing.T, taskID string) []byte {
	t.Helper()
	id := taskID
	if id == "" {
		generated, err := newUUID()
		if err != nil {
			t.Fatalf("generate task id: %v", err)
		}
		id = generated
	}
	body, err := json.Marshal(taskcontract.Task{
		SchemaVersion: taskcontract.SchemaVersion,
		TaskID:        id,
		TaskType:      "request.execute",
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		Payload:       json.RawMessage(`{"url":"http://127.0.0.1/fixture"}`),
	})
	if err != nil {
		t.Fatalf("marshal task: %v", err)
	}
	return body
}

// testTaskID builds a real UUID because the contract rejects anything else, and
// a test that used a friendly name would be testing a different code path.
func testTaskID(t *testing.T, hint string) string {
	t.Helper()
	id, err := newUUID()
	if err != nil {
		t.Fatalf("generate task id for %s: %v", hint, err)
	}
	return id
}

func TestBrokerSchemeSelectsTheTransport(t *testing.T) {
	// Redis is the only broker, so every other scheme must come back as
	// unsupported rather than being silently mapped onto it.
	cases := map[string]string{
		"redis://127.0.0.1:6379/0":        "redis",
		"rediss://cache:6380/1":           "redis",
		"unix:///tmp/rr.sock":             "redis",
		"amqp://guest:guest@127.0.0.1/2/": "",
		"amqps://broker/":                 "",
		"kafka://127.0.0.1:9092":          "",
		"127.0.0.1:6379":                  "",
		"":                                "",
	}
	for url, want := range cases {
		if got := brokerScheme(url); got != want {
			t.Errorf("brokerScheme(%q) = %q, want %q", url, got, want)
		}
	}
}

func TestParseRedisBrokerURLRejectsAnUnusableAddress(t *testing.T) {
	if _, err := parseRedisBrokerURL("amqp://guest@127.0.0.1:5672//"); err == nil {
		t.Fatal("an AMQP URL must not be accepted as a Redis address")
	}
	options, err := parseRedisBrokerURL("redis://:secret@127.0.0.1:6380/4")
	if err != nil {
		t.Fatalf("parse redis url: %v", err)
	}
	if options.Addr != "127.0.0.1:6380" || options.DB != 4 || options.Password != "secret" {
		t.Fatalf("unexpected options %+v", options)
	}
}

func TestRedisOutcomeTTLIsExplicitAndOverridable(t *testing.T) {
	t.Setenv("ENGINE_BROKER_OUTCOME_TTL", "")
	if got := redisOutcomeTTL(); got != defaultRedisOutcomeTTL {
		t.Fatalf("default ttl = %s, want %s", got, defaultRedisOutcomeTTL)
	}
	t.Setenv("ENGINE_BROKER_OUTCOME_TTL", "0")
	if got := redisOutcomeTTL(); got != 0 {
		t.Fatalf("disabled ttl = %s, want 0", got)
	}
	t.Setenv("ENGINE_BROKER_OUTCOME_TTL", "90")
	if got := redisOutcomeTTL(); got != 90*time.Second {
		t.Fatalf("override ttl = %s, want 90s", got)
	}
	t.Setenv("ENGINE_BROKER_OUTCOME_TTL", "not-a-number")
	if got := redisOutcomeTTL(); got != defaultRedisOutcomeTTL {
		t.Fatalf("invalid ttl = %s, want the documented default", got)
	}
}

func TestRedisTaskDeliverySettlesExactlyOnce(t *testing.T) {
	fake := newFakeRedis()
	body := taskBody(t, "")
	_ = fake.LPush(context.Background(), redisInflightList(redisTaskQueue), string(body))
	delivery := &redisTaskDelivery{client: fake, body: body, queue: redisTaskQueue}

	if err := delivery.Ack(false); err != nil {
		t.Fatalf("ack: %v", err)
	}
	if err := delivery.Ack(false); err != nil {
		t.Fatalf("second ack must be a no-op, got %v", err)
	}
	if err := delivery.Nack(false, true); err != nil {
		t.Fatalf("nack after ack must be a no-op, got %v", err)
	}
	if got := fake.snapshot(redisTaskQueue); len(got) != 0 {
		t.Fatalf("the queue must be empty after an ack, has %v", got)
	}
	if got := fake.snapshot(redisInflightList(redisTaskQueue)); len(got) != 0 {
		t.Fatalf("the in-flight list must be empty after an ack, has %v", got)
	}
}

func TestRedisNackRequeuesAndRejectDeadLetters(t *testing.T) {
	fake := newFakeRedis()
	requeued := taskBody(t, "")
	_ = fake.LPush(context.Background(), redisInflightList(redisTaskQueue), string(requeued))
	requeueDelivery := &redisTaskDelivery{client: fake, body: requeued, queue: redisTaskQueue}
	if err := requeueDelivery.Nack(false, true); err != nil {
		t.Fatalf("nack: %v", err)
	}
	if got := fake.snapshot(redisTaskQueue); len(got) != 1 {
		t.Fatalf("a requeued task must be back on the queue, has %v", got)
	}
	if got := fake.snapshot(redisInflightList(redisTaskQueue)); len(got) != 0 {
		t.Fatalf("a requeued task must leave the in-flight list, has %v", got)
	}

	rejected := taskBody(t, "")
	_ = fake.LPush(context.Background(), redisInflightList(redisTaskQueue), string(rejected))
	rejectDelivery := &redisTaskDelivery{client: fake, body: rejected, queue: redisTaskQueue}
	if err := rejectDelivery.Reject(false); err != nil {
		t.Fatalf("reject: %v", err)
	}
	if got := fake.snapshot(redisDeadList(redisTaskQueue)); len(got) != 1 {
		t.Fatalf("a rejected task must be kept as a dead letter, has %v", got)
	}
	if got := fake.snapshot(redisTaskQueue); len(got) != 1 {
		t.Fatalf("a rejected task must not be retried, queue has %v", got)
	}
}

func TestRecoverRedisInflightReturnsOrphanedWorkInOrder(t *testing.T) {
	fake := newFakeRedis()
	first := taskBody(t, "")
	second := taskBody(t, "")
	// The in-flight list is pushed at the head, so the tail is the oldest task.
	_ = fake.LPush(context.Background(), redisInflightList(redisTaskQueue), string(first))
	_ = fake.LPush(context.Background(), redisInflightList(redisTaskQueue), string(second))

	recovered, err := recoverRedisInflight(context.Background(), fake, redisTaskQueue)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if recovered != 2 {
		t.Fatalf("recovered %d messages, want 2", recovered)
	}
	// A queue is served from the tail, so the recovered order is the reverse of
	// the list as stored: the task taken first must be served first again.
	queue := fake.snapshot(redisTaskQueue)
	if len(queue) != 2 || queue[1] != string(first) || queue[0] != string(second) {
		t.Fatalf("recovered order = %v, want the order they were taken in", queue)
	}
	if got := fake.snapshot(redisInflightList(redisTaskQueue)); len(got) != 0 {
		t.Fatalf("in-flight list must be drained, has %v", got)
	}
}

func TestAnEmptyQueueIsIdleAndNotAFailedSession(t *testing.T) {
	fake := newFakeRedis()
	// Nothing to recover and nothing to read: both are redis.Nil, and both must
	// leave the session running instead of ending it.
	if recovered, err := recoverRedisInflight(context.Background(), fake, redisTaskQueue); err != nil || recovered != 0 {
		t.Fatalf("recovering an empty list = %d, %v; want 0, nil", recovered, err)
	}
	body, err := fake.BLMove(context.Background(), redisTaskQueue, redisInflightList(redisTaskQueue), "RIGHT", "LEFT", time.Millisecond).Result()
	if !isRedisNil(err) {
		t.Fatalf("an empty queue must read as redis.Nil, got %v", err)
	}
	if body != "" {
		t.Fatalf("an empty queue must produce no body, got %q", body)
	}
}

func TestRecoverRedisInflightReportsAFailedMove(t *testing.T) {
	fake := newFakeRedis()
	fake.moveErr = errors.New("connection reset")
	if _, err := recoverRedisInflight(context.Background(), fake, redisTaskQueue); err == nil {
		t.Fatal("a failed recovery must be reported, not swallowed")
	}
}

func TestRedisOutcomeCacheSurvivesARestartedProcess(t *testing.T) {
	broker := newFakeRedis()
	durableID := testTaskID(t, "durable")
	first := &redisOutcomeCache{client: broker, local: newTaskOutcomeRegistry(), ttl: time.Hour}
	result, err := newTaskResult(durableID, "completed", json.RawMessage(`{"pages":[]}`), nil)
	if err != nil {
		t.Fatalf("build result: %v", err)
	}
	first.Put(durableID, result)

	// A different process-local registry stands in for a restarted engine: the
	// durable copy is what stops the side effect from happening twice.
	second := &redisOutcomeCache{client: broker, local: newTaskOutcomeRegistry(), ttl: time.Hour}
	cached, ok := second.Get(durableID)
	if !ok {
		t.Fatal("a recorded outcome must be found by a new process")
	}
	if cached.TaskID != durableID || cached.State != "completed" {
		t.Fatalf("cached outcome = %+v", cached)
	}
	// Deleting the acknowledgement keeps the durable copy, so the next
	// redelivery still replays the same answer.
	second.Delete(durableID)
	if _, ok := second.Get(durableID); !ok {
		t.Fatal("the durable outcome must outlive the in-process copy")
	}
}

func TestRedisOutcomeCacheCanBeDisabled(t *testing.T) {
	broker := newFakeRedis()
	cache := &redisOutcomeCache{client: broker, local: newTaskOutcomeRegistry(), ttl: 0}
	disabledID := testTaskID(t, "no-ttl")
	result, err := newTaskResult(disabledID, "completed", json.RawMessage(`{}`), nil)
	if err != nil {
		t.Fatalf("build result: %v", err)
	}
	cache.Put(disabledID, result)
	if _, ok := cache.Get(disabledID); !ok {
		t.Fatal("with the durable cache disabled only the in-process copy answers")
	}
	fresh := &redisOutcomeCache{client: broker, local: newTaskOutcomeRegistry(), ttl: 0}
	if _, ok := fresh.Get(disabledID); ok {
		t.Fatal("a disabled durable cache must not answer for a new process")
	}
}

func TestRedisOutcomeCacheIgnoresAnUnreadableEntry(t *testing.T) {
	broker := newFakeRedis()
	broker.values[redisOutcomeKey("task-broken")] = "{not json"
	cache := &redisOutcomeCache{client: broker, local: newTaskOutcomeRegistry(), ttl: time.Hour}
	if _, ok := cache.Get("task-broken"); ok {
		t.Fatal("an unreadable entry must not be treated as a result")
	}
}

func TestRedisResultPublisherPushesTheContractJSON(t *testing.T) {
	broker := newFakeRedis()
	publisher := redisResultPublisher{client: broker, queue: redisResultQueue}
	body, err := newTaskResult(testTaskID(t, "publish"), "completed", json.RawMessage(`{"pages":[]}`), nil)
	if err != nil {
		t.Fatalf("build result: %v", err)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	if err := publisher.PublishResult(payload); err != nil {
		t.Fatalf("publish: %v", err)
	}
	published := broker.snapshot(redisResultQueue)
	if len(published) != 1 || published[0] != string(payload) {
		t.Fatalf("published = %v, want the exact contract JSON", published)
	}
}

func TestRedisResultPublisherReportsAFailedPush(t *testing.T) {
	broker := newFakeRedis()
	broker.pushErr = errors.New("broker stopped")
	publisher := redisResultPublisher{client: broker, queue: redisResultQueue}
	if err := publisher.PublishResult([]byte("{}")); err == nil {
		t.Fatal("a failed publish must be reported so the delivery can be requeued")
	}
}

func TestARedeliveredTaskReplaysTheSameResultEvent(t *testing.T) {
	// The ledger deduplicates by event_id, so a replay must carry the event_id
	// that was recorded the first time: a fresh envelope would be stored as a
	// second completion of the same task.
	broker := newFakeRedis()
	outcomes := &redisOutcomeCache{client: broker, local: newTaskOutcomeRegistry(), ttl: time.Hour}
	dispatcher := &fakeTaskDispatcher{result: json.RawMessage(`{"status":200}`)}
	publisher := &fakeResultPublisher{}
	body := taskBody(t, "")

	first := &fakeTaskDelivery{body: body}
	processTaskDelivery(context.Background(), first, dispatcher, publisher, outcomes)
	recorded := decodePublishedResult(t, publisher)
	dispatcher.calls = 0
	publisher.calls = 0
	publisher.bodies = nil

	second := &fakeTaskDelivery{body: body}
	processTaskDelivery(context.Background(), second, dispatcher, publisher, outcomes)

	if dispatcher.calls != 0 {
		t.Fatalf("a redelivered task must not run the handler again, got %d calls", dispatcher.calls)
	}
	if len(publisher.bodies) != 1 {
		t.Fatalf("a replay publishes exactly one answer, got %d", len(publisher.bodies))
	}
	replayed := decodePublishedResult(t, publisher)
	if replayed.EventID != recorded.EventID {
		t.Fatalf("replay event_id = %s, want the recorded %s", replayed.EventID, recorded.EventID)
	}
	if !second.acked {
		t.Fatal("a replayed task must be acknowledged")
	}
}

func TestTheProcessLocalOutcomeCacheOnlyCoversAnUnacknowledgedTask(t *testing.T) {
	// Why the durable copy exists, stated as a test: the in-process registry is
	// cleared once the message is acknowledged, so it covers a duplicate that
	// arrives while the first copy is still in flight and nothing more. A
	// redelivery after the ack therefore runs the task again unless the outcome
	// also lives in the broker.
	outcomes := newTaskOutcomeRegistry()
	dispatcher := &fakeTaskDispatcher{result: json.RawMessage(`{"status":200}`)}
	publisher := &fakeResultPublisher{}
	body := taskBody(t, "")

	processTaskDelivery(context.Background(), &fakeTaskDelivery{body: body}, dispatcher, publisher, outcomes)
	if dispatcher.calls != 1 {
		t.Fatalf("first delivery must run the handler, got %d calls", dispatcher.calls)
	}
	processTaskDelivery(context.Background(), &fakeTaskDelivery{body: body}, dispatcher, publisher, outcomes)
	if dispatcher.calls != 2 {
		t.Fatalf("after the ack the in-process cache is empty, so the task runs again: %d calls", dispatcher.calls)
	}
}

func TestRedisConsumerTakesATaskInFlightAndAcksAfterTheResult(t *testing.T) {
	broker := newFakeRedis()
	body := taskBody(t, "")
	_ = broker.LPush(context.Background(), redisTaskQueue, string(body))

	dispatcher := &fakeTaskDispatcher{}
	publisher := &fakeResultPublisher{}
	delivery, err := broker.BLMove(
		context.Background(), redisTaskQueue, redisInflightList(redisTaskQueue),
		"RIGHT", "LEFT", time.Second,
	).Result()
	if err != nil {
		t.Fatalf("take task: %v", err)
	}
	if delivery != string(body) {
		t.Fatalf("taken %q, want the published task", delivery)
	}
	if broker.blockTTL <= 0 {
		t.Fatal("the take must block for a bounded, non-zero time")
	}
	processTaskDelivery(
		context.Background(),
		&redisTaskDelivery{client: broker, body: []byte(delivery), queue: redisTaskQueue},
		dispatcher,
		publisher,
		&redisOutcomeCache{client: broker, local: newTaskOutcomeRegistry(), ttl: time.Hour},
	)
	if len(publisher.bodies) == 0 {
		t.Fatal("the handler must publish a result")
	}
	if got := broker.snapshot(redisInflightList(redisTaskQueue)); len(got) != 0 {
		t.Fatalf("the in-flight list must be empty after the ack, has %v", got)
	}
}

func TestRedisConsumerRejectsAMalformedTaskWithoutRunningIt(t *testing.T) {
	broker := newFakeRedis()
	_ = broker.LPush(context.Background(), redisTaskQueue, "{not json")
	dispatcher := &fakeTaskDispatcher{}
	publisher := &fakeResultPublisher{}
	body, _ := broker.BLMove(
		context.Background(), redisTaskQueue, redisInflightList(redisTaskQueue),
		"RIGHT", "LEFT", time.Second,
	).Result()
	processTaskDelivery(
		context.Background(),
		&redisTaskDelivery{client: broker, body: []byte(body), queue: redisTaskQueue},
		dispatcher,
		publisher,
	)
	if dispatcher.calls != 0 {
		t.Fatalf("a malformed task must not reach the handler, got %d calls", dispatcher.calls)
	}
	dead := broker.snapshot(redisDeadList(redisTaskQueue))
	if len(dead) != 1 || dead[0] != "{not json" {
		t.Fatalf("a malformed task must be kept as a dead letter, has %v", dead)
	}
}

// TestRedisBrokerTests run against a real Redis when one is listening, because
// the two facts that matter — that a blocking move is one command, and that the
// oldest message is served first — are properties of the server, not of a fake.
func TestRedisBrokerRoundTrip(t *testing.T) {
	url := strings.TrimSpace(os.Getenv("RR_REDIS_TEST_URL"))
	if url == "" {
		url = "redis://127.0.0.1:6379/15"
	}
	client, err := newRedisClient(url)
	if err != nil {
		t.Skipf("redis URL %q is not usable: %v", url, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Skipf("no Redis broker at %s: %v", url, err)
	}
	queue := "rr.test.tasks.v1"
	_ = client.Del(ctx, queue, redisInflightList(queue), redisDeadList(queue)).Err()
	_ = client.LPush(ctx, queue, `{"first":true}`).Err()
	_ = client.LPush(ctx, queue, `{"second":true}`).Err()

	body, err := client.BLMove(ctx, queue, redisInflightList(queue), "RIGHT", "LEFT", time.Second).Result()
	if err != nil {
		t.Fatalf("blocking move: %v", err)
	}
	if body != `{"first":true}` {
		t.Fatalf("the oldest message must be served first, got %s", body)
	}
	if err := client.LRem(ctx, redisInflightList(queue), 1, body).Err(); err != nil {
		t.Fatalf("settle: %v", err)
	}
	length, err := client.LLen(ctx, redisInflightList(queue)).Result()
	if err != nil {
		t.Fatalf("length: %v", err)
	}
	if length != 0 {
		t.Fatalf("in-flight length = %d after the ack, want 0", length)
	}
	_ = client.Del(ctx, queue, redisInflightList(queue)).Err()
}

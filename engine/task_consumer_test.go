package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"intruder/engine/pkg/taskcontract"
)

type fakeTaskDelivery struct {
	body     []byte
	acked    bool
	nacked   bool
	rejected bool
	requeue  bool
}

func (delivery *fakeTaskDelivery) Body() []byte {
	return delivery.body
}

func (delivery *fakeTaskDelivery) Ack(bool) error {
	delivery.acked = true
	return nil
}

func (delivery *fakeTaskDelivery) Nack(_, requeue bool) error {
	delivery.nacked = true
	delivery.requeue = requeue
	return nil
}

func (delivery *fakeTaskDelivery) Reject(requeue bool) error {
	delivery.rejected = true
	delivery.requeue = requeue
	return nil
}

type fakeResultPublisher struct {
	body      []byte
	bodies    [][]byte
	err       error
	failAt    int
	calls     int
	onPublish func()
}

func (publisher *fakeResultPublisher) PublishResult(body []byte) error {
	publisher.calls++
	if publisher.onPublish != nil {
		publisher.onPublish()
	}
	publisher.body = append([]byte(nil), body...)
	publisher.bodies = append(publisher.bodies, append([]byte(nil), body...))
	if publisher.failAt == publisher.calls {
		return errors.New("injected publish failure")
	}
	return publisher.err
}

type fakeTaskDispatcher struct {
	result json.RawMessage
	err    error
	called bool
	calls  int
}

func (dispatcher *fakeTaskDispatcher) Dispatch(context.Context, taskcontract.Task) (json.RawMessage, error) {
	dispatcher.called = true
	dispatcher.calls++
	return dispatcher.result, dispatcher.err
}

func validTask(taskType string, payload string) taskcontract.Task {
	return taskcontract.Task{
		SchemaVersion: taskcontract.SchemaVersion,
		TaskID:        "6f0e8400-e29b-41d4-a716-446655440000",
		TaskType:      taskType,
		CreatedAt:     "2026-09-27T09:00:00Z",
		Payload:       json.RawMessage(payload),
	}
}

func encodeTask(t *testing.T, task taskcontract.Task) []byte {
	t.Helper()
	data, err := json.Marshal(task)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func decodePublishedResult(t *testing.T, publisher *fakeResultPublisher) taskcontract.Result {
	t.Helper()
	var result taskcontract.Result
	if err := json.Unmarshal(publisher.body, &result); err != nil {
		t.Fatalf("decode published result: %v", err)
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("published result violates contract: %v", err)
	}
	return result
}

func TestProcessTaskDeliveryPublishesBeforeAck(t *testing.T) {
	delivery := &fakeTaskDelivery{body: encodeTask(t, validTask("request.execute", `{"url":"http://fixture.test/"}`))}
	dispatcher := &fakeTaskDispatcher{result: json.RawMessage(`{"status":200}`)}
	publisher := &fakeResultPublisher{onPublish: func() {
		if delivery.acked {
			t.Error("input delivery was acked before result publish confirmation")
		}
	}}

	processTaskDelivery(context.Background(), delivery, dispatcher, publisher)

	if !dispatcher.called || publisher.calls != 2 {
		t.Fatalf("dispatch/publish calls = %v/%d, want true/2", dispatcher.called, publisher.calls)
	}
	var accepted taskcontract.Result
	if err := json.Unmarshal(publisher.bodies[0], &accepted); err != nil || accepted.State != "accepted" {
		t.Fatalf("first published event must be accepted, got %#v (%v)", accepted, err)
	}
	result := decodePublishedResult(t, publisher)
	if result.State != "completed" || result.TaskID != "6f0e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("published result = %#v", result)
	}

	if !delivery.acked || delivery.nacked || delivery.rejected {
		t.Fatalf("delivery settlement ack/nack/reject = %v/%v/%v", delivery.acked, delivery.nacked, delivery.rejected)
	}
}

func TestTaskExecutionRegistryCancelsOnlyMatchingTask(t *testing.T) {
	registry := newTaskExecutionRegistry()
	taskContext, finish, duplicate := registry.Start("task-1", context.Background())
	defer finish()
	if duplicate {
		t.Fatal("first task registration was marked duplicate")
	}
	if duplicateContext, duplicateFinish, repeated := registry.Start("task-1", context.Background()); !repeated || duplicateContext != nil || duplicateFinish != nil {
		t.Fatal("concurrent duplicate task must not start a second execution")
	}

	if !registry.Cancel("task-1") {
		t.Fatal("active task must be cancellable")
	}
	select {
	case <-taskContext.Done():
	case <-time.After(time.Second):
		t.Fatal("task context did not observe cancellation")
	}
	if registry.Cancel("task-2") {
		t.Fatal("unknown task must not be reported as cancelled")
	}
}

func TestInProcessTaskDispatcherHandlesTaskCancellation(t *testing.T) {
	registry := newTaskExecutionRegistry()
	taskContext, finish, duplicate := registry.Start("target-task", context.Background())
	defer finish()
	if duplicate {
		t.Fatal("first task registration was marked duplicate")
	}
	task := validTask("engine.task.cancel", `{"task_id":"target-task"}`)

	result, err := (inProcessTaskDispatcher{registry: registry}).Dispatch(context.Background(), task)
	if err != nil {
		t.Fatalf("dispatch cancellation command: %v", err)
	}
	var output map[string]any
	if err := json.Unmarshal(result, &output); err != nil {
		t.Fatalf("decode cancellation result: %v", err)
	}
	if output["cancelled"] != true {
		t.Fatalf("cancellation result = %#v", output)
	}
	select {
	case <-taskContext.Done():
	case <-time.After(time.Second):
		t.Fatal("target task context did not observe cancellation")
	}
}

func TestProcessTaskDeliveryRequeuesWhenResultPublishFails(t *testing.T) {
	delivery := &fakeTaskDelivery{body: encodeTask(t, validTask("request.execute", `{"url":"http://fixture.test/"}`))}
	dispatcher := &fakeTaskDispatcher{result: json.RawMessage(`{"status":200}`)}
	publisher := &fakeResultPublisher{err: errors.New("broker unavailable")}

	processTaskDelivery(context.Background(), delivery, dispatcher, publisher)

	if delivery.acked || !delivery.nacked || !delivery.requeue {
		t.Fatalf("delivery should requeue after unconfirmed result: %#v", delivery)
	}
}

func TestProcessTaskDeliveryReusesOutcomeAfterTerminalPublishFailure(t *testing.T) {
	task := validTask("request.execute", `{"url":"http://fixture.test/"}`)
	dispatcher := &fakeTaskDispatcher{result: json.RawMessage(`{"status":200}`)}
	publisher := &fakeResultPublisher{failAt: 2}
	outcomes := newTaskOutcomeRegistry()

	first := &fakeTaskDelivery{body: encodeTask(t, task)}
	processTaskDelivery(context.Background(), first, dispatcher, publisher, outcomes)
	if !first.nacked || !first.requeue || !dispatcher.called {
		t.Fatalf("first delivery settlement = %#v, dispatched=%v", first, dispatcher.called)
	}

	publisher.failAt = 0
	retry := &fakeTaskDelivery{body: encodeTask(t, task)}
	processTaskDelivery(context.Background(), retry, dispatcher, publisher, outcomes)
	if !retry.acked || dispatcher.calls != 1 {
		t.Fatalf("retry delivery settlement = %#v, dispatched=%v", retry, dispatcher.called)
	}
	if publisher.calls != 3 {
		t.Fatalf("publish attempts = %d, want accepted once and terminal retried once", publisher.calls)
	}
	if _, cached := outcomes.Get(task.TaskID); cached {
		t.Fatal("confirmed terminal result and ack must release the cached outcome")
	}
}

func TestProcessTaskDeliveryExplicitlyFailsUnsupportedTask(t *testing.T) {
	delivery := &fakeTaskDelivery{body: encodeTask(t, validTask("request.delete", `{}`))}
	publisher := &fakeResultPublisher{}

	processTaskDelivery(context.Background(), delivery, inProcessTaskDispatcher{
		handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("unsupported task must not invoke an engine handler")
		}),
	}, publisher)

	result := decodePublishedResult(t, publisher)
	if result.State != "failed" || result.Error == nil || result.Error.Code != "UNSUPPORTED_TASK_TYPE" {
		t.Fatalf("unsupported task result = %#v", result)
	}
	if !delivery.acked {
		t.Fatal("unsupported task must be acked after publishing its failure")
	}
}

func TestProcessTaskDeliveryHandlesMalformedAndInvalidContract(t *testing.T) {
	t.Run("malformed message with correlation", func(t *testing.T) {
		body := append(encodeTask(t, validTask("request.execute", `{"url":"http://fixture.test/"}`)), []byte(" !")...)
		delivery := &fakeTaskDelivery{body: body}
		publisher := &fakeResultPublisher{}
		processTaskDelivery(context.Background(), delivery, &fakeTaskDispatcher{}, publisher)

		result := decodePublishedResult(t, publisher)
		if result.State != "failed" || result.Error == nil || result.Error.Code != "MALFORMED_TASK" || !delivery.acked {
			t.Fatalf("malformed task handling result=%#v delivery=%#v", result, delivery)
		}
	})
	t.Run("unidentifiable malformed message is rejected", func(t *testing.T) {
		delivery := &fakeTaskDelivery{body: []byte(`{"payload":`)}
		publisher := &fakeResultPublisher{}
		processTaskDelivery(context.Background(), delivery, &fakeTaskDispatcher{}, publisher)

		if !delivery.rejected || delivery.acked || publisher.calls != 0 {
			t.Fatalf("malformed task handling = %#v publisher calls=%d", delivery, publisher.calls)
		}
	})
	t.Run("invalid schema with correlation", func(t *testing.T) {
		task := validTask("request.execute", `{"url":"http://fixture.test/"}`)
		task.SchemaVersion = 2
		delivery := &fakeTaskDelivery{body: encodeTask(t, task)}
		publisher := &fakeResultPublisher{}
		processTaskDelivery(context.Background(), delivery, &fakeTaskDispatcher{}, publisher)

		result := decodePublishedResult(t, publisher)
		if result.State != "failed" || result.Error == nil || result.Error.Code != "INVALID_TASK" || !delivery.acked {
			t.Fatalf("invalid contract handling result=%#v delivery=%#v", result, delivery)
		}
	})
}

func TestProcessTaskDeliveryPublishesCancelledState(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	delivery := &fakeTaskDelivery{body: encodeTask(t, validTask("request.execute", `{"url":"http://fixture.test/"}`))}
	dispatcher := &fakeTaskDispatcher{err: context.Canceled}
	publisher := &fakeResultPublisher{}
	cancel(errEngineTaskCancelled)

	processTaskDelivery(ctx, delivery, dispatcher, publisher)

	result := decodePublishedResult(t, publisher)
	if result.State != "cancelled" || result.Result != nil || result.Error != nil || !delivery.acked {
		t.Fatalf("cancelled task result=%#v delivery=%#v", result, delivery)
	}
}

func TestInProcessTaskDispatcherDelegatesRequestToRegisteredHandler(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/proxy/request" {
			t.Errorf("request routed to %s %s", r.Method, r.URL.Path)
		}
		var input map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Errorf("decode request payload: %v", err)
		}
		if _, ok := input["headers"]; !ok {
			t.Error("request payload was not delegated intact")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":200,"body":"fixture response"}`))
	})
	task := validTask("request.execute", `{"method":"GET","url":"http://fixture.test/","headers":{"X-Test":"yes"}}`)

	result, err := (inProcessTaskDispatcher{handler: handler}).Dispatch(context.Background(), task)
	if err != nil {
		t.Fatalf("dispatch request: %v", err)
	}
	if string(result) != `{"status":200,"body":"fixture response"}` {
		t.Fatalf("dispatch result = %s", result)
	}
}

func TestInProcessTaskDispatcherForwardsRouteGeneration(t *testing.T) {
	generation := uint64(23)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(routeGenerationHeader); got != "23" {
			t.Errorf("route generation header = %q, want 23", got)
		}
		_, _ = w.Write([]byte(`{"status":200}`))
	})
	task := validTask("request.execute", `{"method":"GET","url":"http://fixture.test/"}`)
	task.RouteGeneration = &generation

	_, err := (inProcessTaskDispatcher{handler: handler}).Dispatch(context.Background(), task)
	if err != nil {
		t.Fatalf("dispatch request with generation: %v", err)
	}
}

func TestInProcessTaskDispatcherReportsHandlerFailure(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "private handler detail", http.StatusBadGateway)
	})
	_, err := (inProcessTaskDispatcher{handler: handler}).Dispatch(
		context.Background(),
		validTask("request.execute", `{"url":"http://fixture.test/"}`),
	)
	var failure executionFailure
	if !errors.As(err, &failure) || !failure.retryable {
		t.Fatalf("handler failure = %v, want retryable execution failure", err)
	}
	if strings.Contains(err.Error(), "private handler detail") {
		t.Fatalf("handler response detail leaked into error: %v", err)
	}
}

func TestInProcessTaskDispatcherPollsTargetMapToTerminal(t *testing.T) {
	var mu sync.Mutex
	polls := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/proxy/target-map":
			_, _ = w.Write([]byte(`{"map_id":42,"status":"running"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/proxy/target-map/42":
			mu.Lock()
			polls++
			currentPoll := polls
			mu.Unlock()
			state := "running"
			if currentPoll == 2 {
				state = "completed"
			}
			_, _ = w.Write([]byte(`{"map_id":42,"status":"` + state + `","pages":[]}`))
		default:
			t.Errorf("unexpected target handler request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	})

	result, err := (inProcessTaskDispatcher{handler: handler, pollInterval: time.Millisecond}).Dispatch(
		context.Background(),
		validTask("target.crawl", `{"url":"http://fixture.test/"}`),
	)
	if err != nil {
		t.Fatalf("dispatch target crawl: %v", err)
	}
	mu.Lock()
	pollCount := polls
	mu.Unlock()
	if !strings.Contains(string(result), `"status":"completed"`) || pollCount != 2 {
		t.Fatalf("target result=%s poll count=%d", result, pollCount)
	}
}

func TestInProcessTaskDispatcherCancelsTargetMapOnContextCancellation(t *testing.T) {
	polled := make(chan struct{})
	var once sync.Once
	deleted := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/proxy/target-map":
			_, _ = w.Write([]byte(`{"map_id":43,"status":"running"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/proxy/target-map/43":
			once.Do(func() { close(polled) })
			_, _ = w.Write([]byte(`{"map_id":43,"status":"running","pages":[]}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/proxy/target-map/43":
			close(deleted)
			w.WriteHeader(http.StatusAccepted)
		default:
			t.Errorf("unexpected target handler request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := (inProcessTaskDispatcher{handler: handler, pollInterval: time.Hour}).Dispatch(
			ctx,
			validTask("target.crawl", `{"url":"http://fixture.test/"}`),
		)
		result <- err
	}()
	<-polled
	cancel()
	select {
	case <-deleted:
	case <-time.After(time.Second):
		t.Fatal("target map was not cancelled after context cancellation")
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("dispatch cancellation error = %v", err)
	}
}

func TestSharedTaskFixturePassesConsumerContractValidation(t *testing.T) {
	fixturePath := filepath.Join("..", "contracts", "engine-task-v1.json")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read shared task fixture: %v", err)
	}
	var task taskcontract.Task
	if err := json.Unmarshal(data, &task); err != nil {
		t.Fatalf("decode shared task fixture: %v", err)
	}
	if err := task.Validate(); err != nil {
		t.Fatalf("shared task fixture should validate: %v", err)
	}
}

func TestEngineBrokerUsesTheContractQueueNames(t *testing.T) {
	// The queue names are the contract with the Django side, on the same names
	// the Redis lists and the documentation use.
	if engineTaskQueue != "rr.engine.tasks.v1" {
		t.Fatalf("task queue = %q", engineTaskQueue)
	}
	if engineResultQueue != "rr.engine.results.v1" {
		t.Fatalf("result queue = %q", engineResultQueue)
	}
}

func TestAnOldBrokerURLIsRefusedWithAnActionableMessage(t *testing.T) {
	// An engine left on the removed broker would otherwise sit there looking
	// healthy while quietly consuming nothing, which is the worst possible state
	// for a task queue.
	for _, brokerURL := range []string{
		"amqp://guest:guest@127.0.0.1:5672//",
		"amqps://broker/",
		"127.0.0.1:6379",
		"",
	} {
		if brokerScheme(brokerURL) == "redis" {
			t.Fatalf("brokerScheme(%q) must not be accepted", brokerURL)
		}
		message := unsupportedBrokerError(brokerURL).Error()
		for _, expected := range []string{brokerURL, "Redis", "redis://127.0.0.1:6379/0"} {
			if !strings.Contains(message, expected) {
				t.Fatalf("error for %q does not mention %q: %s", brokerURL, expected, message)
			}
		}
	}
}

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"time"

	"intruder/engine/pkg/taskcontract"
)

// Queue names are the contract, identical on both sides of the broker.
const (
	engineTaskQueue   = "rr.engine.tasks.v1"
	engineResultQueue = "rr.engine.results.v1"
)

type taskDispatcher interface {
	Dispatch(context.Context, taskcontract.Task) (json.RawMessage, error)
}

type taskResultPublisher interface {
	PublishResult([]byte) error
}

type taskDelivery interface {
	Body() []byte
	Ack(bool) error
	Nack(bool, bool) error
	Reject(bool) error
}

type executionFailure struct {
	retryable bool
}

type taskExecutionRegistry struct {
	mu     sync.Mutex
	active map[string]context.CancelCauseFunc
}

func newTaskExecutionRegistry() *taskExecutionRegistry {
	return &taskExecutionRegistry{active: make(map[string]context.CancelCauseFunc)}
}

func (registry *taskExecutionRegistry) Start(taskID string, parent context.Context) (context.Context, func(), bool) {
	registry.mu.Lock()
	if _, exists := registry.active[taskID]; exists {
		registry.mu.Unlock()
		return nil, nil, true
	}
	ctx, cancel := context.WithCancelCause(parent)
	registry.active[taskID] = cancel
	registry.mu.Unlock()
	return ctx, func() {
		cancel(nil)
		registry.mu.Lock()
		delete(registry.active, taskID)
		registry.mu.Unlock()
	}, false
}

func (registry *taskExecutionRegistry) Cancel(taskID string) bool {
	registry.mu.Lock()
	cancel, exists := registry.active[taskID]
	registry.mu.Unlock()
	if exists {
		cancel(errEngineTaskCancelled)
	}
	return exists
}

var errEngineTaskCancelled = errors.New("engine task cancelled by command")

type taskOutcomeRegistry struct {
	mu       sync.Mutex
	outcomes map[string]taskcontract.Result
}

func newTaskOutcomeRegistry() *taskOutcomeRegistry {
	return &taskOutcomeRegistry{outcomes: make(map[string]taskcontract.Result)}
}

func (registry *taskOutcomeRegistry) Get(taskID string) (taskcontract.Result, bool) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	result, exists := registry.outcomes[taskID]
	return result, exists
}

func (registry *taskOutcomeRegistry) Put(taskID string, result taskcontract.Result) {
	registry.mu.Lock()
	registry.outcomes[taskID] = result
	registry.mu.Unlock()
}

func (registry *taskOutcomeRegistry) Delete(taskID string) {
	registry.mu.Lock()
	delete(registry.outcomes, taskID)
	registry.mu.Unlock()
}

func (failure executionFailure) Error() string {
	return "engine task execution failed"
}

type unsupportedTaskError struct{}

func (unsupportedTaskError) Error() string {
	return "unsupported engine task type"
}

type inProcessTaskDispatcher struct {
	handler      http.Handler
	pollInterval time.Duration
	registry     *taskExecutionRegistry
}

func (dispatcher inProcessTaskDispatcher) Dispatch(ctx context.Context, task taskcontract.Task) (json.RawMessage, error) {
	if task.TaskType == "engine.task.cancel" {
		var payload struct {
			TaskID string `json:"task_id"`
		}
		if err := json.Unmarshal(task.Payload, &payload); err != nil || payload.TaskID == "" {
			return nil, errors.New("cancel command has invalid target task id")
		}
		cancelled := false
		if dispatcher.registry != nil {
			cancelled = dispatcher.registry.Cancel(payload.TaskID)
		}
		output, err := json.Marshal(map[string]any{"task_id": payload.TaskID, "cancelled": cancelled})
		return output, err
	}
	ctx = context.WithValue(ctx, suppressRequestLogsKey{}, true)
	switch task.TaskType {
	case "request.execute":
		response, status, err := dispatcher.serveTask(ctx, http.MethodPost, "/proxy/request", task)
		if err != nil {
			return nil, err
		}
		if status < http.StatusOK || status >= http.StatusMultipleChoices {
			return nil, executionFailure{retryable: status >= http.StatusInternalServerError}
		}
		if err := validateResponseObject(response); err != nil {
			return nil, err
		}
		return response, nil
	case "target.crawl":
		return dispatcher.runTargetCrawl(ctx, task)
	default:
		return nil, unsupportedTaskError{}
	}
}

func (dispatcher inProcessTaskDispatcher) runTargetCrawl(ctx context.Context, task taskcontract.Task) (json.RawMessage, error) {
	response, status, err := dispatcher.serveTask(ctx, http.MethodPost, "/proxy/target-map", task)
	if err != nil {
		return nil, err
	}
	if status != http.StatusAccepted && (status < http.StatusOK || status >= http.StatusMultipleChoices) {
		return nil, executionFailure{retryable: status >= http.StatusInternalServerError}
	}
	var started struct {
		MapID uint64 `json:"map_id"`
	}
	if err := json.Unmarshal(response, &started); err != nil || started.MapID == 0 {
		return nil, executionFailure{}
	}

	interval := dispatcher.pollInterval
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	for {
		select {
		case <-ctx.Done():
			dispatcher.cancelTargetMap(ctx, started.MapID)
			return nil, ctx.Err()
		default:
		}

		statusPath := "/proxy/target-map/" + strconv.FormatUint(started.MapID, 10)
		response, status, err = dispatcher.serveTask(ctx, http.MethodGet, statusPath, task)
		if err != nil {
			dispatcher.cancelTargetMap(ctx, started.MapID)
			return nil, err
		}
		if status < http.StatusOK || status >= http.StatusMultipleChoices {
			dispatcher.cancelTargetMap(ctx, started.MapID)
			return nil, executionFailure{retryable: status >= http.StatusInternalServerError}
		}
		var snapshot struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(response, &snapshot); err != nil {
			dispatcher.cancelTargetMap(ctx, started.MapID)
			return nil, executionFailure{}
		}
		switch snapshot.Status {
		case "completed":
			return response, nil
		case "cancelled":
			return nil, context.Canceled
		case "failed":
			return nil, executionFailure{}
		case "running", "cancelling":
		default:
			dispatcher.cancelTargetMap(ctx, started.MapID)
			return nil, executionFailure{}
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			dispatcher.cancelTargetMap(ctx, started.MapID)
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (dispatcher inProcessTaskDispatcher) cancelTargetMap(ctx context.Context, mapID uint64) {
	cancelContext := context.WithoutCancel(ctx)
	_, _, _ = dispatcher.serve(cancelContext, http.MethodDelete,
		"/proxy/target-map/"+strconv.FormatUint(mapID, 10), nil)
}

func (dispatcher inProcessTaskDispatcher) serveTask(ctx context.Context, method, path string, task taskcontract.Task) ([]byte, int, error) {
	if dispatcher.handler == nil {
		return nil, 0, errors.New("engine handler is unavailable")
	}
	body, err := json.Marshal(task.Payload)
	if err != nil {
		return nil, 0, err
	}
	request, err := http.NewRequestWithContext(ctx, method, path, strings.NewReader(string(body)))
	if err != nil {
		return nil, 0, err
	}
	if task.RouteGeneration != nil {
		request.Header.Set(routeGenerationHeader, strconv.FormatUint(*task.RouteGeneration, 10))
	}
	recorder := httptest.NewRecorder()
	dispatcher.handler.ServeHTTP(recorder, request)
	return recorder.Body.Bytes(), recorder.Code, nil
}

func (dispatcher inProcessTaskDispatcher) serve(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	if dispatcher.handler == nil {
		return nil, 0, errors.New("engine handler is unavailable")
	}
	request := httptest.NewRequest(method, path, strings.NewReader(string(body))).WithContext(ctx)
	recorder := httptest.NewRecorder()
	dispatcher.handler.ServeHTTP(recorder, request)
	return recorder.Body.Bytes(), recorder.Code, nil
}

func validateResponseObject(response []byte) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(response, &object); err != nil || object == nil {
		return executionFailure{}
	}
	return nil
}

// taskOutcomeCache remembers a finished task so a redelivered message does not
// perform its side effect twice. The in-process registry is one implementation;
// the Redis transport wraps it with a durable copy that survives a restart.
type taskOutcomeCache interface {
	Get(taskID string) (taskcontract.Result, bool)
	Put(taskID string, result taskcontract.Result)
	Delete(taskID string)
}

func processTaskDelivery(
	ctx context.Context,
	delivery taskDelivery,
	dispatcher taskDispatcher,
	publisher taskResultPublisher,
	outcomeCaches ...taskOutcomeCache,
) {
	var outcomes taskOutcomeCache
	if len(outcomeCaches) > 0 {
		outcomes = outcomeCaches[0]
	}
	var task taskcontract.Task
	decodeErr := decodeTaskMessage(delivery.Body(), &task)
	var result taskcontract.Result

	switch {
	case decodeErr != nil:
		result, decodeErr = newTaskResult(task.TaskID, "failed", nil, &taskcontract.TaskError{
			Code: "MALFORMED_TASK", Message: "task message is not valid JSON", Retryable: false,
		})
		if decodeErr != nil {
			rejectTaskDelivery(delivery)
			return
		}
	case task.Validate() != nil:
		result, decodeErr = newTaskResult(task.TaskID, "failed", nil, &taskcontract.TaskError{
			Code: "INVALID_TASK", Message: "task does not satisfy the engine task contract", Retryable: false,
		})
		if decodeErr != nil {
			rejectTaskDelivery(delivery)
			return
		}
	default:
		// Signature before anything else: a forged task has the right shape by
		// construction, so shape validation has already passed it. A bad
		// signature goes straight to the dead-letter list with no result
		// published — publishing a failure for the named task would let a
		// forgery fail somebody else's real run.
		if err := verifyEnvelopeSignature(delivery.Body()); err != nil {
			log.Printf("redis task refused reason=%v", err)
			rejectTaskDelivery(delivery)
			return
		}
		var cached bool
		if outcomes != nil {
			result, cached = outcomes.Get(task.TaskID)
		}
		if cached {
			// A redelivered message replays the recorded answer as it was
			// recorded, event_id included. Wrapping it in a fresh envelope would
			// invent a second completion for one fact, and the ledger
			// deduplicates by event_id precisely so a repeat is recognised as
			// the same fact rather than stored again.
			if err := publishResultEnvelope(result, publisher); err != nil {
				_ = delivery.Nack(false, true)
				return
			}
			if err := delivery.Ack(false); err == nil && outcomes != nil {
				outcomes.Delete(result.TaskID)
			}
			return
		}
		if err := publishTaskResult(task.TaskID, "accepted", nil, nil, publisher); err != nil {
			_ = delivery.Nack(false, true)
			return
		}
		output, dispatchErr := dispatcher.Dispatch(ctx, task)
		switch {
		case errors.Is(context.Cause(ctx), errEngineTaskCancelled):
			result, decodeErr = newTaskResult(task.TaskID, "cancelled", nil, nil)
		case dispatchErr == nil:
			result, decodeErr = newTaskResult(task.TaskID, "completed", output, nil)
		case ctx.Err() != nil:
			_ = delivery.Nack(false, true)
			return
		case errors.Is(dispatchErr, context.Canceled):
			result, decodeErr = newTaskResult(task.TaskID, "cancelled", nil, nil)
		default:
			code, message, retryable := "ENGINE_EXECUTION_FAILED", "engine task execution failed", false
			var unsupported unsupportedTaskError
			var execution executionFailure
			if errors.As(dispatchErr, &unsupported) {
				code, message = "UNSUPPORTED_TASK_TYPE", "engine task type is not supported"
			} else if errors.As(dispatchErr, &execution) {
				retryable = execution.retryable
			}
			result, decodeErr = newTaskResult(task.TaskID, "failed", nil, &taskcontract.TaskError{
				Code: code, Message: message, Retryable: retryable,
			})
		}
		if decodeErr != nil {
			rejectTaskDelivery(delivery)
			return
		}
		if outcomes != nil && (ctx.Err() == nil || result.State == "completed") {
			outcomes.Put(task.TaskID, result)
		}
	}

	// The answer that is published is the same value that was recorded for
	// idempotency. Building a second envelope here would give the broker and the
	// ledger two different event_ids for one outcome, and a redelivery would
	// then replay an event nobody has ever seen.
	if err := publishResultEnvelope(result, publisher); err != nil {
		_ = delivery.Nack(false, true)
		return
	}
	if err := delivery.Ack(false); err == nil && outcomes != nil {
		outcomes.Delete(result.TaskID)
	}
}

// publishResultEnvelope publishes one already-built result exactly as it is.
// It is used for every result the engine keeps, so a replay is byte-identical
// to the original answer instead of a fresh event that merely looks the same.
func publishResultEnvelope(result taskcontract.Result, publisher taskResultPublisher) error {
	if err := result.Validate(); err != nil {
		return err
	}
	// Signed at the single choke point every result passes through: new results
	// and replays alike. Deterministic, so a replay keeps its original bytes.
	if err := signTaskResult(&result); err != nil {
		return err
	}
	body, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return publisher.PublishResult(body)
}

func publishTaskResult(taskID, state string, output json.RawMessage, taskErr *taskcontract.TaskError, publisher taskResultPublisher) error {
	result, err := newTaskResult(taskID, state, output, taskErr)
	if err != nil {
		return err
	}
	if err := result.Validate(); err != nil {
		return err
	}
	if err := signTaskResult(&result); err != nil {
		return err
	}
	body, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return publisher.PublishResult(body)
}

func decodeTaskMessage(body []byte, task *taskcontract.Task) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(task); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("task message contains multiple JSON values")
		}
		return err
	}
	return nil
}

func rejectTaskDelivery(delivery taskDelivery) {
	_ = delivery.Reject(false)
}

func newTaskResult(taskID, state string, output json.RawMessage, taskErr *taskcontract.TaskError) (taskcontract.Result, error) {
	eventID, err := newUUID()
	if err != nil {
		return taskcontract.Result{}, err
	}
	result := taskcontract.Result{
		SchemaVersion: taskcontract.SchemaVersion,
		TaskID:        taskID,
		EventID:       eventID,
		State:         state,
		OccurredAt:    time.Now().UTC().Format(time.RFC3339Nano),
		Result:        output,
		Error:         taskErr,
	}
	if err := result.Validate(); err != nil {
		return taskcontract.Result{}, err
	}
	return result, nil
}

func newUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	encoded := make([]byte, 36)
	hex.Encode(encoded[0:8], value[0:4])
	encoded[8] = '-'
	hex.Encode(encoded[9:13], value[4:6])
	encoded[13] = '-'
	hex.Encode(encoded[14:18], value[6:8])
	encoded[18] = '-'
	hex.Encode(encoded[19:23], value[8:10])
	encoded[23] = '-'
	hex.Encode(encoded[24:36], value[10:16])
	return string(encoded), nil
}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"intruder/engine/pkg/taskcontract"
)

// The engine side of the engine task transport, over Redis.
//
// A task is the JSON object in contracts/engine-task-v1.json and a result is the
// one in contracts/engine-result-v1.json, byte for byte — the same contract the
// Django side writes, because both ends speak it directly. This file owns
// exactly three things: taking the next task while holding it in a recoverable
// place, publishing results, and remembering a finished task so a restarted
// process does not perform its side effect twice.
//
// Reliability is explicit rather than borrowed. Redis pops are destructive, so
// a message is taken with BLMOVE into <queue>.inflight in one command: a crash
// between the take and the ack leaves the message there, and the next session
// returns it to the queue instead of losing it. Publishing is LPUSH, the same
// command the Django side uses, so producers on both ends write to the head and
// consumers read the oldest message from the tail.
const (
	redisTaskQueue   = engineTaskQueue
	redisResultQueue = engineResultQueue

	redisInflightSuffix = ".inflight"
	redisDeadSuffix     = ".dead"
	redisOutcomePrefix  = "rr.engine.outcome."
)

// defaultRedisOutcomeTTL bounds how long a finished task is remembered across
// restarts. It is a cache, not a limit on work: it only decides how long a
// redelivered task replays its recorded result instead of running again, and an
// operator can raise or disable it with ENGINE_BROKER_OUTCOME_TTL.
const defaultRedisOutcomeTTL = time.Hour

// redisCommands is the slice of go-redis this transport uses. Keeping it narrow
// means the session logic is testable without a broker, and it documents which
// commands the reliability argument actually depends on.
type redisCommands interface {
	BLMove(ctx context.Context, source, destination, srcPos, destPos string, timeout time.Duration) *redis.StringCmd
	LMove(ctx context.Context, source, destination, srcPos, destPos string) *redis.StringCmd
	LPush(ctx context.Context, key string, values ...any) *redis.IntCmd
	LRem(ctx context.Context, key string, count int64, value any) *redis.IntCmd
	LLen(ctx context.Context, key string) *redis.IntCmd
	Del(ctx context.Context, keys ...string) *redis.IntCmd
	Get(ctx context.Context, key string) *redis.StringCmd
	Set(ctx context.Context, key string, value any, expiration time.Duration) *redis.StatusCmd
	Ping(ctx context.Context) *redis.StatusCmd
	Close() error
}

// isRedisNil reports the one "error" a list command returns when it has nothing
// to return. Redis has no empty-element reply, so a drained list and a broken
// connection would otherwise be indistinguishable — and treating an idle queue
// as a failed session would reconnect the engine once per second.
func isRedisNil(err error) bool {
	return errors.Is(err, redis.Nil)
}

func redisInflightList(queue string) string { return queue + redisInflightSuffix }
func redisDeadList(queue string) string     { return queue + redisDeadSuffix }

func redisOutcomeKey(taskID string) string { return redisOutcomePrefix + taskID }

// brokerScheme names the transport an ENGINE_BROKER_URL selects. An empty or
// unrecognised scheme is reported rather than guessed: sending a task envelope
// to the wrong transport fails later, in the engine, where it looks like a
// target problem.
func brokerScheme(brokerURL string) string {
	scheme, _, found := strings.Cut(strings.TrimSpace(brokerURL), "://")
	if !found {
		return ""
	}
	switch strings.ToLower(scheme) {
	case "redis", "rediss", "unix":
		return "redis"
	default:
		return ""
	}
}

// unsupportedBrokerError names what to do with a configuration this deployment
// can no longer serve. An engine left on an old broker URL would otherwise sit
// there looking healthy while quietly consuming nothing, which is the worst
// possible state for a task queue.
func unsupportedBrokerError(brokerURL string) error {
	return fmt.Errorf(
		"ENGINE_BROKER_URL %q is not a supported broker: this deployment uses "+
			"Redis, so set redis://127.0.0.1:6379/0 (or rediss://, unix://) "+
			"and start a Redis server",
		brokerURL,
	)
}

func parseRedisBrokerURL(brokerURL string) (*redis.Options, error) {
	options, err := redis.ParseURL(brokerURL)
	if err != nil {
		return nil, errors.New("redis broker URL is not valid")
	}
	if options.Addr == "" {
		options.Addr = "127.0.0.1:6379"
	}
	return options, nil
}

func redisOutcomeTTL() time.Duration {
	raw := strings.TrimSpace(os.Getenv("ENGINE_BROKER_OUTCOME_TTL"))
	if raw == "" {
		return defaultRedisOutcomeTTL
	}
	if strings.EqualFold(raw, "0") || strings.EqualFold(raw, "off") {
		return 0
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds < 0 {
		log.Printf("ENGINE_BROKER_OUTCOME_TTL=%q is not a number of seconds; using %s", raw, defaultRedisOutcomeTTL)
		return defaultRedisOutcomeTTL
	}
	return time.Duration(seconds) * time.Second
}

func newRedisClient(brokerURL string) (redisCommands, error) {
	options, err := parseRedisBrokerURL(brokerURL)
	if err != nil {
		return nil, err
	}
	return redis.NewClient(options), nil
}

type redisResultPublisher struct {
	client redisCommands
	queue  string
}

func (publisher redisResultPublisher) PublishResult(body []byte) error {
	// The publish is on its own deadline: a stopped broker must produce an
	// error this handler can requeue on, not a goroutine that waits forever.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := publisher.client.LPush(ctx, publisher.queue, body).Err(); err != nil {
		return fmt.Errorf("result publish failed: %w", err)
	}
	return nil
}

type redisTaskDelivery struct {
	client   redisCommands
	body     []byte
	queue    string
	settled  bool
	settleMu sync.Mutex
}

func (delivery *redisTaskDelivery) Body() []byte { return delivery.body }

func (delivery *redisTaskDelivery) Ack(bool) error {
	return delivery.settle(func() error {
		return delivery.client.LRem(context.Background(), redisInflightList(delivery.queue), 1, string(delivery.body)).Err()
	})
}

func (delivery *redisTaskDelivery) Nack(_, requeue bool) error {
	return delivery.settle(func() error {
		if err := delivery.client.LRem(context.Background(), redisInflightList(delivery.queue), 1, string(delivery.body)).Err(); err != nil {
			return err
		}
		if !requeue {
			return delivery.client.LPush(context.Background(), redisDeadList(delivery.queue), delivery.body).Err()
		}
		return delivery.client.LPush(context.Background(), delivery.queue, delivery.body).Err()
	})
}

func (delivery *redisTaskDelivery) Reject(requeue bool) error {
	return delivery.Nack(false, requeue)
}

func (delivery *redisTaskDelivery) settle(apply func() error) error {
	delivery.settleMu.Lock()
	defer delivery.settleMu.Unlock()
	if delivery.settled {
		return nil
	}
	if err := apply(); err != nil {
		return err
	}
	delivery.settled = true
	return nil
}

// redisOutcomeCache remembers a finished task in the broker, so a process that
// restarts while a task message is being redelivered replays the recorded
// result instead of sending the request a second time. The in-process registry
// stays the fast path, and the durable entry is what survives a restart.
type redisOutcomeCache struct {
	client redisCommands
	local  *taskOutcomeRegistry
	ttl    time.Duration
}

func (cache *redisOutcomeCache) Get(taskID string) (taskcontract.Result, bool) {
	if result, ok := cache.local.Get(taskID); ok {
		return result, true
	}
	if cache.ttl <= 0 {
		return taskcontract.Result{}, false
	}
	body, err := cache.client.Get(context.Background(), redisOutcomeKey(taskID)).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			log.Printf("redis outcome lookup failed task_id=%s reason=%v", taskID, err)
		}
		return taskcontract.Result{}, false
	}
	var result taskcontract.Result
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		log.Printf("redis outcome entry is unreadable task_id=%s", taskID)
		return taskcontract.Result{}, false
	}
	cache.local.Put(taskID, result)
	return result, true
}

func (cache *redisOutcomeCache) Put(taskID string, result taskcontract.Result) {
	cache.local.Put(taskID, result)
	if cache.ttl <= 0 {
		return
	}
	body, err := json.Marshal(result)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := cache.client.Set(ctx, redisOutcomeKey(taskID), body, cache.ttl).Err(); err != nil {
		log.Printf("redis outcome store failed task_id=%s reason=%v", taskID, err)
	}
}

// Delete only forgets the in-process copy. The durable entry is what makes a
// redelivery after a restart safe, so it is left to expire on its own TTL.
func (cache *redisOutcomeCache) Delete(taskID string) {
	cache.local.Delete(taskID)
}

func runRedisConsumer(ctx context.Context, brokerURL string, handler http.Handler) error {
	registry := newTaskExecutionRegistry()
	ttl := redisOutcomeTTL()
	log.Printf("redis task consumer starting broker=%s outcome_ttl=%s", brokerURL, ttl)
	for {
		if ctx.Err() != nil {
			return nil
		}
		err := consumeRedisSession(ctx, brokerURL, handler, registry, ttl)
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			log.Printf("redis session ended; reconnecting")
		} else {
			log.Printf("redis session failed; reconnecting reason=%v", err)
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func consumeRedisSession(
	ctx context.Context,
	brokerURL string,
	handler http.Handler,
	registry *taskExecutionRegistry,
	outcomeTTL time.Duration,
) error {
	client, err := newRedisClient(brokerURL)
	if err != nil {
		return err
	}
	defer client.Close()

	pingContext, cancelPing := context.WithTimeout(ctx, 5*time.Second)
	defer cancelPing()
	if err := client.Ping(pingContext).Err(); err != nil {
		return fmt.Errorf("redis broker is not reachable: %w", err)
	}
	if recovered, err := recoverRedisInflight(ctx, client, redisTaskQueue); err != nil {
		return err
	} else if recovered > 0 {
		log.Printf("redis inflight recovered queue=%s messages=%d", redisTaskQueue, recovered)
	}

	local := newTaskOutcomeRegistry()
	outcomes := &redisOutcomeCache{client: client, local: local, ttl: outcomeTTL}
	dispatcher := inProcessTaskDispatcher{handler: handler, registry: registry}
	publisher := redisResultPublisher{client: client, queue: redisResultQueue}

	var active sync.WaitGroup
	defer active.Wait()
	for {
		if ctx.Err() != nil {
			return nil
		}
		body, err := client.BLMove(ctx, redisTaskQueue, redisInflightList(redisTaskQueue), "RIGHT", "LEFT", time.Second).Result()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if isRedisNil(err) {
				// The block timed out with an empty queue: the engine is idle.
				continue
			}
			return fmt.Errorf("redis task read failed: %w", err)
		}
		if body == "" {
			continue
		}
		if ctx.Err() != nil {
			_ = client.LPush(ctx, redisTaskQueue, body)
			continue
		}
		taskContext := ctx
		finishTask := func() {}
		var task taskcontract.Task
		if decodeTaskMessage([]byte(body), &task) == nil &&
			task.Validate() == nil &&
			task.TaskType != "engine.task.cancel" {
			var alreadyActive bool
			taskContext, finishTask, alreadyActive = registry.Start(task.TaskID, ctx)
			if alreadyActive {
				// The same task is already running here: acknowledge this copy
				// so the broker does not hand it out again, and let the running
				// handler publish the one authoritative result.
				if err := client.LRem(ctx, redisInflightList(redisTaskQueue), 1, body).Err(); err != nil {
					log.Printf("redis duplicate ack failed task_id=%s reason=%v", task.TaskID, err)
				}
				continue
			}
		}
		active.Add(1)
		go func(body string, taskContext context.Context, finishTask func()) {
			defer active.Done()
			defer finishTask()
			processTaskDelivery(taskContext, &redisTaskDelivery{
				client: client,
				body:   []byte(body),
				queue:  redisTaskQueue,
			}, dispatcher, publisher, outcomes)
		}(body, taskContext, finishTask)
	}
}

// recoverRedisInflight returns messages a previous process took but never
// settled. It runs before the loop starts, when this process owns the queue and
// no live handler can still be holding one of those messages.
func recoverRedisInflight(ctx context.Context, client redisCommands, queue string) (int, error) {
	recovered := 0
	for {
		// LMove, not BLMove: a zero timeout means "block forever" to a blocking
		// command, and recovery must not wait for a message that may never come.
		body, err := client.LMove(ctx, redisInflightList(queue), queue, "RIGHT", "LEFT").Result()
		if err != nil {
			if isRedisNil(err) {
				// Nothing was left in flight, which is the normal case.
				return recovered, nil
			}
			return recovered, fmt.Errorf("redis inflight recovery failed: %w", err)
		}
		if body == "" {
			return recovered, nil
		}
		recovered++
	}
}

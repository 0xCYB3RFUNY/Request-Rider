package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"intruder/engine/pkg/scanner"
)

// OAST-джерело для Scanner — те саме, що вже є в рушіє, а не другий.
//
// Рушій не може бути сервером протоколу interactsh: `engine/oast.go` — це
// OAST-*клієнт*, який реєструється у провайдера й опитує його. Але клієнт — це
// вже все, що потрібно шаблону з `{{interactsh-url}}`: адреса для зворотного
// дзвінка й запит «чи прийшов дзвінок».
//
// Тому тут немає нічого нового: `registerOAST` і `pollOAST` уже існують і
// використовуються обробником `POST /proxy/oast`. Цей тип бере їх, а не
// пише другу реєстрацію — інакше це був би паралельний шлях.

// oastScannerSource is the scanner's view of this engine's OAST capability.
type oastScannerSource struct {
	server *server

	mu     sync.Mutex
	jobs   map[string]*oastListener
	source map[uint64]*oastListener
	seq    uint64
}

// oastProviderURL returns the provider this source registers with.
//
// It is configuration, not a default this project may invent: an OAST provider is
// somewhere else, on someone's infrastructure, and choosing one here would decide
// where a stranger's target reports back to. Without it there is no source, and
// the scanner says so by name instead of sending a literal placeholder.
// The same value Django already sends for its own OAST listener: `web/lab/views.py`
// defaults `server_url` to `http://127.0.0.1:8766` when the caller names none.
//
// Defaulting to it here rather than inventing a second variable is the point: a
// provider address that two places each defaulted separately would be two
// configurations for one service, and an operator would be left wondering which one
// the scanner used.
const defaultOASTProviderURL = "http://127.0.0.1:8766"

func oastProviderURL() string {
	if configured := strings.TrimSpace(os.Getenv("RR_OAST_PROVIDER_URL")); configured != "" {
		return strings.TrimRight(configured, "/")
	}
	return defaultOASTProviderURL
}

// newOASTScannerSource returns the source for a run, or nil when none is
// configured.
//
// Nil is the honest answer here and not a degraded one: `{{interactsh-url}` then
// produces a refusal naming what is missing, which is a state the operator can
// act on.
func (s *server) newOASTScannerSource(_ context.Context) scanner.OASTSource {
	provider := oastProviderURL()
	if provider == "" {
		return nil
	}
	if _, err := validateOASTProviderURL(provider); err != nil {
		return nil
	}
	return &oastScannerSource{
		server: s,
		jobs:   map[string]*oastListener{},
		source: map[uint64]*oastListener{},
	}
}

// NewPayload registers one listener and returns the address a template sends.
func (o *oastScannerSource) NewPayload(ctx context.Context) (string, error) {
	provider := oastProviderURL()
	payloadURL, domain, err := o.server.registerOAST(ctx, provider, "", []string{"http", "https"})
	if err != nil {
		return "", err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.seq++
	id := o.seq
	job := &oastListener{
		status:       "listening",
		providerURL:  provider,
		payloadURL:   payloadURL,
		domain:       domain,
		routeContext: ctx,
		protocols:    []string{"http", "https"},
		startedAt:    time.Now().UTC(),
	}
	o.jobs[payloadURL] = job
	o.source[id] = job
	return payloadURL, nil
}

// Await reports whether a callback to the address arrived within the bound.
//
// It polls the provider the same way the listener does, so a template's callback
// and an operator's `GET /proxy/oast/<id>` see the same events rather than two
// answers to one question.
func (o *oastScannerSource) Await(ctx context.Context, payloadURL string, wait time.Duration) (bool, error) {
	o.mu.Lock()
	job, ok := o.jobs[payloadURL]
	o.mu.Unlock()
	if !ok {
		return false, fmt.Errorf("no listener is registered for %s", payloadURL)
	}
	if wait <= 0 {
		wait = 10 * time.Second
	}
	deadline := time.Now().Add(wait)
	poll := oastScannerPollInterval(wait)
	for {
		events, err := o.server.pollOAST(ctx, job)
		if err != nil {
			return false, err
		}
		if len(events) > 0 {
			job.mu.Lock()
			job.events = append(job.events, sanitizeOASTEvent(events[0]))
			job.status = "callback_received"
			job.finishedAt = time.Now().UTC()
			job.mu.Unlock()
			return true, nil
		}
		if time.Now().After(deadline) {
			job.mu.Lock()
			job.status = "no_callback"
			job.timedOut = true
			job.mu.Unlock()
			return false, nil
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(poll):
		}
	}
}

// oastScannerPollInterval is how often a scanner template's callback is checked.
//
// It is the listener's own poll interval, and it is shortened for a short wait: a
// template that waits two seconds and is polled every thirty would report "no
// callback" for a callback that had already arrived.
func oastScannerPollInterval(wait time.Duration) time.Duration {
	interval := 5 * time.Second
	if configured, err := time.ParseDuration(os.Getenv("RR_OAST_POLL_INTERVAL")); err == nil && configured > 0 {
		interval = configured
	}
	if quarter := wait / 4; quarter > 0 && quarter < interval {
		interval = quarter
	}
	if interval < 200*time.Millisecond {
		interval = 200 * time.Millisecond
	}
	return interval
}

// withOASTSource gives a run the callback capability when one is configured.
//
// It is a no-op when no provider is set, and that is deliberate: the source is an
// external dependency with a real cost, so its absence has to be visible in the
// report rather than filled in by a default.
func (s *server) withOASTSource(ctx context.Context) context.Context {
	source := s.newOASTScannerSource(ctx)
	if source == nil {
		return ctx
	}
	return scanner.WithOASTSource(ctx, source)
}

package passive

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"
	"time"
)

// NewCaptureTransport records requests made by an engine tool in the shared
// Traffic store while preserving the route transport used by ordinary requests.
//
// sourceIP resolves the address the route exits from, and it is the same resolver
// the passive proxy uses, so an exchange recorded here carries the same field an
// exchange recorded through the proxy does. It is optional: without it the run is
// still recorded, just without the address — which is what every tool did until
// this was added, and the reason a scanner's rows showed an empty column while
// the run's own response carried a value.
//
// The resolver is called per exchange and not once per run, because the run's
// answer is the answer of whichever exchange triggered it: a route that changes
// mid-run must not leave later rows claiming the exit that was in force before.
func NewCaptureTransport(next http.RoundTripper, store *Store, captureContext string, sourceIP func(context.Context) string) http.RoundTripper {
	if next == nil || store == nil {
		return next
	}
	return &captureTransport{
		next:           next,
		store:          store,
		captureContext: normalizeCaptureContext(captureContext),
		sourceIP:       sourceIP,
	}
}

type captureTransport struct {
	next           http.RoundTripper
	store          *Store
	captureContext string
	sourceIP       func(context.Context) string
}

// stampSourceIP fills the address on a recorded exchange.
//
// The lookup runs on its own goroutine and the request is never made to wait for
// it, which is what the proxy has always done and for the same reason: the field
// is one status column and an unreachable endpoint already produces "". The
// context is `WithoutCancel` so that a client which gives up on its own response
// cannot throw the value away — the exchange still happened, and the address it
// left through is still worth recording.
func (transport *captureTransport) stampSourceIP(request *http.Request, eventID uint64) {
	if transport.sourceIP == nil || eventID == 0 {
		return
	}
	go func() {
		resolved := transport.sourceIP(context.WithoutCancel(request.Context()))
		if resolved == "" {
			return
		}
		transport.store.Update(eventID, func(event *Event) {
			event.SourceIP = resolved
		})
	}()
}

func (transport *captureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	outbound := request.Clone(request.Context())
	var requestBytes []byte
	if outbound.Body != nil {
		body, err := readAndRestore(&outbound.Body)
		if err != nil {
			eventID := transport.store.Add(Event{
				Source:         "tool",
				CaptureContext: transport.captureContext,
				Timestamp:      time.Now().UTC(),
				Method:         request.Method,
				URL:            request.URL.String(),
				Host:           requestHost(request),
				RequestHeader:  flattenHeaders(request.Header),
			})
			if eventID != 0 {
				transport.store.Update(eventID, func(event *Event) {
					event.Error = err.Error()
					event.Latency = 0
				})
				transport.stampSourceIP(request, eventID)
			}
			return nil, err
		}
		requestBytes = body
		outbound.Body = io.NopCloser(bytes.NewReader(body))
	}

	requestBody, requestEncoding, requestBase64 := encodeBody(requestBytes)
	started := time.Now()
	eventID := transport.store.Add(Event{
		Source:              "tool",
		CaptureContext:      transport.captureContext,
		Timestamp:           started.UTC(),
		Method:              request.Method,
		URL:                 request.URL.String(),
		Host:                requestHost(request),
		RequestHeader:       flattenHeaders(request.Header),
		RequestBody:         requestBody,
		RequestBodyEncoding: requestEncoding,
		RequestBodyBase64:   requestBase64,
	})
	transport.stampSourceIP(request, eventID)

	response, err := transport.next.RoundTrip(outbound)
	if err != nil {
		transport.store.Update(eventID, func(event *Event) {
			event.Error = err.Error()
			event.Latency = time.Since(started).Milliseconds()
		})
		return response, err
	}
	if response == nil {
		err := io.ErrUnexpectedEOF
		transport.store.Update(eventID, func(event *Event) {
			event.Error = err.Error()
			event.Latency = time.Since(started).Milliseconds()
		})
		return nil, err
	}

	responseHeaders := flattenHeaders(response.Header)
	responseContentType := response.Header.Get("Content-Type")
	transport.store.Update(eventID, func(event *Event) {
		event.Status = response.StatusCode
		event.ResponseHeader = responseHeaders
		event.ResponseContentType = responseContentType
	})
	if response.Body == nil {
		transport.store.Update(eventID, func(event *Event) {
			event.Latency = time.Since(started).Milliseconds()
		})
		return response, nil
	}
	response.Body = &captureBody{
		body:           response.Body,
		store:          transport.store,
		eventID:        eventID,
		started:        started,
		expectedLength: response.ContentLength,
	}
	return response, nil
}

type captureBody struct {
	body           io.ReadCloser
	store          *Store
	eventID        uint64
	started        time.Time
	expectedLength int64

	mu        sync.Mutex
	captured  bytes.Buffer
	finalized bool
}

func (body *captureBody) Read(buffer []byte) (int, error) {
	count, err := body.body.Read(buffer)
	if count > 0 {
		body.mu.Lock()
		_, _ = body.captured.Write(buffer[:count])
		body.mu.Unlock()
	}
	if err != nil {
		body.finish(err)
	}
	return count, err
}

func (body *captureBody) Close() error {
	err := body.body.Close()
	body.mu.Lock()
	finalized := body.finalized
	capturedLength := int64(body.captured.Len())
	expectedLength := body.expectedLength
	body.mu.Unlock()
	if !finalized {
		if expectedLength >= 0 && capturedLength >= expectedLength {
			body.finish(io.EOF)
		} else {
			body.finish(io.ErrUnexpectedEOF)
		}
	}
	return err
}

func (body *captureBody) finish(readError error) {
	body.mu.Lock()
	if body.finalized {
		body.mu.Unlock()
		return
	}
	body.finalized = true
	captured := append([]byte(nil), body.captured.Bytes()...)
	body.mu.Unlock()

	responseBody, encoding, responseBase64 := encodeBody(captured)
	body.store.Update(body.eventID, func(event *Event) {
		event.ResponseBody = responseBody
		event.ResponseBodyEncoding = encoding
		event.ResponseBodyBase64 = responseBase64
		event.ResponseSize = len(captured)
		event.Latency = time.Since(body.started).Milliseconds()
		if readError != nil && readError != io.EOF {
			event.Error = readError.Error()
		}
	})
}

package passive

import (
	"bytes"
	"io"
	"net/http"
	"sync"
	"time"
)

// NewCaptureTransport records requests made by an engine tool in the shared
// Traffic store while preserving the route transport used by ordinary requests.
func NewCaptureTransport(next http.RoundTripper, store *Store, captureContext string) http.RoundTripper {
	if next == nil || store == nil {
		return next
	}
	return &captureTransport{
		next:           next,
		store:          store,
		captureContext: normalizeCaptureContext(captureContext),
	}
}

type captureTransport struct {
	next           http.RoundTripper
	store          *Store
	captureContext string
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

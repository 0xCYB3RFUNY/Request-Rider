package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// The cross-language vector, shared with web/lab/test_broker_auth.py: the same
// envelope, key and expected signature must match on both sides byte for byte.
// The payload deliberately contains `<`, `>` and non-ASCII, which is where two
// JSON encoders disagree.

const brokerAuthTestKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

const brokerAuthTestEnvelope = `{"created_at":"2026-09-27T09:00:00Z","payload":{"note":"<b>ü</b>","url":"http://127.0.0.1:8000/fixture?a=1&b=2"},"project_id":7,"route_generation":1,"schema_version":1,"task_id":"6f0e8400-e29b-41d4-a716-446655440000","task_type":"target.crawl"}`

const brokerAuthTestSig = "cd3c6f6cd2e88639d34c40fe5be144f5dfc7025c7763429579234fe2f7d10109"

func withBrokerKey(t *testing.T, key string) {
	t.Helper()
	t.Setenv(brokerKeyEnv, key)
}

func TestCanonicalFormMatchesPython(t *testing.T) {
	canonical, err := canonicalEnvelopeBytes([]byte(brokerAuthTestEnvelope))
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	if string(canonical) != brokerAuthTestEnvelope {
		t.Fatalf("canonical form differs from Python's:\n got: %s\nwant: %s", canonical, brokerAuthTestEnvelope)
	}
}

func TestCrossLanguageSignature(t *testing.T) {
	withBrokerKey(t, brokerAuthTestKey)
	signed, err := signEnvelopeBytes([]byte(brokerAuthTestEnvelope))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !strings.Contains(string(signed), `"sig":"`+brokerAuthTestSig+`"`) {
		t.Fatalf("signature differs from Python's: %s", signed)
	}
	if err := verifyEnvelopeSignature(signed); err != nil {
		t.Fatalf("own signature rejected: %v", err)
	}
}

func TestTamperedEnvelopeIsRejected(t *testing.T) {
	withBrokerKey(t, brokerAuthTestKey)
	signed, err := signEnvelopeBytes([]byte(brokerAuthTestEnvelope))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	forged := strings.Replace(string(signed), `"project_id":7`, `"project_id":8`, 1)
	if err := verifyEnvelopeSignature([]byte(forged)); err == nil {
		t.Fatal("tampered envelope accepted")
	} else if !strings.Contains(err.Error(), "BAD_SIGNATURE") {
		t.Fatalf("wrong reason: %v", err)
	}
}

func TestMissingSignatureIsRejectedWhenKeyIsSet(t *testing.T) {
	withBrokerKey(t, brokerAuthTestKey)
	if err := verifyEnvelopeSignature([]byte(brokerAuthTestEnvelope)); err == nil {
		t.Fatal("unsigned envelope accepted with a key configured")
	}
}

func TestWrongKeyIsRejected(t *testing.T) {
	withBrokerKey(t, brokerAuthTestKey)
	signed, err := signEnvelopeBytes([]byte(brokerAuthTestEnvelope))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	withBrokerKey(t, strings.Repeat("ff", 32))
	if err := verifyEnvelopeSignature(signed); err == nil {
		t.Fatal("signature from another key accepted")
	}
}

func TestCompatModeAcceptsUnsignedWithoutAKey(t *testing.T) {
	t.Setenv(brokerKeyEnv, "")
	if brokerSigningEnabled() {
		t.Fatal("signing should be off without a key")
	}
	if err := verifyEnvelopeSignature([]byte(brokerAuthTestEnvelope)); err != nil {
		t.Fatalf("compat mode rejected an unsigned envelope: %v", err)
	}
}

func TestMalformedKeyIsCompatMode(t *testing.T) {
	withBrokerKey(t, "not-hex")
	if brokerSigningEnabled() {
		t.Fatal("a malformed key must not enable signing")
	}
}

func TestForgedTaskIsDeadLetteredWithoutExecution(t *testing.T) {
	withBrokerKey(t, brokerAuthTestKey)
	// Valid shape, no signature: exactly what a local forger would push.
	body, err := json.Marshal(map[string]any{
		"schema_version": 1,
		"task_id":        "6f0e8400-e29b-41d4-a716-446655440000",
		"task_type":      "request.execute",
		"created_at":     "2026-09-27T09:00:00Z",
		"payload":        map[string]any{"url": "http://evil.example/"},
	})
	if err != nil {
		t.Fatal(err)
	}
	delivery := &fakeTaskDelivery{body: body}
	publisher := &fakeResultPublisher{}
	dispatcher := &fakeTaskDispatcher{result: json.RawMessage(`{"status":200}`)}

	processTaskDelivery(context.Background(), delivery, dispatcher, publisher)

	if !delivery.rejected || delivery.requeue {
		t.Fatalf("forged task: rejected=%v requeue=%v, want dead-letter", delivery.rejected, delivery.requeue)
	}
	if dispatcher.called {
		t.Fatal("forged task was executed")
	}
	if publisher.calls != 0 {
		t.Fatal("a result was published for a forged task")
	}
}

func TestSignedTaskExecutesNormally(t *testing.T) {
	withBrokerKey(t, brokerAuthTestKey)
	body, err := json.Marshal(map[string]any{
		"schema_version": 1,
		"task_id":        "6f0e8400-e29b-41d4-a716-446655440000",
		"task_type":      "request.execute",
		"created_at":     "2026-09-27T09:00:00Z",
		"payload":        map[string]any{"url": "http://127.0.0.1:8000/fixture"},
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signEnvelopeBytes(body)
	if err != nil {
		t.Fatal(err)
	}
	delivery := &fakeTaskDelivery{body: signed}
	publisher := &fakeResultPublisher{}
	dispatcher := &fakeTaskDispatcher{result: json.RawMessage(`{"status":200}`)}

	processTaskDelivery(context.Background(), delivery, dispatcher, publisher)

	if !dispatcher.called {
		t.Fatal("signed task was not executed")
	}
	if !delivery.acked {
		t.Fatal("signed task was not acked")
	}
}

func TestPublishedResultsCarryAValidSignature(t *testing.T) {
	withBrokerKey(t, brokerAuthTestKey)
	delivery := &fakeTaskDelivery{body: mustSignedTask(t)}
	publisher := &fakeResultPublisher{}
	dispatcher := &fakeTaskDispatcher{result: json.RawMessage(`{"status":200}`)}

	processTaskDelivery(context.Background(), delivery, dispatcher, publisher)

	if publisher.calls == 0 {
		t.Fatal("no result published")
	}
	for _, published := range publisher.bodies {
		if err := verifyEnvelopeSignature(published); err != nil {
			t.Fatalf("published result has no valid signature: %v\n%s", err, published)
		}
	}
}

func mustSignedTask(t *testing.T) []byte {
	t.Helper()
	withBrokerKey(t, brokerAuthTestKey)
	body, err := json.Marshal(map[string]any{
		"schema_version": 1,
		"task_id":        "6f0e8400-e29b-41d4-a716-446655440000",
		"task_type":      "request.execute",
		"created_at":     "2026-09-27T09:00:00Z",
		"payload":        map[string]any{"url": "http://127.0.0.1:8000/fixture"},
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signEnvelopeBytes(body)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

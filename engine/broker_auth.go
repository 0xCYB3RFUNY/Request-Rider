package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"intruder/engine/pkg/taskcontract"
)

// HMAC authentication for the Redis task/result envelopes, mirroring
// web/lab/broker_auth.py.
//
// Every envelope crossing the broker carries `sig`: an HMAC-SHA256 over the
// canonical JSON of the envelope, keyed by the per-installation key both sides
// share through RR_ENGINE_BROKER_KEY. A forged envelope has the right shape by
// construction, so shape validation cannot catch it — only the signature can.
//
// Canonical form, byte-identical on both sides: the envelope without `sig`,
// keys sorted, compact separators, UTF-8, no HTML escaping. Numbers are kept as
// their original literals (json.Number), because decoding them to float64 would
// reformat large integers and break every signature over them.

const brokerKeyEnv = "RR_ENGINE_BROKER_KEY"
const brokerSigField = "sig"

var brokerCompatWarnOnce sync.Once

// brokerKey returns the shared key, or nil when this install has none.
// A malformed value is treated as missing, loudly: refusing to boot on a bad
// key would brick a running stack over a typo.
func brokerKey() []byte {
	raw := strings.TrimSpace(os.Getenv(brokerKeyEnv))
	if raw == "" {
		return nil
	}
	key, err := hex.DecodeString(raw)
	if err != nil || len(key) < 16 {
		brokerCompatWarnOnce.Do(func() {
			log.Printf("broker_auth_compat reason=%s_no_usable_key envelopes_are_unsigned_and_unverified", brokerKeyEnv)
		})
		return nil
	}
	return key
}

func brokerSigningEnabled() bool { return brokerKey() != nil }

// canonicalEnvelopeBytes renders raw envelope JSON in the canonical form.
func canonicalEnvelopeBytes(raw []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	envelope, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("envelope is not an object")
	}
	delete(envelope, brokerSigField)
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(envelope); err != nil {
		return nil, err
	}
	// json.Encoder appends a newline; the canonical form has none.
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}

func envelopeSignature(canonical []byte, key []byte) string {
	sum := hmac.New(sha256.New, key)
	sum.Write(canonical)
	return hex.EncodeToString(sum.Sum(nil))
}

// signEnvelopeBytes returns a copy of the raw envelope carrying a fresh `sig`.
// Without a configured key it returns the input unchanged (compatibility mode).
func signEnvelopeBytes(raw []byte) ([]byte, error) {
	key := brokerKey()
	if key == nil {
		return raw, nil
	}
	canonical, err := canonicalEnvelopeBytes(raw)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var envelope map[string]any
	if err := decoder.Decode(&envelope); err != nil {
		return nil, err
	}
	envelope[brokerSigField] = envelopeSignature(canonical, key)
	return marshalCanonical(envelope)
}

// marshalCanonical renders a decoded envelope with sorted keys and no HTML
// escaping. encoding/json sorts map keys, so this is the canonical form.
func marshalCanonical(envelope map[string]any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(envelope); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}

// verifyEnvelopeSignature rejects raw envelope bytes without a valid `sig`.
// In compatibility mode (no key) it accepts anything, once with a warning.
func verifyEnvelopeSignature(raw []byte) error {
	key := brokerKey()
	if key == nil {
		brokerCompatWarnOnce.Do(func() {
			log.Printf("broker_auth_compat reason=%s_not_configured unsigned_envelopes_are_accepted", brokerKeyEnv)
		})
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var envelope map[string]any
	if err := decoder.Decode(&envelope); err != nil {
		return fmt.Errorf("envelope is not valid JSON (BAD_SIGNATURE)")
	}
	presented, _ := envelope[brokerSigField].(string)
	if presented == "" {
		return fmt.Errorf("envelope is not signed (BAD_SIGNATURE)")
	}
	canonical, err := canonicalEnvelopeBytes(raw)
	if err != nil {
		return fmt.Errorf("envelope is not valid JSON (BAD_SIGNATURE)")
	}
	expected := envelopeSignature(canonical, key)
	if !hmac.Equal([]byte(presented), []byte(expected)) {
		return fmt.Errorf("envelope signature is invalid (BAD_SIGNATURE)")
	}
	return nil
}

// signTaskResult attaches a fresh signature to a result the engine publishes.
// It is deterministic: the same result always yields the same bytes, which is
// what keeps a replayed outcome byte-identical to the original answer.
func signTaskResult(result *taskcontract.Result) error {
	key := brokerKey()
	if key == nil {
		return nil
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	canonical, err := canonicalEnvelopeBytes(raw)
	if err != nil {
		return err
	}
	result.Sig = envelopeSignature(canonical, key)
	return nil
}

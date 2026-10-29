package main

// Tests for Pwned Passwords, the source this transform has and gosearch does not.
//
// gosearch at `687f9ed` resolves a hash into a plaintext (`weakpass.go:18`) and
// stops there. It never asks how many breaches that password appears in, which is
// the number an operator acts on: a leaked password seen once and a leaked
// password in nine thousand breaches are not the same finding, and without the
// count the run cannot tell them apart.
//
// The one rule that is not negotiable is k-anonymity. The range API takes the first
// five characters of a SHA-1 and returns every suffix sharing that prefix; the
// match is made locally. Posting the password, or its full hash, would turn this
// transform into an oracle for every password an operator ran it on — so the tests
// below assert on what actually went over the wire, not only on the result.

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// pwnedFixture serves the range API and records what was asked.
type pwnedFixture struct {
	// corpus maps a five-character prefix to the suffixes that share it.
	corpus map[string]string
	mu     sync.Mutex
	asked  []string
	status int
}

// The range API answers **404 when the prefix is absent from the corpus**, which is
// the live service's way of saying "no password with this prefix has ever been
// breached". Measured against api.pwnedpasswords.com on 2026-10-07: a prefix with
// matches returns 200 and a body; one without returns 404 and nothing. Treating that
// 404 as a failure would have left every clean password without a count — which is
// exactly the half an operator wants told apart from "nobody asked".

func (fixture *pwnedFixture) handler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/range/"), ".txt")
		fixture.mu.Lock()
		fixture.asked = append(fixture.asked, r.URL.Path)
		status := fixture.status
		body, known := fixture.corpus[prefix]
		fixture.mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		if !known {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		fmt.Fprint(w, body)
	})
}

func (fixture *pwnedFixture) serve(t *testing.T) {
	t.Helper()
	served := httptest.NewServer(fixture.handler(t))
	previous := breachExposurePwnedEndpoint
	breachExposurePwnedEndpoint = served.URL + "/range/"
	t.Cleanup(func() { breachExposurePwnedEndpoint = previous; served.Close() })
}

func (fixture *pwnedFixture) askedFor() []string {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	out := make([]string, len(fixture.asked))
	copy(out, fixture.asked)
	return out
}

// pwnedCorpus builds the range body a real corpus would return for a password:
// the wanted suffix plus a few neighbours, so a test that matched on the first
// line would pass by accident.
func pwnedCorpus(wanted string, count int) (prefix, body string) {
	sum := sha1.Sum([]byte(wanted))
	hexed := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix = hexed[:5]
	suffix := hexed[5:]
	body = "00000AAAAA:" + strconv.Itoa(count+3) + "\r\n" +
		suffix + ":" + strconv.Itoa(count) + "\r\n" +
		"FFFFFFFFFF:" + "17\r\n"
	return prefix, body
}

func pwnedFetch(t *testing.T, fixture *pwnedFixture, findings []breachExposureResult) (map[string]int, []string) {
	t.Helper()
	fixture.serve(t)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	return breachExposureCountKnownPasswords(context.Background(), client, findings,
		5_000_000_000, 0)
}

// TestPwnedPasswordsReportsHowOftenAPasswordWasBreached is the whole point: the
// count, which the original never produced.
func TestPwnedPasswordsReportsHowOftenAPasswordWasBreached(t *testing.T) {
	prefix, body := pwnedCorpus("Summer2018", 9037)
	fixture := &pwnedFixture{corpus: map[string]string{prefix: body}}

	counts, warnings := pwnedFetch(t, fixture, []breachExposureResult{
		{Source: "proxynova", Email: "leaked.user@yandex.ru", Pass: "Summer2018"},
	})
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if counts["Summer2018"] != 9037 {
		t.Errorf("password_breach_count = %d, want 9037 — the match must be on the exact suffix, not the first line",
			counts["Summer2018"])
	}
}

// TestPwnedPasswordsNeverSendsThePassword: the k-anonymity guarantee. What went over
// the wire is five hex characters; if a full hash or the password itself appeared
// there, every operator who ran this transform would have handed the service a
// lookup oracle for whatever they typed.
func TestPwnedPasswordsNeverSendsThePassword(t *testing.T) {
	prefix, body := pwnedCorpus("Winter2019", 12043)
	fixture := &pwnedFixture{corpus: map[string]string{prefix: body}}

	const password = "Winter2019"
	pwnedFetch(t, fixture, []breachExposureResult{
		{Source: "proxynova", Email: "a@yandex.ru", Pass: password},
	})

	sum := sha1.Sum([]byte(password))
	fullHash := strings.ToUpper(hex.EncodeToString(sum[:]))

	asked := fixture.askedFor()
	if len(asked) == 0 {
		t.Fatal("nothing was asked of the service")
	}
	for _, path := range asked {
		if strings.Contains(strings.ToUpper(path), fullHash) {
			t.Fatalf("a full SHA-1 went over the wire: %s", path)
		}
		if strings.Contains(path, password) {
			t.Fatalf("the password went over the wire: %s", path)
		}
		if !strings.HasSuffix(strings.ToUpper(path), prefix) {
			t.Errorf("the request %q does not end with the five-character prefix", path)
		}
		if count := len(strings.TrimSuffix(strings.TrimPrefix(path, "/range/"), ".txt")); count != 5 {
			t.Errorf("the request carried %d characters of the hash, want 5", count)
		}
	}
}

// TestPwnedPasswordsAsksOncePerDistinctPassword: the same password in forty
// breaches is one question with one answer, and the service is a free third party.
func TestPwnedPasswordsAsksOncePerDistinctPassword(t *testing.T) {
	prefix, body := pwnedCorpus("Summer2018", 9037)
	fixture := &pwnedFixture{corpus: map[string]string{prefix: body}}

	findings := []breachExposureResult{
		{Source: "proxynova", Email: "a@yandex.ru", Pass: "Summer2018"},
		{Source: "breachdirectory", Email: "a@yandex.ru", Pass: "Summer2018"},
		{Source: "breachdirectory", Email: "b@yandex.ru", Pass: "Summer2018"},
	}
	counts, _ := pwnedFetch(t, fixture, findings)
	if len(counts) != 1 {
		t.Errorf("got %d counted passwords, want 1", len(counts))
	}
	if len(fixture.askedFor()) != 1 {
		t.Errorf("the service was asked %d times for one distinct password", len(fixture.askedFor()))
	}
}

// TestPwnedPasswordsZeroIsNotAnError: a password outside the range is a **zero** and
// must be written as zero, while a service that failed leaves the count absent.
// Collapsing the two would put "never breached" next to a credential nobody asked
// about, which is the reassurance nobody may get from an error.
func TestPwnedPasswordsZeroIsNotAnError(t *testing.T) {
	fixture := &pwnedFixture{corpus: map[string]string{}}

	counts, warnings := pwnedFetch(t, fixture, []breachExposureResult{
		{Source: "proxynova", Email: "a@yandex.ru", Pass: "never-seen-anywhere"},
	})
	if len(warnings) != 0 {
		t.Errorf("a password outside the corpus is not a warning: %v", warnings)
	}
	if value, ok := counts["never-seen-anywhere"]; !ok {
		t.Error("a password outside the corpus carries no count at all; absence and zero must differ")
	} else if value != 0 {
		t.Errorf("password_breach_count = %d, want 0 for a password not in the corpus", value)
	}
}

// TestPwnedPasswordsFailureLeavesTheCountAbsent is the other half: a 500 must not
// become a zero.
func TestPwnedPasswordsFailureLeavesTheCountAbsent(t *testing.T) {
	fixture := &pwnedFixture{corpus: map[string]string{}, status: http.StatusInternalServerError}

	counts, warnings := pwnedFetch(t, fixture, []breachExposureResult{
		{Source: "proxynova", Email: "a@yandex.ru", Pass: "Summer2018"},
	})
	if _, ok := counts["Summer2018"]; ok {
		t.Errorf("a failed lookup wrote the count %d; an unanswered service must leave the field absent",
			counts["Summer2018"])
	}
	if len(warnings) == 0 {
		t.Error("the failing service is not named in the warnings")
	}
}

// TestPwnedPasswordsDoesNotAsksForAnEmptyPassword: a finding with no password has
// nothing to count, and asking about the empty string would send the hash of nothing
// to a third party and put a number on every credential-less finding.
func TestPwnedPasswordsDoesNotAsksForAnEmptyPassword(t *testing.T) {
	fixture := &pwnedFixture{corpus: map[string]string{}}

	counts, warnings := pwnedFetch(t, fixture, []breachExposureResult{
		{Source: "proxynova", Email: "a@yandex.ru", Pass: ""},
		{Source: "breachdirectory", Email: "b@yandex.ru", SHA1: "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"},
	})
	if len(counts) != 0 {
		t.Errorf("got %d counts, want none: a finding with no password has nothing to ask about", len(counts))
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if len(fixture.askedFor()) != 0 {
		t.Errorf("the service was asked %d times about nothing", len(fixture.askedFor()))
	}
}

// TestPwnedPasswordsCountReachesTheEntity pins the whole path: the number the
// service returned has to arrive on the node and on the credential row, because a
// lookup that answers and then drops its answer is a lookup that cost a request and
// told nobody anything.
func TestPwnedPasswordsCountReachesTheEntity(t *testing.T) {
	prefix, body := pwnedCorpus("Summer2018", 9037)
	pwned := &pwnedFixture{corpus: map[string]string{prefix: body}}
	pwned.serve(t)

	// The other three sources are served by the shared breach fixture, so the run
	// exercises the whole chain and the count has somewhere to arrive.
	upstream := &breachFixture{
		proxynovaBody:  `{"count":1,"lines":["leaked.user@yandex.ru:Summer2018"]}`,
		directoryBody:  `{"found":0,"result":[]}`,
		weakpassByHash: map[string]string{},
	}
	upstream.serve(t)
	t.Setenv(breachExposureAPIKeyEnv, "fixture-key")

	server := &server{}
	result, err := server.runOSINTTransformWithCollector(context.Background(), osintTransformInput{
		Transform:      "breach_exposure",
		Value:          "leaked.user@yandex.ru",
		ConfirmNetwork: true,
	}, nil)
	if err != nil {
		t.Fatalf("breach_exposure returned %v", err)
	}

	var found bool
	for _, item := range breachCredentialEntities(&result) {
		if item.Properties["password_breach_count"] != 9037 {
			t.Errorf("the node carries %v as password_breach_count, want 9037",
				item.Properties["password_breach_count"])
		}
		rows, _ := item.Properties["credentials"].([]map[string]interface{})
		for _, row := range rows {
			if row["password_breach_count"] == 9037 {
				found = true
			}
		}
		found = true
	}
	if !found {
		t.Error("no credential node carries the count the service returned")
	}
	if result.Metadata["credential_values_returned"] != true {
		t.Error("the run does not state that it returns credential values, which this source adds to")
	}
}

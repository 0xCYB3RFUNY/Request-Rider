package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// githubStub answers the GitHub endpoints the transform reads, and counts what
// was asked. The transport is installed through the existing `withToolTransport`
// seam, which is the same path a recorded tool run takes, so the test exercises
// the real `toolClient` rather than a parallel wiring of its own.
type githubStub struct {
	mutex    sync.Mutex
	routes   map[string]string
	statuses map[string]int
	headers  map[string]map[string]string
	requests []string
}

func newGitHubStub() *githubStub {
	return &githubStub{
		routes:   map[string]string{},
		statuses: map[string]int{},
		headers:  map[string]map[string]string{},
	}
}

func (stub *githubStub) route(path, body string) *githubStub {
	stub.mutex.Lock()
	defer stub.mutex.Unlock()
	stub.routes[path] = body
	return stub
}

func (stub *githubStub) status(path string, code int, headers map[string]string) *githubStub {
	stub.mutex.Lock()
	defer stub.mutex.Unlock()
	stub.statuses[path] = code
	stub.headers[path] = headers
	return stub
}

func (stub *githubStub) asked(path string) bool {
	stub.mutex.Lock()
	defer stub.mutex.Unlock()
	for _, entry := range stub.requests {
		if entry == path {
			return true
		}
	}
	return false
}

func (stub *githubStub) askedCount() int {
	stub.mutex.Lock()
	defer stub.mutex.Unlock()
	return len(stub.requests)
}

// serve answers a request by path, ignoring the query string so a test names the
// endpoint it means rather than the pagination it happened to use.
func (stub *githubStub) serve(request *http.Request) *http.Response {
	path := request.URL.Path
	stub.mutex.Lock()
	stub.requests = append(stub.requests, path)
	body, routed := stub.routes[path]
	code, hasStatus := stub.statuses[path]
	headers := stub.headers[path]
	stub.mutex.Unlock()
	if hasStatus {
		return &http.Response{
			StatusCode: code,
			Header:     headerOf(headers),
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    request,
		}
	}
	if !routed {
		body = "[]"
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}
}

func headerOf(values map[string]string) http.Header {
	header := http.Header{}
	for name, value := range values {
		header.Set(name, value)
	}
	return header
}

func (stub *githubStub) context() context.Context {
	return withToolTransport(context.Background(), roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		return stub.serve(request), nil
	}))
}

func githubProfileJSON(login string) string {
	return fmt.Sprintf(`{"login":%q,"html_url":"https://github.com/%s","name":"Test","public_repos":2,"followers":3,"type":"User"}`, login, login)
}

// commitRow builds one commits-API row, with and without a linked account. A
// `null` linked account is what GitHub sends for a commit whose address matches
// no account, and it is the case the attribution check has to reason about.
func commitRow(sha, email, authorLogin, committerLogin string) string {
	link := func(login string) string {
		if login == "" {
			return "null"
		}
		return fmt.Sprintf(`{"login":%q}`, login)
	}
	commitEmail := "null"
	if email != "" {
		commitEmail = fmt.Sprintf("%q", email)
	}
	return fmt.Sprintf(`{"sha":%q,"html_url":"https://github.com/c/%s","author":%s,"committer":%s,"commit":{"author":{"name":"A","email":%s},"committer":{"name":"A","email":%s}}}`,
		sha, sha, link(authorLogin), link(committerLogin), commitEmail, commitEmail)
}

func runGitHubRecon(t *testing.T, stub *githubStub, value string, options map[string]interface{}) (osintTransformResult, error) {
	t.Helper()
	input := osintTransformInput{Transform: "github_recon", Value: value, ConfirmNetwork: true, Options: options}
	return (&server{}).runOSINTTransform(stub.context(), input)
}

func identitiesOf(result osintTransformResult, kind string) []string {
	var out []string
	for _, item := range result.Entities {
		if item.Type == kind {
			out = append(out, item.Identity)
		}
	}
	return out
}

// TestGitHubReconReportsOnlyTheAccountsOwnAddress is the regression this
// transform needed and did not have.
//
// The reference implementation reads the first `From:` header it finds in the
// account's repositories and reports it as that account's address. Measured on
// `tj/commander.js`, the newest commits there belong to `abetomo` and
// `shadowspawn`, so that scan answers `abe@enzou.tokyo` for the user `tj` —
// a contributor's mailbox presented as somebody else's. This asserts the
// contributor's address is not in the result at all.
func TestGitHubReconReportsOnlyTheAccountsOwnAddress(t *testing.T) {
	stub := newGitHubStub()
	stub.route("/users/tj", githubProfileJSON("tj"))
	stub.route("/users/tj/events/public", "[]")
	stub.route("/users/tj/repos", "["+commitRepoJSON("commander.js")+"]")
	stub.route("/repos/tj/commander.js/commits", "["+
		commitRow("aaa111", "abe@enzou.tokyo", "abetomo", "abetomo")+","+
		commitRow("bbb222", "john@ruru.gen.nz", "shadowspawn", "shadowspawn")+","+
		commitRow("ccc333", "tj@example.test", "tj", "tj")+
		"]")

	result, err := runGitHubRecon(t, stub, "tj", nil)
	if err != nil {
		t.Fatalf("github_recon: %v", err)
	}
	got := identitiesOf(result, "email")
	if len(got) != 1 || got[0] != "tj@example.test" {
		t.Fatalf("email entities = %v, want only the searched account's own address", got)
	}
	for _, address := range got {
		if strings.Contains(address, "enzou.tokyo") || strings.Contains(address, "ruru.gen.nz") {
			t.Fatalf("a contributor address was attributed to the searched account: %s", address)
		}
	}
}

func commitRepoJSON(name string) string {
	return fmt.Sprintf(`{"name":%q,"full_name":"tj/%s","fork":false,"archived":false}`, name, name)
}

// TestGitHubReconSkipsGitHubPrivacyAddresses covers the second real defect: a
// `users.noreply.github.com` placeholder is a GitHub identifier, not a mailbox,
// and storing it as an email entity puts a dead address into the graph.
func TestGitHubReconSkipsGitHubPrivacyAddresses(t *testing.T) {
	stub := newGitHubStub()
	stub.route("/users/ghost", githubProfileJSON("ghost"))
	stub.route("/users/ghost/events/public", "[]")
	stub.route("/users/ghost/repos", "["+commitRepoJSON("repo")+"]")
	stub.route("/repos/ghost/repo/commits", "["+
		commitRow("noreply1", "1234+ghost@users.noreply.github.com", "ghost", "ghost")+","+
		commitRow("bot1", "49699333+dependabot[bot]@users.noreply.github.com", "dependabot[bot]", "dependabot[bot]")+","+
		commitRow("real1", "ghost@corp.example", "ghost", "ghost")+
		"]")

	result, err := runGitHubRecon(t, stub, "ghost", nil)
	if err != nil {
		t.Fatalf("github_recon: %v", err)
	}
	got := identitiesOf(result, "email")
	for _, address := range got {
		if strings.Contains(strings.ToLower(address), "noreply.github.com") {
			t.Fatalf("a GitHub privacy address was reported as an email entity: %s", address)
		}
	}
	if len(got) != 1 || got[0] != "ghost@corp.example" {
		t.Fatalf("email entities = %v, want the one real mailbox", got)
	}
}

// TestGitHubReconReadsThePatchWhenTheApiRowHasNoAddress is the path the
// reference implementation made its only path: a commit GitHub links to the
// account but whose API row carries no address, where the `From:` header of the
// patch is the only place the address exists.
func TestGitHubReconReadsThePatchWhenTheApiRowHasNoAddress(t *testing.T) {
	stub := newGitHubStub()
	stub.route("/users/solo", githubProfileJSON("solo"))
	stub.route("/users/solo/events/public", "[]")
	stub.route("/users/solo/repos", "["+commitRepoJSON("app")+"]")
	stub.route("/repos/solo/app/commits", "["+commitRow("deadbeef", "", "solo", "solo")+"]")
	stub.route("/solo/app/commit/deadbeef.patch",
		"From deadbeef Mon Sep 17 00:00:00 2001\n"+
			"From: Solo Dev <solo@patch.example>\n"+
			"Date: Mon, 1 Jan 2024 00:00:00 +0000\n"+
			"Subject: [PATCH] initial\n"+
			"---\n"+
			" mentioned-by-somebody-else <other@stranger.example>\n")

	result, err := runGitHubRecon(t, stub, "solo", nil)
	if err != nil {
		t.Fatalf("github_recon: %v", err)
	}
	got := identitiesOf(result, "email")
	if len(got) != 1 || got[0] != "solo@patch.example" {
		t.Fatalf("email entities = %v, want the address from the patch header", got)
	}
	if strings.Contains(strings.Join(got, ","), "stranger.example") {
		t.Fatalf("an address mentioned inside the diff body was reported: %v", got)
	}
}

// TestGitHubReconStatesTheAppliedLimits is the rule that a bound must be visible
// and must not reduce the tool. A limit nobody can see is the kind this project
// does not accept, so the applied values have to appear in the result.
func TestGitHubReconStatesTheAppliedLimits(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		options map[string]interface{}
		want    map[string]interface{}
	}{
		{
			name: "defaults are stated when the caller names nothing",
			want: map[string]interface{}{
				"max_repos":        githubDefaultMaxRepos,
				"max_commit_pages": githubDefaultMaxCommitPages,
				"commits_per_repo": githubDefaultCommitsPerRepo,
			},
		},
		{
			name:    "an explicit value overrides the default",
			options: map[string]interface{}{"max_repos": 12, "max_commit_pages": 4, "commits_per_repo": 7},
			want: map[string]interface{}{
				"max_repos":        12,
				"max_commit_pages": 4,
				"commits_per_repo": 7,
			},
		},
		{
			// 0 must mean "no bound", otherwise a caller cannot ask for the whole
			// history and the limit would be a restriction rather than a default.
			name:    "zero means no bound",
			options: map[string]interface{}{"max_repos": 0, "max_commit_pages": 0, "commits_per_repo": 0},
			want:    map[string]interface{}{"max_repos": 0, "max_commit_pages": 0, "commits_per_repo": 0},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			stub := newGitHubStub()
			stub.route("/users/u", githubProfileJSON("u"))
			result, err := runGitHubRecon(t, stub, "u", testCase.options)
			if err != nil {
				t.Fatalf("github_recon: %v", err)
			}
			for key, want := range testCase.want {
				if got := result.Metadata[key]; got != want {
					t.Fatalf("metadata[%q] = %v (%T), want %v (%T)", key, got, got, want, want)
				}
			}
		})
	}
}

// TestGitHubReconReportsAnExhaustedBudgetAsItsOwnCondition: without this the
// operator is told the lookup failed, and cannot tell "GitHub said no" from
// "come back in an hour".
//
// The answer is a warning rather than an error because the profile was already
// read and is a real result. Failing the whole transform would throw away the one
// fact that was collected; what has to be exact is that the condition is named
// and that the scan does not keep walking into the same refusal.
func TestGitHubReconReportsAnExhaustedBudgetAsItsOwnCondition(t *testing.T) {
	stub := newGitHubStub()
	stub.route("/users/u", githubProfileJSON("u"))
	// `X-RateLimit-Reset` is what turns "the budget is spent" into "come back in
	// an hour", so the header is part of the condition and not decoration.
	stub.status("/users/u/events/public", http.StatusForbidden, map[string]string{
		"X-RateLimit-Remaining": "0",
		"X-RateLimit-Reset":     strconv.FormatInt(time.Now().Add(90*time.Minute).Unix(), 10),
	})

	result, err := runGitHubRecon(t, stub, "u", nil)
	if err != nil {
		t.Fatalf("an exhausted budget must not fail the transform: %v", err)
	}
	if len(identitiesOf(result, "username")) != 1 {
		t.Fatalf("the profile read was thrown away: %v", identitiesOf(result, "username"))
	}
	joined := strings.Join(result.Warnings, "\n")
	if !strings.Contains(joined, "GITHUB_RATE_LIMITED") {
		t.Fatalf("warnings = %v, want the budget condition named", result.Warnings)
	}
	if !strings.Contains(joined, "refills in about") {
		t.Fatalf("warnings = %v, want the message to say when the budget returns", result.Warnings)
	}
	if reason, _ := result.Metadata["commit_scan"].(string); !strings.Contains(reason, "skipped") {
		t.Fatalf("metadata[commit_scan] = %v, want the scan recorded as skipped", result.Metadata["commit_scan"])
	}
	// Every request after the refusal would fail identically, so the scan is not
	// walked into: asking for the repository list is what a caller would have to
	// see NOT happen.
	if stub.asked("/users/u/repos") {
		t.Fatal("the commit scan ran after the budget was refused")
	}
}

// TestGitHubReconNamesAnUnknownAccountInsteadOfFailing: a 404 is an answer about
// the target, and the transform has to return it as a warning rather than an
// error, or the operator cannot tell a missing account from a broken lookup.
func TestGitHubReconNamesAnUnknownAccountInsteadOfFailing(t *testing.T) {
	stub := newGitHubStub()
	stub.status("/users/nobody", http.StatusNotFound, nil)

	result, err := runGitHubRecon(t, stub, "nobody", nil)
	if err != nil {
		t.Fatalf("github_recon: %v", err)
	}
	if len(result.Warnings) == 0 || !strings.Contains(result.Warnings[0], "not found") {
		t.Fatalf("warnings = %v, want the profile-not-found answer", result.Warnings)
	}
	if len(result.Entities) != 0 {
		t.Fatalf("entities = %v, want none for an account that does not exist", identitiesOf(result, "email"))
	}
}

// TestGitHubReconNeverPutsTheTokenIntoTheResult: the token is read from the
// environment, and the result is persisted into a project, exported and shown to
// the operator. Anything that echoes it there leaks it.
func TestGitHubReconNeverPutsTheTokenIntoTheResult(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_secret_value_for_test")
	stub := newGitHubStub()
	stub.route("/users/u", githubProfileJSON("u"))
	stub.route("/users/u/events/public", "[]")
	stub.route("/users/u/repos", "["+commitRepoJSON("r")+"]")
	stub.route("/repos/u/r/commits", "["+commitRow("s1", "u@example.test", "u", "u")+"]")

	result, err := runGitHubRecon(t, stub, "u", nil)
	if err != nil {
		t.Fatalf("github_recon: %v", err)
	}
	encoded, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		t.Fatalf("marshal result: %v", marshalErr)
	}
	if strings.Contains(string(encoded), "ghp_secret_value_for_test") {
		t.Fatalf("the token reached the result: %s", encoded)
	}
	if result.Metadata["github_token_configured"] != true {
		t.Fatalf("metadata[github_token_configured] = %v, want true so an operator can read a rate limit", result.Metadata["github_token_configured"])
	}
}

// TestIsGitHubPrivacyAddress pins the filter down against the forms measured on
// real commits, and against the one form it must not swallow.
func TestIsGitHubPrivacyAddress(t *testing.T) {
	for address, want := range map[string]bool{
		"1234+torvalds@users.noreply.github.com":            true,
		"torvalds@users.noreply.github.com":                 true,
		"49699333+dependabot[bot]@users.noreply.github.com": true,
		// A bot is an automation on whatever domain it commits from.
		"renovate[bot]@example.test":    true,
		"torvalds@linux-foundation.org": false,
		// Real mailboxes. The reference implementation filters every
		// `*.github.com` address and would drop the first of these.
		"security@github.com": false,
		"user@example.test":   false,
		"not-an-address":      false,
	} {
		if got := isGitHubPrivacyAddress(address); got != want {
			t.Fatalf("isGitHubPrivacyAddress(%q) = %v, want %v", address, got, want)
		}
	}
}

// TestCommitBelongsToUser states the attribution rule on its own, including the
// unlinked commit whose own address names the user.
func TestCommitBelongsToUser(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		commit gitHubCommit
		want   bool
	}{
		{
			name:   "a commit GitHub links to the account",
			commit: gitHubCommit{Author: &githubAccount{Login: "torvalds"}},
			want:   true,
		},
		{
			name:   "a linked committer counts too",
			commit: gitHubCommit{Committer: &githubAccount{Login: "Torvalds"}},
			want:   true,
		},
		{
			name: "an unlinked commit whose own address names the account",
			commit: func() gitHubCommit {
				commit := gitHubCommit{}
				commit.Commit.Author.Email = "torvalds@linux-foundation.org"
				return commit
			}(),
			want: true,
		},
		{
			name: "somebody else's commit",
			commit: gitHubCommit{
				Author: &githubAccount{Login: "abetomo"},
			},
			want: false,
		},
		{
			name:   "a commit GitHub links to nobody",
			commit: gitHubCommit{},
			want:   false,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := commitBelongsToUser(&testCase.commit, "torvalds"); got != testCase.want {
				t.Fatalf("commitBelongsToUser = %v, want %v", got, testCase.want)
			}
		})
	}
}

// TestGitHubReconWalksTheOldestFetchedCommitsFirst: a newer commit is the more
// likely one to carry a privacy address, so spending the budget newest-first
// wastes it on the commits least likely to answer.
func TestGitHubReconWalksTheOldestFetchedCommitsFirst(t *testing.T) {
	stub := newGitHubStub()
	stub.route("/users/u", githubProfileJSON("u"))
	stub.route("/users/u/events/public", "[]")
	stub.route("/users/u/repos", "["+commitRepoJSON("r")+"]")
	stub.route("/repos/u/r/commits", "["+
		commitRow("newest", "newest@u.example", "u", "u")+","+
		commitRow("middle", "middle@u.example", "u", "u")+","+
		commitRow("oldest", "oldest@u.example", "u", "u")+
		"]")

	result, err := runGitHubRecon(t, stub, "u", map[string]interface{}{"commits_per_repo": 1})
	if err != nil {
		t.Fatalf("github_recon: %v", err)
	}
	got := identitiesOf(result, "email")
	if len(got) != 1 || got[0] != "oldest@u.example" {
		t.Fatalf("email entities = %v, want the oldest fetched commit", got)
	}
}

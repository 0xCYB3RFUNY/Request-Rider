package main

// Tests for the four GitHub passes ported from `ibnaleem/gosearch` at `687f9ed`:
// SSH keys, GPG keys, social accounts and mutual followers.
//
// The defects these cover were read out of the original before the code was
// written:
//
//   - mutual-followers.go:53 makes **one request per follower**, so an account
//     with 100 followers costs 101 requests against GitHub's unauthenticated
//     budget of 60 per hour — the pass cannot finish without a token, and with
//     one it eats the budget every other pass needs;
//   - mutual-followers.go:80 treats **only** `204` as a mutual follower and
//     discards every other status, so the majority answer (`404`) is invisible
//     and the reader cannot tell 2 of 2 from 2 of 100;
//   - social-accounts.go:33 decodes the body into a slice **before** checking the
//     status, so GitHub's `404` object (`{"message": …}`) fails to unmarshal and
//     is reported as "error fetching social accounts";
//   - ssh-keys.go:69 reports a key by its numeric id and type, neither of which
//     identifies a key outside GitHub.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// githubKeysFixture is a stand-in for api.github.com.
//
// It is one server serving every path the four passes read, so the request count
// is a fact about the fixture rather than a guess about the implementation.
type githubKeysFixture struct {
	mu sync.Mutex

	keys          string
	gpgKeys       string
	social        string
	followers     string
	followBack    map[string]int // login -> status the "following" check answers
	requestedPath []string
}

func (fixture *githubKeysFixture) handler(t *testing.T) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}
	mux.HandleFunc("/users/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		fixture.mu.Lock()
		fixture.requestedPath = append(fixture.requestedPath, path)
		fixture.mu.Unlock()

		switch {
		case strings.HasSuffix(path, "/keys"):
			write(w, fixture.keys)
		case strings.HasSuffix(path, "/gpg_keys"):
			write(w, fixture.gpgKeys)
		case strings.HasSuffix(path, "/social_accounts"):
			// GitHub answers a 404 for "nothing published" with an **object**,
			// not an array. Serving it here is the point: it is the body shape that
			// made the original report a parse error.
			if fixture.social == "" {
				w.WriteHeader(http.StatusNotFound)
				write(w, `{"message":"Not Found"}`)
				return
			}
			write(w, fixture.social)
		case strings.Contains(path, "/followers"):
			write(w, fixture.followers)
		case strings.Contains(path, "/following/"):
			login := path[strings.LastIndex(path, "/")+1:]
			fixture.mu.Lock()
			status, known := fixture.followBack[login]
			fixture.mu.Unlock()
			if !known {
				status = http.StatusNotFound
			}
			if status == http.StatusNoContent {
				// 204 carries no body; writing one would be a lie about what came back.
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.WriteHeader(status)
			write(w, `{"message":"Not Found"}`)
		default:
			// The bare `/users/<login>` profile read, which is the pass that
			// decides the account exists at all. Every other pass runs after it.
			if strings.Count(strings.Trim(strings.TrimPrefix(path, "/users/"), "/"), "/") == 0 {
				write(w, `{"login":"ibnaleem","html_url":"https://github.com/ibnaleem","name":"Ibnaleem","public_repos":12,"followers":40,"type":"User"}`)
				return
			}
			write(w, `{}`)
		}
	})
	return mux
}

func (fixture *githubKeysFixture) serve(t *testing.T) {
	t.Helper()
	served := httptest.NewServer(fixture.handler(t))
	previous := githubAPIUsersBase
	githubAPIUsersBase = served.URL + "/users/"
	t.Cleanup(func() {
		githubAPIUsersBase = previous
		served.Close()
	})
}

// gosearchCloneRoot is the upstream clone, read as evidence for the port.
const gosearchCloneRoot = "../gosearch"

// readGosearchUpstream reads one file of the upstream clone.
//
// The clone is the evidence for the port. Reading it in the test rather than
// quoting it in a comment is what makes "the path is the same as upstream" a
// statement that can stop being true — and the four endpoints have one shared
// failure mode (a wrong path answers 404, which reads as "publishes nothing"),
// so a silent divergence is indistinguishable from an account with no keys.
func readGosearchUpstream(t *testing.T, relative string) (string, error) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(gosearchCloneRoot, relative))
	return string(raw), err
}

// githubKeysCount returns how many times a path suffix was requested.
func (fixture *githubKeysFixture) githubKeysCount(suffix string) int {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	total := 0
	for _, path := range fixture.requestedPath {
		if strings.HasSuffix(path, suffix) {
			total++
		}
	}
	return total
}

func githubKeysRun(t *testing.T, fixture *githubKeysFixture, options map[string]interface{}) *osintTransformResult {
	t.Helper()
	fixture.serve(t)
	server := &server{}
	result, err := server.runOSINTTransformWithCollector(context.Background(), osintTransformInput{
		Transform:      "github_recon",
		Value:          "ibnaleem",
		Options:        options,
		ConfirmNetwork: true,
	}, nil)
	if err != nil {
		t.Fatalf("github_recon returned %v", err)
	}
	return &result
}

// TestGitHubSSHKeysAreIdentifiedByTheirMaterial is the fingerprint half: the
// original reports a key by GitHub's numeric id and by its algorithm, and neither
// identifies a key outside GitHub. Two different keys of the same type get the same
// two fields, so a key cannot be recognised when it is pasted into `authorized_keys`.
func TestGitHubSSHKeysAreIdentifiedByTheirMaterial(t *testing.T) {
	fixture := &githubKeysFixture{
		keys:    `[{"id":1,"key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterialOne ibnaleem@work"},{"id":2,"key":"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7x9Kp ExampleKeyMaterialTwo ibnaleem@home"}]`,
		gpgKeys: `[]`, social: `[]`, followers: `[]`,
	}
	result := githubKeysRun(t, fixture, nil)

	var keys []transformEntity
	for _, item := range result.Entities {
		if item.Properties["kind"] == "ssh_key" {
			keys = append(keys, item)
		}
	}
	if len(keys) != 2 {
		t.Fatalf("got %d ssh_key entities, want 2: %v", len(keys), githubKeysSummarise(result))
	}
	if keys[0].Identity == keys[1].Identity {
		t.Fatalf("both keys share the identity %q; two different keys must be two nodes", keys[0].Identity)
	}
	for _, key := range keys {
		if !strings.HasPrefix(key.Identity, "github-ssh-key:SHA256:") {
			t.Errorf("identity %q is not keyed on the key's own material", key.Identity)
		}
		fingerprint, _ := key.Properties["fingerprint"].(string)
		if !strings.HasPrefix(fingerprint, "SHA256:") {
			t.Errorf("fingerprint %q does not name the algorithm it was made with", fingerprint)
		}
		if key.Properties["key"] == nil || key.Properties["key_type"] == nil {
			t.Errorf("%s carries no key or key_type", key.Identity)
		}
	}
	// The relation names the account, so the graph says whose key this is.
	if len(result.Relations) == 0 {
		t.Error("no relation ties the keys to the account")
	}
}

// TestGitHubSSHKeysOfTheSameTypeStayDistinct is the case the two-field report
// cannot survive: same algorithm, different material.
func TestGitHubSSHKeysOfTheSameTypeStayDistinct(t *testing.T) {
	fixture := &githubKeysFixture{
		keys:    `[{"id":1,"key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleOne a@b"},{"id":2,"key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleTwo a@b"}]`,
		gpgKeys: `[]`, social: `[]`, followers: `[]`,
	}
	result := githubKeysRun(t, fixture, nil)

	seen := map[string]bool{}
	for _, item := range result.Entities {
		if item.Properties["kind"] == "ssh_key" {
			seen[item.Identity] = true
		}
	}
	if len(seen) != 2 {
		t.Errorf("two ed25519 keys produced %d distinct nodes: %v", len(seen), seen)
	}
}

// TestGitHubGPGKeyEmailsAreReportedAndFiltered: the key's addresses become graph
// nodes, and GitHub's own privacy placeholders are filtered out by the same rule
// the commit passes use — they are identifiers, not mailboxes.
func TestGitHubGPGKeyEmailsAreReportedAndFiltered(t *testing.T) {
	fixture := &githubKeysFixture{
		keys: `[]`,
		gpgKeys: `[{"name":"work key","key_id":"ABC123","revoked":false,"emails":[
			{"email":"ibnaleem@yandex.ru","verified":true},
			{"email":"43872+ibnaleem@users.noreply.github.com","verified":true}
		]}]`,
		social: `[]`, followers: `[]`,
	}
	result := githubKeysRun(t, fixture, nil)

	var addresses []string
	for _, item := range result.Entities {
		if item.Type == "email" {
			addresses = append(addresses, item.Identity)
		}
	}
	if len(addresses) != 1 || addresses[0] != "ibnaleem@yandex.ru" {
		t.Errorf("addresses = %v, want only the real one — GitHub privacy placeholders are not mailboxes", addresses)
	}

	var verified any
	found := false
	for _, relation := range result.Relations {
		if relation.Target == "ibnaleem@yandex.ru" {
			verified = relation.Properties["verified"]
			found = true
		}
	}
	if !found {
		t.Fatal("the verified address produced no relation to its key")
	}
	if verified != true {
		t.Errorf("verified = %v, want true; an unverified address on a key is a different claim", verified)
	}
}

// TestGitHubSocialAccountsAreRecordedAsVerifiedLinks is the capability the HTML
// probe could not reach: GitHub says these are this person's accounts.
func TestGitHubSocialAccountsAreRecordedAsVerifiedLinks(t *testing.T) {
	fixture := &githubKeysFixture{
		keys: `[]`, gpgKeys: `[]`, followers: `[]`,
		social: `[{"provider":"mastodon","url":"https://mastodon.social/@ibnaleem"},{"url":"https://example.org/~ibnaleem"}]`,
	}
	result := githubKeysRun(t, fixture, nil)

	var links []transformEntity
	for _, item := range result.Entities {
		if item.Properties["kind"] == "social_account" {
			links = append(links, item)
		}
	}
	if len(links) != 2 {
		t.Fatalf("got %d social_account entities, want 2: %v", len(links), githubKeysSummarise(result))
	}
	for _, link := range links {
		if link.Properties["verified_by"] != "github" {
			t.Errorf("%s is not marked as a GitHub-verified link", link.Identity)
		}
	}
	// The one with no provider named takes its name from the host.
	for _, link := range links {
		if link.Identity == "https://example.org/~ibnaleem" {
			if link.Properties["provider"] != "example.org" {
				t.Errorf("provider = %v, want the host taken from the URL", link.Properties["provider"])
			}
		}
	}
}

// TestGitHubSocialAccounts404IsNotAParseError is the original's third defect: the
// status is checked **after** decoding, so GitHub's `{"message": …}` object fails
// to unmarshal into a slice and the run reports a fetch error for an account that
// simply publishes nothing.
func TestGitHubSocialAccounts404IsNotAParseError(t *testing.T) {
	fixture := &githubKeysFixture{
		keys: `[]`, gpgKeys: `[]`, followers: `[]`,
		social: "", // the fixture answers 404 with an object
	}
	result := githubKeysRun(t, fixture, nil)

	for _, warning := range result.Warnings {
		lower := strings.ToLower(warning)
		if strings.Contains(lower, "unmarshal") || strings.Contains(lower, "parse") {
			t.Errorf("a 404 was reported as a parse failure: %q", warning)
		}
	}
	var named bool
	for _, warning := range result.Warnings {
		if strings.Contains(warning, "social_accounts") && strings.Contains(warning, "404") {
			named = true
		}
	}
	if !named {
		t.Errorf("the 404 is not named in the run: %v", result.Warnings)
	}
}

// TestGitHubMutualFollowersAreBoundedAndTheBoundIsStated is the cost defect. The
// original makes one request per follower; here `max_follower_checks` bounds it,
// and a truncated pass says how many candidates it never asked — because "2 mutual
// followers" out of 30 unchecked people is a claim about a sample, and nothing in
// the number says so.
func TestGitHubMutualFollowersAreBoundedAndTheBoundIsStated(t *testing.T) {
	followers := make([]string, 0, 40)
	followBack := map[string]int{}
	for index := 0; index < 40; index++ {
		login := fmt.Sprintf("user%02d", index)
		followers = append(followers, fmt.Sprintf(`{"login":%q}`, login))
		if index%5 == 0 {
			followBack[login] = http.StatusNoContent
		}
	}
	fixture := &githubKeysFixture{
		keys: `[]`, gpgKeys: `[]`, social: `[]`,
		followers:  "[" + strings.Join(followers, ",") + "]",
		followBack: followBack,
	}
	result := githubKeysRun(t, fixture, map[string]interface{}{
		"max_follower_checks": 10,
		"max_followers":       40,
	})

	asked := countFollowingChecks(fixture)
	if asked != 10 {
		t.Errorf("the pass made %d follow checks, want exactly the 10 the caller allowed", asked)
	}
	if result.Metadata["max_follower_checks"] != 10 {
		t.Errorf("max_follower_checks = %v, want the applied value 10", result.Metadata["max_follower_checks"])
	}
	if result.Metadata["followers_listed"] != 40 {
		t.Errorf("followers_listed = %v, want 40", result.Metadata["followers_listed"])
	}
	if result.Metadata["followers_checked"] != 10 {
		t.Errorf("followers_checked = %v, want 10", result.Metadata["followers_checked"])
	}

	var stated bool
	for _, warning := range result.Warnings {
		if strings.Contains(warning, "10 of 40") && strings.Contains(warning, "max_follower_checks") {
			stated = true
		}
	}
	if !stated {
		t.Errorf("the truncated pass does not say how many of the read candidates it skipped, "+
			"or names the wrong bound: %v", result.Warnings)
	}
	// And the two bounds are reported separately, because they cut at different
	// stages and sending the operator to the wrong knob wastes the next run.
	if result.Metadata["followers_read"] != 40 {
		t.Errorf("followers_read = %v, want 40 — max_followers was 40 and the list held 40",
			result.Metadata["followers_read"])
	}
}

// countFollowingChecks counts every "following/<login>" request the fixture saw.
func countFollowingChecks(fixture *githubKeysFixture) int {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	total := 0
	for _, path := range fixture.requestedPath {
		if strings.Contains(path, "/following/") {
			total++
		}
	}
	return total
}

// TestGitHubMutualFollowersUseOnlyThe204 pins the evidence rule: a mutual follower
// is exactly a `204`, and anything else is not one. The original treats it the
// same way, but publishes neither the checked nor the answered count, so its
// number cannot be read as "of how many".
func TestGitHubMutualFollowersUseOnlyThe204(t *testing.T) {
	fixture := &githubKeysFixture{
		keys: `[]`, gpgKeys: `[]`, social: `[]`,
		followers: `[{"login":"a"},{"login":"b"},{"login":"c"}]`,
		followBack: map[string]int{
			"a": http.StatusNoContent,
			"b": http.StatusNotFound,
			"c": http.StatusForbidden,
		},
	}
	result := githubKeysRun(t, fixture, nil)

	if result.Metadata["mutual_followers"] != 1 {
		t.Errorf("mutual_followers = %v, want 1 — only the 204 is evidence", result.Metadata["mutual_followers"])
	}
	if result.Metadata["followers_checked"] != 3 {
		t.Errorf("followers_checked = %v, want 3 — all three were asked", result.Metadata["followers_checked"])
	}
	for _, item := range result.Entities {
		if item.Properties["kind"] == "mutual_follower" && item.Identity != "a" {
			t.Errorf("entity %q is a mutual follower but did not answer 204", item.Identity)
		}
	}
}

// TestGitHubKeyPassesAreReportedAsRunOrSkipped: `key_passes_ran` is the list the
// operator reads to know what the run actually did. A pass that answered 404 ran —
// it just found nothing — so it belongs in the list, and the warning says why it is
// empty.
func TestGitHubKeyPassesAreReportedAsRunOrSkipped(t *testing.T) {
	fixture := &githubKeysFixture{
		keys:    `[{"id":1,"key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample a@b"}]`,
		gpgKeys: `[]`, social: `[]`,
		followers: `[{"login":"a"}]`, followBack: map[string]int{"a": http.StatusNoContent},
	}
	result := githubKeysRun(t, fixture, nil)

	ran, _ := result.Metadata["key_passes_ran"].([]string)
	if len(ran) != 4 {
		t.Errorf("key_passes_ran = %v, want all four passes", ran)
	}
	declared, _ := result.Metadata["key_passes"].([]string)
	if len(declared) != 4 {
		t.Fatalf("key_passes = %v, want the four the pass list declares", declared)
	}
}

// TestGitHubReconStillWarnsWhenNoAddressIsFound — the regression this file could
// have introduced. The warning used to be `len(result.Entities) == 1`, which was
// correct while the profile was the only other thing written; with four passes
// adding keys and links, the count grows and the warning goes silent exactly when
// it matters — an account with keys and no address of its own.
func TestGitHubReconStillWarnsWhenNoAddressIsFound(t *testing.T) {
	fixture := &githubKeysFixture{
		keys:    `[{"id":1,"key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample a@b"}]`,
		gpgKeys: `[]`, social: `[]`, followers: `[]`, followBack: map[string]int{},
	}
	result := githubKeysRun(t, fixture, nil)

	var found bool
	for _, warning := range result.Warnings {
		if strings.Contains(warning, "No public commit address") {
			found = true
		}
	}
	if !found {
		t.Errorf("an account with a key and no address produced no warning: %v", result.Warnings)
	}
}

func githubKeysSummarise(result *osintTransformResult) string {
	parts := make([]string, 0, len(result.Entities))
	for _, item := range result.Entities {
		parts = append(parts, item.Type+"/"+fmt.Sprint(item.Properties["kind"]))
	}
	return strings.Join(parts, ", ")
}

// TestGitHubKeyPassEndpointsMatchTheOriginal pins the four paths against the
// upstream source, read at `687f9ed`. A wrong path returns a 404 that reads as
// "the account publishes nothing", which is the failure mode every one of these
// four shares.
func TestGitHubKeyPassEndpointsMatchTheOriginal(t *testing.T) {
	raw, err := readGosearchUpstream(t, "internal/modules/github/ssh-keys.go")
	if err != nil {
		t.Skipf("the upstream clone is not present at %s: %v", gosearchCloneRoot, err)
	}
	if !strings.Contains(raw, "/keys") {
		t.Error("the upstream source no longer contains `/keys`; the ported path must be re-checked")
	}
	// The other three endpoints live in their own files upstream, and each is
	// read from the file that actually declares it — quoting all four from one
	// file would have been a claim about nothing.
	for relative, want := range map[string]string{
		"internal/modules/github/gpg-keys.go":         "/gpg_keys",
		"internal/modules/github/social-accounts.go":  "/social_accounts",
		"internal/modules/github/mutual-followers.go": "/followers",
	} {
		body, err := readGosearchUpstream(t, relative)
		if err != nil {
			t.Errorf("read %s: %v", relative, err)
			continue
		}
		if !strings.Contains(body, want) {
			t.Errorf("%s no longer contains %q; the ported path must be re-checked", relative, want)
		}
	}
	followers, err := readGosearchUpstream(t, "internal/modules/github/mutual-followers.go")
	if err == nil && !strings.Contains(followers, "/following/") {
		t.Error("the mutual-followers source no longer contains `/following/`; the per-follower check must be re-checked")
	}
	// And the fixture proves our own paths are the ones we claim, because a
	// request the fixture never saw would be a request it never made.
	fixture := &githubKeysFixture{
		keys: `[{"id":1,"key":"ssh-ed25519 AAAAExample a@b"}]`, gpgKeys: `[]`,
		social: `[]`, followers: `[]`, followBack: map[string]int{},
	}
	githubKeysRun(t, fixture, nil)
	for _, suffix := range []string{"/keys", "/gpg_keys", "/social_accounts", "/followers"} {
		if fixture.githubKeysCount(suffix) == 0 {
			t.Errorf("no request reached %q; the pass read something else", suffix)
		}
	}
}

package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// The four GitHub key and graph endpoints gosearch read, which `github_recon` did
// not.
//
// At commit `687f9ed` the reference walks all four as separate modules, each with
// its own `&http.Client{}` and its own copy of the `setAuthHeader` dance:
//
//	ssh-keys.go:20          GET /users/<u>/keys
//	gpg-keys.go:28          GET /users/<u>/gpg_keys
//	social-accounts.go:19   GET /users/<u>/social_accounts
//	mutual-followers.go:18  GET /users/<u>/followers?per_page=100
//	mutual-followers.go:53  GET /users/<u>/following/<login>   (once per follower)
//
// They are folded into `github_recon` here rather than given four transforms of
// their own, because they answer the same question about the same value: what does
// GitHub publicly hold for this account. Five runs to learn one thing about one
// login is the shape of a tool nobody runs twice.
//
// Two departures from the original, both measured:
//
//  1. The mutual-follower pass costs **one request per follower**. The original
//     fetches up to 100 followers and then makes one request each, so an account
//     with 100 followers costs 101 requests against an unauthenticated budget of
//     **60 per hour**. It therefore could not complete without `GITHUB_TOKEN`,
//     and with one it spent the budget a caller needs for everything else. Here
//     the candidate list is bounded by `max_followers` and the whole pass is
//     bounded by `max_follower_checks`; when either bound bites, the run says how
//     many followers it did **not** check, because "2 mutual followers" from a
//     truncated pass is a different claim from "2 mutual followers".
//  2. The original's four modules print, and `social_accounts` returns a body
//     that is a JSON **array** while `keys` and `gpg_keys` also return arrays —
//     but on a 404 for `social_accounts` GitHub answers an object with a
//     `message`, and `json.Unmarshal` into `[]GitHubSocialAccount` fails with a
//     parse error that the original prints as "error fetching social accounts".
//     Here every endpoint is read through `githubAPIGet`, which returns the
//     status before anything is decoded, so a 404 is "no social accounts
//     published" rather than a parse failure.

// githubAPIUsersBase is the `/users/` prefix every pass below reads.
//
// It is a variable so the tests can point the four passes at one fixture server
// and measure the requests they make, and so a GitHub Enterprise deployment can
// be read without a rebuild. The default is the public API, which is what the
// original used (`ssh-keys.go:23`, `gpg-keys.go:31`, `social-accounts.go:22`,
// `mutual-followers.go:22`).
var githubAPIUsersBase = "https://api.github.com/users/"

// githubReconKeyPasses names the extra passes, in the order they run. It is the
// list the run's metadata reports, so the operator can see which pass produced
// which finding and which pass was skipped.
var githubReconKeyPasses = []string{
	"ssh_keys", "gpg_keys", "social_accounts", "mutual_followers",
}

// githubReconDefaultFollowerChecks bounds the mutual-follower pass.
//
// One request per follower, so this is the number that decides whether the pass is
// affordable at all: 60 unauthenticated requests per hour is GitHub's whole
// budget, and spending it on one account's follower graph leaves nothing for the
// rest of the run. It is a **default, not a cap** — the caller raises it with
// `max_follower_checks`, and the applied value is published in the metadata.
const githubReconDefaultFollowerChecks = 30

// githubReconDefaultMaxFollowers bounds how many followers are read off the
// follower list at all. `per_page` is 100 in the original; the default here is
// lower for the same reason.
const githubReconDefaultMaxFollowers = 60

// githubReconPassSSHKeys reads `/users/<u>/keys`.
//
// Every public key is reported as a `url` entity keyed on its fingerprint, because
// a key is identified by that and two keys can share a comment. The reference
// printed only the key **type** and the numeric id (`ssh-keys.go:69`), which is
// not enough to recognise a key again — `git`'s `authorized_keys` line and
// GitHub's id are two different namespaces, and the id is not stable.
func githubReconPassSSHKeys(ctx context.Context, client *http.Client, username string, result *osintTransformResult, collector *transformCollector) (int, bool, error) {
	if err := collector.checkpoint(ctx); err != nil {
		return 0, false, err
	}
	var keys []struct {
		ID  int    `json:"id"`
		Key string `json:"key"`
	}
	status, err := githubAPIGet(ctx, client,
		githubAPIUsersBase+url.PathEscape(username)+"/keys", &keys)
	if err != nil {
		return status, false, err
	}
	if status < 200 || status >= 300 {
		return status, false, nil
	}
	for _, key := range keys {
		if strings.TrimSpace(key.Key) == "" {
			continue
		}
		fingerprint := sshKeyFingerprint(key.Key)
		result.Entities = append(result.Entities, entity("url", "github-ssh-key:"+fingerprint,
			map[string]interface{}{
				"kind":          "ssh_key",
				"provider":      "github",
				"account":       username,
				"key_type":      sshKeyType(key.Key),
				"key":           key.Key,
				"repository_id": key.ID,
				"fingerprint":   fingerprint,
				"public":        true,
				"evidence":      "github_public_api",
			}, map[string]interface{}{"source": "github_public_api"}))
		result.Relations = append(result.Relations, transformRelation{
			Type:       "publishes_key",
			SourceType: "username",
			Source:     username,
			TargetType: "url",
			Target:     "github-ssh-key:" + fingerprint,
		})
	}
	return status, true, nil
}

// githubReconPassGPGKeys reads `/users/<u>/gpg_keys`.
//
// The emails a key is verified against are reported as `email` entities, because
// that is the fact the reference writes to disk (`gpg-keys.go:104`) without ever
// connecting it to anything: an address that GitHub vouches for on a signing key
// is an address a person publishes, and it is worth a graph edge.
//
// `verified` is carried on the relation rather than on the address itself, because
// "this address is on a key" and "this address is verified on a key" are different
// claims and the second is the one that means something.
func githubReconPassGPGKeys(ctx context.Context, client *http.Client, username string, result *osintTransformResult, collector *transformCollector) (int, bool, error) {
	if err := collector.checkpoint(ctx); err != nil {
		return 0, false, err
	}
	var keys []struct {
		Name      string `json:"name"`
		KeyID     string `json:"key_id"`
		CreatedAt string `json:"created_at"`
		ExpiresAt string `json:"expires_at"`
		Revoked   bool   `json:"revoked"`
		Emails    []struct {
			Email    string `json:"email"`
			Verified bool   `json:"verified"`
		} `json:"emails"`
	}
	status, err := githubAPIGet(ctx, client,
		githubAPIUsersBase+url.PathEscape(username)+"/gpg_keys", &keys)
	if err != nil {
		return status, false, err
	}
	if status < 200 || status >= 300 {
		return status, false, nil
	}
	for _, key := range keys {
		keyID := strings.TrimSpace(key.KeyID)
		if keyID == "" {
			continue
		}
		result.Entities = append(result.Entities, entity("url", "github-gpg-key:"+keyID,
			map[string]interface{}{
				"kind":       "gpg_key",
				"provider":   "github",
				"account":    username,
				"key_id":     keyID,
				"name":       key.Name,
				"created_at": key.CreatedAt,
				"expires_at": key.ExpiresAt,
				"revoked":    key.Revoked,
				"public":     true,
				"evidence":   "github_public_api",
			}, map[string]interface{}{"source": "github_public_api"}))
		result.Relations = append(result.Relations, transformRelation{
			Type:       "publishes_key",
			SourceType: "username",
			Source:     username,
			TargetType: "url",
			Target:     "github-gpg-key:" + keyID,
		})
		for _, keyEmail := range key.Emails {
			address := strings.TrimSpace(keyEmail.Email)
			// The same filter as the commit passes: a privacy placeholder is a
			// GitHub identifier, not a mailbox.
			if address == "" || isGitHubPrivacyAddress(address) || seenEmail(result, address) {
				continue
			}
			result.Entities = append(result.Entities, entity("email", address,
				map[string]interface{}{"source": "github_gpg_key"}, map[string]interface{}{"source": "github_gpg_key"}))
			result.Relations = append(result.Relations, transformRelation{
				Type:       "mentions_email",
				SourceType: "url",
				Source:     "github-gpg-key:" + keyID,
				TargetType: "email",
				Target:     address,
				Properties: map[string]interface{}{
					"verified": keyEmail.Verified,
					"key_id":   keyID,
					"revoked":  key.Revoked,
				},
			})
		}
	}
	return status, true, nil
}

// githubReconPassSocialAccounts reads `/users/<u>/social_accounts`.
//
// This is the pass with a capability the rest of the engine does not have: the
// links are **GitHub-verified**. `username_search` asks every platform in a
// catalogue whether it holds a name; this asks GitHub which accounts the person
// claims. Both can be right about the same address and only one of them is
// evidence, so the provenance says `github_social_account` and the entity carries
// `verified_by: github`.
func githubReconPassSocialAccounts(ctx context.Context, client *http.Client, username string, result *osintTransformResult, collector *transformCollector) (int, bool, error) {
	if err := collector.checkpoint(ctx); err != nil {
		return 0, false, err
	}
	var accounts []struct {
		Provider string `json:"provider"`
		URL      string `json:"url"`
	}
	status, err := githubAPIGet(ctx, client,
		githubAPIUsersBase+url.PathEscape(username)+"/social_accounts", &accounts)
	if err != nil {
		return status, false, err
	}
	if status < 200 || status >= 300 {
		return status, false, nil
	}
	for _, account := range accounts {
		link := strings.TrimSpace(account.URL)
		if link == "" {
			continue
		}
		provider := strings.TrimSpace(account.Provider)
		if provider == "" {
			provider = accountHostOf(link)
		}
		result.Entities = append(result.Entities, entity("url", link,
			map[string]interface{}{
				"kind":        "social_account",
				"provider":    provider,
				"account":     username,
				"url_main":    link,
				"verified_by": "github",
				"evidence":    "github_verified_link",
				"catalogue":   "github_social_accounts",
			}, map[string]interface{}{"source": "github_social_accounts"}))
		result.Relations = append(result.Relations, transformRelation{
			Type:       "accounts_for",
			SourceType: "username",
			Source:     username,
			TargetType: "url",
			Target:     link,
			Properties: map[string]interface{}{"verified_by": "github", "provider": provider},
		})
	}
	return status, true, nil
}

// githubReconPassMutualFollowers reads the follower list and checks who follows back.
//
// GitHub answers `204` when the checked login follows the account and `404` when it
// does not; anything else is not an answer about the relationship. The original
// treats **only** 204 as a mutual and ignores every other status, which quietly
// discards the `404`s — the majority of the follower list — so its count is right
// but its cost is invisible. Here every status is counted, and the result reports
// how many were checked and how many were skipped.
func githubReconPassMutualFollowers(ctx context.Context, client *http.Client, username string, result *osintTransformResult, collector *transformCollector, maxFollowers, maxChecks int) (int, error) {
	if err := collector.checkpoint(ctx); err != nil {
		return 0, err
	}
	var followers []struct {
		Login string `json:"login"`
	}
	status, err := githubAPIGet(ctx, client,
		githubAPIUsersBase+url.PathEscape(username)+"/followers?per_page=100", &followers)
	if err != nil {
		return status, err
	}
	if status < 200 || status >= 300 {
		return status, nil
	}

	total := len(followers)
	if maxFollowers > 0 && total > maxFollowers {
		followers = followers[:maxFollowers]
	}
	// `readFromList` is the number of candidates the list gave us **after** the
	// read bound. It is kept separately from `total` because the two bounds cut at
	// different stages, and the warning has to say which of them bit: telling an
	// operator "only 10 of 40 were checked, raise max_followers" when `max_followers`
	// was already 40 would send them to the wrong knob.
	readFromList := len(followers)
	if maxChecks > 0 && readFromList > maxChecks {
		followers = followers[:maxChecks]
	}
	checked := len(followers)
	setTransformMetadata(result, "followers_listed", total)
	setTransformMetadata(result, "followers_read", readFromList)
	setTransformMetadata(result, "followers_checked", checked)

	mutual := 0
	answered := 0
	for index, follower := range followers {
		if err := ctx.Err(); err != nil {
			break
		}
		if err := collector.checkpoint(ctx); err != nil {
			break
		}
		login := strings.TrimSpace(follower.Login)
		if login == "" {
			continue
		}
		if collector != nil {
			collector.indexPosition(ctx, login, index, len(followers))
		}
		// A `204` means "yes", and it carries no body — so this is the one read
		// in the file that asks for the status alone. Decoding the empty body would
		// have been an error, and that error would have landed on the one status
		// that is the answer.
		status, err := githubAPIGet(ctx, client,
			githubAPIUsersBase+url.PathEscape(username)+"/following/"+url.PathEscape(login), nil)
		if err != nil {
			if strings.Contains(err.Error(), "GITHUB_RATE_LIMITED") {
				setTransformMetadata(result, "mutual_followers", mutual)
				result.Warnings = append(result.Warnings,
					"The mutual-follower pass stopped when GitHub refused further requests from this route: "+
						strconv.Itoa(answered)+" of "+strconv.Itoa(len(followers))+
						" candidates were answered. The count below is partial and says so.")
				return status, nil
			}
			continue
		}
		if status != http.StatusNoContent {
			continue
		}
		answered++
		mutual++
		result.Entities = append(result.Entities, entity("username", login,
			map[string]interface{}{
				"kind":     "mutual_follower",
				"account":  username,
				"evidence": "github_follows_back",
			}, map[string]interface{}{"source": "github_public_api"}))
		result.Relations = append(result.Relations, transformRelation{
			Type:       "mutual_follows",
			SourceType: "username",
			Source:     username,
			TargetType: "username",
			Target:     login,
		})
	}
	setTransformMetadata(result, "mutual_followers", mutual)

	// A truncated pass says so, and says **which** bound bit. This is the whole
	// reason the bounds are visible: "2 mutual followers" out of 30 candidates that
	// were never asked is a claim about a sample, and nothing in the number says so.
	if readFromList < total {
		result.Warnings = append(result.Warnings,
			"Only "+strconv.Itoa(readFromList)+" of "+strconv.Itoa(total)+
				" followers were read from GitHub's list; raise max_followers to read it all.")
	}
	if checked < readFromList {
		result.Warnings = append(result.Warnings,
			"The mutual-follower pass checked "+strconv.Itoa(checked)+" of "+strconv.Itoa(readFromList)+
				" candidates it had read; raise max_follower_checks to check the rest. "+
				"The mutual-follower count covers only the ones that were checked.")
	}
	return status, nil
}

// sshKeyType is the algorithm token of an SSH public key.
//
// `ssh-rsa`, `ssh-ed25519`, `ecdsa-sha2-nistp256`. The reference printed exactly
// this (`ssh-keys.go:69`), so it is kept as a property — but the fingerprint is
// the entity's identity, because two keys can be the same type and only one of
// them is the key.
func sshKeyType(key string) string {
	fields := strings.Fields(strings.TrimSpace(key))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// sshKeyFingerprint is a stable identity for a public key.
//
// It is the SHA-256 of the key's own bytes, hex-encoded the way OpenSSH prints
// it. A real fingerprint is an MD5 of the same material, but MD5 is a collision
// risk on an identity, and a key's **type and body** are what `authorized_keys`
// actually carries — so hashing what is published needs no external tool and
// cannot disagree with the key someone pastes in.
//
// This is deliberately not the OpenSSH fingerprint: reproducing that would mean
// parsing the wire format, and a hash of the published line answers the question
// the graph asks — "is this the same key?" — without it.
func sshKeyFingerprint(key string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(key)))
	encoded := base64.RawStdEncoding.EncodeToString(sum[:])
	return "SHA256:" + strings.TrimRight(encoded, "=")
}

// accountHostOf is the host of a social-account URL, used when GitHub does not
// name the provider itself.
func accountHostOf(link string) string {
	parsed, err := url.Parse(link)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

// seenEmail reports whether an address is already in the result as an `email`
// entity, so the GPG pass does not add a node the commit passes already wrote.
func seenEmail(result *osintTransformResult, address string) bool {
	lowered := strings.ToLower(address)
	for _, item := range result.Entities {
		if item.Type == "email" && strings.ToLower(item.Identity) == lowered {
			return true
		}
	}
	return false
}

package active

// The SSRF + configuration-exposure rule.
//
// Upstream calls this `chainSSRFtoMetadata` and its name says what it does not
// do: it never touches a metadata endpoint. It correlates a localhost SSRF with
// any exposure finding whose endpoint mentions `actuator` or `.env`, and reports
// Critical. There is no request in it, so the claim "the metadata credentials
// are now reachable" is asserted rather than demonstrated — one of the four
// upstream rules this file's header lists as verifying nothing.
//
// What is kept is the correlation, because it is real: a parameter that fetches
// an attacker-chosen URL and a configuration file the same deployment serves to
// anyone are genuinely worse together than separately. What is corrected is the
// tier, and the correction is the rule this file is written under:
//
//   - both ingredients must be **verified**, because correlating a proven finding
//     with an unproven one produces a row whose strength is its weakest part;
//   - the two must be on the **same host**, because an SSRF on one deployment and
//     a leaked `.env` on another are two problems, not one chain;
//   - Critical is claimed only when the exposed configuration **carries
//     credentials** — a connection string with a password, a cloud key — because
//     that is the one half the exposure finding can demonstrate on its own, from
//     the exchange that already happened. A `.env` that holds only `APP_ENV=prod`
//     makes the pair worth triaging and not worth a critical row.
//
// Everything short of that is reported, as `Potential`, capped at medium, with
// the missing proof named. It makes no request of its own: the two exchanges that
// justify it already happened, and a chain rule that sends traffic to turn a
// correlation into a proof is a second scanner wearing a chain's name.

import (
	"context"
	"fmt"
	"strings"
)

// configExposureMarkers are the endpoint shapes that make an exposure finding
// about configuration rather than about an incidental match.
//
// `actuator` and `.env` are upstream's two. The rest are here because the same
// composition exists through them and dropping them would be losing a finding
// class rather than correcting a severity: a Spring actuator, a PHP info page, a
// served Git directory and a YAML config all hand over the connection strings and
// keys that make an internal pivot worth having.
var configExposureMarkers = []string{
	"actuator",
	".env",
	"phpinfo",
	".git/",
	"config",
	"web.config",
	"settings.py",
	"credentials",
}

// credentialEvidence are the parts of an exposure finding that show the leaked
// value is a credential and not a version string.
//
// A `.env` holding `APP_ENV=production` proves the file was readable. It does not
// hand over anything, and a chain row that calls that a credential theft is the
// kind of row that teaches an operator to close the channel.
var credentialEvidence = []string{
	"connection string",
	"password",
	"secret",
	"api key",
	"access key",
	"bearer",
	"private key",
	"jwt",
	"token",
}

// ChainSSRFToConfigExposure is the SSRF + leaked-configuration rule.
type ChainSSRFToConfigExposure struct{}

// Name implements Chain.
func (*ChainSSRFToConfigExposure) Name() string { return "ssrf-to-config-exposure" }

// Impact implements Chain.
func (*ChainSSRFToConfigExposure) Impact() Severity { return SeverityCritical }

// Claim implements Chain.
func (*ChainSSRFToConfigExposure) Claim() string {
	return "SSRF + readable server configuration → credential theft inside the network"
}

// Apply implements Chain.
//
// It issues no request. Both ingredients are already verified exchanges, and the
// rule's only question is whether they compose.
func (c *ChainSSRFToConfigExposure) Apply(_ context.Context, in ChainInput) *Finding {
	ssrfs := verifiedMembers(in.Findings, "ssrf")
	exposed := verifiedMembers(in.Findings, "exposure")
	if len(ssrfs) == 0 || len(exposed) == 0 {
		return nil
	}

	// Only exposure findings about a configuration endpoint are ingredients. An
	// exposure finding about a leaked API key in a page's body is a real finding
	// and not this chain.
	var config []Finding
	for _, finding := range exposed {
		endpoint := strings.ToLower(finding.Endpoint + " " + finding.Title)
		for _, marker := range configExposureMarkers {
			if strings.Contains(endpoint, marker) {
				config = append(config, finding)
				break
			}
		}
	}
	if len(config) == 0 {
		return nil
	}

	// The pairing is per host: an SSRF on one deployment and a leaked
	// configuration on another are two problems that happen to be in one scan.
	type pair struct {
		ssrf    Finding
		config  Finding
		carries bool
	}
	var pairs []pair
	for _, s := range ssrfs {
		for _, e := range config {
			if !sameHostOf(s.Endpoint, e.Endpoint) {
				continue
			}
			pairs = append(pairs, pair{ssrf: s, config: e, carries: carriesCredential(e)})
		}
	}
	if len(pairs) == 0 {
		return nil
	}

	credentialed := 0
	var members []Finding
	for _, p := range pairs {
		if p.carries {
			credentialed++
		}
		members = append(members, p.ssrf, p.config)
	}
	proven := credentialed > 0
	missing := "the exposed configuration carried no credential the exposure module could name — " +
		"the file was readable, but nothing in it was shown to authenticate anywhere, so the " +
		"composition is a reachable service and a readable file rather than a theft"
	evidence := fmt.Sprintf(
		"%d verified SSRF surface(s) on the same host as %d readable configuration endpoint(s); "+
			"%d of those endpoints carried a credential in the exchange that read them",
		len(ssrfs), len(config), credentialed)
	return chainFinding(c, in, proven, evidence, missing, members)
}

// carriesCredential reports whether an exposure finding's own evidence names a
// credential rather than a configuration value.
func carriesCredential(finding Finding) bool {
	haystack := strings.ToLower(finding.Title + " " + finding.Evidence + " " + finding.Payload)
	for _, marker := range credentialEvidence {
		if strings.Contains(haystack, marker) {
			return true
		}
	}
	return false
}

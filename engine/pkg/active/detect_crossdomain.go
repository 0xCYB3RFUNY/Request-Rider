package active

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// CrossDomain probes for overly permissive Flash and Silverlight cross-domain policies.
// Corresponds to Burp Suite checks:
// 0x00200400 (Flash cross-domain policy)
// 0x00200500 (Silverlight cross-domain policy)
type CrossDomain struct{}

// Name implements Module.
func (CrossDomain) Name() string { return "crossdomain" }

// Level implements Module.
// Runs once per host.
func (CrossDomain) Level() Level { return LevelHost }

// crossDomainPaths are the two policy locations this module asks for on its own
// account, and they are a table rather than two literals for the same reason
// `defaultGraphQLPaths` and `defaultOpenAPIPaths` are: the interesting-paths
// measurement subtracts the paths a detector owns, and it reads that set from the
// package's own tables so a path added to one is subtracted from the next run
// without the test being touched.
var crossDomainPaths = []string{"/crossdomain.xml", "/clientaccesspolicy.xml"}

func (c CrossDomain) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	parsed, err := url.Parse(p.URL)
	if err != nil || parsed.Host == "" {
		return nil
	}

	var out []Finding

	// Check 1: /crossdomain.xml (0x00200400)
	flashURL := fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, crossDomainPaths[0])
	respFlash, err := t.Do(ctx, http.MethodGet, flashURL, nil, false, nil)
	if err == nil && respFlash != nil && respFlash.StatusCode == http.StatusOK {
		lowerBody := strings.ToLower(respFlash.Body)
		if strings.Contains(lowerBody, "<cross-domain-policy>") && strings.Contains(lowerBody, `domain="*"`) {
			finding, _ := NewFinding(Spec{
				Module:      "crossdomain",
				Title:       "Flash Cross-Domain Policy Allows Arbitrary Domains",
				Claimed:     SeverityMedium,
				Tier:        TierVerified,
				Point:       Point{URL: flashURL, Method: http.MethodGet, Origin: p.Origin},
				Payload:     "GET " + flashURL,
				Evidence:    Snippet(respFlash.Body, `domain="*"`, 150),
				Description: "The /crossdomain.xml file contains a wildcard (<allow-access-from domain=\"*\"/>). Any external Flash applet or SWF object can read cross-origin data from this application.",
				Remediation: "Remove the wildcard policy or restrict domain attributes to trusted origins only. If Flash is no longer required, remove crossdomain.xml entirely.",
			})
			out = append(out, finding)
		}
	}

	// Check 2: /clientaccesspolicy.xml (0x00200500)
	slURL := fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, crossDomainPaths[1])
	respSL, err := t.Do(ctx, http.MethodGet, slURL, nil, false, nil)
	if err == nil && respSL != nil && respSL.StatusCode == http.StatusOK {
		lowerBody := strings.ToLower(respSL.Body)
		if strings.Contains(lowerBody, "<access-policy>") && strings.Contains(lowerBody, `uri="*"`) {
			finding, _ := NewFinding(Spec{
				Module:      "crossdomain",
				Title:       "Silverlight Cross-Domain Policy Allows Arbitrary Domains",
				Claimed:     SeverityMedium,
				Tier:        TierVerified,
				Point:       Point{URL: slURL, Method: http.MethodGet, Origin: p.Origin},
				Payload:     "GET " + slURL,
				Evidence:    Snippet(respSL.Body, `uri="*"`, 150),
				Description: "The /clientaccesspolicy.xml file contains a wildcard (<domain uri=\"*\"/>). Any external Silverlight application can read cross-origin data.",
				Remediation: "Restrict the URI attribute in clientaccesspolicy.xml to authorized origins or remove the policy file if Silverlight is not supported.",
			})
			out = append(out, finding)
		}
	}

	return out
}

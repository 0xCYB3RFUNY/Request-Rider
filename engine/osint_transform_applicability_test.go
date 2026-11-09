package main

import (
	"context"
	"sort"
	"strings"
	"testing"
)

// The values below were measured against a real `.ru` site; see the
// DEVELOPMENT_LOG.md entry of 2026-09-29 for the recorded run.

const (
	matrixDomain    = "pravda.ru"
	matrixSubdomain = "www.pravda.ru"
	matrixIP        = "94.137.92.20"
	matrixCIDR      = "94.137.92.0/24"
	matrixURL       = "https://www.pravda.ru/"
	matrixEmail     = "home@pravda.ru"
	matrixUsername  = "github"
	matrixPort      = "443"
	matrixASN       = "AS12389"
	matrixTech      = "cloudflare"
	matrixBucket    = "pravda-media"
)

// A declared entity type is the strong signal: the answer is exact, and it does not
// depend on being able to recognise the value.
func TestDeclaredEntityTypeIsAcceptedOnlyWhereTheRegistrySaysSo(t *testing.T) {
	for _, item := range transformRegistry {
		accepts := transformAccepts(item)
		if len(accepts) == 0 {
			t.Fatalf("%s declares no accepted kinds", item["id"])
		}
		seen := map[string]bool{}
		for _, kind := range accepts {
			if !knownEntityKinds[kind] {
				t.Fatalf("%s accepts %q, which is not an entity kind", item["id"], kind)
			}
			if seen[kind] {
				t.Fatalf("%s lists %q twice", item["id"], kind)
			}
			seen[kind] = true
			input := osintTransformInput{
				Transform: item["id"].(string), Value: matrixValueForKind(kind), EntityType: kind,
			}
			if code, message, ok := transformApplicabilityError(&input); !ok {
				t.Fatalf("%s refused its own kind %q: %s %s", item["id"], kind, code, message)
			}
		}
		kinds := make([]string, 0, len(knownEntityKinds))
		for kind := range knownEntityKinds {
			if !seen[kind] {
				kinds = append(kinds, kind)
			}
		}
		sort.Strings(kinds)
		for _, kind := range kinds {
			input := osintTransformInput{
				Transform: item["id"].(string), Value: matrixValueForKind(kind), EntityType: kind,
			}
			code, message, ok := transformApplicabilityError(&input)
			if ok {
				t.Fatalf("%s accepted a %s entity it does not accept (%s)", item["id"], kind, accepts)
			}
			if code != "TRANSFORM_NOT_APPLICABLE" || !strings.Contains(message, kind) {
				t.Fatalf("%s on a %s entity = %s %q, want a named refusal", item["id"], kind, code, message)
			}
		}
	}
}

// matrixValueForKind gives every entity kind a value of its own shape, so the
// declared-type test cannot pass by accident on a value of the wrong shape.
func matrixValueForKind(kind string) string {
	switch kind {
	case "domain":
		return matrixDomain
	case "subdomain":
		return matrixSubdomain
	case "ip":
		return matrixIP
	case "cidr":
		return matrixCIDR
	case "url":
		return matrixURL
	case "email":
		return matrixEmail
	case "username":
		return matrixUsername
	case "asn":
		return matrixASN
	case "certificate":
		return matrixDomain
	case "technology":
		return matrixTech
	case "port":
		return matrixPort
	case "cloud_asset":
		return matrixBucket
	default:
		return "value"
	}
}

// The seventeen pairs the application offers and that work today must keep passing
// validation, or this change has broken the product it was meant to protect.
func TestEveryWorkingOfferedPairStillPassesValidation(t *testing.T) {
	offered := [][2]string{
		{"url_host", matrixURL},
		{"domain_normalize", matrixDomain},
		{"domain_normalize", matrixSubdomain},
		{"subdomains", matrixDomain},
		{"subdomains", matrixSubdomain},
		{"dns_records", matrixDomain},
		{"dns_records", matrixSubdomain},
		{"wayback_urls", matrixDomain},
		{"wayback_urls", matrixSubdomain},
		{"wayback_urls", matrixURL},
		{"s3_buckets", matrixDomain},
		{"reverse_dns", matrixIP},
		{"reverse_dns", matrixSubdomain},
		{"ip_geo", matrixIP},
		{"email_recon", matrixEmail},
		{"email_domain", matrixEmail},
		{"username_normalize", matrixUsername},
		{"username_enum", matrixUsername},
		{"github_recon", matrixUsername},
	}
	for _, pair := range offered {
		input := osintTransformInput{Transform: pair[0], Value: pair[1]}
		if code, message, ok := transformApplicabilityError(&input); !ok {
			t.Fatalf("offered pair %s(%s) was refused: %s %s", pair[0], pair[1], code, message)
		}
	}
}

// Two pairs the application offers do not work: `domain_normalize` on a URL entity
// and `ip_geo` on a CIDR entity both failed on well-formed values in the live run
// (INVALID_DOMAIN and INVALID_IP). They are named here so the failure is a pinned
// fact and a fix is a one-line change to this list, rather than a silent widening of
// `accepts` that would make a broken button look healthy.
func TestTwoOfferedPairsArePinnedAsProductBugs(t *testing.T) {
	broken := [][3]string{
		{"domain_normalize", matrixURL, "url"},
		{"ip_geo", matrixCIDR, "cidr"},
	}
	for _, pair := range broken {
		input := osintTransformInput{Transform: pair[0], Value: pair[1]}
		code, _, ok := transformApplicabilityError(&input)
		if ok {
			t.Fatalf("%s(%s) is listed as broken but validation now accepts it — "+
				"if the transform was fixed, remove it from this list", pair[0], pair[1])
		}
		if code != "TRANSFORM_NOT_APPLICABLE" {
			t.Fatalf("%s(%s) = %s, want TRANSFORM_NOT_APPLICABLE", pair[0], pair[1], code)
		}
	}
}

// The class the live matrix exposed: a value that is not a name, sent to a transform
// that needs a name, used to walk the certificate indexes and the DNS. The refusal
// has to come from the transform entry point, before the body runs.
func TestTransformRefusesValuesNoReadingMakesValid(t *testing.T) {
	cases := [][2]string{
		{"subdomains", matrixPort},
		{"subdomains", matrixTech},
		{"subdomains", matrixASN},
		{"subdomains", matrixBucket},
		{"dns_records", matrixPort},
		{"dns_records", matrixTech},
		{"wayback_urls", matrixPort},
		{"wayback_urls", matrixTech},
		{"s3_buckets", matrixPort},
		{"s3_buckets", matrixTech},
		{"reverse_dns", matrixPort},
		{"reverse_dns", matrixTech},
		{"domain_normalize", matrixPort},
		{"domain_normalize", matrixASN},
		{"ip_geo", matrixPort},
		{"ip_geo", matrixTech},
		{"url_host", matrixPort},
		{"email_recon", matrixPort},
		{"email_domain", matrixPort},
	}
	for _, pair := range cases {
		_, err := (&server{}).runOSINTTransform(context.Background(), osintTransformInput{
			Transform: pair[0], Value: pair[1], ConfirmNetwork: true,
		})
		if err == nil {
			t.Fatalf("%s(%q) ran, want TRANSFORM_NOT_APPLICABLE", pair[0], pair[1])
		}
		if !strings.Contains(err.Error(), "TRANSFORM_NOT_APPLICABLE") {
			t.Fatalf("%s(%q) = %v, want TRANSFORM_NOT_APPLICABLE", pair[0], pair[1], err)
		}
	}
}

// An opaque kind is exactly what a shape-based classifier cannot recognise, so a
// transform that works on usernames keeps its own value validation instead of being
// refused by a guess. `github_recon("443")` is therefore still allowed to run: GitHub
// answers that lookup with a real account, so whether an operator should be able to
// ask for it is a question for the owner, not something this check may decide.
func TestOpaqueAcceptsFallBackToTheTransformsOwnValidation(t *testing.T) {
	for _, pair := range [][2]string{
		{"github_recon", matrixUsername},
		{"github_recon", matrixPort},
		{"username_enum", matrixPort},
		{"username_normalize", matrixTech},
	} {
		input := osintTransformInput{Transform: pair[0], Value: pair[1]}
		if code, message, ok := transformApplicabilityError(&input); !ok {
			t.Fatalf("%s(%q) was refused as inapplicable: %s %s", pair[0], pair[1], code, message)
		}
	}
}

// A domain is not a username, and the transform used to say "completed" and write a
// `username` entity holding a domain the graph already had. A dotted username is
// real and stays valid.
func TestUsernameTransformRejectsADomainAndKeepsADottedUsername(t *testing.T) {
	server := &server{}
	for _, transform := range []string{"username_enum", "username_normalize"} {
		// A domain-shaped value is refused with a reason that names what it is,
		// because the character pattern accepts it and the operator would otherwise
		// be told nothing useful.
		for _, value := range []string{matrixDomain, matrixSubdomain} {
			_, err := server.runOSINTTransform(context.Background(), osintTransformInput{
				Transform: transform, Value: value,
			})
			if err == nil {
				t.Fatalf("%s(%q) ran, want INVALID_USERNAME", transform, value)
			}
			if !strings.Contains(err.Error(), "INVALID_USERNAME") ||
				!strings.Contains(err.Error(), "domain") {
				t.Fatalf("%s(%q) = %v, want INVALID_USERNAME naming the domain", transform, value, err)
			}
		}
		// An address is refused too, on its own ground: the "@" is not a character a
		// username may contain, and saying so is more useful than saying it looks
		// like a domain.
		_, err := server.runOSINTTransform(context.Background(), osintTransformInput{
			Transform: transform, Value: matrixEmail,
		})
		if err == nil || !strings.Contains(err.Error(), "INVALID_USERNAME") {
			t.Fatalf("%s(%q) = %v, want INVALID_USERNAME", transform, matrixEmail, err)
		}
		for _, value := range []string{"john.doe", "analyst_01", matrixUsername} {
			result, err := server.runOSINTTransform(context.Background(), osintTransformInput{
				Transform: transform, Value: value,
			})
			if err != nil {
				t.Fatalf("%s(%q) = %v, want a result", transform, value, err)
			}
			if len(result.Entities) != 1 || result.Entities[0].Type != "username" {
				t.Fatalf("%s(%q) result = %#v", transform, value, result.Entities)
			}
		}
	}
}

// The classifier is what the undeclared path leans on, so its reading of every real
// value is pinned here. A wrong reading would refuse a pair the product offers, and
// the refusal would look like a regression rather than a misclassification.
func TestClassifierReadsEveryMatrixValue(t *testing.T) {
	cases := map[string]string{
		matrixIP:        transformKindIP,
		matrixCIDR:      transformKindCIDR,
		matrixURL:       transformKindURL,
		matrixEmail:     transformKindEmail,
		matrixDomain:    transformKindDomain,
		matrixSubdomain: transformKindDomain,
		matrixPort:      "",
		matrixASN:       "",
		matrixTech:      "",
		matrixBucket:    "",
		matrixUsername:  "",
		// A URL carrying credentials is still a URL as far as the shape reader is
		// concerned; refusing its credentials is `url_host`'s own validation, and
		// duplicating that here would give the operator the reason from the wrong place.
		"https://user:pass@example.com/": transformKindURL,
		"":                               "",
		// A reserved zone is a real name for a lab. Refusing it here would be
		// zone-based blocking, so these classify as domains even though no authority
		// delegates them — the fixtures the engine's own tests run on depend on it.
		"example.test": transformKindDomain,
		"pravda.test":  transformKindDomain,
		// The graph folds case; the classifier has to fold it with the same rule, or
		// `Yandex.RU` reads as an unknown name.
		"Yandex.RU": transformKindDomain,
	}
	for value, want := range cases {
		if got := classifyTransformValue(value); got != want {
			t.Fatalf("classify(%q) = %q, want %q", value, got, want)
		}
	}
}

// The two rules that answer "domain or dotted username" are deliberately different,
// and this pins both halves of the difference.
//
// The username rule asks the Public Suffix List, so it refuses a name under a
// delegated zone and keeps a dotted label. The classifier does not, so a reserved
// zone stays a domain. Neither half may be quietly widened into the other: widening
// the classifier to the delegated zones would refuse `example.test` and every lab
// name, and narrowing the username rule to a dot would refuse `john.doe`.
func TestDomainOrDottedUsernameIsSplitByZoneDelegation(t *testing.T) {
	server := &server{}
	refused := []string{matrixDomain, matrixSubdomain, "a.co.uk", "Yandex.RU", matrixURL, matrixIP, matrixCIDR, matrixEmail}
	for _, value := range refused {
		_, err := server.runOSINTTransform(context.Background(), osintTransformInput{
			Transform: "username_enum", Value: value,
		})
		if err == nil || !strings.Contains(err.Error(), "INVALID_USERNAME") {
			t.Fatalf("username_enum(%q) = %v, want INVALID_USERNAME", value, err)
		}
	}
	// A dotted label is a username. A name under a reserved zone is accepted here
	// too, and that is the cost of not blocking on zones: the declared entity type is
	// what settles it, and it is what the application will start sending.
	accepted := []string{"john.doe", "ivan.petrov", "analyst_01", "example_user", matrixUsername, "example.test", "dev.local"}
	for _, value := range accepted {
		result, err := server.runOSINTTransform(context.Background(), osintTransformInput{
			Transform: "username_enum", Value: value,
		})
		if err != nil {
			t.Fatalf("username_enum(%q) = %v, want a result", value, err)
		}
		if len(result.Entities) != 1 || result.Entities[0].Type != "username" {
			t.Fatalf("username_enum(%q) result = %#v", value, result.Entities)
		}
	}
}

// The refusal has to reach the caller as a code, not only as a sentence inside the
// message. A caller that cannot recognise `TRANSFORM_NOT_APPLICABLE` reports an
// ordinary failure and offers a retry that cannot work; `INVALID_USERNAME` is in the
// same position, because the transform used to answer "completed" and the operator
// had no signal at all. An unrecognised code stays generic, so a caller is never
// handed a string it was not taught.
func TestRefusalCodesReachTheCallerAsCodes(t *testing.T) {
	for _, testCase := range []struct{ message, want string }{
		{"TRANSFORM_NOT_APPLICABLE: subdomains needs a domain", "TRANSFORM_NOT_APPLICABLE"},
		{"INVALID_USERNAME: value is a domain name, not a username", "INVALID_USERNAME"},
		{"NETWORK_CONFIRMATION_REQUIRED: this transform performs a network request", "NETWORK_CONFIRMATION_REQUIRED"},
		{"GITHUB_LOOKUP_FAILED: rate limited", "OSINT_TRANSFORM_FAILED"},
		{"", "OSINT_TRANSFORM_FAILED"},
	} {
		if got := promotedTransformErrorCode(testCase.message); got != testCase.want {
			t.Fatalf("promotedTransformErrorCode(%q) = %q, want %q", testCase.message, got, testCase.want)
		}
	}
}

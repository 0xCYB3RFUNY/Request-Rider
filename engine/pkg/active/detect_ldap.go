// LDAP injection.
//
// # The technique that is actually decisive
//
// An LDAP filter is a parenthesised expression grammar, and its most useful
// property to an attacker is not an error message but a wildcard: `(&(uid=*))`
// matches every account, and `(&(uid=a*)(|(uid=*))))` matches every account whose
// name starts with `a`. That is the difference between a filter that is
// concatenated and a filter that is built, and it is observable without any error
// being raised at all — which is why the wildcard probe is the first technique
// here and not a second one.
//
// The error signatures follow, and they are the reason this detector can claim
// verification. Upstream's `ldap_injection/errors.txt` is twenty-nine strings
// across four stacks — Java `javax.naming`, the Apache directory client,
// OpenLDAP and Microsoft's `IPWorksASP` — and each of them is a string a server
// emits *because it tried to parse the submitted filter and could not*. That is
// stronger than a behaviour change: the server has said, in its own words, that
// the input reached a filter.
//
// # Why the stack is reported rather than discarded
//
// "Invalid DN syntax" is a useful sentence to an operator and a useless one to a
// report. The stack behind it decides what to do next: `javax.naming` means the
// application's own code built the filter, `IPWorksASP` means a third-party ASP
// component did, and those two have different owners and different fixes. So the
// grouping is carried through to the finding rather than flattened into the
// evidence string, exactly as in the XPath detector.
package active

import (
	"context"
	"fmt"
	"strings"
)

// ldapErrorSignatures are the directory-server parse errors, grouped by stack.
//
// Every entry here is one of the twenty-nine strings in upstream's
// `ldap_injection/errors.txt`, with the stack each belongs to made explicit.
// Nothing has been added and nothing has been paraphrased: OpenLDAP's
// capitalisation and phrasing are preserved verbatim, because a signature tidied
// into house style stops matching the only server that emits it.
//
// Upstream's list contains no Active Directory entry, and none is invented here.
// Guessing at an ADSI message is how a signature table fills with strings that
// match nothing, and an invented entry is indistinguishable in the table from a
// measured one — so the gap is left visible instead of papered over.
var ldapErrorSignatures = []struct {
	stack     string
	signature string
}{
	// Java / JNDI.
	{"Java JNDI", "supplied argument is not a valid ldap"},
	{"Java JNDI", "javax.naming.NameNotFoundException"},
	{"Java JNDI", "javax.naming.directory.InvalidSearchFilterException"},
	{"Java JNDI", "com.sun.jndi.ldap"},
	{"Java JNDI", "LDAPException"},
	// OpenLDAP and slapd.
	{"OpenLDAP", "Search: Bad search filter"},
	{"OpenLDAP", "Protocol error occurred"},
	{"OpenLDAP", "Size limit has exceeded"},
	{"OpenLDAP", "An inappropriate matching occurred"},
	{"OpenLDAP", "A constraint violation occurred"},
	{"OpenLDAP", "The syntax is invalid"},
	{"OpenLDAP", "Object does not exist"},
	{"OpenLDAP", "The alias is invalid"},
	{"OpenLDAP", "The distinguished name has an invalid syntax"},
	{"OpenLDAP", "The server does not handle directory requests"},
	{"OpenLDAP", "There was a naming violation"},
	{"OpenLDAP", "There was an object class violation"},
	{"OpenLDAP", "Results returned are too large"},
	{"OpenLDAP", "Unknown error occurred"},
	{"OpenLDAP", "Local error occurred"},
	{"OpenLDAP", "The search filter is incorrect"},
	{"OpenLDAP", "The search filter is invalid"},
	{"OpenLDAP", "The search filter cannot be recognized"},
	{"OpenLDAP", "Invalid DN syntax"},
	{"OpenLDAP", "No Such Object"},
	// Third-party components, which are worth naming separately because they are
	// a licensing and version problem rather than an application one.
	{"IPWorks ASP", "IPWorksASP.LDAP"},
	{"IPWorks ASP", "Module Products.LDAPMultiPlugins"},
}

// ldapWildcardProbes are the filters that widen a match.
//
// `*` alone is the first and it is a separate probe rather than part of the
// boolean pair because it needs no boolean at all: on a filter that is
// concatenated, a wildcard matches accounts the injected value could not have
// matched. `*)(uid=*` is the shape that actually breaks out of a filter written
// as `(&(uid=<here>))`, and `)(|(uid=*` breaks out of the commoner
// `(&(uid=<here>)(objectClass=person)))` form by closing the first `&` and opening
// an `|`.
var ldapWildcardProbes = []struct {
	name    string
	payload string
}{
	{"wildcard", `*`},
	{"filter break", `*)(uid=*`},
	{"or break", `)(|(uid=*`},
	{"not break", `)(!(&(uid=*`},
}

// ldapDecoy converts a filter fragment into one of the same shape that cannot
// widen a match.
//
// The substitution is `*` → `z`: the decoy has the same parentheses, the same
// attribute name and the same length as the probe, so a response that differs
// between them differs because of the wildcard and not because the input was a
// different string. Every character a filter fragment is built from survives the
// substitution, which is the point — a decoy with different punctuation would
// itself change the parse on a vulnerable target.
func ldapDecoy(payload string) string {
	return strings.ReplaceAll(payload, "*", "z")
}

// LDAP is the LDAP injection detector.
type LDAP struct{}

// Name implements Module.
func (LDAP) Name() string { return "ldap" }

// Level implements Module.
func (LDAP) Level() Level { return LevelParam }

// Scan probes one surface: wildcard widening first, then parser disclosure.
func (m LDAP) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if finding := ldapWildcardProbe(ctx, t, p, baseline); finding != nil {
		return []Finding{*finding}
	}
	if finding := ldapErrorProbe(ctx, t, p, baseline); finding != nil {
		return []Finding{*finding}
	}
	return nil
}

// ldapWildcardProbe looks for a filter that returns more than the original value
// would have returned.
//
// The claim is capped. A widened result set is the ordinary shape of this bug and
// it is also the shape of an application whose list re-sorts on input, so the row
// is reported at `TierPotential` — the surface is real and the triager is owed the
// hint, but nothing in a widened page proves a filter was parsed.
func ldapWildcardProbe(ctx context.Context, t *Transport, p Point, baseline *Response) *Finding {
	if baseline == nil {
		return nil
	}
	for _, probe := range ldapWildcardProbes {
		if ctx.Err() != nil {
			return nil
		}
		resp, err := t.Fire(ctx, p, p.Param, probe.payload, false, nil)
		if err != nil {
			continue
		}
		// The decoy, for the same reason the NoSQL operator probe has one and for
		// the same discovered reason: comparing against the unmodified page alone
		// credits **every** page that echoes its input, because the echoed
		// fragment is itself a difference. An echo is removed from both responses
		// before they are compared, so what is left is the result set.
		decoyPayload := ldapDecoy(probe.payload)
		decoy, decoyErr := t.Fire(ctx, p, p.Param, decoyPayload, false, nil)
		if decoyErr != nil || decoy == nil {
			continue
		}
		divergence := Divergence(stripEcho(decoy.Body, decoyPayload), stripEcho(resp.Body, probe.payload))
		if divergence < ldapDivergenceFloor {
			continue
		}
		// The widening has to be there when the same pair is asked again; see
		// `confirmDivergence`. Without it a target that merely answered differently
		// once produced a row, which is what a live run against a real site showed.
		if !confirmDivergence(ctx, t, p, probe.payload, decoyPayload, ldapDivergenceFloor) {
			continue
		}
		finding, _ := NewFinding(Spec{
			Module:  "ldap",
			Title:   "LDAP Injection (filter widening, " + probe.name + ")",
			Claimed: SeverityHigh,
			Tier:    TierPotential,
			Point:   p,
			Payload: probe.payload,
			Evidence: fmt.Sprintf("the submitted filter fragment changes the result by %.3f relative to a "+
				"same-shape fragment with no wildcard, with both echoed values removed, so the "+
				"difference is in the accounts matched rather than in the echo", divergence),
			Description: "The parameter appears to reach an LDAP search filter. A submitted wildcard or a " +
				"submitted closing parenthesis changes what the filter matches, which is consistent with the " +
				"value being concatenated into the expression. The row is capped because a page that reorders " +
				"on input produces the same difference with no injection behind it.",
			Remediation: "Escape the value as an LDAP filter component before assembling the filter — " +
				"RFC 4515 lists the characters that must be escaped — or bind the search value as a " +
				"parameter rather than concatenating it.",
		})
		return &finding
	}
	return nil
}

// ldapDivergenceFloor is how far a widened result has to move the document before
// it is credited.
//
// It is the same argument as the NoSQL operator floor and the same number: the
// row it produces is capped, so the floor exists to stop a nonce from being
// reported, not to decide whether a finding is real.
const ldapDivergenceFloor = 0.001

// ldapErrorProbe looks for the directory server saying the filter did not parse.
//
// This is the verified path: the message names a failure to parse the submitted
// filter, which is the server reporting that the input reached it. `FreshFold` is
// applied for the same reason as everywhere else — several of these strings are
// quotable in a document about directory integration, and a page that documents
// its own errors is not a page with an injection.
func ldapErrorProbe(ctx context.Context, t *Transport, p Point, baseline *Response) *Finding {
	// The payload that provokes a parse failure is the same one for every stack:
	// an unbalanced parenthesis terminates the expression the application
	// assembled, so the server has to reject it.
	payload := `)(|(objectClass=*`
	resp, err := t.Fire(ctx, p, p.Param, payload, false, nil)
	if err != nil {
		return nil
	}
	for _, entry := range ldapErrorSignatures {
		if !FreshFold(baseline, resp, entry.signature) {
			continue
		}
		finding, _ := NewFinding(Spec{
			Module:   "ldap",
			Title:    "LDAP Injection (directory error, " + entry.stack + ")",
			Claimed:  SeverityHigh,
			Tier:     TierVerified,
			Point:    p,
			Payload:  payload,
			Evidence: Snippet(resp.Body, entry.signature, 140),
			Description: "The submitted value was parsed as part of a directory search filter and the server " +
				"reported a filter failure in its own words. The signature was absent from the unmodified " +
				"response, so the failure is a consequence of the injection. The stack named in the title (" +
				entry.stack + ") tells the operator whether the filter is assembled by application code or " +
				"by a third-party component, which is where the fix belongs.",
			Remediation: "Escape each value as a filter component per RFC 4515 and assemble the filter from " +
				"the escaped components. Never concatenate a raw parameter into a search filter.",
		})
		return &finding
	}
	return nil
}

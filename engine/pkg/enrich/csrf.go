package enrich

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"sort"
	"strings"
)

// CSRFKind classifies why a form is or is not protected.
type CSRFKind string

const (
	// CSRFNoForm is reported when a page has forms at all but none was
	// collected. It exists so the status line can say "no forms on this page"
	// instead of "no CSRF problems found", which are different claims.
	CSRFNoForm CSRFKind = "no_form"
	// CSRFInsecure is a form that changes state and carries no anti-CSRF token
	// and no SameSite cookie. This is the finding.
	CSRFInsecure CSRFKind = "insecure"
	// CSRFSameSiteOnly is a form protected by cookie attributes alone. Weaker
	// than a token, and worth naming separately because it reads as protected
	// in every other tool.
	CSRFSameSiteOnly CSRFKind = "samesite_only"
	// CSRFWeakToken is a form with a token that does not vary: it is
	// predictable, static across pages, or reused across URLs.
	CSRFWeakToken CSRFKind = "weak_token"
	// CSRFTokenPresent is a form whose token varies per page. Reported too, so
	// the map shows what was checked rather than only what failed.
	CSRFTokenPresent CSRFKind = "token_present"
)

// CSRFTokenVerdict is what can be said about one token value.
type CSRFTokenVerdict struct {
	// Length is the character count of the value.
	Length int `json:"length"`
	// ShannonEntropy is bits per character. A token of many repeats has low
	// entropy even at a large length, which is why length alone is not the test.
	ShannonEntropy float64 `json:"entropy"`
	// HashType names the shape of the value when it is recognised, e.g. `md5`
	// for a 32-hex-digit token. Empty when unrecognised.
	HashType string `json:"hash_type,omitempty"`
	// Digits and Letters count the two character classes, which together
	// separate a real token from a page counter.
	Digits  int `json:"digits"`
	Letters int `json:"letters"`
	// Weak lists the specific reasons, so a verdict is never just "weak".
	Weak []string `json:"weak,omitempty"`
}

// CSRFIssue is one form's verdict.
type CSRFIssue struct {
	Kind   CSRFKind          `json:"kind"`
	Form   string            `json:"form,omitempty"`
	Method string            `json:"method,omitempty"`
	Field  string            `json:"field,omitempty"`
	Token  *CSRFTokenVerdict `json:"token,omitempty"`
	Reason string            `json:"reason,omitempty"`
	Forms  []string          `json:"forms,omitempty"`
}

// CSRFReport is the whole verdict for one page.
type CSRFReport struct {
	Issues   []CSRFIssue `json:"issues"`
	Forms    int         `json:"forms"`
	Findings int         `json:"findings"`
	Reused   []CSRFReuse `json:"reused,omitempty"`
}

// CSRFReuse names one token value seen on more than one form.
type CSRFReuse struct {
	Value string   `json:"value"`
	Forms []string `json:"forms"`
}

// csrfFieldRe recognises the conventional token parameter names.
//
// Port of the capability, not the code: `s0md3v/Bolt`
// (`core/evaluate.py`, commit 37aa096db93e026f0524fe94c67dc1dae8985f3e) is GPL-3.0
// and is a CSRF scanner, not the URL fuzzer it was described as; the capability
// worth having is "collect token-looking fields from forms and judge them", and
// that is what is re-implemented here.
//
// The list is longer than upstream's, because a token field is frequently named
// after the library that documents it rather than after CSRF.
var csrfFieldNames = []string{
	"csrf", "csrfmiddlewaretoken", "csrf_token", "csrftoken", "xsrf",
	"xsrftoken", "_csrf", "_token", "__requesttoken", "__token",
	"authenticity_token", "requestverificationtoken", "antiforgerytoken",
	"verificationtoken", "_csrf_token", "csrfmiddleware", "csrfkey",
	"formtoken", "validate", "validation", "token",
}

// CSRFAssess judges every state-changing form in an HTML document.
//
// The judgement order is the point of this function and it is not arbitrary:
//
//  1. no form at all → nothing to say;
//  2. a form with no token and no SameSite → insecure;
//  3. a form with a token → judge the token, because a token that never varies
//     is worse than no token, since it reads as protection in every other tool;
//  4. a form with SameSite only → named separately, because it is genuinely
//     weaker than a token and a report that calls it "protected" is wrong.
//
// `sameSiteCookies` is what the response actually set, passed in by the caller:
// this function sees a body, and a `Set-Cookie` header is not in a body.
func CSRFAssess(body string, sameSiteCookies bool) CSRFReport {
	forms := collectForms(body)
	report := CSRFReport{Forms: len(forms)}
	if len(forms) == 0 {
		report.Issues = append(report.Issues, CSRFIssue{Kind: CSRFNoForm})
		return report
	}
	byValue := map[string][]string{}
	for _, form := range forms {
		method := strings.ToUpper(form.method)
		if method == "" {
			method = "GET"
		}
		if method == "GET" {
			// A GET form does not change state, so a missing token on it is not
			// a finding. Counting it would report every search box on a site as
			// an insecure form.
			continue
		}
		token, field := formToken(form)
		switch {
		case token == "" && !sameSiteCookies:
			report.Issues = append(report.Issues, CSRFIssue{
				Kind: CSRFInsecure, Form: form.action, Method: method,
				Reason: "state-changing form with no anti-CSRF token and no SameSite cookie",
			})
		case token == "":
			report.Issues = append(report.Issues, CSRFIssue{
				Kind: CSRFSameSiteOnly, Form: form.action, Method: method,
				Reason: "protected by cookie attributes only",
			})
		default:
			verdict := JudgeToken(token)
			byValue[token] = append(byValue[token], form.action)
			kind := CSRFTokenPresent
			reason := ""
			if len(verdict.Weak) > 0 {
				kind = CSRFWeakToken
				reason = strings.Join(verdict.Weak, "; ")
			}
			report.Issues = append(report.Issues, CSRFIssue{
				Kind: kind, Form: form.action, Method: method, Field: field,
				Token: &verdict, Reason: reason,
			})
		}
	}
	for value, formsOf := range byValue {
		if len(formsOf) < 2 {
			continue
		}
		report.Reused = append(report.Reused, CSRFReuse{
			Value: maskToken(value), Forms: formsOf,
		})
	}
	sort.Slice(report.Reused, func(i, j int) bool { return report.Reused[i].Value < report.Reused[j].Value })
	report.Findings = len(report.Issues)
	return report
}

type formTag struct {
	action string
	method string
	inputs map[string]string
}

// collectForms reads forms and their inputs from a document.
func collectForms(body string) []formTag {
	// One walk, not a nested one: an inner full-document scan per form would be
	// quadratic and would read every input on the page into every form.
	var out []formTag
	var current *formTag
	forEachTag(body, func(tag string, attrs map[string]string, closing bool) {
		if closing {
			if tag == "form" && current != nil {
				out = append(out, *current)
				current = nil
			}
			return
		}
		switch tag {
		case "form":
			if current != nil {
				// An unclosed form: close it where the next one begins rather
				// than merging two forms into one.
				out = append(out, *current)
			}
			current = &formTag{
				action: strings.TrimSpace(attrs["action"]),
				method: strings.TrimSpace(attrs["method"]),
				inputs: map[string]string{},
			}
		case "input", "button":
			if current == nil {
				return
			}
			name := strings.ToLower(strings.TrimSpace(attrs["name"]))
			if name == "" {
				return
			}
			if strings.EqualFold(attrs["type"], "submit") && attrs["value"] == "" {
				return
			}
			if _, exists := current.inputs[name]; !exists {
				current.inputs[name] = attrs["value"]
			}
		}
	})
	if current != nil {
		out = append(out, *current)
	}
	return out
}

// formToken returns the first token-looking field value and its name.
func formToken(form formTag) (value, name string) {
	best := ""
	for _, candidate := range csrfFieldNames {
		if v, ok := form.inputs[candidate]; ok && len(v) >= 6 {
			return v, candidate
		}
		if v, ok := form.inputs[candidate]; ok && v != "" && len(best) == 0 {
			best = v
		}
	}
	if best != "" {
		return best, "token"
	}
	return "", ""
}

// JudgeToken scores one token value and says why, if it is weak.
//
// The reasons are what make this useful. "Weak" on its own is a word; "32 hex
// digits, entropy 3.5 bits/char, reused on four forms" is a sentence an analyst
// can act on, and the difference is the whole reason this function returns a
// list rather than a bool.
func JudgeToken(value string) CSRFTokenVerdict {
	verdict := CSRFTokenVerdict{
		Length:   len(value),
		HashType: detectTokenHash(value),
	}
	if value == "" {
		verdict.Weak = append(verdict.Weak, "empty token")
		return verdict
	}
	for _, c := range value {
		switch {
		case c >= '0' && c <= '9':
			verdict.Digits++
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			verdict.Letters++
		}
	}
	verdict.ShannonEntropy = shannonEntropy(value)

	if verdict.Length < 16 {
		verdict.Weak = append(verdict.Weak, "shorter than 16 characters")
	}
	// Entropy, not length: 32 identical characters are long and worthless.
	if verdict.ShannonEntropy < 2.5 {
		verdict.Weak = append(verdict.Weak, "entropy below 2.5 bits per character")
	}
	if verdict.Digits == 0 || verdict.Letters == 0 {
		verdict.Weak = append(verdict.Weak, "uses only one character class")
	}
	if isCounterLike(value) {
		verdict.Weak = append(verdict.Weak, "value reads as a counter or a timestamp")
	}
	// A *shape* is not evidence. Per-request tokens are routinely 32 or 64 hex
	// digits, and judging every one of them weak turns this feature into noise:
	// the first version did exactly that and its own fixture flagged a correct
	// token. What is evidence is a value equal to a well-known constant, which
	// is a specific match rather than a length rule.
	if constant, known := knownConstantDigests[strings.ToLower(value)]; known {
		verdict.Weak = append(verdict.Weak,
			"value is the "+constant+" of the empty string, a constant found in thousands of templates")
	}
	return verdict
}

// knownConstantDigests are digests of the empty string. They appear in default
// configurations, in copied templates and in code that hashes "" instead of a
// random value. Matching the exact value is a fact; matching its length is not.
var knownConstantDigests = map[string]string{
	"d41d8cd98f00b204e9800998ecf8427e":                                 "MD5",
	"da39a3ee5e6b4b0d3255bfef95601890afd80709":                         "SHA-1",
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "SHA-256",
}

func shannonEntropy(value string) float64 {
	if value == "" {
		return 0
	}
	counts := map[rune]float64{}
	for _, r := range value {
		counts[r]++
	}
	total := float64(len([]rune(value)))
	entropy := 0.0
	for _, n := range counts {
		p := n / total
		entropy -= p * math.Log2(p)
	}
	return math.Round(entropy*1000) / 1000
}

func isHex(value string) bool {
	for _, c := range value {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// isCounterLike recognises values that a generator produced from a predictable
// step: all digits, or all digits and one non-digit.
func isCounterLike(value string) bool {
	digits, others := 0, 0
	for _, c := range value {
		if c >= '0' && c <= '9' {
			digits++
			continue
		}
		others++
	}
	if digits == 0 {
		return false
	}
	return others <= 1
}

// detectTokenHash names the digest shape of a value. Length plus alphabet is
// enough for the shapes that matter in a token field.
func detectTokenHash(value string) string {
	switch {
	case len(value) == 32 && isHex(value):
		return "md5"
	case len(value) == 40 && isHex(value):
		return "sha1"
	case len(value) == 64 && isHex(value):
		return "sha256"
	case len(value) == 128 && isHex(value):
		return "sha512"
	}
	return ""
}

// maskToken keeps a reused token identifiable in a report without publishing
// the value: first four characters plus a digest. The report is exported and
// emailed, and a full token in it is a credential in a document.
func maskToken(value string) string {
	if len(value) <= 4 {
		return strings.Repeat("*", len(value))
	}
	sum := sha256.Sum256([]byte(value))
	return value[:4] + "…" + hex.EncodeToString(sum[:])[:8]
}

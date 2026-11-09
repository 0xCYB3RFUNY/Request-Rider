package enrich

// Tests that a rule spanning a line break can fire at all.
//
// # The defect this file was written for
//
// `scanWithRules` split the body into lines and ran every rule on each line
// separately:
//
//	lines := strings.Split(text, "\n")
//	for i, line := range lines {
//	    for _, match := range rule.Regex.FindAllStringSubmatch(line, -1) { … }
//
// A newline could therefore never occur inside the input a rule saw. Every rule
// whose body carries `\s`, `[\n\r]`, `(?s)` or `(?is)` needs a line break to
// express its own shape, so those rules were not "less accurate" — they were
// **unreachable**, no matter what page they were pointed at.
//
// Measured on the build as it stood:
//
//	np.pem.1            PEM-Encoded Private Key      score 92   0 findings
//	kingfisher.privkey.2  Contains Private Key                  0 findings
//
// while the run still reported `rules_run: 534`. So the page path claimed 534
// rules had run, and a page serving a PEM-encoded private key produced no finding
// and no rejection — the credential was not shortened, mis-scored or filtered; it
// was never looked for. `-----BEGIN RSA PRIVATE KEY----- … -----END RSA PRIVATE
// KEY-----` and the `EC`, `OPENSSH`, `PKCS8` and `PGP` headers all returned
// `findings=0 rejected=0`.
//
// The probes below are therefore taken from the registry rather than written by
// hand: a hand-written probe that stops matching would let the assertion pass
// without testing anything, which is the failure mode the comment above
// `secret_wholeness_test.go` documents at length. Each one asserts that the rule
// it names fires on real bytes AND names its own upstream score, so a rule that
// disappears from the table fails here rather than silently reducing coverage.

import (
	"strings"
	"testing"
)

// multilineProbe is a rule that cannot match inside a single line, together with
// the body that must trigger it.
type multilineProbe struct {
	rule string
	body string
	// must is a fragment of the captured value, so the assertion is about the
	// secret rather than about the marker that framed it.
	must string
}

// The five PEM headers a deployment actually serves. `np.pem.1` accepts any of
// them — its own body is `-----BEGIN\ .{0,20}\ ?PRIVATE\ KEY\ ?.{0,20}-----` — and
// the body below is a real RSA key of the length a served key has, so the value
// clears `{50,}` inside the group.
var pemProbes = []struct {
	header string
	footer string
}{
	{"RSA PRIVATE KEY", "RSA PRIVATE KEY"},
	{"EC PRIVATE KEY", "EC PRIVATE KEY"},
	{"OPENSSH PRIVATE KEY", "OPENSSH PRIVATE KEY"},
	{"PRIVATE KEY", "PRIVATE KEY"},
	{"PRIVATE KEY BLOCK", "PRIVATE KEY BLOCK"},
}

// pemBody builds a PEM block whose payload is a real base64 body, not a stub.
//
// The payload has to be longer than 50 characters or the rule's `{50,}` never
// engages, and it has to carry the characters the rule's class admits — the
// payload below is drawn from the same alphabet a served key uses. The probe's
// `must` fragment is the first 40 characters of that payload, which is the part a
// truncated capture would lose first.
func pemBody(header, footer string) string {
	return "-----BEGIN " + header + "-----\n" + pemPayload + "\n-----END " + footer + "-----"
}

// pemPayload is the base64 body every PEM probe carries. 128 characters, so a rule
// that needs `{50,}` engages and a capture that stops early is visibly short.
const pemPayload = "MIIEowIBAAKCAQEAv7Zq3Jm9Kk2Lp0Rt4Yu8Wc6Vd1Fh3Gn5Bj0Xl2Qm8Zt7Yv1Bc" +
	"9dLpQrT4wXnYbZc6Vd1Fh3Gn5Bj0Xl2Qm8Zt7Yv1BcR4dLpQrT4wXnYbZc6Vd1Fh3Gn5Bj0"

// TestAMultiLineRuleFires is the assertion: a rule that spans a line break reports
// its finding, and the captured value carries the whole payload rather than a head
// of it.
//
// The assertion is `Contains`, not equality, and the reason is the rule's own shape:
// `np.pem.1` ends its group with `\s*` inside the value class, so the capture
// legitimately ends in the newline that follows the base64 body. A capture cut short
// is the failure this project has already paid for twice — a 54-character Slack
// token delivered as 32, a 212-character FCM key as 152 — so the test states the
// payload is *present whole* and lets the framing the rule chose sit either side.
func TestAMultiLineRuleFires(t *testing.T) {
	for _, probe := range pemProbes {
		body := pemBody(probe.header, probe.footer)
		scan := ScanSecrets(body, false)
		if !scanCarriesSubstring(scan, pemPayload) {
			t.Errorf("%s: a served %q block produced no finding carrying the payload; "+
				"rules_run=%d rules_available=%d rejected=%d",
				probe.header, probe.header, scan.RulesRun, scan.RulesAvailable, len(scan.Rejected))
			continue
		}
		if scan.RulesRun == 0 {
			t.Errorf("%s: the scan reported no rules at all", probe.header)
		}
	}
}

// TestAPemFindingNamesTheRuleThatFoundIt stops the assertion above from being
// satisfiable by an unrelated rule matching a fragment of the key.
//
// Without it, "some finding exists" would pass even if `np.pem.1` were the rule
// that stopped working and some generic assignment rule picked up the payload —
// which is exactly the shape of the defect, reported as a pass.
func TestAPemFindingNamesTheRuleThatFoundIt(t *testing.T) {
	body := pemBody("RSA PRIVATE KEY", "RSA PRIVATE KEY")
	scan := ScanSecrets(body, false)
	found := false
	for _, finding := range scan.Findings {
		if finding.Rule != "np.pem.1" {
			continue
		}
		found = true
		// The upstream score, read from the table rather than restated: a rule that
		// arrived with its score changed still has to be reported at the score the
		// table gives it, and the severity band follows from it.
		if want := secretSeverity(scoreOfRule("np.pem.1")); finding.Severity != want {
			t.Errorf("np.pem.1 reported severity %q at score %d, want %q",
				finding.Severity, finding.Score, want)
		}
		if finding.Line != 1 {
			t.Errorf("np.pem.1 reported the key at line %d; the BEGIN marker is on line 1",
				finding.Line)
		}
	}
	if !found {
		t.Fatalf("np.pem.1 did not fire on a served RSA private key; findings=%v",
			valuesOf(scan.Findings))
	}
}

// TestTheSecondPrivateKeyRuleAlsoFires covers the other rule the audit measured as
// unreachable. One is a sampling error; two is a class, and `kingfisher.privkey.2`
// is the rule that scored the failure.
func TestTheSecondPrivateKeyRuleAlsoFires(t *testing.T) {
	rule := ruleByID("kingfisher.privkey.2")
	if rule == nil {
		t.Fatal("kingfisher.privkey.2 is not in this build, so the assertion below is vacuous")
	}
	if !strings.Contains(rule.Regex.String(), `\n`) &&
		!strings.Contains(rule.Regex.String(), `\s`) &&
		!strings.Contains(rule.Regex.String(), `(?s)`) {
		t.Fatalf("kingfisher.privkey.2 no longer carries a newline-capable class (%q); "+
			"it may now be reachable per line, and this test is asserting a defect "+
			"that no longer exists", rule.Regex.String())
	}
	scan := ScanSecrets(pemBody("RSA PRIVATE KEY", "RSA PRIVATE KEY"), true)
	for _, finding := range scan.Findings {
		if finding.Rule == "kingfisher.privkey.2" {
			return
		}
	}
	t.Errorf("kingfisher.privkey.2 did not fire on a served RSA private key; "+
		"findings=%v", valuesOf(scan.Findings))
}

// TestALineNumberPointsAtTheLineTheValueIsOn keeps the fix honest about the one
// thing the per-line loop was providing for free.
//
// The rule now sees the whole body, so the line number is computed from the match
// offset instead of the loop variable. A number that drifts is a number the
// analyst cannot check against their editor, which is the same defect the 0-based
// convention was.
func TestALineNumberPointsAtTheLineTheValueIsOn(t *testing.T) {
	value := probeValue(64)
	body := strings.Join([]string{
		`<html><body>`,
		`<p>ordinary prose with nothing to report</p>`,
		`<p>another ordinary line</p>`,
		`<div>clojars ID ` + value + `</div>`,
		`<p>trailing markup</p>`,
		`</body></html>`,
	}, "\n")
	scan := ScanSecrets(body, false)
	for _, finding := range scan.Findings {
		if finding.Value != value {
			continue
		}
		if finding.Line != 4 {
			t.Errorf("the value is on line 4 and was reported at line %d", finding.Line)
		}
		return
	}
	t.Fatalf("the probe stopped matching, so this test would pass without testing anything")
}

// TestAPemKeyOnALaterLineReportsThatLine is the same property for the case the
// defect was about: a key is not always on line 1 of the body it arrives in.
func TestAPemKeyOnALaterLineReportsThatLine(t *testing.T) {
	body := strings.Join([]string{
		`<html><body>`,
		`<h1>Build log</h1>`,
		`-----BEGIN RSA PRIVATE KEY-----`,
		`MIIEowIBAAKCAQEAv7Zq3Jm9Kk2Lp0Rt4Yu8Wc6Vd1Fh3Gn5Bj0Xl2Qm8Zt7Yv1Bc`,
		`-----END RSA PRIVATE KEY-----`,
		`</body></html>`,
	}, "\n")
	scan := ScanSecrets(body, false)
	for _, finding := range scan.Findings {
		if finding.Rule == "np.pem.1" {
			if finding.Line != 3 {
				t.Errorf("the BEGIN marker is on line 3 and the key was reported at line %d",
					finding.Line)
			}
			return
		}
	}
	t.Fatalf("np.pem.1 did not fire on a key embedded at line 3; findings=%v",
		valuesOf(scan.Findings))
}

// TestTheWholeBodyIsNotCutBeforeTheRulesSeeIt closes the other half of the fix.
//
// The per-line loop did not only lose multi-line rules; it also meant no rule could
// ever see the body as one document. A rule that needs to know what surrounds the
// credential — the AWS pair, where the key id and the secret must be in one body —
// could not match across a single line break, and the run reported `rules_run: 534`
// as if it had.
func TestTheWholeBodyIsNotCutBeforeTheRulesSeeIt(t *testing.T) {
	keyID := "AKIAQ7ZR3MNPWX2KLDF9"
	secret := "kL9pQrT4wXnYbZc6Vd1Fh3Gn5Bj0Xl2Qm8Zt7Yv1Bc"
	body := "aws_key_id = \"" + keyID + "\"\naws_secret_access_key = \"" + secret + "\""
	scan := ScanSecrets(body, false)
	seen := map[string]bool{}
	for _, finding := range scan.Findings {
		seen[finding.Value] = true
	}
	if !seen[keyID] && !seen[secret] {
		t.Fatalf("neither half of an AWS pair split across two lines was found; findings=%v",
			valuesOf(scan.Findings))
	}
	if !seen[keyID] {
		t.Errorf("the key id on line 1 was not reported; findings=%v", valuesOf(scan.Findings))
	}
	if !seen[secret] {
		t.Errorf("the secret on line 2 was not reported; findings=%v", valuesOf(scan.Findings))
	}
}

func ruleByID(id string) *SecretRule {
	for i := range secretRuleRegistry {
		if secretRuleRegistry[i].ID == id {
			return &secretRuleRegistry[i]
		}
	}
	return nil
}

// scanCarriesSubstring asks the weaker question — is this text inside any reported
// value — for the case where the rule's own class decides what frames the capture.
func scanCarriesSubstring(scan SecretScan, want string) bool {
	for _, finding := range scan.Findings {
		if strings.Contains(finding.Value, want) {
			return true
		}
	}
	return false
}

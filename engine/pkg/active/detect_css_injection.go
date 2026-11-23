package active

import (
	"context"
	"regexp"
)

// CSSInjection probes parameters reflected into stylesheet or style contexts.
// Corresponds to Burp Suite checks:
// 0x00501300 (CSS injection - reflected)
// 0x00501301 (CSS injection - stored)
type CSSInjection struct{}

// Name implements Module.
func (CSSInjection) Name() string { return "css-injection" }

// Level implements Module.
func (CSSInjection) Level() Level { return LevelParam }

var (
	styleTagRe  = regexp.MustCompile(`(?is)<style[^>]*>.*?rr-css-canary.*?</style>`)
	styleAttrRe = regexp.MustCompile(`(?is)style\s*=\s*["'][^"']*?rr-css-canary[^"']*?["']`)
)

func (c CSSInjection) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil || baseline.StatusCode >= 400 || isPublicResource(p.URL) {
		return nil
	}

	canaryPayload := `}body{color:red;background-image:url('https://rr-css-canary.invalid')}`
	resp, err := t.Fire(ctx, p, p.Param, canaryPayload, false, nil)
	if err != nil || resp == nil {
		return nil
	}

	if !Fresh(baseline, resp, "rr-css-canary.invalid") {
		return nil
	}

	// Must be reflected in a style context (<style> or style="")
	inStyleTag := styleTagRe.MatchString(resp.Body)
	inStyleAttr := styleAttrRe.MatchString(resp.Body)

	if !inStyleTag && !inStyleAttr {
		return nil
	}

	evidence := Snippet(resp.Body, "rr-css-canary", 120)
	finding, _ := NewFinding(Spec{
		Module:      "css-injection",
		Title:       "CSS Injection (Reflected)",
		Claimed:     SeverityMedium,
		Tier:        TierVerified,
		Point:       p,
		Payload:     canaryPayload,
		Evidence:    evidence,
		Description: "The parameter is reflected unescaped into a stylesheet or inline style context. Attackers can inject arbitrary CSS to extract sensitive data (such as anti-CSRF tokens) using CSS attribute selectors, or deface the page.",
		Remediation: "Contextually encode user input before placing it in style attributes or style tags, or avoid reflecting user input into CSS entirely.",
	})

	return []Finding{finding}
}

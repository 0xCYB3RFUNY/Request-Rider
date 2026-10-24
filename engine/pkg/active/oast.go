package active

// OASTClient talks to the out-of-band service an operator configured.
//
// # Why the scanner needs a listener of its own
//
// Five rows of the Burp register — the four out-of-band ones and the JWT key
// headers — can only be settled by a *callback*. The evidence is not in the
// response the application gave us; it is a connection the application opened
// to an address we named, seconds after the request, and nothing in the HTTP
// exchange shows it happened. So the run has to be able to say "here is an
// address, tell me when somebody calls it", which is what this client does.
//
// It speaks the same protocol the engine's own OAST tool speaks — `POST
// /register`, `GET /poll?listener_id=…`, `DELETE /listener/<id>` — and reads
// the same two settings. So an operator who already runs the OAST tool has
// nothing new to configure, and the two agree about what a callback is.
//
// # Why a run without it is silent rather than wrong
//
// A detector that could not observe the callback would have to guess, and a
// guess in this family is indistinguishable from a target that resisted: both
// produce no row. So `OutOfBand` returns nothing when there is no client, and
// the register says why. The capability is present; the *observation* is the
// operator's to supply, exactly as it is for Burp's Collaborator.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// OAST settings the scanner reads when the run does not carry them.
//
// The values are the same ones the engine's own OAST tool reads, read from the
// same two places, so an operator who configured one has configured both. They
// are environment rather than a hard-coded host on purpose: a scanner that
// reported callbacks against an address it invented would be reporting against
// somebody's server.
const (
	// OASTServerEnv is the base address of the out-of-band service. The name is
	// the project's own: `Документация/oast.md` and the local band already speak
	// of an OAST server by it, so the scanner uses the same spelling rather than
	// inventing a second one an operator would have to keep in their head.
	OASTServerEnv = "OAST_SERVER_URL"
	// OASTTokenEnv is the token that authenticates to it, read from the
	// environment the engine's own OAST tool already reads.
	OASTTokenEnv = "OAST_AUTH_TOKEN"
)

// oastCallTimeout bounds one call to the service. It is a bound and not a
// ceiling: a service that accepts a connection and never answers would otherwise
// hold the whole run, and the operator sees a run stuck in `running` with no
// error and no way to tell whether the scan or the service is at fault.
const oastCallTimeout = 15 * time.Second

// OASTClient is a registered listener at the out-of-band service.
type OASTClient struct {
	// base is the service's root, with no trailing slash.
	base string
	// token authenticates the run to it.
	token string
	// http issues the calls; nil means a client bounded by oastCallTimeout.
	http *http.Client
	// PollInterval is how often a waiting run asks for events.
	PollInterval time.Duration
	// Wait is how long a probe waits for a callback before declaring the target
	// silent. Zero means the service's own default, which is one interval.
	Wait time.Duration
	// listenerID is what the service knows this run by.
	listenerID string
	// payload is the address a probe offers the target.
	payload string
	// domainName is the hostname the target resolves, when the service named one.
	domainName string
}

// OASTSettings is what a run needs to reach the service.
type OASTSettings struct {
	// ServerURL is the service's base address. Empty means read OASTServerEnv.
	ServerURL string
	// AuthToken authenticates the run. Empty means read OASTTokenEnv.
	AuthToken string
	// PollInterval and Wait are the operator's own timings.
	PollInterval time.Duration
	Wait         time.Duration
}

// NewOASTClient registers one listener and returns the client for it.
//
// A missing server address is an error rather than a silent nil client: the
// caller's two states are "there is a service and it answered" and "there is
// none", and the difference decides whether the run reports nothing for a reason
// it can name or for one it cannot.
func NewOASTClient(ctx context.Context, settings OASTSettings, next http.RoundTripper) (*OASTClient, error) {
	base := strings.TrimSpace(settings.ServerURL)
	if base == "" {
		base = strings.TrimSpace(os.Getenv(OASTServerEnv))
	}
	token := strings.TrimSpace(settings.AuthToken)
	if token == "" {
		token = strings.TrimSpace(os.Getenv(OASTTokenEnv))
	}
	if base == "" {
		return nil, fmt.Errorf("no out-of-band service configured: set %s or ScanRequest.OAST.ServerURL",
			OASTServerEnv)
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("out-of-band service address %q is not an absolute URL", base)
	}
	client := &OASTClient{
		base:         strings.TrimRight(base, "/"),
		token:        token,
		PollInterval: settings.PollInterval,
		Wait:         settings.Wait,
		listenerID:   "rr-active-" + urlOverrideCanary(),
	}
	if next != nil {
		client.http = &http.Client{Transport: next, Timeout: oastCallTimeout}
	} else {
		client.http = &http.Client{Timeout: oastCallTimeout}
	}
	if err := client.register(ctx); err != nil {
		return nil, err
	}
	return client, nil
}

// PayloadURL is the address a probe offers the target: what the service will
// watch for this run.
func (c *OASTClient) PayloadURL() string { return c.payload }

// Domain is the hostname the target resolves, when the service returned one. A
// probe that needs a bare host — a JWT `jku`, an SSRF target, a DNS lookup —
// uses this rather than parsing the payload URL again.
func (c *OASTClient) Domain() string {
	if strings.TrimSpace(c.domainName) != "" {
		return c.domainName
	}
	parsed, err := url.Parse(c.payload)
	if err != nil {
		return ""
	}
	return parsed.Host
}

// register tells the service which listener this run is and reads back the
// address it will watch.
func (c *OASTClient) register(ctx context.Context) error {
	body := map[string]interface{}{"listener_id": c.listenerID, "protocols": []string{"http", "dns"}}
	var response map[string]interface{}
	if err := c.call(ctx, http.MethodPost, c.base+"/register", body, &response); err != nil {
		return fmt.Errorf("register the out-of-band listener: %w", err)
	}
	payload, _ := response["payload_url"].(string)
	if strings.TrimSpace(payload) == "" {
		return fmt.Errorf("out-of-band service returned no payload_url for %s", c.listenerID)
	}
	callback, err := url.Parse(payload)
	if err != nil || callback.Scheme == "" || callback.Host == "" {
		return fmt.Errorf("out-of-band service returned an unusable payload_url %q", payload)
	}
	domain, _ := response["domain"].(string)
	c.payload, c.domainName = payload, domain
	return nil
}

// OASTEvent is one callback the service observed.
type OASTEvent struct {
	// Protocol is the transport the callback came over.
	Protocol string `json:"protocol"`
	// Source is where it came from, as the service reports it.
	Source string `json:"source"`
	// Raw is the whole record, so an evidence line can show what the service
	// actually said rather than the two fields this type names.
	Raw map[string]interface{} `json:"-"`
}

// Events polls for callbacks this listener has received.
func (c *OASTClient) Events(ctx context.Context) ([]OASTEvent, error) {
	var response struct {
		Events []map[string]interface{} `json:"events"`
	}
	endpoint := c.base + "/poll?listener_id=" + url.QueryEscape(c.listenerID)
	if err := c.call(ctx, http.MethodGet, endpoint, nil, &response); err != nil {
		return nil, err
	}
	out := make([]OASTEvent, 0, len(response.Events))
	for _, event := range response.Events {
		out = append(out, OASTEvent{
			Protocol: strings.ToLower(strings.TrimSpace(fmt.Sprint(event["protocol"]))),
			Source:   strings.TrimSpace(fmt.Sprint(event["source"])),
			Raw:      event,
		})
	}
	return out, nil
}

// WaitFor polls until the service reports a callback or the wait expires.
//
// An expired wait is a result and not an error: "the target did not call back
// in the time we watched" is the negative answer the row needs, and returning
// an error for it would make a caller report a failure where there was one.
//
// The default window is two intervals rather than a longer settle, and the
// window is measured: a run whose surfaces are dozens long spent most of its wall
// time waiting here rather than scanning. Two intervals is one immediate poll
// plus one more, which is what a callback from the request just sent needs.
func (c *OASTClient) WaitFor(ctx context.Context, deadline time.Duration) ([]OASTEvent, error) {
	interval := c.PollInterval
	if interval <= 0 {
		interval = time.Second
	}
	if deadline <= 0 {
		deadline = 2 * interval
	}
	var seen []OASTEvent
	stop := time.Now().Add(deadline)
	for {
		if ctx.Err() != nil {
			return seen, ctx.Err()
		}
		events, err := c.Events(ctx)
		if err != nil {
			return seen, err
		}
		if len(events) > 0 {
			return append(seen, events...), nil
		}
		if !time.Now().Before(stop) {
			return seen, nil
		}
		select {
		case <-ctx.Done():
			return seen, ctx.Err()
		case <-time.After(interval):
		}
	}
}

// Close releases the listener, so the service stops watching an address no run
// is offering any more.
func (c *OASTClient) Close(ctx context.Context) error {
	endpoint := c.base + "/listener/" + url.PathEscape(c.listenerID)
	return c.call(ctx, http.MethodDelete, endpoint, nil, &struct{}{})
}

// call issues one request to the service.
func (c *OASTClient) call(ctx context.Context, method, endpoint string, payload interface{}, output interface{}) error {
	requestContext, cancel := context.WithTimeout(ctx, oastCallTimeout)
	defer cancel()
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(requestContext, method, endpoint, body)
	if err != nil {
		return err
	}
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("out-of-band service %s %s: %s: %s", method, endpoint,
			response.Status, firstLine(string(raw)))
	}
	if output == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	return json.Unmarshal(raw, output)
}

func statusCodeString(resp *Response) string {
	if resp == nil {
		return "nil"
	}
	return strconv.Itoa(resp.StatusCode)
}

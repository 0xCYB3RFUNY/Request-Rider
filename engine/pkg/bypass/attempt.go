package bypass

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
)

// The walk: one refused request, then the ladder, then an answer that says which
// form reached the resource.

// # Why the driver is a value and not a package global
//
// The thing it has to remember — which form worked for which resource — is
// per-run state. A package global would make two scans of two targets share
// what they learned, and a form that worked once on one host would then be
// applied to a second host it was never tried on. That is not a small mistake:
// it is a request shaped for target A sent to target B, and the answer would be
// recorded as though it were about A.

// # Why the ladder carries no protocol form
//
// The PortSwigger extension's most distinctive capability is downgrading the
// exchange to HTTP/1.0 and sending it with no headers at all, and this package
// does not carry it. The reason is measured rather than assumed, and it is two
// findings:
//
//   - Go writes the request line as a literal in `net/http`'s `Request.write`, so
//     no `RoundTripper` can produce an HTTP/1.0 exchange. The field on the
//     request is not read.
//   - The only way to send one is to write it to a socket yourself. That socket
//     would go to the target directly rather than through the local MITM proxy,
//     and this project's decision is that every tool's traffic goes through that
//     proxy so the exchange lands in History with its complete raw request and
//     response.
//
// An unrecorded exchange is a worse outcome than a missing one: a report would
// claim coverage of a request nobody stored, which is exactly the failure the
// recording transport was introduced to prevent. So the capability is recorded as
// not ported, with the reason, in `upstreams_reconciliation.md` — and what it
// would take is a protocol downgrade in the passive proxy itself, which is a
// change to the recording layer rather than to a probe.

// refusedStatus reports that the *shape* was refused rather than the resource
// served.
//
// `403` is the refusal this package exists for. `400` is here because it is the
// standard answer to a request line the server could not parse: a form that sends
// a target the server cannot read has been refused as a shape, and counting that
// as a bypass would claim access to a page from a malformed request. That is not
// a hypothetical — it is what the double-encoded form produced before the leading
// separator was kept out of the encoder, and the walk reported success while the
// server had answered 400 every time.
//
// `401` and `405` are here for the same reason: an authentication wall and a
// method the resource does not offer are both refusals of access, and a walk that
// stopped at either would report "reached" for a page it never read. `501` is here
// because the server said it does not implement the verb at all.
//
// A `429` is deliberately **not** here. Rate limiting is a statement about how
// much was asked, not about the shape of this request, and answering it with
// twenty-six more requests is the wrong answer to it.
func refusedStatus(status int) bool {
	switch status {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
		http.StatusMethodNotAllowed, http.StatusNotImplemented:
		return true
	}
	return false
}

// servedStatus reports whether a status means the target served the resource.
//
// It exists because "not refused" is not the same claim, and conflating the two
// produced a false bypass on a live target. Measured 2026-10-03 against
// `www.liveinternet.ru/.git/config`: `OPTIONS` answered **501** and `DELETE`
// answered **501**. Both are the server saying it does not implement the method
// — the resource was never read — and both are not `403`, so the walk called them
// success and the report named a form that reached nothing.
//
// The rule is therefore stated positively rather than by exclusion: the target
// served the resource when it answered `2xx`. A redirect is not it either, since
// the client follows redirects and this function is called on what came back.
func servedStatus(status int) bool {
	return status >= 200 && status < 300
}

// Refused reports whether a status is a refusal of the request's *shape*.
//
// It is exported because a caller that decorates a transport has to make this
// decision itself, before it decides whether to spend anything on a walk. The
// crawl is such a caller: it must ask the site plainly through its own
// navigator-shaped transport, and only then decide whether the answer was a
// refusal. Keeping the predicate private would mean the crawler either re-typed
// `403` or called `Attempt`, and both are worse — the first duplicates the rule,
// including the `400` case, and the second re-sends the plain request through a
// different transport, so the navigator headers the crawl exists to send would
// be missing from the request whose refusal started the walk.
func Refused(status int) bool { return refusedStatus(status) }

// ErrNoFormReached is what a walk returns when no form was served the resource
// and the caller has no refusal of its own to fall back on.
//
// It exists because the alternative — a nil response with a nil error — is a trap
// rather than a convenience. Every caller of a walk ends in `resp.Body.Close()`,
// and that dereferences nil.
var ErrNoFormReached = errors.New("bypass: no form reached the resource and no refusal was supplied")

// Tried is one request the walk made and what came back.
type Tried struct {
	// Form is the name of the form that produced the request.
	Form string
	// Method and URL are what went on the wire.
	Method string
	URL    string
	// Status is the answer's status code, or 0 when the request did not complete.
	Status int
	// Skipped says the form never went out because it does not apply to this URL.
	//
	// It is recorded because a form that is inapplicable and a form that was lost
	// are indistinguishable in a report that only lists what was tried, and an
	// operator reading "walked 3 of 9" has to be able to say which six went
	// missing and why. Measured 2026-10-04 on `www.liveinternet.ru/.git/config`, a
	// two-segment path: six traversal forms were inapplicable and the report said
	// nothing about any of them.
	Skipped bool
}

// Attempt is the whole walk for one resource.
//
// It is returned alongside the response rather than logged from inside, because
// the caller is the component that decides what a run reports, and a driver that
// reported on its own would put a second accounting in the product next to the
// one the caller already keeps.
type Attempt struct {
	// Resource is the original request: what was asked for.
	Method string
	URL    string
	// Status is what the original request was answered with.
	Status int
	// Tried is every request the walk made, in order. It is empty when the
	// original was not refused and the ladder was never entered.
	Tried []Tried
	// SucceededBy is the form that reached the resource, or "" when none did.
	SucceededBy string
	// SucceededURL is the URL that form asked for, so a report can show what was
	// actually sent rather than only which form it was.
	SucceededURL string
	// ServedSiteRoot says the successful answer was the site's root page rather
	// than the resource that was asked for.
	//
	// It is separate from SucceededBy because the two are different claims, and a
	// report that gives only the first is wrong: a traversal that lands on the
	// home page *did* get a `2xx` and did not get the file. Measured 2026-10-03 on
	// `www.liveinternet.ru/.git/config`, where `/../` answers `200` with the home
	// page — 34885 bytes — while the file answers `403` with 437.
	ServedSiteRoot bool
	// Note is one sentence saying which of the two happened, for the report.
	Note string
}

// ReachedTheNamedResource reports whether the walk got the resource it was asked
// for, which is a stricter question than whether anything answered.
//
// It is the question an analyst is actually asking, and it is the one a tool that
// treats any `2xx` as success gets wrong.
func (a *Attempt) ReachedTheNamedResource() bool {
	return a != nil && a.SucceededBy != "" && !a.ServedSiteRoot
}

// Bypassed reports whether a form reached the resource.
func (a *Attempt) Bypassed() bool { return a != nil && a.SucceededBy != "" }

// Requests is how many requests the whole walk made, including the original.
//
// It is the number an operator reads to judge how hard a scan pressed a target,
// which is the same reason `Transport.Requests` counts at its own single point:
// counted by the caller, the number misses the walk entirely.
func (a *Attempt) Requests() int {
	if a == nil {
		return 0
	}
	return 1 + len(a.Tried)
}

// Driver walks the ladder.
type Driver struct {
	ladder  []Form
	enabled map[string]bool
	// learned maps a resource key to the form that reached it. It is written by
	// every walk and read by every walk, and a scan probes the same resource
	// concurrently, so it is a `sync.Map` and not a map.
	learned sync.Map
	// requests counts every request every walk made.
	requests atomic.Int64
}

// New builds a driver.
//
// A nil `enabled` means every form. An empty, non-nil `enabled` means none, and
// the two are different requests: the first says "walk everything", the second
// says "the operator selected nothing", and reading them the same way would make
// an empty selection behave like a full one.
func New(enabled []string) *Driver {
	return &Driver{ladder: Ladder(), enabled: toSet(enabled)}
}

// Requests is how many requests every walk this driver made has spent.
func (d *Driver) Requests() int { return int(d.requests.Load()) }

// LearnedForm is the form that reached a resource before, or "".
func (d *Driver) LearnedForm(method, rawURL string) string {
	if value, ok := d.learned.Load(resourceKey(method, rawURL)); ok {
		if form, isString := value.(string); isString {
			return form
		}
	}
	return ""
}

// Forget drops what was learned about a resource.
//
// The route generation is the reason this exists: `Apply route` opens a new
// generation, and a form that reached a resource on the previous route says
// nothing about the next one. Forgetting is what keeps a driver from applying an
// old answer to a new network path.
func (d *Driver) Forget() {
	d.learned.Range(func(key, _ any) bool { d.learned.Delete(key); return true })
}

// resourceKey is the identity of a thing worth learning about.
//
// It is the method, the host and the path, and the path is in it on purpose.
// A form that reached `/admin` on a host says nothing about `/api` on that same
// host: the filter that refused the second is a different filter. Learning per
// origin would apply a known answer to resources it was never tried on, which is
// a request shaped for one page sent to another.
func resourceKey(method, rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return strings.ToUpper(method) + " " + rawURL
	}
	return strings.ToUpper(method) + " " + parsed.Host + parsed.EscapedPath()
}

// allowed reports whether a form is in the operator's selection.
func (d *Driver) allowed(name string) bool {
	if d.enabled == nil {
		return true
	}
	return d.enabled[name]
}

// Attempt sends `req`, and walks the ladder if the target refuses it.
//
// The client is the caller's on purpose. This package has no client of its own:
// the probe client holds the cookie jar and the recording transport that puts an
// exchange into History, and a bypass answer that did not come through it would
// be a request the analyst cannot see — which is worse than not trying, because
// the report would claim coverage of a request nobody stored.
func (d *Driver) Attempt(
	ctx context.Context, client *http.Client, req *http.Request,
) (*http.Response, *Attempt, error) {
	if req == nil || req.URL == nil {
		return nil, nil, fmt.Errorf("bypass: Attempt requires a request with a URL")
	}
	if client == nil {
		return nil, nil, fmt.Errorf("bypass: Attempt requires the caller's client, got nil")
	}

	// The form that worked here before goes first, and it is not sent as an extra
	// step: it *replaces* the original, because a form is the shape that reached
	// the resource and asking for it plainly first would spend the refusal that
	// made this walk necessary.
	if learned := d.LearnedForm(req.Method, req.URL.String()); learned != "" && d.allowed(learned) {
		if resp, ok := d.tryLearned(ctx, client, req, learned); ok {
			d.requests.Add(1)
			return resp, &Attempt{
				Method: req.Method, URL: req.URL.String(),
				Status: resp.StatusCode, SucceededBy: learned, SucceededURL: req.URL.String(),
			}, nil
		}
	}

	resp, err := client.Do(req.Clone(ctx))
	d.requests.Add(1)
	if err != nil {
		return nil, nil, err
	}
	record := &Attempt{Method: req.Method, URL: req.URL.String(), Status: resp.StatusCode}
	if !refusedStatus(resp.StatusCode) {
		// Not a refusal, so not this package's question. The response goes back
		// untouched, including a `403` that arrived as the answer to a redirect.
		return resp, record, nil
	}
	return d.walk(ctx, client, req, record, true)
}

// tryLearned re-asks the resource in the shape that worked, once.
//
// It is one attempt, not a walk. The learning is a hint, and a hint that did not
// work this time means something about the target changed; the ordinary walk
// below is what finds out what.
func (d *Driver) tryLearned(
	ctx context.Context, client *http.Client, req *http.Request, name string,
) (*http.Response, bool) {
	for _, form := range d.ladder {
		if form.Name != name {
			continue
		}
		rewritten, ok := form.Rewrite(req)
		if !ok {
			return nil, false
		}
		rebuilt, ok := rewind(rewritten)
		if !ok {
			return nil, false
		}
		resp, err := client.Do(rebuilt)
		if err != nil {
			return nil, false
		}
		if refusedStatus(resp.StatusCode) {
			return nil, false
		}
		return resp, true
	}
	return nil, false
}

// Walk asks the same resource in every shape, for a caller that has already sent
// the plain request itself and already been refused.
//
// It exists because the two places that need a walk ask for it differently.
// `Attempt` owns the whole exchange: it sends the plain request and walks if the
// answer refuses. The crawl cannot use that, because its plain request carries
// navigator headers its own transport adds, and `Attempt` would route around that
// transport. So the crawl sends its request, reads the answer, and calls this.
//
// `refused` is the status the caller already received. When every form refuses,
// this returns a nil response rather than re-sending the plain request: asking
// again costs a request and can only produce the status the caller already has.
// The caller keeps its own answer, which is the truthful one.
func (d *Driver) Walk(
	ctx context.Context, client *http.Client, req *http.Request, refused int,
) (*http.Response, *Attempt, error) {
	if req == nil || req.URL == nil {
		return nil, nil, fmt.Errorf("bypass: Walk requires a request with a URL")
	}
	if client == nil {
		return nil, nil, fmt.Errorf("bypass: Walk requires the caller's client, got nil")
	}
	record := &Attempt{Method: req.Method, URL: req.URL.String(), Status: refused}
	return d.walk(ctx, client, req, record, false)
}

// TriedSummary names the forms that were refused, compactly.
//
// It exists for a caller that has no report to put a table in — the crawl logs
// one line per page — and it says the useful half: how many shapes were tried
// and what the first one was. A log line reading "no form reached" without the
// count cannot distinguish an edge that refused on shape from one that refused
// everything, and that distinction is the whole question the walk was asked.
func (a *Attempt) TriedSummary() string {
	if a == nil || len(a.Tried) == 0 {
		return "no form was sent"
	}
	names := make([]string, 0, 4)
	for _, tried := range a.Tried {
		if tried.Status == 0 {
			names = append(names, tried.Form+"(unsent)")
			continue
		}
		names = append(names, tried.Form)
		if len(names) == 3 {
			break
		}
	}
	if len(a.Tried) > len(names) {
		return fmt.Sprintf("%d forms refused, first %s", len(a.Tried), strings.Join(names, ", "))
	}
	return fmt.Sprintf("%d form(s) refused: %s", len(a.Tried), strings.Join(names, ", "))
}

// walk tries every allowed form and returns the first answer that is not a 403.
//
// `resend` says what to do when every form refuses: `Attempt` sends the plain
// request again, because the caller has nothing to return otherwise, while
// `Walk` does not, because the caller already holds that answer.
func (d *Driver) walk(
	ctx context.Context, client *http.Client, req *http.Request, record *Attempt, resend bool,
) (*http.Response, *Attempt, error) {
	for _, form := range d.ladder {
		if ctx.Err() != nil {
			return nil, record, ctx.Err()
		}
		if !d.allowed(form.Name) {
			continue
		}
		rewritten, ok := form.Rewrite(req)
		if !ok {
			// The form declined — usually because this URL has fewer segments
			// than the form names. It is recorded rather than skipped, because
			// "walked 3 form(s)" when nine were selected is a report that cannot
			// be told apart from one where six were lost. Measured 2026-10-04 on
			// `www.liveinternet.ru/.git/config`, a two-segment path: six
			// traversal forms were inapplicable and the report said nothing.
			record.Tried = append(record.Tried, Tried{
				Form: form.Name, Method: req.Method, URL: req.URL.String(), Skipped: true,
			})
			continue
		}
		rebuilt, ok := rewind(rewritten)
		if !ok {
			continue
		}
		resp, err := client.Do(rebuilt)
		d.requests.Add(1)
		if err != nil {
			// A form that could not be sent is not a form that failed: the target
			// was never asked. It goes in the record so the report can say so, and
			// the walk continues — one unreachable shape says nothing about the
			// next.
			record.Tried = append(record.Tried, Tried{
				Form: form.Name, Method: rebuilt.Method, URL: rebuilt.URL.String(),
			})
			continue
		}
		status := resp.StatusCode
		record.Tried = append(record.Tried, Tried{
			Form: form.Name, Method: rebuilt.Method, URL: rebuilt.URL.String(), Status: status,
		})
		if !servedStatus(status) {
			// Not served: the target did not read the resource. Close it, so a
			// refused retry does not leave a socket reading a body nobody will
			// read.
			resp.Body.Close()
			continue
		}
		record.SucceededBy = form.Name
		record.SucceededURL = rebuilt.URL.String()
		// A `2xx` is the target serving something. Whether it served *this*
		// is a separate question, and the one a traversal makes urgent: on a
		// live target `/../` turns a `403` into a `200` carrying the home page.
		record.ServedSiteRoot = sameSiteRoot(ctx, client, req, resp)
		if record.ServedSiteRoot {
			record.Note = "the target answered, but with its root page rather than the " +
				"resource named — that is a traversal to the top, not access to the file"
		}
		d.learned.Store(resourceKey(req.Method, req.URL.String()), form.Name)
		return resp, record, nil
	}

	// Every form refused. The original answer is what the caller gets, because a
	// 403 is a true statement about the resource and a package that answered with
	// the last refusal instead would report the shape of a probe as the state of
	// a page.
	//
	// Which original answer depends on whether this function can reach it, and the
	// two cases are not the same.
	if !resend {
		// The caller sent the plain request itself and already holds the refusal.
		// `Walk` was given its status, not its body, so the response object is not
		// in this function and cannot be returned from here. Re-sending it would
		// cost a request to learn what the caller already knows — and it did: the
		// re-send succeeded, so this returned a nil error, the crawl's transport
		// took its success branch with an empty `SucceededBy`, and a page that no
		// form reached was written to the crawler's log as one a form had reached.
		// Measured 2026-10-04, on the four crawler tests that had never run before
		// that day: the callback fired once with an empty form name, because the
		// `if !resend` branch sat *below* the re-send that made it unreachable.
		//
		// So the honest answer is the error, and the caller keeps its own refusal —
		// which is exactly what `crawlerTransport.RoundTrip` already does with
		// `ErrNoFormReached`. A nil response with a nil error is what this function
		// used to return, and it crashed the caller: `defer resp.Body.Close()` is
		// the obvious thing to write after a walk and it dereferences nil. Measured
		// 2 of 9 answered live runs on `www.liveinternet.ru` ended in SIGSEGV for
		// exactly this reason.
		return nil, record, ErrNoFormReached
	}
	// `Attempt` owns the whole exchange and passes the response it read as nothing
	// at all, so on total refusal the only way to hand the caller a response object
	// to close is to ask the target once more. That request is counted, and a
	// target whose refusal is no longer stable shows up here as a status that
	// differs from the one `Attempt` read.
	if resp, err := client.Do(req.Clone(ctx)); err == nil {
		d.requests.Add(1)
		record.Status = resp.StatusCode
		return resp, record, nil
	}
	return nil, record, ErrNoFormReached
}

// rewind gives a rewritten request a body it can be sent with.
//
// `Do` consumes the body, so the second request built from the same `*http.Request`
// would carry an empty reader — and a form that sends an empty body is asking a
// different question from one that sends the original. `GetBody` is what the
// standard library set for exactly this, and a request without one is refused
// rather than sent with nothing in it.
// rootBodies caches what each site's root serves, so a traversal that landed on
// the home page can be told apart from a traversal that landed on the file.
//
// It is a `sync.Map` keyed by scheme and host rather than a plain cache because
// the driver is shared across concurrent resources and a plain map would race.
// One entry per host, one request per host: the comparison is worth one request,
// and it is only ever paid when a form actually succeeded.
var rootBodies sync.Map

// siteRootBodyLimit is how much of each body is compared.
//
// 4 KiB, and the reason is that a comparison over the whole body answers a
// question nobody asked: whether two pages are byte-identical, rather than whether
// a form reached the resource it named. The first few kilobytes carry the title,
// the chrome and the site's own identity, which is all the answer needs.
const siteRootBodyLimit = 4096

// sameSiteRoot reports whether `resp` served the site's root rather than the
// resource that was asked for.
//
// # Why this exists, measured
//
// On `www.liveinternet.ru/.git/config` the `/../` forms answer `200` — and what
// comes back is the home page, 34885 bytes, titled `LiveInternet @ Статистика и
// дневники`. The file that was asked for answers `403` with 437 bytes. A tool that
// treats any `2xx` as access reports a bypass and is wrong; the original that
// demonstrated this on this very target did exactly that, printing
// `9 bypass(es) confirmed` while its own counters said
// `False Positives Filtered 0`.
//
// So a success is recorded together with what was served, and a success that
// served the root is named as such rather than left for the operator to discover
// in the body.
func sameSiteRoot(ctx context.Context, client *http.Client, req *http.Request, resp *http.Response) bool {
	if req.URL == nil || resp == nil {
		return false
	}
	key := req.URL.Scheme + "://" + req.URL.Host

	root, err := siteRootBody(ctx, client, key, req.URL.Scheme)
	if err != nil || root == nil {
		// The comparison could not be made. Saying "not the root" would be a
		// claim nobody measured, so the caller is told the answer is unknown
		// rather than told it is fine.
		return false
	}

	got := drain(resp)
	if got == nil {
		return false
	}
	return len(got) > 0 && len(root) > 0 && bytes.Equal(got, root)
}

// siteRootBody reads and caches what a host serves at its root.
func siteRootBody(ctx context.Context, client *http.Client, key, scheme string) ([]byte, error) {
	if cached, ok := rootBodies.Load(key); ok {
		switch value := cached.(type) {
		case []byte:
			return value, nil
		case error:
			return nil, value
		}
	}
	schemeToUse := scheme
	if schemeToUse == "" {
		schemeToUse = "https"
	}
	rootURL := schemeToUse + "://" + key[strings.Index(key, "://")+3:] + "/"
	probe, err := http.NewRequestWithContext(ctx, http.MethodGet, rootURL, nil)
	if err != nil {
		rootBodies.Store(key, err)
		return nil, err
	}
	resp, err := client.Do(probe)
	if err != nil {
		rootBodies.Store(key, err)
		return nil, err
	}
	defer resp.Body.Close()
	if !servedStatus(resp.StatusCode) {
		err := fmt.Errorf("bypass: the root of %s answered %d", key, resp.StatusCode)
		rootBodies.Store(key, err)
		return nil, err
	}
	body := readBounded(resp)
	rootBodies.Store(key, body)
	return body, nil
}

// drain reads a bounded prefix of a response and puts a reader for the remainder
// back, so the caller still receives an unread body.
//
// A walk that consumed the body would hand the caller an empty page and a report
// claiming a bypass — the same class of defect, one layer over.
func drain(resp *http.Response) []byte {
	if resp == nil || resp.Body == nil {
		return nil
	}
	buf := make([]byte, siteRootBodyLimit)
	n, _ := io.ReadFull(resp.Body, buf)
	prefix := buf[:n]
	rest, err := io.ReadAll(resp.Body)
	if err != nil && len(rest) == 0 {
		resp.Body = io.NopCloser(bytes.NewReader(prefix))
		return prefix
	}
	resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(prefix), bytes.NewReader(rest)))
	return prefix
}

// readBounded reads up to the comparison limit and leaves nothing behind, for the
// root probe where the body is not handed to anyone.
func readBounded(resp *http.Response) []byte {
	buf := make([]byte, siteRootBodyLimit)
	n, _ := resp.Body.Read(buf)
	if n == 0 {
		return nil
	}
	return buf[:n]
}

func rewind(req *http.Request) (*http.Request, bool) {
	if req.Body == nil || req.Body == http.NoBody {
		return req, true
	}
	if req.GetBody == nil {
		return nil, false
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, false
	}
	out := req.Clone(req.Context())
	out.Body = body
	return out, true
}

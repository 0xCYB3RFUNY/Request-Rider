// XSS, command injection and template injection.
//
// These three detectors share a shape the SQL injection detector does not: a
// marker is sent, the response is examined for the *result* of the server having
// evaluated it, and the marker is chosen so that the result cannot occur by
// accident. A reflected value proves nothing — every page that echoes a search
// term reflects it — so none of them reports on reflection alone.

// A canary is a random token that both sides of the exchange know and the
// application could not have produced on its own.
//
// The randomness is what makes the check sound. A fixed string like
// `VEXORTEST` is a string an application may legitimately contain, a template
// may legitimately print, and a page may legitimately link. Sending a value
// that was not on the page and finding it there is proof that the application
// put there, which is the one thing reflection detection has to establish.
package active

import "crypto/rand"

// put it there, which is the one thing reflection detection has to establish.
func newCanary(prefix string) string {
	const alphabet = "abcdefghijkmnpqrstuvwxyz23456789"
	out := make([]byte, 0, 16)
	raw := make([]byte, 10)
	if _, err := rand.Read(raw); err != nil {
		// crypto/rand failing means the system has no entropy source, which is
		// not a condition under which a security tool should quietly continue
		// with a predictable token. The caller turns this into a detector that
		// reports nothing rather than one that guesses.
		return ""
	}
	for _, b := range raw {
		out = append(out, alphabet[int(b)%len(alphabet)])
	}
	return prefix + string(out)
}

// mathMarkers are the arithmetic facts a template engine or a shell computes
// when it evaluates the injected expression.
//
// They are chosen so the answer is not a number the page already contains.
// 7*7=49 appears in a real page often enough to matter, which is why every
// arithmetic technique is also required to fire its baseline check: the product
// being present before the injection disqualifies it.
var mathMarkers = [][2]int{{7, 7}, {6, 9}, {13, 3}, {11, 11}}

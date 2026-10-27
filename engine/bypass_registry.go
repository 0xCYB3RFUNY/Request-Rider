package main

// The 403-ladder registry: the one place that reports which bypass forms exist.
//
// # Why the list comes from the ladder and not from a table here
//
// The names are read from `bypass.Ladder()` itself rather than kept in a second
// list, because a second list is a promise that somebody has to keep: a form added
// to the ladder and not to this table would be walkable by the engine and absent
// from the operator's choice, which is the same class of defect as the one the
// reconciliation register exists to catch — a capability that exists and is not
// offered.
//
// It is a GET-only endpoint with no side effects, so it carries no tool-run record
// and no route context. That is deliberate and is the same reason
// `/proxy/osint/transforms` takes none: listing what exists is not asking the
// network anything.

import (
	"fmt"
	"net/http"

	"intruder/engine/pkg/bypass"
)

// bypassForms lists every 403 form in the ladder, in the order the ladder walks
// them.
//
// Order is part of the answer, not an implementation detail: the ladder is
// ordered because the cheap, most-likely shapes go first, and an operator reading
// the list needs to see that order to know what they are turning on.
func (s *server) bypassForms(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
			fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": bypass.FormNames()})
}

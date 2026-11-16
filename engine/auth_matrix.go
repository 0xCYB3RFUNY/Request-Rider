package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type authMatrixRoleInput struct {
	ID         int               `json:"id"`
	Name       string            `json:"name"`
	RoleType   string            `json:"role_type"`
	Headers    map[string]string `json:"headers"`
	StripAuth  bool              `json:"strip_auth"`
	IsBaseline bool              `json:"is_baseline"`
}

type authMatrixInput struct {
	BaseRequest requestInput          `json:"base_request"`
	Roles       []authMatrixRoleInput `json:"roles"`
	Concurrency int                   `json:"concurrency"`
}

type authMatrixRoleResult struct {
	RoleID      int               `json:"role_id"`
	RoleName    string            `json:"role_name"`
	RoleType    string            `json:"role_type"`
	IsBaseline  bool              `json:"is_baseline"`
	Status      int               `json:"status"`
	Size        int               `json:"size"`
	TimeMS      int64             `json:"time_ms"`
	Body        string            `json:"body"`
	Headers     map[string]string `json:"headers"`
	RawRequest  string            `json:"raw_request"`
	RawResponse string            `json:"raw_response"`
	JSONKeys    []string          `json:"json_keys"`
	Verdict     string            `json:"verdict"`
	Error       string            `json:"error,omitempty"`
}

var authHeaderStripSet = map[string]bool{
	"authorization":       true,
	"cookie":              true,
	"x-api-key":           true,
	"x-auth-token":        true,
	"x-session-id":        true,
	"x-access-token":      true,
	"x-csrf-token":        true,
	"x-xsrf-token":        true,
	"proxy-authorization": true,
}

func cloneAndApplyRoleHeaders(base map[string]string, role authMatrixRoleInput) map[string]string {
	out := make(map[string]string, len(base)+len(role.Headers))
	strip := role.StripAuth || (strings.EqualFold(role.RoleType, "anon") && len(role.Headers) == 0)
	for k, v := range base {
		if strip && authHeaderStripSet[strings.ToLower(strings.TrimSpace(k))] {
			continue
		}
		out[k] = v
	}
	for rk, rv := range role.Headers {
		cleanKey := strings.TrimSpace(rk)
		if cleanKey == "" {
			continue
		}
		for existingKey := range out {
			if strings.EqualFold(existingKey, cleanKey) {
				delete(out, existingKey)
			}
		}
		out[cleanKey] = rv
	}
	return out
}

func extractJSONKeysFingerprint(body string) []string {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" || (trimmed[0] != '{' && trimmed[0] != '[') {
		return nil
	}
	var parsed interface{}
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		return nil
	}
	keysMap := make(map[string]struct{})
	collectJSONKeys("", parsed, keysMap, 0)
	if len(keysMap) == 0 {
		return nil
	}
	keys := make([]string, 0, len(keysMap))
	for k := range keysMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func collectJSONKeys(prefix string, val interface{}, out map[string]struct{}, depth int) {
	if depth > 6 {
		return
	}
	switch typed := val.(type) {
	case map[string]interface{}:
		for k, v := range typed {
			next := k
			if prefix != "" {
				next = prefix + "." + k
			}
			out[next] = struct{}{}
			collectJSONKeys(next, v, out, depth+1)
		}
	case []interface{}:
		arrPrefix := prefix + "[]"
		for i, item := range typed {
			if i >= 5 {
				break
			}
			collectJSONKeys(arrPrefix, item, out, depth+1)
		}
	}
}

func jsonKeysJaccard(a, b []string) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	setA := make(map[string]struct{}, len(a))
	for _, k := range a {
		setA[k] = struct{}{}
	}
	inter := 0
	union := len(setA)
	for _, k := range b {
		if _, ok := setA[k]; ok {
			inter++
		} else {
			union++
		}
	}
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

func classifyAuthMatrixVerdict(baseline authMatrixRoleResult, roleRes authMatrixRoleResult) string {
	if roleRes.Error != "" || roleRes.Status == 0 {
		return "ERROR"
	}
	if roleRes.IsBaseline {
		return "BASELINE"
	}
	if roleRes.Status == http.StatusUnauthorized || roleRes.Status == http.StatusForbidden || roleRes.Status == http.StatusNotFound {
		return "ENFORCED"
	}
	if roleRes.Status >= 300 && roleRes.Status < 400 {
		for k, v := range roleRes.Headers {
			if strings.EqualFold(k, "Location") {
				loc := strings.ToLower(v)
				if strings.Contains(loc, "login") || strings.Contains(loc, "signin") || strings.Contains(loc, "auth") {
					return "ENFORCED"
				}
			}
		}
	}
	if baseline.Status >= 200 && baseline.Status < 300 {
		if roleRes.Status >= 200 && roleRes.Status < 300 {
			if roleRes.Body == baseline.Body && roleRes.Status == baseline.Status {
				return "BYPASSED_IDENTICAL"
			}
			if len(baseline.JSONKeys) > 0 && len(roleRes.JSONKeys) > 0 {
				overlap := jsonKeysJaccard(baseline.JSONKeys, roleRes.JSONKeys)
				if overlap >= 0.999 && roleRes.Status == baseline.Status {
					return "BYPASSED_IDENTICAL"
				}
				if overlap > 0 {
					return "BYPASSED_PARTIAL"
				}
			}
			return "BYPASSED_PARTIAL"
		}
		return "ENFORCED"
	}
	if roleRes.Status == baseline.Status && roleRes.Body == baseline.Body {
		return "BYPASSED_IDENTICAL"
	}
	return "ENFORCED"
}

func mapEngineResultToRoleResult(role authMatrixRoleInput, res map[string]interface{}, err error) authMatrixRoleResult {
	out := authMatrixRoleResult{
		RoleID:     role.ID,
		RoleName:   role.Name,
		RoleType:   role.RoleType,
		IsBaseline: role.IsBaseline,
		Headers:    map[string]string{},
	}
	if err != nil {
		out.Error = err.Error()
	}
	if res != nil {
		if st, ok := res["status"].(int); ok {
			out.Status = st
		} else if stf, ok := res["status"].(float64); ok {
			out.Status = int(stf)
		}
		if sz, ok := res["size"].(int); ok {
			out.Size = sz
		} else if szf, ok := res["size"].(float64); ok {
			out.Size = int(szf)
		}
		if tm, ok := res["time"].(int64); ok {
			out.TimeMS = tm
		} else if tmi, ok := res["time"].(int); ok {
			out.TimeMS = int64(tmi)
		} else if tmf, ok := res["time"].(float64); ok {
			out.TimeMS = int64(tmf)
		}
		if b, ok := res["body"].(string); ok {
			out.Body = b
		}
		if rr, ok := res["raw_request"].(string); ok {
			out.RawRequest = rr
		}
		if rresp, ok := res["raw_response"].(string); ok {
			out.RawResponse = rresp
		}
		if eStr, ok := res["error"].(string); ok && eStr != "" && out.Error == "" {
			out.Error = eStr
		}
		if hdrs, ok := res["headers"].(map[string]string); ok {
			out.Headers = hdrs
		} else if hdrsAny, ok := res["headers"].(map[string]interface{}); ok {
			for k, v := range hdrsAny {
				out.Headers[k] = fmt.Sprint(v)
			}
		}
	}
	out.JSONKeys = extractJSONKeysFingerprint(out.Body)
	return out
}

func (s *server) repeaterAuthMatrix(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var input authMatrixInput
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err)
		return
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", fmt.Errorf("request body must contain one JSON object"))
		return
	}
	if strings.TrimSpace(input.BaseRequest.URL) == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", fmt.Errorf("base_request.url is required"))
		return
	}

	_, routeContext, release := s.bindRouteContext(r.Context())
	defer release()

	concurrency := input.Concurrency
	if concurrency <= 0 {
		concurrency = 8
	}
	if concurrency > 16 {
		concurrency = 16
	}

	start := time.Now()

	hasExplicitBaseline := false
	baselineIdx := -1
	for i, role := range input.Roles {
		if role.IsBaseline {
			hasExplicitBaseline = true
			baselineIdx = i
			break
		}
	}

	// Prepare tasks: index 0..len(Roles)-1 for roles, and optionally one extra for implicit baseline.
	totalTasks := len(input.Roles)
	if !hasExplicitBaseline {
		totalTasks++
	}

	results := make([]authMatrixRoleResult, len(input.Roles))
	var implicitBaseline authMatrixRoleResult

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	if !hasExplicitBaseline {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res, err := s.executeContextWithSourceIP(routeContext, input.BaseRequest, "")
			implicitBaseline = mapEngineResultToRoleResult(authMatrixRoleInput{
				Name:       "Baseline (Original)",
				RoleType:   "baseline",
				IsBaseline: true,
			}, res, err)
			implicitBaseline.Verdict = "BASELINE"
		}()
	}

	for i, role := range input.Roles {
		wg.Add(1)
		go func(idx int, rl authMatrixRoleInput) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			reqCopy := input.BaseRequest
			reqCopy.Headers = cloneAndApplyRoleHeaders(input.BaseRequest.Headers, rl)

			res, err := s.executeContextWithSourceIP(routeContext, reqCopy, "")
			results[idx] = mapEngineResultToRoleResult(rl, res, err)
		}(i, role)
	}

	wg.Wait()

	baseline := implicitBaseline
	if hasExplicitBaseline && baselineIdx >= 0 && baselineIdx < len(results) {
		baseline = results[baselineIdx]
		baseline.Verdict = "BASELINE"
	}

	for i := range results {
		results[i].Verdict = classifyAuthMatrixVerdict(baseline, results[i])
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":         true,
		"elapsed_ms": time.Since(start).Milliseconds(),
		"baseline":   baseline,
		"results":    results,
		"count":      totalTasks,
	})
}

package scanner

import (
	"fmt"
	"sort"
	"strings"
)

// `variables:` — це блок, який шаблон заповнює сам перед надсиланням, і без
// нього-placeholder на кшталт `{{username}}` не має звідки взятися.
//
// Виміряно на 4 000 шаблонів офіційного корпусу: 598 оголошують `variables:`, і
// вони діляться на два класи, які треба обробляти по-різному.
//
//	простий скаляр ("999999999")                       202 змінних у 153 шаблонах
//	значення з викликом хелпера ("{{rand_base(7)}}")   928 змінних у 504 шаблонах
//
// Другий клас nuclei **відмовляє**: на пробі
//
//	variables:
//	  a: "{{rand_base(7)}}"
//
//    [WRN] [rb] Could not make http request for http://127.0.0.1:20642/:
//          unresolved variables found: rand_base
//
// Тобто хелпер у значенні змінної — це не «підставити пізніше», а відмова
// всього документа. Наш ранзер повторює саме це, з текстом, який називає змінну.

// readVariables turns a `variables:` block into the values a request may use.
//
// A value that names another variable is resolved, because that is ordinary
// templating and nuclei resolves it. A value that calls a helper is not: it is
// the refusal case above, and pretending otherwise would mean substituting
// something the original tool never substitutes.
func readVariables(raw map[string]interface{}) (map[string]string, string) {
	if len(raw) == 0 {
		return nil, ""
	}
	names := make([]string, 0, len(raw))
	for name := range raw {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make(map[string]string, len(raw))
	for _, name := range names {
		value := variableScalar(raw[name])
		if value == "" {
			return nil, fmt.Sprintf("the variable %q has no value, so a request that uses {{%s}} has "+
				"nothing to send in its place", name, name)
		}
		// A helper call is checked first, because nuclei refuses the whole
		// document on it before any substitution is attempted.
		if helper := firstHelperCall(value); helper != "" {
			return nil, fmt.Sprintf(
				"the variable %q is %s, and nuclei v3.11.1 refuses a document whose variable value "+
					"calls a helper — measured, it reports `unresolved variables found: %s` and sends "+
					"nothing. A helper in a variable is therefore a refusal, not a later substitution",
				name, value, helper)
		}
		out[name] = value
	}
	// Then names that spell other names. A variable's value may be
	// `https://{{domain}}/p`, and that is ordinary templating.
	//
	// The passes are bounded by the number of declared names: each pass resolves
	// at least the self-references it can, and a value that never stops referring
	// to a declared name — `a: "{{a}}"` — stops being informative after one round,
	// so the loop is capped rather than left to run until it exhausts itself.
	for pass := 0; pass <= len(names); pass++ {
		changed := false
		for _, name := range names {
			expanded := expandDynamic(out[name], mustParseTarget(""), out)
			if expanded != out[name] {
				out[name] = expanded
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	for _, name := range names {
		if strings.Contains(out[name], "{{") {
			return nil, fmt.Sprintf("the variable %q resolves to %q, and the document defines no such "+
				"name — it does not define it", name, firstUnresolvedPlaceholder(out[name]))
		}
	}
	return out, ""
}

// firstHelperCall names the first placeholder that is a call rather than a name.
//
// `{{domain}}` is a name and nuclei resolves it. `{{rand_base(7)}}` is a call, and
// nuclei refuses the document — the difference is the parentheses, so that is what
// this looks at.
func firstHelperCall(value string) string {
	for _, token := range placeholderPattern.FindAllString(value, -1) {
		if strings.Contains(localPlaceholderName(token), "(") {
			return localPlaceholderName(token)
		}
	}
	return ""
}

// variableScalar reads one variable's value in whichever spelling it was written.
func variableScalar(value interface{}) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(typed)
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

// firstUnresolvedPlaceholder names the first placeholder a value still carries.
func firstUnresolvedPlaceholder(value string) string {
	tokens := placeholderPattern.FindAllString(value, -1)
	if len(tokens) == 0 {
		return value
	}
	return tokens[0]
}

// mergedValues joins the document's own variables with the run's callback address.
//
// One map, because both are read by the same substitution: a placeholder cannot
// be resolved from one and not the other, and two maps would be a second mechanism
// that could drift from the first.
func mergedValues(declared, oast map[string]string) map[string]string {
	if len(declared) == 0 && len(oast) == 0 {
		return nil
	}
	out := make(map[string]string, len(declared)+len(oast))
	for name, value := range declared {
		out[name] = value
	}
	for name, value := range oast {
		out[name] = value
	}
	return out
}

// usableRaw drops the raw entries of one block that cannot be built.
//
// It is the same rule as `usablePaths`, applied to the other spelling: a `raw:`
// block's entries are separate requests, and the corpus puts unresolved variables
// inside them — `{{username}}` and `{{password}}` in an XML login body is the
// shape that 308 of 4 000 templates use. Measured on `CVE-2011-4640`: three raw
// entries, one unbuildable, and nuclei sends the other two.
func usableRaw(request passiveRequest, dynamic map[string]string) ([]string, string) {
	if len(request.Raw) == 0 {
		return nil, ""
	}
	kept := make([]string, 0, len(request.Raw))
	var dropped []string
	for _, raw := range request.Raw {
		if refusals := ungeneratedPlaceholders(raw, dynamic); len(refusals) > 0 {
			dropped = append(dropped, strings.Join(refusals, ", "))
			continue
		}
		kept = append(kept, raw)
	}
	if len(kept) == len(request.Raw) {
		return request.Raw, ""
	}
	note := fmt.Sprintf("skipped %d of the %d raw request(s) of this block because a placeholder in "+
		"them could not be generated (%s)", len(dropped), len(request.Raw), strings.Join(dropped, "; "))
	if len(kept) == 0 {
		return nil, "the block has no raw request that can be built: " + note
	}
	return kept, note
}

// usablePaths drops the paths of one block that cannot be built and says why.
//
// This is the difference between a document that is refused and a document that
// runs. Measured on `http/cves/2011/CVE-2011-4640`: three raw entries, the second
// carrying `{{username}}`/`{{password}}` that nothing defines. nuclei logs
// `unresolved variables found: username,password`, sends the other two, and reports
// the document as `not_matched` — a record whose reason is empty. Refusing the whole
// document would throw away two real requests to be strict about one that cannot be
// built, and the binary is the measure here: it is the tool whose verdict these
// templates are written against.
//
// When every path is dropped the returned reason is the refusal, because then there
// is genuinely nothing to send.
func usablePaths(request passiveRequest, dynamic map[string]string) ([]string, string) {
	if len(request.Path) == 0 {
		// A block written as `raw:` has no path list at all, and there is nothing
		// to drop: the raw entries are checked on their own way in. Returning an
		// empty reason here would look like a refusal with no explanation.
		return nil, ""
	}
	// A structured block is one request made of parts: a path, a body and headers
	// travel together. So one unresolvable placeholder anywhere in it makes the
	// whole request unbuildable — dropping only the path while still sending the
	// literal in a header would be exactly the dishonesty this check exists to
	// prevent. Measured on `CVE-2020-22209`: the path is clean and the token lives
	// in a header, so checking the path alone sends the request with a literal.
	if refusals := blockPlaceholderRefusals(request, dynamic); len(refusals) > 0 {
		return nil, fmt.Sprintf(
			"this request cannot be built: %d placeholder(s) in it are not generated (%s), and sending "+
				"them literally would score the target's answer to the literal text as the template's verdict",
			len(refusals), strings.Join(refusals, ", "))
	}
	return request.Path, ""
}

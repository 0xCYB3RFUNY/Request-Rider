package active

// FormSemantics reads the shapes a page's own forms declare: a form that carries
// a file input, and a form that submits a password over GET.
//
// Burp reports both under different checks — `0x00500980` (File upload
// functionality) and `0x00400300` (Password submitted using GET method) — and
// both are answered by the markup the surface already returned, which is why
// this module costs no request at all. A detector that fired a probe to learn
// what a form says about itself would spend the target's time to rediscover a
// fact it is holding.
//
// Why this is not the auth-bypass or the form-hijack detector's job: those two
// read a form to reach a *result* (a 403 ladder, an `action` attribute). This
// one reads a form to classify what it *is*. A login page that sends its
// password in the query string is a page the URL bar, the proxy log and every
// `Referer` header already has the credential from, and that is a statement
// about the form rather than about the request the scanner happens to send.

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/net/html"
)

// FormSemantics names what the page's forms say they are.
type FormSemantics struct{}

// Name implements Module.
func (FormSemantics) Name() string { return "form-semantics" }

// Level implements Module.
func (FormSemantics) Level() Level { return LevelEndpoint }

// Scan reads the baseline and reports the form shapes it declares.
func (FormSemantics) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil || baseline.StatusCode >= 400 {
		return nil
	}
	if !strings.Contains(strings.ToLower(baseline.HeaderValue("Content-Type")), "text/html") {
		return nil
	}
	if strings.TrimSpace(baseline.Body) == "" {
		return nil
	}

	forms := formsOf(baseline.Body)
	if len(forms) == 0 {
		return nil
	}

	var out []Finding
	if uploads := formShapes(forms, formHasFile); len(uploads) > 0 {
		out = append(out, formSemanticsFinding(p, uploads, "upload",
			"File Upload Functionality", SeverityInfo,
			"The page declares "+strconv.Itoa(len(uploads))+" form(s) that accept a file. "+
				"Upload is the surface where a filter has to be right once: the name, the "+
				"extension, the MIME type and the content type are four separate decisions, "+
				"and a page that takes a file is a page an operator has to test all four on.",
			"List what the endpoint accepts, validate the extension and content type "+
				"server-side against a list of what the application needs, store the upload "+
				"outside the document root under a generated name, and never interpret it."))
	}
	if gets := formShapes(forms, formSubmitsPasswordByGET); len(gets) > 0 {
		out = append(out, formSemanticsFinding(p, gets, "password-get",
			"Password Submitted Using GET Method", SeverityMedium,
			"A form on this page carries a password field and submits by GET. The "+
				"credential then travels in the query string, where the browser history, "+
				"the proxy log, the access log and every `Referer` header of the next "+
				"request read it.",
			"Submit the form by POST, and treat any query string that arrives carrying a "+
				"password as a defect in the form rather than as data."))
	}
	return out
}

// pageForm is one parsed `<form>` reduced to the two facts this module reads:
// how it submits and what it carries.
type pageForm struct {
	// method is the submission method the markup declared, upper-cased.
	method string
	// hasFile is whether any input on the form accepts a file.
	hasFile bool
	// hasPassword is whether any input on the form is a password field.
	hasPassword bool
	// inputs counts what the form carries, so the evidence line can say how
	// big the thing being described is.
	inputs int
	// action is where the form submits, for the same reason.
	action string
	// index is the form's position in the document, so a row on a page with
	// three forms says which one.
	index int
	// names are the `name` attributes of the form's fields, lower-cased.
	//
	// They are here because a detector that has to *submit* a value needs to know
	// which field to put it in, and counting inputs cannot tell it: a form with
	// `email` and `password` has two inputs and two completely different classes
	// of check, and the class that needs the password field cannot run on the
	// email one without writing a credential-shaped value into the wrong place.
	names []string
}

// formsOf parses a page and returns its forms in document order.
func formsOf(body string) []pageForm {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil || doc == nil {
		return nil
	}
	var out []pageForm
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, "form") {
			out = append(out, formOfNode(n, len(out)))
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	return out
}

// formOfNode reads one form element. The method defaults to GET because that is
// what the specification says and what a browser does, and a form whose method
// attribute is missing, empty or nonsense is the common case rather than the
// exception — guessing the other way would report a GET there as a POST.
func formOfNode(form *html.Node, index int) pageForm {
	parsed := pageForm{index: index, method: http.MethodGet, action: attrValue(form, "action")}
	if declared := strings.ToUpper(strings.TrimSpace(attrValue(form, "method"))); declared != "" {
		parsed.method = declared
	}
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, "input") {
			parsed.inputs++
			if name := strings.ToLower(strings.TrimSpace(attrValue(n, "name"))); name != "" {
				parsed.names = append(parsed.names, name)
			}
			switch strings.ToLower(strings.TrimSpace(attrValue(n, "type"))) {
			case "file":
				parsed.hasFile = true
			case "password":
				parsed.hasPassword = true
			}
		}
		// A `<textarea>` is not an `<input>`, but a name the password check
		// needs to know about: a page that collects a "password" into a textarea
		// is a page that shows what it collected.
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, "textarea") {
			parsed.inputs++
			if name := strings.ToLower(strings.TrimSpace(attrValue(n, "name"))); name != "" {
				parsed.names = append(parsed.names, name)
			}
			if strings.Contains(strings.ToLower(attrValue(n, "name")+attrValue(n, "id")), "password") {
				parsed.hasPassword = true
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(form)
	return parsed
}

// formFieldNames returns a form's field names.
func formFieldNames(f pageForm) []string { return f.names }

// formHasNamedField reports whether a form carries a field whose name contains
// the wanted fragment, and answers which field it was.
func formHasNamedField(f pageForm, wanted string) (string, bool) {
	for _, name := range f.names {
		if strings.Contains(name, wanted) {
			return name, true
		}
	}
	return "", false
}

// formHasFile reports whether a form carries a file input.
func formHasFile(f pageForm) bool { return f.hasFile }

// formSubmitsPasswordByGET reports whether a form submits a password field over
// GET, which is the combination that puts the credential in a URL.
func formSubmitsPasswordByGET(f pageForm) bool { return f.hasPassword && f.method == http.MethodGet }

// formShapes keeps the forms a predicate accepts, so the evidence lists the
// forms the claim is about rather than the whole page.
func formShapes(forms []pageForm, accept func(pageForm) bool) []pageForm {
	var out []pageForm
	for _, form := range forms {
		if accept(form) {
			out = append(out, form)
		}
	}
	return out
}

// formSemanticsFinding renders one row naming the forms it measured.
func formSemanticsFinding(p Point, forms []pageForm, kind, title string, claimed Severity, description, remediation string) Finding {
	shown := forms
	more := 0
	if len(shown) > 3 {
		more = len(shown) - 3
		shown = shown[:3]
	}
	lines := make([]string, 0, len(shown))
	for _, form := range shown {
		action := strings.TrimSpace(form.action)
		if action == "" {
			action = "(self)"
		}
		lines = append(lines, "form #"+strconv.Itoa(form.index+1)+": "+form.method+" "+action+
			" ("+strconv.Itoa(form.inputs)+" input(s))")
	}
	evidence := strings.Join(lines, "\n")
	if more > 0 {
		evidence += "\n…and " + strconv.Itoa(more) + " more"
	}
	finding, _ := NewFinding(Spec{
		Module:      "form-semantics",
		Title:       title,
		Claimed:     claimed,
		Tier:        TierVerified,
		Point:       p,
		Evidence:    evidence,
		Description: description,
		Remediation: remediation,
	})
	return finding
}

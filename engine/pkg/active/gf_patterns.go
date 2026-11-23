package active

// GF Parameter collections categorized by vulnerability class,
// ported from Gf-Patterns (upstream MIT license).

var (
	// GfSSRFParams contains high-signal candidate parameter names for Server-Side Request Forgery.
	GfSSRFParams = []string{
		"dest", "redirect", "uri", "path", "continue", "url", "window", "next",
		"data", "reference", "site", "html", "val", "validate", "domain", "callback",
		"return", "feed", "host", "port", "to", "out", "view", "dir", "show",
		"navigation", "open", "file", "document", "folder", "php_path", "style", "doc", "img", "filename",
	}

	// GfRCEParams contains high-signal candidate parameter names for Remote Code / Command Execution.
	GfRCEParams = []string{
		"daemon", "upload", "dir", "download", "log", "ip", "cli", "cmd",
		"exec", "command", "execute", "ping", "query", "run", "process",
	}

	// GfLFIParams contains high-signal candidate parameter names for Local File Inclusion / Path Traversal.
	GfLFIParams = []string{
		"file", "document", "folder", "root", "path", "pg", "style", "pdf",
		"template", "php_path", "doc", "page", "name", "loc", "include", "layout",
	}

	// GfSSTIParams contains high-signal candidate parameter names for Server-Side Template Injection.
	GfSSTIParams = []string{
		"template", "preview", "id", "view", "activity", "name", "content", "redirect",
		"render", "layout", "page", "msg", "message",
	}

	// GfRedirectParams contains candidate parameter names for Open Redirect.
	GfRedirectParams = []string{
		"url", "redirect", "next", "target", "rurl", "dest", "destination", "go",
		"goto", "return", "return_to", "checkout_url", "redir", "uri", "continue",
		"forward", "image_url", "login_url", "logout", "next_page", "page_url",
	}

	// GfIDORParams contains candidate parameter names for IDOR / Broken Object-Level Auth.
	GfIDORParams = []string{
		"user_id", "account_id", "id", "user", "order_id", "account", "key",
		"no", "number", "group_id", "profile_id", "org_id", "member_id", "doc_id",
	}

	// GfSQLiParams contains candidate parameter names for SQL Injection discovery.
	GfSQLiParams = []string{
		"id", "select", "report", "role", "update", "query", "user", "name",
		"sort", "where", "search", "params", "process", "row", "table", "from",
		"sel", "results", "sleep", "fetch", "order", "keyword", "column", "field", "filter",
	}
)

// GfParamsByCategory returns candidate parameters for a specific vulnerability class.
func GfParamsByCategory(category string) []string {
	switch category {
	case "ssrf":
		return append([]string(nil), GfSSRFParams...)
	case "rce", "cmdi":
		return append([]string(nil), GfRCEParams...)
	case "lfi", "traversal":
		return append([]string(nil), GfLFIParams...)
	case "ssti":
		return append([]string(nil), GfSSTIParams...)
	case "redirect", "open_redirect":
		return append([]string(nil), GfRedirectParams...)
	case "idor":
		return append([]string(nil), GfIDORParams...)
	case "sqli":
		return append([]string(nil), GfSQLiParams...)
	default:
		return nil
	}
}

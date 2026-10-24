package enrich

import "testing"

func TestRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"www.example.ru":     "example.ru",
		"example.ru":         "example.ru",
		"shop.example.ru":    "example.ru",
		"a.b.example.ru":     "example.ru",
		"www.example.co.uk":  "example.co.uk",
		"shop.example.co.uk": "example.co.uk",
		"cdn.tracker.net":    "tracker.net",
		"localhost":          "localhost",
		"":                   "",
	}
	for host, want := range cases {
		if got := registrableDomain(host); got != want {
			t.Errorf("registrableDomain(%q) = %q, want %q", host, got, want)
		}
	}
}

// A subdomain of the crawled site is in scope for the map; a different
// registrable domain is a fact about the page and is reported elsewhere. Putting
// one in the other list is exactly the kind of quiet wrong answer that a map
// built from is worse than useless.
func TestSubdomainsSeparatesOwnDomainFromForeign(t *testing.T) {
	refs := ExtractReferences(`<html><body>
	<a href="https://shop.example.ru/cart">1</a>
	<a href="https://cdn.example.ru/x.js">2</a>
	<a href="https://www.example.ru/">3</a>
	<a href="https://tracker.net/pixel">4</a>
	<a href="https://notexample.ru/">5</a>
	<a href="/local/path">6</a>
	</body></html>`)
	got := Subdomains(refs, "www.example.ru")
	if len(got) != 2 {
		t.Fatalf("expected 2 subdomains of example.ru, got %v", got)
	}
	if got[0] != "cdn.example.ru" || got[1] != "shop.example.ru" {
		t.Errorf("subdomains must be sorted and exclude the origin itself, got %v", got)
	}
	for _, host := range got {
		if host == "tracker.net" || host == "notexample.ru" {
			t.Errorf("foreign registrable domain %q leaked into the subdomain list", host)
		}
	}
}

func TestSubdomainsAreSortedAndDeduplicated(t *testing.T) {
	refs := ExtractReferences(`<a href="https://z.example.ru/">z</a>
	<a href="https://a.example.ru/">a</a>
	<a href="https://a.example.ru/again">a2</a>`)
	got := Subdomains(refs, "example.ru")
	if len(got) != 2 || got[0] != "a.example.ru" || got[1] != "z.example.ru" {
		t.Fatalf("want [a.example.ru z.example.ru], got %v", got)
	}
}

func TestSubdomainsWithoutOriginIsEmpty(t *testing.T) {
	refs := ExtractReferences(`<a href="https://shop.example.ru/">x</a>`)
	if got := Subdomains(refs, ""); got != nil {
		t.Fatalf("without an origin host there is no parent domain, got %v", got)
	}
}

func TestHostOfHandlesProtocolRelative(t *testing.T) {
	if got := hostOf("//static.example.ru/a.js"); got != "static.example.ru" {
		t.Errorf("hostOf(protocol-relative) = %q", got)
	}
	if got := hostOf("https://a.example.ru:8443/x"); got != "a.example.ru" {
		t.Errorf("hostOf must drop the port, got %q", got)
	}
}

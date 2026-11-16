package enrich

import (
	"net/url"
	"sort"
	"strings"
)

// multiLabelZones are the public suffixes made of two labels, so that
// `shop.example.co.uk` is recognised as belonging to `example.co.uk` and not
// to `co.uk`.
//
// It is a list, not a fetch of the Public Suffix List, for two reasons: the
// crawler must work offline and must not make a network call per page, and a
// list that can be wrong here is a list that is wrong loudly — a missed zone
// means a subdomain is not attributed to its parent, which shows up as an empty
// list rather than as a wrong block.
var multiLabelZones = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "me.uk": true,
	"com.au": true, "net.au": true, "org.au": true, "edu.au": true,
	"co.jp": true, "or.jp": true, "ne.jp": true, "ac.jp": true,
	"com.br": true, "com.mx": true, "com.ar": true, "com.tr": true,
	"com.cn": true, "co.kr": true, "co.in": true, "co.za": true,
	"com.ua": true, "com.ru": true, "net.ru": true, "org.ru": true,
}

// registrableDomain returns the domain a host belongs to, or the host itself when
// it is already a registrable domain. `www.example.ru` → `example.ru`,
// `example.ru` → `example.ru`, `a.b.example.co.uk` → `example.co.uk`.
func registrableDomain(host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	host = strings.TrimPrefix(host, "www.")
	labels := strings.Split(host, ".")
	if len(labels) <= 2 {
		return host
	}
	lastTwo := strings.Join(labels[len(labels)-2:], ".")
	if multiLabelZones[lastTwo] && len(labels) >= 3 {
		return strings.Join(labels[len(labels)-3:], ".")
	}
	return lastTwo
}

// Subdomains returns the hostnames the page references that belong to the
// crawled site's own registrable domain.
//
// The capability is `chm0dx/creepyCrawler` (subdomain discovery while crawling);
// our own implementation, because upstream ships no licence at all and copying is
// therefore not permitted. The engine already has subdomain discovery of a
// different kind — certificate-transparency zones and DNS wordlists, reached from
// the OSINT transforms — and this is the part a crawl can answer on its own: a
// host that a single page already references is a host that exists, with no
// external index involved.
//
// Only hosts under the origin's registrable domain are returned. A different
// registrable domain is an external host and is reported separately, because
// `cdn.example.com` is in scope for the map and `tracker.net` is a fact about
// the page, not about the site being crawled.
func Subdomains(refs []Reference, originHost string) []string {
	if originHost == "" {
		return nil
	}
	originHost = strings.ToLower(strings.TrimSpace(originHost))
	if originHost == "" {
		return nil
	}
	origin := registrableDomain(originHost)
	if origin == "" {
		return nil
	}
	seen := map[string]bool{originHost: true}
	var out []string
	for _, ref := range refs {
		if !ref.Absolute && !ref.ProtocolRelative {
			continue
		}
		// The full host is what belongs in the list; the registrable domain is
		// only the membership test. Comparing the registrable domain and then
		// testing it for a suffix was the first version's bug and it returned an
		// empty list for every input, because a registrable domain is by
		// definition equal to the origin.
		host := hostOf(ref.Raw)
		if host == "" || seen[host] {
			continue
		}
		if registrableDomain(host) != origin {
			continue
		}
		seen[host] = true
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

// hostOf returns the hostname of an absolute or protocol-relative URL reference.
func hostOf(raw string) string {
	candidate := raw
	if !strings.Contains(candidate, "://") {
		candidate = "https:" + candidate
	}
	parsed, err := url.Parse(candidate)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

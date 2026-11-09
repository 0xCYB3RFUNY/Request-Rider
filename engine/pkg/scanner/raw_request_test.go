package scanner

import (
	"strings"
	"testing"
)

// Директиви `@` стоять над рядком запиту, і це не рідкість: 34 шаблони з 4 000
// відкривають так свій `raw:`. Перша версія розбору брала їх за заголовок і
// віддавала `the raw header line "POST /… HTTP/1.1" has no colon`, бо справжній
// рядок запиту опинявся на місці заголовка.
//
// Другий бік тієї ж помилки: директиви без рядка запиту після них — це не
// «запит без методу», а відмова з власною причиною.
func TestARawDirectiveLineIsNotReadAsAHeader(t *testing.T) {
	parsed, reason := parseRawRequest(
		"@timeout 10s\nGET /wp-admin/admin-ajax.php?type=json HTTP/1.1\nHost: example.test\n\n",
		"http://target.test/", nil)
	if reason != "" {
		t.Fatalf("a raw request with a directive was refused: %s", reason)
	}
	if parsed.Method != "GET" || parsed.Path != "/wp-admin/admin-ajax.php?type=json" {
		t.Fatalf("the request line was misread: method=%q path=%q", parsed.Method, parsed.Path)
	}
	if parsed.Host != "example.test" {
		t.Fatalf("Host = %q, want example.test", parsed.Host)
	}
}

func TestADirectiveWithoutARequestLineIsRefusedWithItsOwnReason(t *testing.T) {
	_, reason := parseRawRequest("@timeout 10s\n@tls-sni example.test\n", "http://target.test/", nil)
	if reason == "" {
		t.Fatal("directives with no request line produced no reason")
	}
	if !strings.Contains(reason, "directive") {
		t.Fatalf("the reason does not say a directive was the problem: %q", reason)
	}
}

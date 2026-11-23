package scanner

import (
	"strings"
	"testing"
)

// 596 з 98 636 шаблонів кажуть цільці звернутися на унікальний хост, і nuclei
// відповідає реєстрацією цього хоста в OAST-сервері.
//
// Без `-iserver` бінарник бере свій список, і його власний `-h` друкує його:
// `oast.pro, oast.live, oast.site, oast.online, oast.fun, oast.me`. Тобто всі
// 596 перевірок дають вердикт — і всі 596 одночасно звітують третій стороні,
// тоді як власний слухач проєкту (`POST /api/oast`) не бачить нічого.
//
// Рушій не може бути цим сервером: `engine/oast.go` — це OAST-*клієнт*
// (`POST <provider>/register`, потім `GET <provider>/poll`), а не реалізація
// протоколу interactsh, який говорить nuclei. Тому чесна правка — дати
// оператору назвати той сервер, який він підняв у своїй інфраструктурі.

func TestAnInteractshServerIsPassedThroughWhenTheOperatorNamesOne(t *testing.T) {
	args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
		Options: NucleiOptions{InteractshURL: "http://127.0.0.1:9070"},
	})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	if value := argValue(t, args, "-iserver"); value != "http://127.0.0.1:9070" {
		t.Fatalf("-iserver = %q, want the operator's server: %v", value, args)
	}
}

// A trailing slash or a path is part of the address the binary dials, so the
// value must arrive exactly as written rather than being normalised.
func TestTheInteractshAddressIsPassedVerbatim(t *testing.T) {
	const server = "https://oast.internal.example:8443/interactsh"
	args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
		Options: NucleiOptions{InteractshURL: server},
	})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	if value := argValue(t, args, "-iserver"); value != server {
		t.Fatalf("-iserver = %q, want it verbatim: %v", value, args)
	}
}

// An untouched panel must not name a server: that is the binary's own default,
// and choosing it is the operator's call, not this tool's.
func TestAnUntouchedPanelNamesNoInteractshServer(t *testing.T) {
	args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	if hasArg(args, "-iserver") {
		t.Fatalf("an empty panel invented an OAST server: %v", args)
	}
	if hasArg(args, "-itoken") {
		t.Fatalf("an empty panel invented an OAST token: %v", args)
	}
}

// A malformed address makes the binary exit 2 with `invalid interactsh server
// url`, which surfaces as a bare exit status for the whole batch. An empty
// `-iserver` argument is worse still: it looks configured and silently falls
// back to the public list.
func TestAMalformedInteractshServerIsRejectedWithTheReason(t *testing.T) {
	for _, bad := range []string{"oast.internal.example", "://nope", "ftp://oast.internal", "/only/a/path"} {
		_, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
			Options: NucleiOptions{InteractshURL: bad},
		})
		if err == nil {
			t.Fatalf("%q was accepted", bad)
		}
		if !strings.Contains(err.Error(), "interactsh_url") {
			t.Fatalf("the error does not name the field: %v", err)
		}
	}
}

// A token without a server is a credential sent nowhere, and the binary takes
// `-itoken` only with `-iserver`.
func TestAnInteractshTokenNeedsAServer(t *testing.T) {
	_, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
		Options: NucleiOptions{InteractshToken: "secret-token"},
	})
	if err == nil {
		t.Fatal("a token without a server was accepted")
	}
	if !strings.Contains(err.Error(), "interactsh_url") {
		t.Fatalf("the error does not say what is missing: %v", err)
	}

	args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
		Options: NucleiOptions{InteractshURL: "http://127.0.0.1:9070", InteractshToken: "secret-token"},
	})
	if err != nil {
		t.Fatalf("a token with a server was rejected: %v", err)
	}
	if value := argValue(t, args, "-itoken"); value != "secret-token" {
		t.Fatalf("-itoken = %q: %v", value, args)
	}
}

// Disabling OAST and naming a server are opposites, and the binary accepts
// neither combination cleanly: `-ni` excludes every OAST template, so a server
// would be configured for nothing. Saying so is better than a flag the binary
// quietly ignores.
func TestDisablingInteractshWhileNamingAServerIsRejected(t *testing.T) {
	off := false
	_, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
		Options: NucleiOptions{Interactsh: &off, InteractshURL: "http://127.0.0.1:9070"},
	})
	if err == nil {
		t.Fatal("interactsh was disabled while a server was named")
	}
	if !strings.Contains(err.Error(), "interactsh") {
		t.Fatalf("the error does not name the conflict: %v", err)
	}
}

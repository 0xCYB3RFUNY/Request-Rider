package main

// A login form that accepts one specific password, so a test can ask for a
// credential a transformation chain has to preserve. `fakeLoginTarget` takes the
// same constant because most tests use the same credential; this variant exists
// because `lowercase` legitimately breaks a mixed-case password, and a test that
// quietly expected a broken password would fail for the wrong reason.
//
// Both forms echo the submitted username and vary a CSRF nonce and a timestamp,
// because those three things are what make every answer of a real login page
// differ byte for byte, and a detector that only works on a stable page proves
// nothing.

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
)

const adminPassword = "CorrectHorseBattery9!"

type loginPageForm struct {
	password string
	nonce    atomic.Int64
}

func (f *loginPageForm) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	nonce := f.nonce.Add(1)
	raw, _ := io.ReadAll(r.Body)
	values, _ := url.ParseQuery(string(raw))
	page := func(message string) string {
		return fmt.Sprintf(`<html><body><input name="csrf_token" value="csrf%d9f8e7d6c5b4a3021">`+
			`<div class="error">%s for %s</div><p>Server time 17123456%d</p></body></html>`,
			nonce, message, values.Get("user"), nonce)
	}
	w.Header().Set("Set-Cookie", "login_test_cookie=always; path=/")
	if values.Get("user") == "admin" && values.Get("pass") == f.password {
		w.Header().Set("Set-Cookie", "login_test_cookie=always; path=/, session_9f2b=alive; path=/")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, page("Welcome back")+strings.Repeat("<p>admin panel row</p>", 40))
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, page("Unknown username or incorrect password"))
}

// newFakeLoginTarget is the default form. The constructor exists instead of a
// literal because the password is a constant every test has to agree on: the
// first version of these tests had the form expect one password and the modes
// test ask for another, and every assertion failed for a reason that had nothing
// to do with detection.
func newFakeLoginTarget() *loginPageForm { return &loginPageForm{password: adminPassword} }

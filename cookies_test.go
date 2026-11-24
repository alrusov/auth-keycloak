package kc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

//----------------------------------------------------------------------------------------------------------------------------//

func TestSafeReferer(t *testing.T) {
	base := "https://idc.example:4200"

	cases := map[string]string{
		"":                                "/",
		"/screens/1?x=2":                  "/screens/1?x=2",
		"https://idc.example:4200/a":      "https://idc.example:4200/a",
		"HTTPS://IDC.example:4200/a":      "HTTPS://IDC.example:4200/a",
		"https://evil.example/a":          "/",
		"http://idc.example:4200/a":       "/", // другая схема
		"https://idc.example:4201/a":      "/", // другой порт
		"//evil.example/a":                "/",
		`/\evil.example`:                  "/",
		"https://u@idc.example:4200/a":    "/",
		"javascript:alert(1)":             "/",
		"https://idc.example:4200.evil/a": "/",
		"relative/path":                   "/",
	}

	for in, exp := range cases {
		if got := safeReferer(in, base); got != exp {
			t.Errorf(`safeReferer(%q) = %q, expected %q`, in, got, exp)
		}
	}
}

//----------------------------------------------------------------------------------------------------------------------------//

func TestSetCookieFlags(t *testing.T) {
	ah := &AuthHandler{options: &methodOptions{Domain: ".idc.example"}}

	w := httptest.NewRecorder()
	ah.setCookie(w, "https://idc.example", accessTokenName, "tkn", 0)
	ah.setCookie(w, "http://idc.example", refreshTokenName, "tkn", 0)
	ah.setCookie(w, "http://idc.example", stateCookieName, "", -1)

	cc := w.Header().Values("Set-Cookie")
	if len(cc) != 3 {
		t.Fatalf(`expected 3 cookies, got %v`, cc)
	}

	for _, c := range cc {
		if !strings.Contains(c, "HttpOnly") || !strings.Contains(c, "SameSite=Lax") {
			t.Errorf(`no HttpOnly/SameSite: %s`, c)
		}
	}
	if !strings.Contains(cc[0], "Secure") {
		t.Errorf(`https cookie without Secure: %s`, cc[0])
	}
	if strings.Contains(cc[1], "Secure") {
		t.Errorf(`http cookie with Secure: %s`, cc[1])
	}
	if !strings.Contains(cc[2], "Max-Age=0") {
		t.Errorf(`deleted cookie without Max-Age=0: %s`, cc[2])
	}
}

//----------------------------------------------------------------------------------------------------------------------------//

func TestStateNonce(t *testing.T) {
	a, err := newStateNonce()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := newStateNonce()

	if len(a) != stateNonceLen || a == b {
		t.Fatalf(`bad nonce: %q %q`, a, b)
	}
}

//----------------------------------------------------------------------------------------------------------------------------//

func TestCallbackRejectsForeignState(t *testing.T) {
	ah := &AuthHandler{
		options:              &methodOptions{Domain: ".idc.example"},
		callbackRedirectPath: "/oauth/callback",
	}

	nonce, _ := newStateNonce()
	other, _ := newStateNonce()
	state := url.QueryEscape(nonce + url.QueryEscape("https://evil.example/"))

	check := func(name string, cookie string) {
		r := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=x&state="+state, nil)
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: stateCookieName, Value: cookie})
		}
		w := httptest.NewRecorder()

		if !ah.Handler(1, "", "/oauth/callback", w, r) {
			t.Fatalf(`%s: not processed`, name)
		}
		if w.Code != http.StatusBadRequest {
			t.Errorf(`%s: expected %d, got %d`, name, http.StatusBadRequest, w.Code)
		}
	}

	check("no cookie", "")
	check("other cookie", other)
}

//----------------------------------------------------------------------------------------------------------------------------//

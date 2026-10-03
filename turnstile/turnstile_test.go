package turnstile

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// stub returns a Verifier that talks to a fake siteverify server.
func stub(t *testing.T, handler http.HandlerFunc, opts Options) *Verifier {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	opts.Endpoint = srv.URL
	opts.HTTPClient = srv.Client()
	return New("secret-for-test", opts)
}

func TestVerifySuccess(t *testing.T) {
	v := stub(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("response") != "good-token" {
			t.Errorf("response = %q, want good-token", r.FormValue("response"))
		}
		if r.FormValue("secret") != "secret-for-test" {
			t.Error("secret not sent")
		}
		if r.FormValue("remoteip") != "1.2.3.4" {
			t.Errorf("remoteip = %q", r.FormValue("remoteip"))
		}
		_, _ = w.Write([]byte(`{"success":true,"hostname":"app.example.com"}`))
	}, Options{})
	if err := v.Verify(context.Background(), "good-token", "1.2.3.4"); err != nil {
		t.Errorf("want success, got %v", err)
	}
}

func TestVerifyFailsClosed(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"rejected": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"success":false,"error-codes":["invalid-input-response"]}`))
		},
		"garbage body": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`not json`)) },
		"server error": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) },
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			if err := stub(t, h, Options{}).Verify(context.Background(), "tok", ""); !errors.Is(err, ErrFailed) {
				t.Errorf("err = %v, want ErrFailed", err)
			}
		})
	}
}

func TestVerifyUnreachableFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	v := New("s", Options{Endpoint: url})
	if err := v.Verify(context.Background(), "tok", ""); !errors.Is(err, ErrFailed) {
		t.Errorf("err = %v, want ErrFailed", err)
	}
}

func TestVerifyEmptyTokenSkipsNetwork(t *testing.T) {
	called := false
	v := stub(t, func(w http.ResponseWriter, _ *http.Request) {
		called = true
		_, _ = w.Write([]byte(`{"success":true}`))
	}, Options{})
	if err := v.Verify(context.Background(), "  ", ""); !errors.Is(err, ErrFailed) {
		t.Errorf("err = %v, want ErrFailed", err)
	}
	if called {
		t.Error("an empty token must be refused without calling Cloudflare")
	}
}

func TestVerifyHostname(t *testing.T) {
	h := func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"hostname":"evil.example.net"}`))
	}
	if err := stub(t, h, Options{Hostnames: []string{"app.example.com"}}).Verify(context.Background(), "tok", ""); !errors.Is(err, ErrFailed) {
		t.Errorf("foreign hostname: err = %v, want ErrFailed", err)
	}
	if err := stub(t, h, Options{Hostnames: []string{"EVIL.example.net"}}).Verify(context.Background(), "tok", ""); err != nil {
		t.Errorf("listed hostname (case-insensitive): err = %v", err)
	}
}

func TestNoSecretIsNotConfigured(t *testing.T) {
	v := New("  ", Options{})
	if v.Enabled() {
		t.Error("blank secret reported as enabled")
	}
	if err := v.Verify(context.Background(), "tok", ""); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("err = %v, want ErrNotConfigured", err)
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "10.0.0.1:5555"
	r.Header.Set("CF-Connecting-IP", "203.0.113.9")
	r.Header.Set("X-Forwarded-For", "1.1.1.1")

	if got := ClientIP(r, ClientIPOptions{TrustCloudflare: true}); got != "203.0.113.9" {
		t.Errorf("trusted: got %q, want 203.0.113.9", got)
	}
	if got := ClientIP(r, ClientIPOptions{}); got != "10.0.0.1" {
		t.Errorf("untrusted header must be ignored: got %q", got)
	}

	r6 := httptest.NewRequest("POST", "/", nil)
	r6.RemoteAddr = "[::1]:5555"
	if got := ClientIP(r6, ClientIPOptions{TrustCloudflare: true}); got != "::1" {
		t.Errorf("IPv6 peer: got %q, want ::1", got)
	}
}

func TestVerifyErrorSaysWhy(t *testing.T) {
	v := stub(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":false,"error-codes":["timeout-or-duplicate"]}`))
	}, Options{})
	err := v.Verify(context.Background(), "tok", "")
	if !errors.Is(err, ErrFailed) {
		t.Fatalf("err = %v, want ErrFailed", err)
	}
	if !strings.Contains(err.Error(), "timeout-or-duplicate") {
		t.Errorf("err = %q, want Cloudflare's error code in the text", err)
	}
}

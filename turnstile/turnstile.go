// Package turnstile verifies Cloudflare Turnstile tokens on the server.
//
// Embedding the widget in a page is only half of the job: a bot can skip the
// widget and post straight to the API. The token the widget produces has to be
// sent to Cloudflare's siteverify endpoint and the request refused unless it
// passes. This package does that second step and fails closed: if Cloudflare
// cannot be reached or answers with anything but success, Verify returns
// ErrFailed. Failing open would let an attacker bypass the check by disrupting
// the connection to Cloudflare.
package turnstile

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// VerifyURL is Cloudflare's siteverify endpoint.
const VerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

var (
	// ErrFailed means the token was rejected or could not be checked
	// (missing, forged, expired, reused, wrong hostname, Cloudflare unreachable).
	ErrFailed = errors.New("turnstile: verification failed")
	// ErrNotConfigured means Verify was called on a Verifier with no secret.
	ErrNotConfigured = errors.New("turnstile: no secret configured")
)

// Options tune a Verifier. The zero value is valid.
type Options struct {
	// Hostnames, when non-empty, also requires the hostname Cloudflare reports
	// for the token to be one of these, so a token solved on another site that
	// shares the site key is refused.
	Hostnames []string
	// HTTPClient overrides the client used to call Cloudflare. The default has
	// a 10-second timeout.
	HTTPClient *http.Client
	// Endpoint overrides VerifyURL, for tests.
	Endpoint string
}

// Verifier checks tokens against Cloudflare.
type Verifier struct {
	secret   string
	client   *http.Client
	endpoint string
	hosts    map[string]bool
}

// New returns a Verifier for secret. An empty secret gives a Verifier whose
// Enabled reports false and whose Verify returns ErrNotConfigured, so a
// missing secret can never silently disable the check.
func New(secret string, opts Options) *Verifier {
	v := &Verifier{
		secret:   strings.TrimSpace(secret),
		client:   opts.HTTPClient,
		endpoint: opts.Endpoint,
	}
	if v.client == nil {
		v.client = &http.Client{Timeout: 10 * time.Second}
	}
	if v.endpoint == "" {
		v.endpoint = VerifyURL
	}
	if len(opts.Hostnames) > 0 {
		v.hosts = map[string]bool{}
		for _, h := range opts.Hostnames {
			v.hosts[strings.ToLower(h)] = true
		}
	}
	return v
}

// Enabled reports whether a secret is configured.
func (v *Verifier) Enabled() bool { return v.secret != "" }

type verifyResp struct {
	Success    bool     `json:"success"`
	Hostname   string   `json:"hostname"`
	ErrorCodes []string `json:"error-codes"`
}

// Verify asks Cloudflare whether token is valid. remoteIP is optional; when
// given, Cloudflare compares it with the address the token was issued to.
func (v *Verifier) Verify(ctx context.Context, token, remoteIP string) error {
	if !v.Enabled() {
		return ErrNotConfigured
	}
	if strings.TrimSpace(token) == "" {
		return ErrFailed
	}

	form := url.Values{"secret": {v.secret}, "response": {token}}
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return ErrFailed
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.client.Do(req)
	if err != nil {
		return ErrFailed
	}
	defer resp.Body.Close()

	var out verifyResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return ErrFailed
	}
	if !out.Success {
		return ErrFailed
	}
	if v.hosts != nil && !v.hosts[strings.ToLower(out.Hostname)] {
		return ErrFailed
	}
	return nil
}

// ClientIPOptions say which proxy headers to believe.
type ClientIPOptions struct {
	// TrustCloudflare uses the CF-Connecting-IP header when present.
	//
	// Cloudflare overwrites this header on every request it proxies, so it
	// cannot be forged by a client whose traffic goes through Cloudflare. It
	// CAN be forged by anyone who reaches the origin directly. Enable this only
	// when the origin is reachable through Cloudflare alone (e.g. a Cloudflare
	// Tunnel, or a firewall that admits only Cloudflare's address ranges).
	TrustCloudflare bool
}

// ClientIP returns the client address for rate limiting and for Verify's
// remoteIP. Without a trusted header it is the connection's peer address.
// X-Forwarded-For is never used: any client can set it.
func ClientIP(r *http.Request, opts ClientIPOptions) string {
	if opts.TrustCloudflare {
		if ip := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.Trim(r.RemoteAddr, "[]")
	}
	return host
}

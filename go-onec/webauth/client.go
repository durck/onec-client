// Package webauth implements observed 1C web-client authentication, separately
// from HTTP Basic service authentication and the native TCP protocol.
package webauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"onec/webprobe"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/net/publicsuffix"
)

type Config struct {
	URL       string
	Timeout   time.Duration
	Insecure  bool
	AllowHTTP bool
}

type Credentials struct{ Username, Password, Method string }

func (Credentials) String() string               { return "web credentials (redacted)" }
func (c Credentials) GoString() string           { return c.String() }
func (Credentials) MarshalJSON() ([]byte, error) { return []byte(`"<redacted>"`), nil }

// Error deliberately excludes server text, URLs, tokens and request bodies.
type Error struct {
	Operation string `json:"operation"`
	Kind      string `json:"kind"`
	Status    int    `json:"http_status,omitempty"`
	Reason    int    `json:"reason,omitempty"`
}

func (e *Error) Error() string { return "web " + e.Operation + ": " + e.Kind }

type LoginResult struct {
	Method               string `json:"method"`
	WebVersion           string `json:"web_version"`
	Authenticated        bool   `json:"authenticated"`
	CredentialsSubmitted bool   `json:"credentials_submitted"`
	ApplicationReady     bool   `json:"application_ready"`
	PasswordStatus       int    `json:"password_status,omitempty"`
	SessionPresent       bool   `json:"session_present"`
	Requests             int    `json:"requests"`
}

// Client owns one attempt and an in-memory cookie/session context. Methods are
// serialized. Logout must be attempted explicitly; Close releases local state.
type Client struct {
	mu                               sync.Mutex
	cfg                              Config
	base                             *url.URL
	http                             *http.Client
	transport                        *http.Transport
	version, session                 string
	attempted, authenticated, closed bool
	requests                         int
}

func (*Client) String() string     { return "1C web client (redacted)" }
func (c *Client) GoString() string { return c.String() }

var versionRE = regexp.MustCompile(`\bvar\s+VERSION\s*=\s*["'](8\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,6})["']`)

func ValidateConfig(cfg Config) error {
	if _, err := webprobe.NewPlan(webprobe.Config{URL: cfg.URL, Timeout: cfg.Timeout}); err != nil {
		return err
	}
	u, _ := url.Parse(cfg.URL)
	if u.Scheme != "https" && !cfg.AllowHTTP {
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return errors.New("authentication requires HTTPS; --allow-http explicitly permits plaintext HTTP (literal loopback is allowed)")
		}
	}
	return nil
}

func newTransport(ctx context.Context, cfg Config) (*Client, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	p, _ := webprobe.NewPlan(webprobe.Config{URL: cfg.URL, Timeout: cfg.Timeout})
	u, _ := url.Parse(p.URL)
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	resolveCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(resolveCtx, u.Hostname())
	if err != nil || len(ips) == 0 {
		return nil, &Error{Operation: "connect", Kind: "dns_failed"}
	}
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	address := net.JoinHostPort(ips[0].String(), port)
	dialer := &net.Dialer{Timeout: min(timeout, 10*time.Second)}
	t := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, address)
	}, TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.Insecure}, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: timeout, MaxResponseHeaderBytes: 64 << 10, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1}
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	h := &http.Client{Transport: t, Jar: jar, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Client{cfg: cfg, base: u, http: h, transport: t}, nil
}

// New fetches only the supplied entry directory to discover its web build.
// Cookies stay in memory; credentials are never inferred from local accounts.
func New(ctx context.Context, cfg Config) (*Client, error) {
	c, err := newTransport(ctx, cfg)
	if err != nil {
		return nil, err
	}
	r, err := c.request(ctx, "bootstrap", "GET", "", nil, nil, false, "")
	if err != nil {
		c.Close()
		return nil, err
	}
	defer clear(r.body)
	if r.status != 200 {
		c.Close()
		return nil, statusError("bootstrap", r)
	}
	m := versionRE.FindSubmatch(r.body)
	if len(m) != 2 {
		c.Close()
		return nil, &Error{Operation: "bootstrap", Kind: "unrecognized_web_client"}
	}
	c.version = string(m[1])
	return c, nil
}

type response struct {
	status int
	header http.Header
	body   []byte
}

func (c *Client) request(ctx context.Context, op, method, path string, q url.Values, body []byte, session bool, basic string) (response, error) {
	u := *c.base
	u.Path += path
	u.RawPath = ""
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return response{}, &Error{Operation: op, Kind: "invalid_request"}
	}
	req.Header.Set("User-Agent", "onec-web-client/1")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	if session && c.session != "" {
		req.Header.Set("vrs-session", c.session)
	}
	if basic != "" {
		req.Header.Set("Authorization", basic)
	}
	c.requests++
	r, err := c.http.Do(req)
	if err != nil {
		return response{}, &Error{Operation: op, Kind: "transport_failed"}
	}
	defer r.Body.Close()
	b, err := io.ReadAll(io.LimitReader(r.Body, (4<<20)+1))
	if err != nil || len(b) > 4<<20 {
		clear(b)
		return response{status: r.StatusCode}, &Error{Operation: op, Kind: "incomplete_response", Status: r.StatusCode}
	}
	return response{r.StatusCode, r.Header, b}, nil
}

func decode(r response) (map[string]json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if json.Unmarshal(bytes.TrimPrefix(r.body, []byte{0xef, 0xbb, 0xbf}), &obj) != nil || obj == nil {
		return nil, &Error{Operation: "decode", Kind: "invalid_json", Status: r.status}
	}
	return obj, nil
}

func statusError(op string, r response) error {
	e := &Error{Operation: op, Kind: "unexpected_status", Status: r.status}
	switch r.status {
	case 401:
		e.Kind = "http_auth_required_or_refused"
	case 402:
		e.Kind = "authentication_refused"
	case 403:
		e.Kind = "forbidden"
	case 404:
		e.Kind = "route_not_found"
	}
	if r.status >= 300 && r.status < 400 {
		e.Kind = "redirect_blocked"
	}
	return e
}

func validSession(s string) bool {
	return len(s) > 0 && len(s) <= 8192 && utf8.ValidString(s) && strings.IndexFunc(s, func(r rune) bool { return r <= 32 || r == 127 }) < 0
}

func (c *Client) captureSession(r response) error {
	if s := r.header.Get("vrs-session"); s != "" {
		if !validSession(s) {
			return &Error{Operation: "session", Kind: "invalid_session_header"}
		}
		c.session = s
	}
	return nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.authenticated = false
	c.session = ""
	if c.http != nil {
		c.http.Jar = nil
	}
	if c.transport != nil {
		c.transport.CloseIdleConnections()
	}
	return nil
}

func (c *Client) SessionPresent() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.session != "" }

func (c *Client) Logout(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return &Error{Operation: "logout", Kind: "client_closed"}
	}
	if c.session == "" {
		return nil
	}
	r, err := c.request(ctx, "logout", "POST", "e1cib/logout", nil, []byte(`{"root":{}}`), true, "")
	if err != nil {
		return err
	}
	defer clear(r.body)
	if r.status != 200 && r.status != 201 && r.status != 204 {
		return statusError("logout", r)
	}
	if len(bytes.TrimSpace(r.body)) > 0 {
		obj, err := decode(r)
		if err != nil {
			return err
		}
		if _, ok := obj["exception"]; ok {
			return &Error{Operation: "logout", Kind: "server_exception", Status: r.status}
		}
	}
	c.session = ""
	c.authenticated = false
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	c.http.Jar = jar
	return nil
}

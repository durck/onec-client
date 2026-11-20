package webprobe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

type Finding struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Endpoint string `json:"endpoint,omitempty"`
	Message  string `json:"message"`
}

type Result struct {
	Request        Request        `json:"request"`
	Status         int            `json:"status"`
	ContentType    string         `json:"content_type,omitempty"`
	Server         string         `json:"server,omitempty"`
	PoweredBy      string         `json:"powered_by,omitempty"`
	Allow          string         `json:"allow,omitempty"`
	AuthSchemes    []string       `json:"auth_schemes,omitempty"`
	BasicRealm     string         `json:"basic_realm,omitempty"`
	Redirect       string         `json:"redirect,omitempty"`
	CookiesPresent bool           `json:"cookies_present"`
	Bytes          int            `json:"bytes"`
	SHA256         string         `json:"sha256,omitempty"`
	Truncated      bool           `json:"truncated"`
	Kind           string         `json:"kind"`
	Summary        map[string]any `json:"summary,omitempty"`
	ElapsedMS      int64          `json:"elapsed_ms"`
	Error          string         `json:"error,omitempty"`
}

type TLSInfo struct {
	Version   string    `json:"version"`
	Cipher    string    `json:"cipher"`
	Verified  bool      `json:"verified"`
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	DNSNames  []string  `json:"dns_names,omitempty"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	SHA256    string    `json:"sha256"`
}

type Report struct {
	Plan                    Plan      `json:"plan"`
	StartedUTC              time.Time `json:"started_utc"`
	ResolvedIP              string    `json:"resolved_ip"`
	TLSVerificationDisabled bool      `json:"tls_verification_disabled"`
	TLS                     *TLSInfo  `json:"tls,omitempty"`
	Complete                bool      `json:"complete"`
	TotalBytes              int       `json:"total_bytes"`
	Results                 []Result  `json:"results"`
	Findings                []Finding `json:"findings"`
}

func (r *Report) finding(severity, code, endpoint, message string) {
	r.Findings = append(r.Findings, Finding{severity, code, endpoint, message})
}

func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// Enumerate uses fresh anonymous requests. HTTP status codes are observations;
// DNS, TLS, transport, read, cancellation and budget failures return an error
// together with the partial report. No response bodies are retained in Report.
func Enumerate(parent context.Context, c Config) (Report, error) {
	p, err := NewPlan(c)
	if err != nil {
		return Report{}, err
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	r := Report{Plan: p, StartedUTC: time.Now().UTC(), TLSVerificationDisabled: c.Insecure, Results: []Result{}, Findings: []Finding{}}
	if c.Insecure {
		r.finding("warn", "tls_unverified", "", "TLS certificate verification explicitly disabled; peer identity is unverified")
	}
	u, _ := url.Parse(p.URL)
	if u.Scheme == "http" {
		r.finding("warn", "plaintext_http", "", "Publication is accessed over unencrypted HTTP")
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, u.Hostname())
	if err != nil || len(ips) == 0 {
		return r, errors.New("cannot resolve publication host")
	}
	r.ResolvedIP = ips[0].String()
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	address := net.JoinHostPort(r.ResolvedIP, port)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		// No environment proxy, OS authentication, client certificate or cookie jar.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: c.Insecure},
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
		MaxResponseHeaderBytes: 64 << 10, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return execute(ctx, client, c, r, 250*time.Millisecond)
}

func execute(ctx context.Context, client *http.Client, c Config, r Report, gap time.Duration) (Report, error) {
	version := ""
	var operationErr error
	for i, spec := range r.Plan.Requests {
		if i > 0 && gap > 0 {
			timer := time.NewTimer(gap)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
			}
		}
		if err := ctx.Err(); err != nil {
			operationErr = err
			break
		}
		remaining := (32 << 20) - r.TotalBytes
		if remaining <= 0 {
			operationErr = errors.New("32 MiB total response budget exhausted")
			break
		}
		limit := 1 << 20
		if c.Assets {
			limit = 8 << 20
		}
		if remaining < limit {
			limit = remaining
		}
		x, body, peer := fetch(ctx, client, versioned(spec, version), int64(limit))
		r.TotalBytes += x.Bytes
		if r.TLS == nil && peer != nil {
			r.TLS = peer
		}
		if x.Error != "" || x.Truncated {
			operationErr = errors.New("one or more requests failed or exceeded the body budget; see partial report")
			r.finding("warn", "incomplete_response", spec.ID, "Response unavailable or incomplete; content was not analyzed")
		} else {
			analyze(&r, &x, body)
		}
		if spec.ID == "entry" && x.Status == http.StatusOK {
			version, _ = x.Summary["web_version"].(string)
		}
		r.Results = append(r.Results, x)
		// Do not repeat a failed TLS handshake/connection for every route.
		if i == 0 && x.Status == 0 {
			break
		}
	}
	r.Complete = len(r.Results) == len(r.Plan.Requests) && operationErr == nil
	compareControl(&r)
	return r, operationErr
}

func fetch(ctx context.Context, client *http.Client, spec Request, limit int64) (Result, []byte, *TLSInfo) {
	x := Result{Request: spec, Kind: "unavailable", Summary: map[string]any{}}
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, spec.Method, spec.URL, nil)
	if err != nil {
		x.Error = "cannot construct request"
		return x, nil, nil
	}
	req.Header.Set("User-Agent", "onec-web-enum/1")
	req.Header.Set("Accept", "*/*")
	if spec.ID == "auth-settings" {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	resp, err := client.Do(req)
	if err != nil {
		x.Error = clean(err.Error(), 1024)
		x.ElapsedMS = time.Since(start).Milliseconds()
		return x, nil, nil
	}
	defer resp.Body.Close()
	x.Status = resp.StatusCode
	x.ContentType = clean(resp.Header.Get("Content-Type"), 256)
	x.Server = clean(resp.Header.Get("Server"), 256)
	x.PoweredBy = clean(resp.Header.Get("X-Powered-By"), 256)
	x.Allow = clean(resp.Header.Get("Allow"), 256)
	x.CookiesPresent = len(resp.Header.Values("Set-Cookie")) > 0
	x.AuthSchemes, x.BasicRealm = authentication(resp.Header.Values("WWW-Authenticate"))
	if location := resp.Header.Get("Location"); location != "" {
		x.Redirect = safeLocation(location)
	}
	var peer *TLSInfo
	if s := resp.TLS; s != nil && len(s.PeerCertificates) > 0 {
		cert := s.PeerCertificates[0]
		peer = &TLSInfo{Version: tls.VersionName(s.Version), Cipher: tls.CipherSuiteName(s.CipherSuite), Verified: len(s.VerifiedChains) > 0, Subject: clean(cert.Subject.String(), 1024), Issuer: clean(cert.Issuer.String(), 1024), NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, SHA256: hash(cert.Raw)}
		for _, name := range cert.DNSNames[:min(len(cert.DNSNames), 64)] {
			peer.DNSNames = append(peer.DNSNames, clean(name, 256))
		}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if int64(len(body)) > limit {
		body = body[:limit]
		x.Truncated = true
	}
	x.Bytes = len(body)
	x.SHA256 = hash(body)
	x.ElapsedMS = time.Since(start).Milliseconds()
	if err != nil {
		x.Error = fmt.Sprintf("response read failed: %s", clean(err.Error(), 512))
	}
	return x, body, peer
}

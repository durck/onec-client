package webauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"onec/secpswd"
	"regexp"
	"strings"
	"unicode/utf8"
)

var uuidRE = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func sessionUUID(s string) (string, error) {
	if uuidRE.MatchString(s) {
		return s, nil
	}
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		b, err := enc.DecodeString(s)
		if err == nil && len(b) >= 36 && uuidRE.Match(b[:36]) {
			id := string(b[:36])
			clear(b)
			return id, nil
		}
		clear(b)
	}
	return "", &Error{Operation: "session", Kind: "unsupported_session_format"}
}

func ValidateCredentials(c Credentials) error {
	switch c.Method {
	case "", "auto", "legacy", "v1", "v3":
	default:
		return &Error{Operation: "login", Kind: "unsupported_method"}
	}
	if c.Username == "" || len(c.Username) > 1024 || len(c.Password) > 4096 || !utf8.ValidString(c.Username) || !utf8.ValidString(c.Password) || strings.ContainsAny(c.Username+c.Password, "\x00\b\r\n") {
		return &Error{Operation: "login", Kind: "invalid_credentials_format"}
	}
	return nil
}

func (c *Client) selectMethod(ctx context.Context, method string) (string, error) {
	if method != "" && method != "auto" {
		return method, nil
	}
	// Read the publication's own client contract before sending credentials.
	// The asset is never executed and cannot redirect the pinned transport.
	r, err := c.request(ctx, "auth_contract", "GET", "scripts/mod_main_loader.js", url.Values{"sysver": {c.version}}, nil, false, "")
	if err != nil {
		return "", err
	}
	defer clear(r.body)
	if r.status != 200 {
		return "", statusError("auth_contract", r)
	}
	return detectAuthMethod(r.body)
}

func (c *Client) Login(ctx context.Context, credentials Credentials) (result LoginResult, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	result.WebVersion = c.version
	defer func() { result.SessionPresent = c.session != ""; result.Requests = c.requests }()
	if c.closed || c.attempted {
		return result, &Error{Operation: "login", Kind: "client_closed_or_already_attempted"}
	}
	if err = ValidateCredentials(credentials); err != nil {
		return result, err
	}
	method, err := c.selectMethod(ctx, credentials.Method)
	if err != nil {
		return result, err
	}
	result.Method = method
	c.attempted = true
	random := make([]byte, 16)
	if _, err = rand.Read(random); err != nil {
		return result, &Error{Operation: "login", Kind: "random_source_failed"}
	}
	random[6] = (random[6] & 15) | 64
	random[8] = (random[8] & 63) | 128
	id := hex.EncodeToString(random)
	clear(random)
	q := url.Values{"version": {c.version}, "nowa": {""}, "nooida": {""}, "clnId": {id[:8] + "-" + id[8:12] + "-" + id[12:16] + "-" + id[16:20] + "-" + id[20:]}}
	if method == "legacy" {
		q.Set("cred", base64.StdEncoding.EncodeToString([]byte(credentials.Username+"\b"+credentials.Password)))
		result.CredentialsSubmitted = true
		r, e := c.request(ctx, "login", "POST", "e1cib/login", q, nil, false, "")
		if e != nil {
			return result, e
		}
		defer clear(r.body)
		if e = c.captureSession(r); e != nil {
			return result, e
		}
		if r.status != 200 {
			return result, c.loginError(r)
		}
		return c.acceptApplication(r, result)
	}
	// The modern web client establishes a preauthentication seance before C1.
	r, e := c.request(ctx, "prelogin", "POST", "e1cib/login", q, nil, false, "")
	if e != nil {
		return result, e
	}
	if e = c.captureSession(r); e != nil {
		clear(r.body)
		return result, e
	}
	if r.status == 200 {
		// An anonymously accepted publication does not validate supplied credentials.
		result, e = c.acceptApplication(r, result)
		clear(r.body)
		return result, e
	}
	if r.status != 402 {
		e = c.loginError(r)
		clear(r.body)
		return result, e
	}
	if e = c.readPreloginSession(r); e != nil {
		clear(r.body)
		return result, e
	}
	clear(r.body)
	// Newer settings can carry S2. An absent cred is an observed alternative,
	// not an authentication failure/downgrade; the same C1 goes to login next.
	codecVersion := secpswd.V3
	if method == "v1" {
		codecVersion = secpswd.V1
	}
	codec, _ := secpswd.NewClient(codecVersion, nil)
	defer codec.Close()
	outgoing, e := codec.Start(credentials.Username, credentials.Password)
	if e != nil {
		return result, &Error{Operation: "login", Kind: "credential_initialization_failed"}
	}
	{
		body, _ := json.Marshal(map[string]string{"cred": outgoing})
		result.CredentialsSubmitted = true
		settingsQuery := url.Values{"sysver": {c.version}}
		if method == "v3" {
			settingsQuery.Set("version", "1")
		}
		r, e = c.request(ctx, "settings", "POST", "e1cib/additionalAuthSettings", settingsQuery, body, true, "")
		clear(body)
		if e != nil {
			return result, e
		}
		if e = c.captureSession(r); e != nil {
			clear(r.body)
			return result, e
		}
		if r.status != 200 {
			e = c.loginError(r)
			clear(r.body)
			return result, e
		}
		obj, e := decode(r)
		clear(r.body)
		if e != nil {
			return result, e
		}
		if _, ok := obj["exception"]; ok {
			return result, &Error{Operation: "settings", Kind: "server_exception"}
		}
		if raw, ok := obj["cred"]; ok {
			var incoming string
			if json.Unmarshal(raw, &incoming) != nil || incoming == "" {
				return result, &Error{Operation: "settings", Kind: "invalid_credential_response"}
			}
			step, e := codec.Receive(incoming)
			if e != nil || step.Completed || step.Credential == "" {
				return result, &Error{Operation: "login", Kind: "credential_proof_failed"}
			}
			outgoing = step.Credential
		}
	}
	for round := 0; round < 3; round++ {
		if c.session != "" {
			sid, e := sessionUUID(c.session)
			if e != nil {
				return result, e
			}
			q.Set("sid", sid)
		}
		body, _ := json.Marshal(map[string]string{"cred": outgoing})
		result.CredentialsSubmitted = true
		r, e = c.request(ctx, "login", "POST", "e1cib/login", q, body, false, "")
		clear(body)
		if e != nil {
			return result, e
		}
		if e = c.captureSession(r); e != nil {
			clear(r.body)
			return result, e
		}
		if r.status != 200 {
			e = c.loginError(r)
			clear(r.body)
			return result, e
		}
		obj, e := decode(r)
		if e != nil {
			clear(r.body)
			return result, e
		}
		if raw, ok := obj["cred"]; ok {
			if _, both := obj["response"]; both {
				clear(r.body)
				return result, &Error{Operation: "login", Kind: "ambiguous_credential_response"}
			}
			var incoming string
			if json.Unmarshal(raw, &incoming) != nil || incoming == "" {
				clear(r.body)
				return result, &Error{Operation: "login", Kind: "invalid_credential_response"}
			}
			step, e := codec.Receive(incoming)
			clear(r.body)
			if e != nil || step.Completed || step.Credential == "" {
				return result, &Error{Operation: "login", Kind: "credential_proof_failed"}
			}
			outgoing = step.Credential
			continue
		}
		app, e := applicationObject(obj)
		if e != nil {
			clear(r.body)
			return result, e
		}
		proofField := "credAns6"
		if method == "v1" {
			proofField = "credAns4"
		}
		var proof string
		if json.Unmarshal(app[proofField], &proof) != nil || proof == "" {
			clear(r.body)
			return result, &Error{Operation: "login", Kind: "missing_final_proof"}
		}
		step, e := codec.Receive(proof)
		if e != nil || !step.Completed || !step.Success {
			clear(r.body)
			return result, &Error{Operation: "login", Kind: "credential_proof_failed"}
		}
		result, e = c.acceptApplication(r, result)
		clear(r.body)
		return result, e
	}
	return result, &Error{Operation: "login", Kind: "credential_round_limit"}
}

func applicationObject(obj map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	if _, ok := obj["exception"]; ok {
		return nil, &Error{Operation: "login", Kind: "server_exception"}
	}
	var payload json.RawMessage
	count := 0
	for k, v := range obj {
		if !strings.HasPrefix(k, "#") {
			payload = v
			count++
		}
	}
	var app map[string]json.RawMessage
	if count != 1 || json.Unmarshal(payload, &app) != nil || app == nil {
		return nil, &Error{Operation: "login", Kind: "invalid_application_document"}
	}
	for _, field := range []string{"user", "config"} {
		if _, ok := app[field]; !ok {
			return nil, &Error{Operation: "login", Kind: "invalid_application_document"}
		}
	}
	return app, nil
}

func (c *Client) acceptApplication(r response, result LoginResult) (LoginResult, error) {
	obj, err := decode(r)
	if err != nil {
		return result, err
	}
	app, err := applicationObject(obj)
	if err != nil {
		return result, err
	}
	if c.session == "" {
		return result, &Error{Operation: "login", Kind: "missing_session"}
	}
	result.Authenticated = true
	c.authenticated = true
	if raw, ok := app["passwordRequirementsComplianceStatus"]; ok {
		if json.Unmarshal(raw, &result.PasswordStatus) != nil {
			return result, &Error{Operation: "login", Kind: "invalid_password_status"}
		}
	}
	switch result.PasswordStatus {
	case 2, 4, 6:
		return result, &Error{Operation: "login", Kind: "password_change_required"}
	case 0, 1, 3, 5:
	default:
		return result, &Error{Operation: "login", Kind: "unsupported_password_status"}
	}
	result.ApplicationReady = true
	return result, nil
}

type serverException struct {
	ClassID string           `json:"clsid"`
	Reason  int              `json:"reason"`
	Factor  int              `json:"reason_2fa"`
	Session string           `json:"seanceID"`
	Inner   *serverException `json:"inner"`
}

func (e *serverException) UnmarshalJSON(data []byte) error {
	// seanceID is the application session; lowercase seanceid is a distinct
	// second-factor identifier and must never replace the application session.
	type plain serverException
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	p.Session = ""
	if raw, ok := fields["seanceID"]; ok {
		if err := json.Unmarshal(raw, &p.Session); err != nil {
			return err
		}
	}
	*e = serverException(p)
	return nil
}

func exceptionOf(r response) *serverException {
	body := bytes.TrimPrefix(r.body, []byte{0xef, 0xbb, 0xbf})
	var wrapper struct {
		Exception *serverException `json:"exception"`
	}
	if json.Unmarshal(body, &wrapper) != nil {
		return nil
	}
	if wrapper.Exception == nil {
		var bare serverException
		if json.Unmarshal(body, &bare) == nil && (strings.EqualFold(bare.ClassID, "580392E6-BA49-4280-AC67-FCD6F2180121") || strings.EqualFold(bare.ClassID, "17EF6DDF-DF7F-481D-B419-86B782720C2B")) {
			return &bare
		}
	}
	return wrapper.Exception
}
func (c *Client) readPreloginSession(r response) error {
	ex := exceptionOf(r)
	if ex == nil {
		return &Error{Operation: "prelogin", Kind: "invalid_session_challenge"}
	}
	for depth := 0; ex != nil && depth < 16; depth++ {
		if ex.Reason == -14 || ex.Factor != 0 {
			return c.loginError(r)
		}
		if ex.Session != "" {
			if !validSession(ex.Session) {
				return &Error{Operation: "prelogin", Kind: "invalid_session"}
			}
			c.session = ex.Session
		}
		ex = ex.Inner
	}
	id, err := sessionUUID(c.session)
	if err != nil || id == "00000000-0000-0000-0000-000000000000" {
		return &Error{Operation: "prelogin", Kind: "invalid_session_challenge"}
	}
	return nil
}
func (c *Client) loginError(r response) error {
	e := statusError("login", r).(*Error)
	for ex, depth := exceptionOf(r), 0; ex != nil && depth < 16; ex, depth = ex.Inner, depth+1 {
		if ex.Session != "" && validSession(ex.Session) {
			c.session = ex.Session
		}
		if ex.Reason != 0 {
			e.Reason = ex.Reason
		}
		switch {
		case ex.Reason == -14 || ex.Factor == 1:
			e.Kind = "second_factor_required"
		case ex.Factor == 3:
			e.Kind = "external_second_factor_required"
		}
	}
	return e
}

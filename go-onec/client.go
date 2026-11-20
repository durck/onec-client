package onec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"onec/secpswd"
	"onec/wire"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type AuthMethod string

const (
	WindowsAuth AuthMethod = "windows"
	LegacyAuth  AuthMethod = "legacy"
	PasswordV1  AuthMethod = "v1"
	PasswordV2  AuthMethod = "v2"
	PasswordV3  AuthMethod = "v3"
)

type Credentials struct {
	Method             AuthMethod
	Username, Password string `json:"-"`
}

func (Credentials) String() string     { return "1C credentials (redacted)" }
func (c Credentials) GoString() string { return c.String() }

// Stats records cumulative evidence, including whether this client ever
// authenticated. Authenticated remains true after a successful logout.
type Stats struct {
	Connections             []string              `json:"connections"`
	RPCRounds               int                   `json:"rpc_rounds"`
	BytesSent               int64                 `json:"bytes_sent"`
	BytesReceived           int64                 `json:"bytes_received"`
	Authenticated           bool                  `json:"authenticated"`
	LogoutConfirmed         bool                  `json:"logout_confirmed"`
	ContextReleased         bool                  `json:"context_released"`
	SecurityClosed          bool                  `json:"security_closed"`
	Closed                  bool                  `json:"closed"`
	AuthenticationMethod    AuthMethod            `json:"authentication_method"`
	SecurityContexts        []SecurityObservation `json:"security_contexts,omitempty"`
	ContextRecoveryAttempts int                   `json:"context_recovery_attempts,omitempty"`
	ContextRecoveries       int                   `json:"context_recoveries,omitempty"` // Reopened and queried contexts, not authenticated logins.
	RetiredContextReleased  bool                  `json:"retired_context_released,omitempty"`
	RetiredSecurityClosed   bool                  `json:"retired_security_closed,omitempty"`
	RetiredConnectionClosed bool                  `json:"retired_connection_closed,omitempty"` // True only after all retired cleanup succeeds.
}

// Client serializes operations on one worker context. Always close it, including
// after failed authentication, to release the context and any cleanup session.
type Client struct {
	mu                               sync.Mutex
	cfg                              Config
	connection                       *connection
	clientID                         wire.UUID
	inner                            SecurityContext
	httpStarted, httpComplete        bool
	lastSync                         uint32
	session                          *sessionHeader
	authenticated, attempted, closed bool
	retryableLogin                   bool
	closeErr                         error
	stats                            Stats
	managerRounds                    int
	managerSent, managerReceived     int64
	applicationAssemblyVersion       string
	applicationConfigVersion         string
	applicationRolesID               string
	workerAddress                    string
	loginCredentialsSent             bool // Monotonic; explicit RetryLogin cannot restore recovery eligibility.
	retiredRounds                    int
	retiredSent, retiredReceived     int64
}

func (c *Client) String() string   { return "1C client (session redacted)" }
func (c *Client) GoString() string { return c.String() }

func ValidateConfig(cfg Config) error { _, e := cfg.normalized(); return e }
func Dial(ctx context.Context, cfg Config) (client *Client, err error) {
	cfg, err = cfg.normalized()
	if err != nil {
		return nil, err
	}
	c := &Client{cfg: cfg}
	defer func() {
		if err != nil {
			err = errors.Join(err, c.Close())
		}
	}()
	process, err := wire.NewUUID()
	if err != nil {
		return nil, err
	}
	c.clientID, err = wire.NewUUID()
	if err != nil {
		return nil, err
	}
	address := cfg.Worker
	if address == "" {
		m, e := openConnection(ctx, cfg, cfg.Server, wire.ManagerContext, "RegMngrCntxt:RegMngrCntxt", wire.UUID{}, process)
		if e != nil {
			return nil, fmt.Errorf("manager: %w", e)
		}
		c.stats.Connections = append(c.stats.Connections, cfg.Server)
		c.stats.SecurityContexts = append(c.stats.SecurityContexts, SecurityObservation{"manager", m.mechanism})
		address, err = func() (address string, err error) {
			defer func() {
				var releaseErr error
				if m.sync {
					cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					releaseErr = m.release(cleanup)
					cancel()
				}
				closeErr := m.closeSocket()
				c.managerRounds = m.rounds
				c.managerSent = m.sent
				c.managerReceived = m.received
				err = errors.Join(err, releaseErr, closeErr)
			}()
			if e := m.query(ctx, wire.SelectInterface); e != nil {
				return "", e
			}
			n, e := m.next()
			if e != nil {
				return "", e
			}
			request, e := wire.SelectRequest(m.target, n, cfg.Infobase, c.clientID, cfg.Profile.Application)
			if e != nil {
				return "", e
			}
			reply, e := m.exchange(ctx, request)
			if e != nil {
				return "", e
			}
			selected, e := wire.ParseSelection(reply)
			if e != nil {
				return "", e
			}
			_, port, e := net.SplitHostPort(selected)
			p, pe := strconv.Atoi(port)
			if e != nil || pe != nil || p < 1 || p > 65535 {
				return "", errors.New("invalid selected worker endpoint")
			}
			host, _, _ := net.SplitHostPort(cfg.Server)
			return net.JoinHostPort(host, port), nil
		}()
		if err != nil {
			return nil, fmt.Errorf("worker discovery: %w", err)
		}
	}
	last, err := wire.NewUUID()
	if err != nil {
		return nil, err
	}
	c.workerAddress = address
	c.connection, err = openConnection(ctx, cfg, address, wire.WorkerContext, cfg.Infobase+":"+cfg.Infobase, last, process)
	if err != nil {
		return nil, fmt.Errorf("worker: %w", err)
	}
	c.stats.Connections = append(c.stats.Connections, address)
	c.stats.SecurityContexts = append(c.stats.SecurityContexts, SecurityObservation{"worker", c.connection.mechanism})
	if err = c.connection.query(ctx, wire.HTTPInterface); err != nil {
		return nil, err
	}
	return c, nil
}
func (c *Client) usable() error {
	if c.closed || c.connection == nil {
		return errors.New("client is closed")
	}
	if !c.connection.sync {
		return errors.New("client connection is not synchronized")
	}
	return nil
}
func (c *Client) sendHTTP(ctx context.Context, pdu, token []byte, security bool) (wire.HTTPReply, error) {
	n, e := c.connection.next()
	if e != nil {
		return wire.HTTPReply{}, e
	}
	p, e := wire.HTTPRequest(c.connection.target, n, pdu, token, security, c.httpStarted)
	if e != nil {
		return wire.HTTPReply{}, e
	}
	c.httpStarted = true
	r, e := c.connection.exchange(ctx, p)
	if e != nil {
		return wire.HTTPReply{}, e
	}
	return wire.ParseHTTPReply(r)
}
func (c *Client) exchangeHTTP(ctx context.Context, pdu []byte) (*wire.HTTP, error) {
	r, e := c.sendHTTP(ctx, pdu, nil, false)
	if e != nil {
		return nil, e
	}
	return c.completeHTTP(ctx, pdu, r)
}

func (c *Client) completeHTTP(ctx context.Context, pdu []byte, r wire.HTTPReply) (*wire.HTTP, error) {
	var e error
	// Public/preliminary replies can complete without constructing inner SSPI.
	// A later login request may negotiate it for the first time. Once an inner
	// context exists (or application login succeeded), renegotiation is rejected.
	if c.httpComplete && (c.inner != nil || c.authenticated) {
		if !r.SecurityComplete || len(r.Token) > 0 {
			return nil, errors.New("unexpected HTTP security renegotiation")
		}
	} else if r.SecurityComplete {
		if len(r.Token) > 0 {
			return nil, errors.New("unexpected completed security token")
		}
		c.httpComplete = true
	} else {
		if len(r.Token) > 0 {
			return nil, errors.New("unexpected initial HTTP security token")
		}
		if c.inner != nil {
			return nil, errors.New("failed HTTP security negotiation cannot be restarted; close this client")
		}
		c.loginCredentialsSent = true
		c.httpComplete = false
		c.inner, e = c.cfg.SecurityFactory()
		if e != nil {
			return nil, e
		}
		name, e := c.inner.Name()
		if e != nil {
			return nil, e
		}
		if (c.cfg.Kerberos != nil || c.cfg.NTLM != nil) && name != c.connection.identity {
			return nil, errors.New("explicit credential identity changed between contexts")
		}
		intro, e := wire.Introduction(name)
		if e != nil {
			return nil, e
		}
		r, e = c.sendHTTP(ctx, pdu, intro, true)
		if e != nil {
			return nil, e
		}
		if r.SecurityComplete {
			return nil, errors.New("premature HTTP security completion")
		}
		target, packageName, e := wire.IntroductionAck(r.Token)
		if e != nil {
			return nil, e
		}
		if packageName != "Negotiate" {
			return nil, errors.New("unsupported HTTP security package")
		}
		var input []byte
		for leg := 0; leg < 3; leg++ {
			token, complete, e := securityStep(ctx, c.inner, target, input)
			clear(input)
			if e != nil {
				return nil, e
			}
			r, e = c.sendHTTP(ctx, pdu, token, true)
			clear(token)
			if e != nil {
				return nil, e
			}
			if r.SecurityComplete {
				if e := finishSecurity(ctx, c.inner, target, complete, r.Token); e != nil {
					return nil, e
				}
				c.httpComplete = true
				c.stats.SecurityContexts = append(c.stats.SecurityContexts, SecurityObservation{"inner", securityMechanism(c.inner)})
				break
			}
			input = r.Token
			if len(input) == 0 {
				return nil, errors.New("missing HTTP security continuation")
			}
		}
		if !c.httpComplete {
			return nil, errors.New("HTTP security round limit")
		}
	}
	if r.PDU == nil {
		return nil, errors.New("completed exchange has no HTTP response")
	}
	return wire.ParseHTTP(r.PDU, true)
}

// Users returns the server's optional prelogin selection list. It does not log in.
func (c *Client) Users(ctx context.Context) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.usable(); e != nil {
		return nil, e
	}
	if c.attempted {
		return nil, errors.New("user listing must precede login")
	}
	target := strings.Replace(c.loginTarget(nil, false), "/e1cib/login?", "/e1cib/users?", 1)
	p, e := c.pdu("GET", target, nil, "", "text/plain", "", 0)
	if e != nil {
		return nil, e
	}
	r, e := c.sendHTTP(ctx, p, nil, false)
	if e != nil {
		return nil, e
	}
	if !r.SecurityComplete || len(r.Token) > 0 || r.PDU == nil {
		return nil, errors.New("unexpected user-list security state")
	}
	h, e := wire.ParseHTTP(r.PDU, false)
	if e != nil {
		return nil, e
	}
	return parseUsers(h)
}
func parseUsers(h *wire.HTTP) ([]string, error) {
	if h.Status != 200 {
		return nil, &StatusError{"users", h.Status}
	}
	types := h.Header("content-type")
	if len(types) != 1 {
		return nil, errors.New("missing user-list content type")
	}
	parts := strings.Split(strings.ToLower(types[0]), ";")
	if strings.TrimSpace(parts[0]) != "text/plain" {
		return nil, errors.New("unexpected user-list content type")
	}
	for _, part := range parts[1:] {
		p := strings.TrimSpace(part)
		if strings.HasPrefix(p, "charset=") && p != "charset=utf-8" && p != "charset=\"utf-8\"" {
			return nil, errors.New("unsupported user-list charset")
		}
	}
	b, e := decodeBody(h, 65536)
	if e != nil {
		return nil, e
	}
	if !utf8.Valid(b) {
		return nil, errors.New("invalid user-list UTF-8")
	}
	text := strings.TrimPrefix(string(b), "\ufeff")
	names := []string{}
	for _, name := range strings.Split(text, "\r\n") {
		if name == "" {
			continue
		}
		if utf8.RuneCountInString(name) > 256 {
			return nil, errors.New("user-name limit")
		}
		for _, r := range name {
			if r < 32 || r == 127 {
				return nil, errors.New("invalid user-list entry")
			}
		}
		names = append(names, name)
	}
	if len(names) > 1000 {
		return nil, errors.New("user-list count limit")
	}
	return names, nil
}

// AuthenticationSettings returns the decoded endpoint body without persisting it.
func (c *Client) AuthenticationSettings(ctx context.Context) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.usable(); e != nil {
		return nil, e
	}
	if c.attempted {
		return nil, errors.New("settings must precede login")
	}
	p, e := c.pdu("POST", c.loginTarget(nil, true), nil, "", "application/xml", "", 0)
	if e != nil {
		return nil, e
	}
	h, e := c.exchangeHTTP(ctx, p)
	if e != nil {
		return nil, e
	}
	if h.Status != 402 {
		return nil, &StatusError{"preliminary password login", h.Status}
	}
	target := strings.Replace(c.loginTarget(nil, false), "/e1cib/login?", "/e1cib/additionalAuthSettings?", 1)
	p, e = c.pdu("GET", target, nil, "", "application/xml", "", 0)
	if e != nil {
		return nil, e
	}
	h, e = c.exchangeHTTP(ctx, p)
	if e != nil {
		return nil, e
	}
	if h.Status != 200 {
		return nil, &StatusError{"authentication settings", h.Status}
	}
	return decodeBody(h, wire.MaxFile)
}
func (c *Client) Login(ctx context.Context, credentials Credentials) error {
	return c.login(ctx, credentials, false)
}

// CanRetryLogin reports whether the last attempt was a complete legacy refusal
// without a session header, on a synchronized transport with completed HTTP
// security framing (not necessarily a negotiated inner SSPI context).
// It does not promise that the remote peer will keep the socket open.
func (c *Client) CanRetryLogin() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.canRetryLogin()
}

func (c *Client) canRetryLogin() bool {
	return c.retryableLogin && c.attempted && !c.authenticated && c.session == nil &&
		c.httpComplete && c.usable() == nil && c.stats.AuthenticationMethod == LegacyAuth
}

// RetryLogin explicitly starts another legacy attempt after CanRetryLogin.
// TCP, RPC counters and existing transport security contexts are retained. A prior
// success, partial exchange, SecPswd failure or policy error cannot be retried.
// Ordinary Login may replace a refused context before sending any credentials;
// it never repeats a credential-bearing login attempt.
func (c *Client) RetryLogin(ctx context.Context, credentials Credentials) error {
	return c.login(ctx, credentials, true)
}

func (c *Client) login(ctx context.Context, credentials Credentials, retry bool) error {
	if (c.cfg.Kerberos != nil || c.cfg.NTLM != nil) && credentials.Method != WindowsAuth {
		return errors.New("explicit OS credentials require WindowsAuth infobase login")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.usable(); e != nil {
		return e
	}
	if retry && (credentials.Method != LegacyAuth || !c.canRetryLogin()) {
		return errors.New("login retry requires a complete legacy refusal without an application session")
	}
	if c.attempted && !retry {
		return errors.New("only one login attempt is allowed per client")
	}
	switch credentials.Method {
	case WindowsAuth, LegacyAuth, PasswordV1, PasswordV2, PasswordV3:
	default:
		return errors.New("explicit authentication method is required")
	}
	if credentials.Method == WindowsAuth && (credentials.Username != "" || credentials.Password != "") {
		return errors.New("Windows authentication cannot submit an infobase username or password")
	}
	c.attempted = true
	c.retryableLogin = false
	c.stats.AuthenticationMethod = credentials.Method
	var e error
	switch credentials.Method {
	case WindowsAuth:
		e = c.simpleLogin(ctx, credentials)
	case LegacyAuth:
		e = c.simpleLogin(ctx, credentials)
	default:
		e = c.secureLogin(ctx, credentials)
	}
	if e != nil {
		return e
	}
	c.authenticated = true
	c.stats.Authenticated = true
	return nil
}
func (c *Client) simpleLogin(ctx context.Context, credentials Credentials) error {
	passwordMode := credentials.Method == LegacyAuth
	var field string
	var e error
	if passwordMode {
		field, e = LegacyCredentialField(credentials.Username, credentials.Password)
		if e != nil {
			return e
		}
	}
	h, e := c.preliminaryLogin(ctx, passwordMode)
	if e != nil {
		return e
	}
	if passwordMode {
		if h.Status != 402 {
			return &StatusError{"preliminary password login", h.Status}
		}
		p, e := c.pdu("POST", c.loginTarget(nil, passwordMode)+"&cred="+queryEscape(field), nil, "", "application/xml", "", 0)
		if e != nil {
			return e
		}
		c.loginCredentialsSent = true
		h, e = c.exchangeHTTP(ctx, p)
		clear(p)
		if e != nil {
			return e
		}
	}
	if h.Status != 200 {
		// Do not treat a routing/session header or a requested close as a clean
		// refusal. Those cases need independent lifecycle evidence.
		c.retryableLogin = passwordMode && (h.Status == 401 || h.Status == 402) &&
			len(h.Header("vrs-session")) == 0 && len(h.Header("connection")) == 0
		return &StatusError{"login", h.Status}
	}
	session, e := parseSession(h)
	if e != nil {
		return e
	}
	c.session = &session
	metadata, e := applicationMetadataXML(h)
	if e != nil {
		return e
	}
	c.applicationAssemblyVersion, c.applicationRolesID = metadata.assemblyVersion, metadata.rolesID
	c.applicationConfigVersion = metadata.configVersion
	return nil
}
func (c *Client) secureLogin(ctx context.Context, credentials Credentials) error {
	version := secpswd.V1
	if credentials.Method == PasswordV2 {
		version = secpswd.V2
	} else if credentials.Method == PasswordV3 {
		version = secpswd.V3
	}
	codec, e := secpswd.NewClient(version, nil)
	if e != nil {
		return e
	}
	defer codec.Close()
	return c.secureLoginWithCodec(ctx, credentials, codec)
}

// The wire exchange is separate from codec construction so it can be verified
// against the same deterministic fixtures as the credential state machine.
func (c *Client) secureLoginWithCodec(ctx context.Context, credentials Credentials, codec *secpswd.Client) error {
	version := codec.Version()
	outgoing, e := codec.Start(credentials.Username, credentials.Password)
	if e != nil {
		return e
	}
	var sid *wire.UUID
	rounds := 2
	if version == secpswd.V3 {
		rounds = 3
	}
	for i := 0; i < rounds; i++ {
		body, e := json.Marshal(map[string]string{"cred": outgoing})
		if e != nil {
			return e
		}
		p, e := c.pdu("POST", c.loginTarget(sid, true), body, "application/json; charset=utf-8", "application/json", "", 0)
		clear(body)
		if e != nil {
			return e
		}
		c.loginCredentialsSent = true
		h, e := c.exchangeHTTP(ctx, p)
		clear(p)
		if e != nil {
			return e
		}
		if h.Status != 200 {
			return &StatusError{"secure login", h.Status}
		}
		session, e := parseSession(h)
		if e != nil {
			return e
		}
		final := i == rounds-1
		if final {
			c.session = &session
		}
		doc, e := responseJSON(h)
		if e != nil {
			return e
		}
		if raw, exists := doc["cred"]; exists {
			cred, ok := raw.(string)
			if final || !ok || cred == "" || hasAny(doc, "response", "credAns4", "credAns6") {
				return errors.New("ambiguous credential response")
			}
			if sid != nil && *sid != session.sid {
				return errors.New("routing session changed during authentication")
			}
			id := session.sid
			sid = &id
			step, e := codec.Receive(cred)
			if e != nil {
				return e
			}
			if step.Completed || step.Credential == "" {
				return errors.New("early credential completion")
			}
			outgoing = step.Credential
			continue
		}
		app, ok := doc["response"].(map[string]any)
		proofName, other := "credAns4", "credAns6"
		if version == secpswd.V3 {
			proofName, other = other, proofName
		}
		proof, proofOK := app[proofName].(string)
		if !final || !ok || !proofOK || proof == "" || hasAny(app, other, "cred") || hasAny(doc, "credAns4", "credAns6") {
			return errors.New("missing final application credential proof")
		}
		step, e := codec.Receive(proof)
		if e != nil {
			return e
		}
		if !step.Completed || !step.Success || !codec.Authenticated() {
			return errors.New("credential proof rejected")
		}
		metadata, e := applicationMetadataJSON(app)
		if e != nil {
			return e
		}
		c.applicationAssemblyVersion, c.applicationRolesID = metadata.assemblyVersion, metadata.rolesID
		c.applicationConfigVersion = metadata.configVersion
		return nil
	}
	return errors.New("credential exchange limit")
}
func hasAny(m map[string]any, keys ...string) bool {
	for _, k := range keys {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}
func (c *Client) nextSync() (uint32, error) {
	if c.lastSync >= 0x7fffffff {
		return 0, errors.New("application sequence exhausted")
	}
	c.lastSync++
	return c.lastSync, nil
}
func (c *Client) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return c.CloseContext(ctx)
}
func (c *Client) CloseContext(ctx context.Context) error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeLocked(ctx)
}

func (c *Client) closeLocked(ctx context.Context) error {
	if c.closed {
		return c.closeErr
	}
	c.closed = true
	var errs []error
	if c.connection != nil {
		if c.session != nil && c.connection.sync {
			if c.lastSync < 1 {
				c.lastSync = 1
			}
			n, e := c.nextSync()
			if e == nil {
				var p []byte
				p, e = c.pdu("POST", "/e1cib/logout", nil, "", "", c.session.raw, n)
				if e == nil {
					var h *wire.HTTP
					h, e = c.exchangeHTTP(ctx, p)
					if e == nil && h.Status != 200 {
						e = &StatusError{"logout", h.Status}
					}
				}
			}
			if e == nil {
				c.stats.LogoutConfirmed = true
			} else {
				errs = append(errs, e)
			}
		} else if c.session != nil {
			errs = append(errs, errors.New("logout skipped after incomplete exchange"))
		}
		if c.connection.sync {
			errs = append(errs, c.connection.release(ctx))
		} else {
			errs = append(errs, errors.New("context release skipped after incomplete exchange"))
		}
		c.stats.ContextReleased = c.connection.released
	}
	c.session = nil
	c.authenticated = false
	securityClosed := true
	if c.inner != nil {
		e := c.inner.Close()
		errs = append(errs, e)
		securityClosed = e == nil
		c.inner = nil
	}
	if c.connection != nil {
		errs = append(errs, c.connection.closeSocket())
		securityClosed = securityClosed && c.connection.securityClosed
	}
	c.closeErr = errors.Join(errs...)
	c.stats.SecurityClosed = securityClosed
	c.stats.Closed = true
	return c.closeErr
}
func (c *Client) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.Connections = append([]string(nil), s.Connections...)
	s.SecurityContexts = append([]SecurityObservation(nil), s.SecurityContexts...)
	s.RPCRounds = c.managerRounds + c.retiredRounds
	s.BytesSent = c.managerSent + c.retiredSent
	s.BytesReceived = c.managerReceived + c.retiredReceived
	if c.connection != nil {
		s.RPCRounds += c.connection.rounds
		s.BytesSent += c.connection.sent
		s.BytesReceived += c.connection.received
	}
	return s
}

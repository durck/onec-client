// Package onec provides an experimental native TCP client for the observed 1C
// protocol subset. It does not load 1C client libraries or a COM connector.
package onec

import (
	"context"
	"errors"
	"net"
	"onec/internal/security"
	"onec/ntlmauth"
	"onec/ticketauth"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type SecurityContext = security.Context

// NewAnonymousSecurity creates a fresh NTLM null-session provider without using
// an account or credential cache. It uses SSPI on Windows and pure Go elsewhere.
// Anonymous completion does not authenticate the server or grant infobase access.
func NewAnonymousSecurity() (SecurityContext, error) { return security.NewAnonymous() }

type Profile struct {
	Version     string
	Application string
}
type Config struct {
	Server          string // Manager host:port. Required for discovery; defaults to 127.0.0.1:1541.
	Worker          string // Explicit host:port bypasses the manager entirely.
	Infobase        string
	Profile         Profile
	TransportPolicy TransportPolicy       // Explicit opt-in; empty/plain preserves the existing framing.
	ServerName      string                // Header identity; defaults to the configured endpoint host.
	Timeout         time.Duration         // Per wire exchange; caller context can impose a shorter bound.
	Kerberos        *ticketauth.Options   // File credentials; requires a direct worker and WindowsAuth login.
	NTLM            *ntlmauth.Credentials // Caller-owned explicit credentials; WindowsAuth login only. Close after Client.Close.
	// DisableContextRecovery prevents the single precredential Login redial after
	// an exact, complete infobase-context-releasing refusal. No credential-bearing
	// login or application request is automatically replayed.
	DisableContextRecovery bool
	// SecurityFactory must return a fresh, independent context on every call,
	// including separate outer/inner exchanges and a permitted context recovery.
	SecurityFactory func() (SecurityContext, error)
	DialContext     func(context.Context, string, string) (net.Conn, error)
}

var versionPattern = regexp.MustCompile(`^8\.[0-9]{1,2}\.[0-9]{1,4}\.[0-9]{1,6}$`)
var namePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,255}$`)

func (c Config) normalized() (Config, error) {
	if _, _, err := policyOptions(c.TransportPolicy); err != nil {
		return c, err
	}
	if c.Server == "" {
		c.Server = "127.0.0.1:1541"
	}
	if c.Infobase == "" {
		return c, errors.New("infobase is required")
	}
	if c.Profile.Version == "" {
		c.Profile.Version = "8.3.18.1208"
	}
	if c.Profile.Application == "" {
		c.Profile.Application = "1CV8C"
	}
	if !versionPattern.MatchString(c.Profile.Version) {
		return c, errors.New("invalid platform version")
	}
	switch c.Profile.Application {
	case "1CV8C", "MobileClient", "WebClient":
	default:
		return c, errors.New("unsupported application profile")
	}
	for _, addr := range []string{c.Server, c.Worker} {
		if addr == "" {
			continue
		}
		host, port, e := net.SplitHostPort(addr)
		p, pe := strconv.Atoi(port)
		if e != nil || pe != nil || p < 1 || p > 65535 || !namePattern.MatchString(host) || strings.Contains(host, ":") {
			return c, errors.New("expected an IPv4 host:port endpoint")
		}
	}
	if c.ServerName == "" {
		addr := c.Server
		if c.Worker != "" {
			addr = c.Worker
		}
		c.ServerName, _, _ = net.SplitHostPort(addr)
	}
	if !namePattern.MatchString(c.ServerName) || !namePattern.MatchString(c.Infobase) {
		return c, errors.New("unsupported server or infobase name")
	}
	if c.Timeout == 0 {
		c.Timeout = 20 * time.Second
	}
	if c.Timeout < 0 {
		return c, errors.New("timeout must be positive")
	}
	if c.NTLM != nil {
		if c.Kerberos != nil || c.SecurityFactory != nil {
			return c, errors.New("choose only one security provider: NTLM, Kerberos or SecurityFactory")
		}
		if err := c.NTLM.Validate(); err != nil {
			return c, err
		}
		credentials := c.NTLM
		c.SecurityFactory = func() (SecurityContext, error) {
			provider, err := credentials.NewContext()
			if err != nil {
				return nil, err
			}
			return provider, nil
		}
	} else if c.Kerberos != nil {
		if c.SecurityFactory != nil {
			return c, errors.New("choose either Kerberos file credentials or a custom SecurityFactory")
		}
		if c.Worker == "" {
			return c, errors.New("Kerberos file mode requires an explicit worker for its pinned SPN")
		}
		opts := *c.Kerberos
		if err := ticketauth.Validate(opts); err != nil {
			return c, err
		}
		c.Kerberos = &opts
		c.SecurityFactory = func() (SecurityContext, error) {
			provider, err := ticketauth.New(opts)
			if err != nil {
				return nil, err
			}
			return provider, nil
		}
	} else if c.SecurityFactory == nil {
		c.SecurityFactory = security.New
	}
	if c.DialContext == nil {
		d := &net.Dialer{Timeout: 5 * time.Second}
		c.DialContext = d.DialContext
	}
	return c, nil
}
func computerName() string {
	n, e := os.Hostname()
	if e != nil || n == "" {
		return "GoClient"
	}
	return n
}

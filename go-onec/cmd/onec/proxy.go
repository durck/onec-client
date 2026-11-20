package main

import (
	"context"
	"errors"
	"flag"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

type proxyOptions struct{ address, authEnv string }
type proxyDialFunc func(context.Context, string, string) (net.Conn, error)

func (o *proxyOptions) flags(f *flag.FlagSet) {
	f.Func("proxy", "SOCKS5 URL, e.g. socks5://127.0.0.1:1080; target DNS via proxy; no direct fallback", func(value string) error {
		if value == "" {
			return errors.New("proxy URL cannot be empty")
		}
		o.address = value
		return nil
	})
	f.Func("proxy-auth-env", "environment variable containing SOCKS5 username:password; inline URL credentials are rejected", func(value string) error {
		if value == "" {
			return errors.New("proxy authentication variable name cannot be empty")
		}
		o.authEnv = value
		return nil
	})
}

// Parsing is offline. Credentials are read once, on the first actual dial,
// so previews and help never access secrets or initialize a connection.
func (o proxyOptions) dialer() (proxyDialFunc, error) {
	bad := errors.New("invalid proxy: use socks5://HOST:PORT or socks5h://HOST:PORT without URL credentials, path, query or fragment")
	if o.address == "" {
		if o.authEnv != "" {
			return nil, errors.New("--proxy-auth-env requires --proxy")
		}
		return nil, nil
	}
	if len(o.address) > 2048 {
		return nil, bad
	}
	u, err := url.Parse(o.address)
	if err != nil || u.Scheme != "socks5" && u.Scheme != "socks5h" || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(o.address, "#") {
		return nil, bad
	}
	host, port, err := net.SplitHostPort(u.Host)
	n, e := strconv.Atoi(port)
	if err != nil || e != nil || n < 1 || n > 65535 {
		return nil, bad
	}
	if net.ParseIP(host) == nil {
		if _, e := checklistHost(host); e != nil {
			return nil, bad
		}
	}
	if len(o.authEnv) > 255 {
		return nil, errors.New("invalid proxy authentication environment variable name")
	}
	for i, c := range o.authEnv {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '_' || i > 0 && c >= '0' && c <= '9') {
			return nil, errors.New("invalid proxy authentication environment variable name")
		}
	}
	var once sync.Once
	var dialer proxy.ContextDialer
	var setupErr error
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		once.Do(func() {
			var auth *proxy.Auth
			if o.authEnv != "" {
				value, found := os.LookupEnv(o.authEnv)
				user, password, ok := strings.Cut(value, ":")
				if !found || !ok || len(user) < 1 || len(user) > 255 || len(password) < 1 || len(password) > 255 {
					setupErr = errors.New("proxy authentication variable must contain username:password (each 1..255 bytes)")
					return
				}
				auth = &proxy.Auth{User: user, Password: password}
			}
			d, err := proxy.SOCKS5("tcp", net.JoinHostPort(host, port), auth, &net.Dialer{Timeout: 10 * time.Second})
			if err != nil {
				setupErr = errors.New("cannot initialize SOCKS5 transport")
				return
			}
			var ok bool
			dialer, ok = d.(proxy.ContextDialer)
			if !ok {
				setupErr = errors.New("SOCKS5 transport does not support cancellation")
			}
		})
		if setupErr != nil {
			return nil, setupErr
		}
		attempt, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		conn, err := dialer.DialContext(attempt, network, address)
		if err != nil {
			if attempt.Err() != nil {
				err = attempt.Err()
			}
			return nil, proxyConnectionError{cause: err}
		}
		return conn, nil
	}, nil
}

// Preserve cancellation and timeout classification without reflecting proxy
// errors or authentication data into command diagnostics.
type proxyConnectionError struct{ cause error }

func (e proxyConnectionError) Error() string {
	return "SOCKS5 connection failed; no direct connection was attempted"
}
func (e proxyConnectionError) Unwrap() error {
	// A refused connection to the proxy is not evidence of a closed target
	// port. Expose only cancellation; keep proxy errno out of target classifiers.
	if errors.Is(e.cause, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(e.cause, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return nil
}
func (e proxyConnectionError) Timeout() bool {
	var n net.Error
	return errors.Is(e.cause, context.DeadlineExceeded) || errors.As(e.cause, &n) && n.Timeout()
}
func (e proxyConnectionError) Temporary() bool { return false }

func (o proxyOptions) report(fields map[string]any) {
	if o.address != "" {
		fields["proxy"] = o.address
		fields["target_dns"] = "proxy"
		fields["proxy_auth_configured"] = o.authEnv != ""
	}
}

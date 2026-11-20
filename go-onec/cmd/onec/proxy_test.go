package main

import (
	"context"
	"errors"
	"io"
	"net"
	"onec"
	"onec/wire"
	"strings"
	"testing"
	"time"
)

func TestProxyValidationAndOfflinePreview(t *testing.T) {
	for _, raw := range []string{"http://127.0.0.1:1080", "127.0.0.1:1080", "socks5://user:secret@localhost:1080", "socks5://localhost", "socks5://localhost:0", "socks5://localhost:65536", "socks5://localhost:1080/path", "socks5://localhost:1080?secret", "socks5://localhost:1080#secret", "socks5://bad host:1080"} {
		_, err := (proxyOptions{address: raw}).dialer()
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("invalid proxy not redacted: %q %v", raw, err)
		}
	}
	if _, err := (proxyOptions{authEnv: "MISSING_PROXY_SECRET"}).dialer(); err == nil {
		t.Fatal("auth without proxy")
	}
	commands := [][]string{{"checklist", "--target", "target.invalid"}, {"login"}, {"users"}, {"settings"}, {"infobases", "--worker", "target.invalid:1560"}, {"admin", "clusters"}, {"ports", "check", "--host", "target.invalid", "--port", "1560"}, {"epf", "methods", "--file", "fixture.epf"}}
	for _, args := range commands {
		args = append(args, "--proxy", "socks5://127.0.0.1:1080", "--proxy-auth-env", "MISSING_PROXY_SECRET")
		var out strings.Builder
		if err := run(args, &out, io.Discard); err != nil {
			t.Fatalf("offline proxy preview %v: %v", args, err)
		}
	}
}

// This local SOCKS peer never forwards traffic: it verifies the requested
// target and serves a short payload on the tunnel itself.
func fixtureSOCKS(t *testing.T, wantTarget string, auth bool, reject bool) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	t.Cleanup(func() {
		listener.Close()
		select {
		case e := <-done:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(3 * time.Second):
			t.Error("SOCKS peer leaked")
		}
	})
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			done <- e
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		read := func(n int) ([]byte, error) { b := make([]byte, n); _, e := io.ReadFull(conn, b); return b, e }
		header, e := read(2)
		if e != nil {
			done <- e
			return
		}
		if header[0] != 5 {
			done <- errors.New("not SOCKS5")
			return
		}
		methods, e := read(int(header[1]))
		if e != nil {
			done <- e
			return
		}
		method := byte(0)
		if auth {
			method = 2
		}
		if !strings.ContainsRune(string(methods), rune(method)) {
			done <- errors.New("missing auth method")
			return
		}
		if _, e = conn.Write([]byte{5, method}); e != nil {
			done <- e
			return
		}
		if auth {
			a, e := read(2)
			if e != nil {
				done <- e
				return
			}
			u, e := read(int(a[1]))
			if e != nil {
				done <- e
				return
			}
			p, e := read(1)
			if e != nil {
				done <- e
				return
			}
			password, e := read(int(p[0]))
			if e != nil {
				done <- e
				return
			}
			if a[0] != 1 || string(u) != "fixture-user" || string(password) != "fixture:password" {
				done <- errors.New("bad proxy credentials")
				return
			}
			if _, e = conn.Write([]byte{1, 0}); e != nil {
				done <- e
				return
			}
		}
		header, e = read(4)
		if e != nil {
			done <- e
			return
		}
		if header[0] != 5 || header[1] != 1 || header[2] != 0 {
			done <- errors.New("not CONNECT")
			return
		}
		var host string
		switch header[3] {
		case 1:
			b, e := read(4)
			if e != nil {
				done <- e
				return
			}
			host = net.IP(b).String()
		case 3:
			n, e := read(1)
			if e != nil {
				done <- e
				return
			}
			b, e := read(int(n[0]))
			if e != nil {
				done <- e
				return
			}
			host = string(b)
		default:
			done <- errors.New("unexpected address type")
			return
		}
		port, e := read(2)
		if e != nil {
			done <- e
			return
		}
		wantHost, wantPort, _ := net.SplitHostPort(wantTarget)
		service, _ := net.LookupPort("tcp", wantPort)
		if host != wantHost || int(port[0])<<8|int(port[1]) != service {
			done <- errors.New("target changed or resolved locally")
			return
		}
		code := byte(0)
		if reject {
			code = 5
		}
		_, e = conn.Write([]byte{5, code, 0, 1, 127, 0, 0, 1, 0, 0})
		if e != nil {
			done <- e
			return
		}
		if !reject {
			_, e = conn.Write([]byte("hello"))
		}
		done <- e
	}()
	return "socks5://" + listener.Addr().String()
}

func TestSOCKS5RemoteDNSAndAuthentication(t *testing.T) {
	for _, auth := range []bool{false, true} {
		t.Run(map[bool]string{false: "anonymous", true: "authenticated"}[auth], func(t *testing.T) {
			o := proxyOptions{address: fixtureSOCKS(t, "unresolvable.invalid:1541", auth, false)}
			if auth {
				o.authEnv = "ONEC_TEST_PROXY_AUTH"
				t.Setenv(o.authEnv, "fixture-user:fixture:password")
			}
			dial, err := o.dialer()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := dial(ctx, "tcp4", "unresolvable.invalid:1541")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			var b [5]byte
			if _, err = io.ReadFull(conn, b[:]); err != nil || string(b[:]) != "hello" {
				t.Fatalf("tunnel failed: %v", err)
			}
		})
	}
}

func TestSOCKS5FailureDoesNotDialTargetDirectly(t *testing.T) {
	trap, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer trap.Close()
	dial, err := (proxyOptions{address: fixtureSOCKS(t, trap.Addr().String(), false, true)}).dialer()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if conn, err := dial(ctx, "tcp4", trap.Addr().String()); err == nil {
		conn.Close()
		t.Fatal("proxy rejection ignored")
	}
	trap.SetDeadline(time.Now().Add(50 * time.Millisecond))
	if conn, err := trap.Accept(); err == nil {
		conn.Close()
		t.Fatal("direct fallback contacted target")
	}
}

func TestSOCKS5CancellationClosesHandshake(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			done <- e
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		cancel()
		_, e = io.Copy(io.Discard, conn)
		done <- e
	}()
	dial, err := (proxyOptions{address: "socks5://" + listener.Addr().String()}).dialer()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dial(ctx, "tcp4", "unresolvable.invalid:1560")
	if conn != nil {
		conn.Close()
		t.Fatal("canceled dial returned connection")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handshake socket leaked")
	}
}

func TestProxyRefusalIsNotReportedAsClosedTargetPort(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	var out strings.Builder
	err = run([]string{"--output", "json", "ports", "check", "--host", "unresolvable.invalid", "--port", "1560", "--proxy", "socks5://" + address, "--execute"}, &out, io.Discard)
	if err == nil || !strings.Contains(out.String(), `"state":"error"`) || strings.Contains(out.String(), `"success":true`) {
		t.Fatalf("proxy refusal misreported: err=%v output=%s", err, out.String())
	}
}

func TestProxyEmptyFlagsAndUnsupportedKDCFailOffline(t *testing.T) {
	for _, args := range [][]string{
		{"users", "--proxy="},
		{"checklist", "--target", "host.invalid", "--proxy="},
		{"ports", "check", "--port", "1560", "--proxy-auth-env="},
		{"login", "--worker", "host.invalid:1560", "--ticket-file", "not-read.kirbi", "--kerberos-spn", "service/host.invalid", "--proxy", "socks5://localhost:1080"},
		{"web", "enum", "--url", "https://host.invalid", "--proxy", "socks5://localhost:1080"},
	} {
		if err := run(args, io.Discard, io.Discard); err == nil {
			t.Fatalf("unsupported options accepted: %v", args)
		}
	}
	for _, command := range [][]string{{"login"}, {"checklist"}, {"infobases"}, {"admin", "clusters"}, {"ports", "check"}} {
		flags := completionFlagSet(command)
		if flags == nil || flags.Lookup("proxy") == nil || flags.Lookup("proxy-auth-env") == nil {
			t.Fatalf("missing proxy help/completion: %v", command)
		}
	}
}

func TestProxyMissingSecretStopsBeforeConnecting(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("ONEC_TEST_INVALID_PROXY_AUTH", "fixture-without-separator")
	o := proxyOptions{address: "socks5://" + listener.Addr().String(), authEnv: "ONEC_TEST_INVALID_PROXY_AUTH"}
	dial, err := o.dialer()
	if err != nil {
		t.Fatal("preview read the variable", err)
	}
	conn, err := dial(context.Background(), "tcp4", "host.invalid:1540")
	if err == nil || conn != nil || strings.Contains(err.Error(), "fixture-without-separator") {
		t.Fatalf("invalid secret handling: %v", err)
	}
	listener.SetDeadline(time.Now().Add(50 * time.Millisecond))
	if c, err := listener.Accept(); err == nil {
		c.Close()
		t.Fatal("connected with invalid proxy authentication")
	}
}

func TestNativeCommandAdaptersUseProxyDialer(t *testing.T) {
	for _, kind := range []string{"common", "admin", "infobases", "ports"} {
		t.Run(kind, func(t *testing.T) {
			address := fixtureSOCKS(t, "host.invalid:1560", false, false)
			check := func(ctx context.Context, dial proxyDialFunc) {
				if dial == nil {
					t.Fatal("missing proxy dialer")
				}
				c, e := dial(ctx, "tcp4", "host.invalid:1560")
				if e != nil {
					t.Fatal(e)
				}
				defer c.Close()
				var b [5]byte
				if _, e = io.ReadFull(c, b[:]); e != nil || string(b[:]) != "hello" {
					t.Fatalf("proxy tunnel failed: %v", e)
				}
			}
			var err error
			switch kind {
			case "common":
				flags, o := newCommandFlags("fixture", io.Discard)
				if _, e := parseCommandFlags(flags, []string{"--proxy", address}); e != nil {
					t.Fatal(e)
				}
				c, e := o.config(false)
				if e != nil {
					t.Fatal(e)
				}
				check(context.Background(), c.DialContext)
			case "admin":
				err = runAdminWith([]string{"clusters", "--proxy", address, "--execute"}, io.Discard, io.Discard, func(ctx context.Context, c onec.AdminConfig, _ onec.AdminRequest) (onec.AdminResult, error) {
					check(ctx, c.DialContext)
					return onec.AdminResult{}, nil
				})
			case "infobases":
				err = runInfobasesWith([]string{"--worker", "host.invalid:1560", "--proxy", address, "--execute"}, io.Discard, io.Discard, func(ctx context.Context, c onec.InfobaseListConfig) (onec.InfobaseListResult, error) {
					check(ctx, c.DialContext)
					return onec.InfobaseListResult{}, nil
				})
			case "ports":
				err = runPortsWith([]string{"check", "--host", "host.invalid", "--port", "1560", "--proxy", address, "--execute"}, io.Discard, io.Discard, func(ctx context.Context, c onec.PortProbeConfig) (onec.PortProbeReport, error) {
					if !c.RemoteDNS || !c.SkipLocalProcess {
						t.Fatal("local DNS/ownership enabled")
					}
					check(ctx, c.DialContext)
					return onec.PortProbeReport{}, nil
				})
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestChecklistProxyCoversEveryStageWithoutLocalDNS(t *testing.T) {
	o, d := checklistTestOptions(), checklistTestDeps()
	o.Proxy = "socks5://127.0.0.1:1080"
	o.WorkerPorts = []int{1560}
	dials := 0
	o.dial = func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp4" || !strings.HasPrefix(address, "lab.test:") {
			t.Fatalf("target scope changed: %s %s", network, address)
		}
		dials++
		return nil, errors.New("injected transport")
	}
	check := func(ctx context.Context, dial proxyDialFunc, address string) {
		if dial == nil {
			t.Fatal("stage lost proxy transport")
		}
		_, _ = dial(ctx, "tcp4", address)
	}
	d.resolve = func(context.Context, string) (string, error) {
		t.Fatal("local target DNS in proxy mode")
		return "", nil
	}
	const cluster = "11111111-2222-3333-4444-555555555555"
	d.admin = func(ctx context.Context, c onec.AdminConfig, r onec.AdminRequest) (onec.AdminResult, error) {
		check(ctx, c.DialContext, c.Agent)
		res := onec.AdminResult{Stats: cleanChecklistAdmin()}
		if r.AgentAuth != nil {
			res.Stats.AgentAuthenticated = true
		}
		if r.ClusterAuth != nil {
			res.Stats.AuthenticatedClusters = []string{cluster}
		}
		switch r.Operation {
		case "agent-admins", "cluster-admins":
			res.Data = []onec.AdminUser{}
		case "clusters":
			res.Data = []onec.AdminCluster{{ID: cluster, Endpoints: []wire.AdminEndpoint{{Host: "outside.invalid", Port: 1641}}}}
		case "bases":
			res.Data = []onec.AdminInfoBase{{ID: "db1", Name: "ManagerBase"}}
		default:
			t.Fatal("unexpected operation")
		}
		return res, nil
	}
	d.probe = func(ctx context.Context, c onec.PortProbeConfig) (onec.PortProbeReport, error) {
		if !c.RemoteDNS || !c.SkipLocalProcess || c.Host != "lab.test" {
			t.Fatalf("incorrect probe scope: %+v", c)
		}
		check(ctx, c.DialContext, net.JoinHostPort(c.Host, "1560"))
		return onec.PortProbeReport{Results: []onec.PortProbeResult{{Port: 1560, State: "open", Protocol: "onec-native", RoleChecks: []onec.PortRoleCheck{{Role: "working-process-administration", Matched: true, ContextOpened: true, ContextReleased: true, Closed: true}}}}}, nil
	}
	d.bases = func(ctx context.Context, c onec.InfobaseListConfig) (onec.InfobaseListResult, error) {
		check(ctx, c.DialContext, c.Worker)
		return onec.InfobaseListResult{Infobases: []onec.InfobaseInfo{{ID: "db2", Name: "WorkerBase"}}, Stats: cleanChecklistStats()}, nil
	}
	configCheck := func(ctx context.Context, c onec.Config) {
		route := c.Worker
		if route == "" {
			route = c.Server
		}
		check(ctx, c.DialContext, route)
	}
	d.users = func(ctx context.Context, c onec.Config) ([]string, onec.Stats, error) {
		configCheck(ctx, c)
		return []string{"alice"}, cleanChecklistStats(), nil
	}
	d.login = func(ctx context.Context, c onec.Config, _ onec.Credentials) checklistLogin {
		configCheck(ctx, c)
		s := cleanChecklistStats()
		s.Authenticated, s.LogoutConfirmed = true, true
		return checklistLogin{Attempted: true, Stats: s}
	}
	r := executeChecklist(context.Background(), o, d, nil)
	if !r.Completed || r.Summary.Databases != 2 || r.Summary.Findings != 4 || dials < 10 {
		t.Fatalf("incomplete routing: dials=%d summary=%+v", dials, r.Summary)
	}
	for _, row := range r.Results {
		if row.ResolvedIP != "" {
			t.Fatal("invented resolved IP")
		}
	}
}

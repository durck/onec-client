package onec

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"onec/internal/security"
	"onec/internal/tcpowner"
	"onec/wire"
	"sort"
	"strconv"
	"sync"
	"time"
)

const MaxProbePorts = 1024

// PortProbeConfig bounds one IPv4 host and an explicit port set. The built-in
// role probes use anonymous NTLM only; they never select or log into a database.
type PortProbeConfig struct {
	Host             string
	Ports            []int
	Timeout          time.Duration // Per port, plus at most 500 ms cleanup per opened role context.
	Concurrency      int
	Version          string
	SkipRoles        bool
	SkipLocalProcess bool                                                    // Local ownership is available for Windows loopback only.
	DialContext      func(context.Context, string, string) (net.Conn, error) // Used for banner AND role connections; nil uses direct TCP.
	RemoteDNS        bool                                                    // Pass the hostname to DialContext, without local DNS or IP pinning. Requires a custom dialer.
}

type PortRoleCheck struct {
	Role            string `json:"role"`
	Matched         bool   `json:"matched"`
	Outcome         string `json:"outcome"`
	ContextOpened   bool   `json:"context_opened"`
	ContextReleased bool   `json:"context_released"`
	Closed          bool   `json:"closed"`
}

type PortProcess = tcpowner.Owner

type PortProbeResult struct {
	Port           int             `json:"port"`
	Address        string          `json:"address"`
	State          string          `json:"state"`    // open, closed, timeout, error, canceled
	Protocol       string          `json:"protocol"` // onec-native, ssh, unknown
	LocalProcesses []PortProcess   `json:"local_processes,omitempty"`
	RoleChecks     []PortRoleCheck `json:"role_checks,omitempty"`
	Observation    string          `json:"observation,omitempty"`
	ElapsedMS      int64           `json:"elapsed_ms"`
}

type PortProbeReport struct {
	Host           string            `json:"host"`
	ResolvedIP     string            `json:"resolved_ip"`
	LocalOwnership string            `json:"local_ownership"`
	DNSResolution  string            `json:"dns_resolution,omitempty"`
	Results        []PortProbeResult `json:"results"`
}

func (c PortProbeConfig) normalized() (PortProbeConfig, error) {
	if c.RemoteDNS && c.DialContext == nil {
		return c, errors.New("remote DNS requires an explicit dialer")
	}
	if c.Host == "" {
		c.Host = "127.0.0.1"
	}
	if !namePattern.MatchString(c.Host) {
		return c, errors.New("expected one IPv4 address or hostname")
	}
	if len(c.Ports) == 0 || len(c.Ports) > MaxProbePorts {
		return c, errors.New("provide between 1 and 1024 ports")
	}
	c.Ports = append([]int(nil), c.Ports...)
	sort.Ints(c.Ports)
	unique := c.Ports[:0]
	for _, p := range c.Ports {
		if p < 1 || p > 65535 {
			return c, errors.New("port must be in 1..65535")
		}
		if len(unique) == 0 || unique[len(unique)-1] != p {
			unique = append(unique, p)
		}
	}
	c.Ports = unique
	if c.Timeout == 0 {
		c.Timeout = 5 * time.Second
	}
	if c.Timeout < 0 || c.Timeout > time.Minute {
		return c, errors.New("per-port timeout must be positive and at most 1 minute")
	}
	if c.Concurrency == 0 {
		c.Concurrency = 4
	}
	if c.Concurrency < 1 || c.Concurrency > 16 {
		return c, errors.New("concurrency must be in 1..16")
	}
	if c.Version == "" {
		c.Version = "8.3.18.1208"
	}
	if !versionPattern.MatchString(c.Version) {
		return c, errors.New("invalid platform version")
	}
	return c, nil
}

// ValidatePortProbeConfig performs no DNS, process lookup, or network I/O.
func ValidatePortProbeConfig(c PortProbeConfig) error { _, err := c.normalized(); return err }

type portProbeDeps struct {
	resolve func(context.Context, string, string) ([]net.IP, error)
	dial    func(context.Context, string, string) (net.Conn, error)
	owners  func(net.IP) (map[int][]tcpowner.Owner, string)
	role    func(context.Context, string, string, time.Duration, bool) PortRoleCheck
}

// ProbePorts normally resolves the host once and probes a pinned IPv4 address.
// RemoteDNS instead passes the supplied host to the required custom dialer. Closed,
// silent, unrecognized and role-rejected ports are results, not operation errors.
// Cancellation returns the ordered partial report and a non-nil context error.
func ProbePorts(ctx context.Context, cfg PortProbeConfig) (PortProbeReport, error) {
	dial := cfg.DialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	role := func(ctx context.Context, address, version string, timeout time.Duration, manager bool) PortRoleCheck {
		return probePortRole(ctx, address, version, timeout, manager, dial)
	}
	return probePorts(ctx, cfg, portProbeDeps{net.DefaultResolver.LookupIP, dial, tcpowner.Snapshot, role})
}

func probePorts(ctx context.Context, options PortProbeConfig, deps portProbeDeps) (report PortProbeReport, err error) {
	cfg, err := options.normalized()
	if err != nil {
		return report, err
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	report.Host = cfg.Host
	host := cfg.Host
	var ip net.IP
	if cfg.RemoteDNS {
		report.DNSResolution = "remote"
		ip = net.ParseIP(host)
	} else {
		resolveCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
		ips, e := deps.resolve(resolveCtx, "ip4", cfg.Host)
		cancel()
		if e != nil {
			if ctx.Err() != nil {
				return report, ctx.Err()
			}
			return report, errors.New("IPv4 host resolution failed")
		}
		for _, candidate := range ips {
			if candidate.To4() != nil {
				ip = candidate.To4()
				break
			}
		}
		if ip == nil {
			return report, errors.New("host has no IPv4 address")
		}
		host = ip.String()
	}
	if ip != nil {
		report.ResolvedIP = ip.String()
	}
	report.LocalOwnership = "disabled"
	var owners map[int][]tcpowner.Owner
	if !cfg.SkipLocalProcess && cfg.DialContext == nil {
		owners, report.LocalOwnership = deps.owners(ip)
	}
	report.Results = make([]PortProbeResult, len(cfg.Ports))
	for i, p := range cfg.Ports {
		report.Results[i] = PortProbeResult{Port: p, Address: net.JoinHostPort(host, strconv.Itoa(p)), State: "canceled", Protocol: "unknown"}
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	for worker := 0; worker < min(cfg.Concurrency, len(cfg.Ports)); worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if ctx.Err() != nil {
					continue
				}
				report.Results[i] = probeOnePort(ctx, cfg, report.Results[i], owners[cfg.Ports[i]], deps)
			}
		}()
	}
dispatch:
	for i := range cfg.Ports {
		select {
		case jobs <- i:
		case <-ctx.Done():
			break dispatch
		}
	}
	close(jobs)
	wg.Wait()
	return report, ctx.Err()
}

func probeOnePort(parent context.Context, cfg PortProbeConfig, result PortProbeResult, owners []tcpowner.Owner, deps portProbeDeps) PortProbeResult {
	start := time.Now()
	ctx, cancel := context.WithTimeout(parent, cfg.Timeout)
	defer cancel()
	conn, err := deps.dial(ctx, "tcp4", result.Address)
	if err != nil {
		result.State = "error"
		var timeout net.Error
		switch {
		case parent.Err() != nil:
			result.State = "canceled"
		case portConnectionRefused(err):
			result.State = "closed"
		case errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout():
			result.State = "timeout"
		}
		result.ElapsedMS = time.Since(start).Milliseconds()
		return result
	}
	result.State = "open"
	result.LocalProcesses = owners
	// Read only five bytes, with a separate short banner budget. Silent services
	// remain open/unknown; no 1C payload is sent to them.
	deadline, _ := ctx.Deadline()
	if d := time.Now().Add(500 * time.Millisecond); d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		result.Observation = "deadline_setup_failed"
		result.ElapsedMS = time.Since(start).Milliseconds()
		return result
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	var greeting [5]byte
	n, readErr := io.ReadFull(conn, greeting[:])
	stop()
	_ = conn.Close()
	switch {
	case n == 5 && bytes.Equal(greeting[:], wire.Greeting):
		result.Protocol = "onec-native"
	case n == 5 && (string(greeting[:]) == "SSH-2" || string(greeting[:]) == "SSH-1"):
		result.Protocol = "ssh"
	case n == 0 && readErr != nil:
		result.Observation = "no_server_greeting"
	default:
		result.Observation = "unrecognized_greeting"
	}
	if !cfg.SkipRoles && result.Protocol == "onec-native" {
		for _, manager := range []bool{false, true} {
			if ctx.Err() != nil {
				break
			}
			// Split remaining time so a silent first context cannot starve the second.
			budget := time.Until(mustDeadline(ctx))
			if !manager {
				budget /= 2
			}
			roleCtx, stopRole := context.WithTimeout(ctx, budget)
			check := deps.role(roleCtx, result.Address, cfg.Version, cfg.Timeout, manager)
			stopRole()
			result.RoleChecks = append(result.RoleChecks, check)
		}
	}
	if parent.Err() != nil {
		result.Observation = "canceled_after_connect"
	}
	result.ElapsedMS = time.Since(start).Milliseconds()
	return result
}

func mustDeadline(ctx context.Context) time.Time { d, _ := ctx.Deadline(); return d }

func probePortRole(ctx context.Context, address, version string, timeout time.Duration, manager bool, dial func(context.Context, string, string) (net.Conn, error)) (check PortRoleCheck) {

	cfg := Config{Profile: Profile{Version: version}, Timeout: timeout, SecurityFactory: security.NewAnonymous, DialContext: dial}
	return probePortRoleWith(ctx, address, cfg, manager)
}

func probePortRoleWith(ctx context.Context, address string, cfg Config, manager bool) (check PortRoleCheck) {
	check.Role = "working-process-administration"
	kind, selector, iid := wire.AdminProcessContext, wire.AdminProcessSelector, wire.InfobaseListInterface
	app := "COMConsole"
	if manager {
		check.Role = "cluster-manager-selection"
		kind, selector, iid = wire.ManagerContext, "RegMngrCntxt:RegMngrCntxt", wire.SelectInterface
		app = "1CV8C"
	}
	check.Outcome = "context_unavailable"
	process, err := wire.NewUUID()
	if err != nil {
		return check
	}
	cfg.Profile.Application = app
	c, err := openConnection(ctx, cfg, address, kind, selector, wire.UUID{}, process)
	if err != nil {
		if ctx.Err() != nil {
			check.Outcome = "timeout_or_canceled"
		}
		return check
	}
	check.ContextOpened = true
	defer func() {
		if c.sync {
			cleanup, cancel := context.WithTimeout(context.Background(), min(cfg.Timeout, 500*time.Millisecond))
			_ = c.release(cleanup)
			cancel()
		}
		closeErr := c.closeSocket()
		check.ContextReleased, check.Closed = c.released, closeErr == nil
	}()
	check.Outcome = "interface_unconfirmed"
	n, err := c.next()
	if err != nil {
		return check
	}
	p, err := wire.QueryRequest(c.target, n, iid)
	if err != nil {
		return check
	}
	reply, err := c.exchange(ctx, p)
	if err != nil {
		return check
	}
	if manager {
		err = wire.ParseQuery(reply)
	} else {
		err = wire.ParseInfobaseInterface(reply)
	}
	if err == nil {
		check.Matched, check.Outcome = true, "interface_confirmed"
	}
	return check
}

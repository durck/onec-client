package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"onec"
	"onec/internal/security"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

const checklistMaxTargets = 4096

// The file format is deliberately a list of hosts, not URLs, CIDRs or endpoints.
func readChecklistTargets(r io.Reader) ([]string, error) {
	data, err := io.ReadAll(io.LimitReader(r, 1<<20+1))
	if err != nil || len(data) > 1<<20 || !utf8.Valid(data) {
		return nil, errors.New("targets must be valid UTF-8, at most 1 MiB")
	}
	scanner := bufio.NewScanner(strings.NewReader(strings.TrimPrefix(string(data), "\ufeff")))
	seen := map[string]bool{}
	var hosts []string
	line := 0
	for scanner.Scan() {
		line++
		host := strings.TrimSpace(scanner.Text())
		if host == "" || strings.HasPrefix(host, "#") {
			continue
		}
		host, err = checklistHost(host)
		if err != nil {
			return nil, fmt.Errorf("invalid target on line %d: use one IPv4 address or ASCII DNS name (punycode for IDNs)", line)
		}
		if !seen[host] {
			hosts = append(hosts, host)
			seen[host] = true
		}
		if len(hosts) > checklistMaxTargets {
			return nil, errors.New("at most 4096 unique targets are supported")
		}
	}
	if scanner.Err() != nil || len(hosts) == 0 {
		return nil, errors.New("target list is empty or contains an oversized line")
	}
	return hosts, nil
}

func checklistHost(host string) (string, error) {
	bad := errors.New("invalid host")
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil || strings.Contains(host, ":") {
			return "", bad
		}
		return ip.String(), nil
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || len(host) > 253 {
		return "", bad
	}
	allNumeric := true
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", bad
		}
		for _, c := range label {
			if c < '0' || c > '9' {
				allNumeric = false
			}
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", bad
			}
		}
	}
	if allNumeric {
		return "", bad
	}
	return host, nil
}

func checklistSecurity(cfg onec.Config, transport string) onec.Config {
	if transport == "anonymous" {
		cfg.SecurityFactory = security.NewAnonymous
	} else {
		cfg.SecurityFactory = security.New
	}
	return cfg
}

func defaultChecklistDeps() checklistDeps {
	return checklistDeps{
		resolve: func(ctx context.Context, host string) (string, error) {
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
			if err != nil {
				return "", err
			}
			for _, ip := range ips {
				if ip.To4() != nil {
					return ip.String(), nil
				}
			}
			return "", errors.New("no IPv4 address")
		},
		admin: onec.RunAdmin,
		probe: onec.ProbePorts,
		bases: onec.ListInfobases,
		users: func(ctx context.Context, cfg onec.Config) ([]string, onec.Stats, error) {
			client, err := onec.Dial(ctx, cfg)
			if err != nil {
				return nil, onec.Stats{}, err
			}
			users, operationErr := client.Users(ctx)
			closeErr := client.Close()
			return users, client.Stats(), errors.Join(operationErr, closeErr)
		},
		login: func(ctx context.Context, cfg onec.Config, cred onec.Credentials) checklistLogin {
			client, err := onec.Dial(ctx, cfg)
			if err != nil {
				return checklistLogin{Err: err}
			}
			operationErr := client.Login(ctx, cred)
			closeErr := client.Close()
			return checklistLogin{Attempted: true, Err: operationErr, CleanupErr: closeErr, Stats: client.Stats()}
		},
	}
}

func runChecklist(args []string, out, diagnostic io.Writer) error {
	return runChecklistWith(args, out, diagnostic, defaultChecklistDeps())
}

func runChecklistWith(args []string, out, diagnostic io.Writer, deps checklistDeps) error {
	f := flag.NewFlagSet("onec checklist", flag.ContinueOnError)
	f.SetOutput(diagnostic)
	f.Usage = func() {
		fmt.Fprintln(diagnostic, "Usage: onec checklist [HOST | --target HOST | --targets-file PATH] [options]\nAudit empty administrative credentials and empty passwords for discovered infobase users.\nOnly the prelogin user selection list is available; coverage is partial.")
		printFlagGroups(f, diagnostic)
	}
	var o checklistOptions
	var proxy proxyOptions
	proxy.flags(f)
	var target, targetsFile, reportPath, workerPorts, auth, policy string
	var execute, failOnFindings bool
	f.StringVar(&target, "target", "", "one IPv4 address or DNS name")
	f.StringVar(&targetsFile, "targets-file", "", "UTF-8 file: one IPv4 address or DNS name per line; blank lines and # comments allowed")
	f.StringVar(&reportPath, "report-file", "", "new JSON report file; default: onec-checklist-<timestamp>.json; existing files are never overwritten")
	f.IntVar(&o.AgentPort, "agent-port", 1540, "central server agent port")
	f.IntVar(&o.ManagerPort, "manager-port", 1541, "fallback manager port when cluster discovery advertises none")
	f.StringVar(&workerPorts, "worker-ports", "1560-1591", "additional worker discovery ports/ranges; none disables this discovery")
	f.StringVar(&o.Version, "client-version", "8.3.18.1208", "advertised build, not detected server version")
	f.StringVar(&auth, "auth", "legacy", "one infobase password method: legacy, v1, v2 or v3; no method fallback")
	f.StringVar(&o.Transport, "transport", "anonymous", "anonymous or explicit current-session windows transport identity")
	f.StringVar(&policy, "transport-policy", "plain", "plain, native27-n or native27-c")
	f.DurationVar(&o.Timeout, "timeout", 20*time.Second, "per-operation timeout, up to 5m; cleanup has a separate bounded timeout")
	f.DurationVar(&o.TotalTimeout, "total-timeout", 30*time.Minute, "whole-run timeout, up to 24h; save partial results on cancellation")
	f.DurationVar(&o.Interval, "interval", time.Second, "minimum delay between credential checks, 0..1m")
	f.IntVar(&o.MaxAttempts, "max-attempts", 1000, "maximum credential checks, 1..100000; accepted admin credentials are reused for inventory")
	f.BoolVar(&execute, "apply", false, "perform network checks; otherwise preview only")
	f.BoolVar(&failOnFindings, "fail-on-findings", false, "exit 1 when empty credentials are accepted; incomplete runs always exit 1")
	// Support the convenient leading positional host without changing common flag parsing.
	var positional string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") && args[0] != "help" {
		positional, args = args[0], args[1:]
	}
	if len(args) > 0 && args[0] == "help" {
		args = []string{"--help"}
	}
	if help, err := parseCommandFlags(f, args); help || err != nil {
		return err
	}
	if positional != "" {
		if target != "" || targetsFile != "" {
			return cliUsage(errors.New("choose a positional host, --target or --targets-file"))
		}
		target = positional
	}
	if (target == "") == (targetsFile == "") {
		return cliUsage(errors.New("choose exactly one of --target or --targets-file"))
	}
	var proxyErr error
	o.dial, proxyErr = proxy.dialer()
	if proxyErr != nil {
		return cliUsage(proxyErr)
	}
	o.Proxy, o.ProxyAuth = proxy.address, proxy.authEnv != ""
	var err error
	if targetsFile != "" {
		file, e := os.Open(targetsFile)
		if e != nil {
			return cliUsage(errors.New("cannot open targets file"))
		}
		o.Targets, err = readChecklistTargets(file)
		closeErr := file.Close()
		err = errors.Join(err, closeErr)
	} else {
		o.Targets, err = readChecklistTargets(strings.NewReader(target))
	}
	if err != nil {
		return cliUsage(err)
	}
	if target != "" && len(o.Targets) != 1 {
		return cliUsage(errors.New("--target accepts exactly one host"))
	}
	if workerPorts != "none" {
		o.WorkerPorts, err = parseProbePorts(workerPorts)
		if err != nil {
			return cliUsage(err)
		}
	}
	o.Auth, o.Policy = onec.AuthMethod(auth), onec.TransportPolicy(policy)
	if o.Transport != "anonymous" && o.Transport != "windows" {
		return cliUsage(errors.New("transport must explicitly be anonymous or windows"))
	}
	if o.Auth != onec.LegacyAuth && o.Auth != onec.PasswordV1 && o.Auth != onec.PasswordV2 && o.Auth != onec.PasswordV3 {
		return cliUsage(errors.New("auth must be legacy, v1, v2 or v3"))
	}
	if o.AgentPort < 1 || o.AgentPort > 65535 || o.ManagerPort < 1 || o.ManagerPort > 65535 {
		return cliUsage(errors.New("agent and manager ports must be in 1..65535"))
	}
	if o.Timeout <= 0 || o.Timeout > 5*time.Minute || o.TotalTimeout <= 0 || o.TotalTimeout > 24*time.Hour || o.Interval < 0 || o.Interval > time.Minute || o.MaxAttempts < 1 || o.MaxAttempts > 100000 {
		return cliUsage(errors.New("invalid timeout, interval or attempt limit; use onec checklist --help"))
	}
	if err := onec.ValidateAdminConfig(onec.AdminConfig{Agent: "127.0.0.1:1540", Version: o.Version, Transport: o.Transport, TransportPolicy: o.Policy, Timeout: o.Timeout}); err != nil {
		return cliUsage(errors.New("invalid client version, transport identity or transport policy"))
	}
	if reportPath == "" {
		reportPath = "onec-checklist-" + time.Now().UTC().Format("20060102T150405.000000000Z") + ".json"
	}
	// Preserve the caller's spelling in reports; do not add a workstation path.
	reportDisplayPath := reportPath
	reportPath, err = filepath.Abs(reportPath)
	if err != nil {
		return cliUsage(errors.New("invalid report path"))
	}
	if !execute {
		return writePreview(out, map[string]any{"operation": "checklist", "mode": "preview", "options": o, "report_file": reportDisplayPath, "coverage": "discovered_objects_only", "network_requests_sent": false})
	}
	// Fail before any network activity if the report cannot be created safely.
	file, err := os.OpenFile(reportPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("cannot create report file; choose a new path in an existing writable directory")
	}
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(signalCtx, o.TotalTimeout)
	defer cancel()
	var progressErr error
	report := executeChecklist(ctx, o, deps, func(row checklistResult) {
		if progressErr != nil {
			return
		}
		if row.CleanupFailed {
			row.Detail += " [cleanup unconfirmed]"
		}
		_, progressErr = fmt.Fprintf(diagnostic, "[%s] %s %s cluster=%q database=%q user=%q: %s\n", row.Status, row.Target, row.Check, row.Cluster, row.Database, row.User, row.Detail)
	})
	report.ReportFile = reportDisplayPath
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	writeErr := encoder.Encode(report)
	syncErr := file.Sync()
	closeErr := file.Close()
	outputErr := writeCommandReport(out, report)
	var auditErr error
	if !report.Completed {
		auditErr = errors.New("checklist incomplete; see report for failed and skipped checks")
	} else if failOnFindings && report.Summary.Findings > 0 {
		auditErr = errors.New("checklist found accepted empty credentials")
	}
	return errors.Join(auditErr, writeErr, syncErr, closeErr, outputErr, progressErr)
}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"onec"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

type portProber func(context.Context, onec.PortProbeConfig) (onec.PortProbeReport, error)

func runPorts(args []string, out, diagnostic io.Writer) error {
	return runPortsWith(args, out, diagnostic, onec.ProbePorts)
}

func runPortsWith(args []string, out, diagnostic io.Writer, probe portProber) error {
	if len(args) == 0 || isHelp(args[0]) {
		printGroupHelp(out, "ports", "Check TCP endpoints and identify supported anonymous 1C interfaces.", []helpCommand{
			{"scan", "Discover a bounded port range"},
			{"check", "Check one endpoint"},
		})
		return nil
	}
	mode := args[0]
	if mode != "scan" && mode != "check" {
		return cliUsage(errors.New("use onec ports scan or onec ports check"))
	}
	f := flag.NewFlagSet("onec ports "+mode, flag.ContinueOnError)
	f.SetOutput(diagnostic)
	f.Usage = func() {
		fmt.Fprintf(diagnostic, "Usage: onec ports %s [options]\nCheck TCP ports and identify supported 1C interfaces.\n", mode)
		printFlagGroups(f, diagnostic)
	}
	var cfg onec.PortProbeConfig
	var proxy proxyOptions
	proxy.flags(f)
	var apply, jsonOutput, roles, localProcess bool
	var ports string
	var port int
	var total time.Duration
	f.StringVar(&cfg.Host, "host", "127.0.0.1", "one IPv4 host; resolved once, selected IP is reported")
	if mode == "scan" {
		f.StringVar(&ports, "ports", "1540-1591", "ports and inclusive ranges, e.g. 1540,1541,1560-1591; at most 1024 unique ports")
		f.IntVar(&cfg.Concurrency, "concurrency", 4, "parallel ports, 1..16")
	} else {
		f.IntVar(&port, "port", 0, "required TCP port, 1..65535")
		cfg.Concurrency = 1
	}
	f.DurationVar(&cfg.Timeout, "timeout", 5*time.Second, "per-port timeout (up to 1m); context cleanup may add up to 1s")
	f.DurationVar(&total, "total-timeout", 2*time.Minute, "total scan timeout, including DNS; cancellation preserves partial results")
	f.StringVar(&cfg.Version, "client-version", "8.3.18.1208", "advertised 1C build for interface checks")
	f.BoolVar(&roles, "roles", true, "after a 1C greeting, query worker/manager interfaces using anonymous NTLM on Windows and Linux")
	f.BoolVar(&localProcess, "local-process", true, "read local Windows listener PID/name for loopback targets")
	f.BoolVar(&jsonOutput, "json", false, "print structured results instead of a table")
	f.BoolVar(&apply, "apply", false, "perform the read-only network checks; otherwise preview only")
	if help, err := parseCommandFlags(f, args[1:]); help || err != nil {
		return err
	}
	if cfg.Timeout <= 0 || total <= 0 {
		return errors.New("timeouts must be positive")
	}
	if mode == "scan" {
		var err error
		cfg.Ports, err = parseProbePorts(ports)
		if err != nil {
			return err
		}
		if cfg.Concurrency < 1 {
			return errors.New("concurrency must be in 1..16")
		}
	} else {
		cfg.Ports = []int{port}
	}
	cfg.SkipRoles, cfg.SkipLocalProcess = !roles, !localProcess
	var proxyErr error
	cfg.DialContext, proxyErr = proxy.dialer()
	if proxyErr != nil {
		return cliUsage(proxyErr)
	}
	if cfg.DialContext != nil {
		cfg.RemoteDNS = true
		cfg.SkipLocalProcess = true
		localProcess = false
	}
	if err := onec.ValidatePortProbeConfig(cfg); err != nil {
		return err
	}
	if !apply {
		report := map[string]any{"mode": "preview", "operation": "ports " + mode, "host": cfg.Host, "ports": cfg.Ports, "concurrency": cfg.Concurrency, "role_checks": roles, "local_process": localProcess, "network_requests_sent": false}
		proxy.report(report)
		return writePreview(out, report)
	}
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(signalCtx, total)
	defer cancel()
	report, operationErr := probe(ctx, cfg)
	if proxy.address != "" {
		for _, result := range report.Results {
			if result.State == "error" || result.State == "timeout" || result.State == "canceled" {
				operationErr = errors.Join(operationErr, errors.New("SOCKS5 port checks incomplete; inspect per-port results"))
				break
			}
		}
	}
	var outputErr error
	if jsonOutput || wantsJSON(out) {
		outputErr = json.NewEncoder(out).Encode(struct {
			Operation string `json:"operation"`
			Success   bool   `json:"success"`
			Proxy     string `json:"proxy,omitempty"`
			onec.PortProbeReport
		}{"ports " + mode, operationErr == nil, proxy.address, report})
	} else {
		outputErr = writePortTable(out, report)
	}
	return errors.Join(operationErr, outputErr)
}

func parseProbePorts(s string) ([]int, error) {
	bad := errors.New("ports must be comma-separated numbers/ranges in 1..65535, at most 1024 unique ports")
	if s == "" || len(s) > 16384 {
		return nil, bad
	}
	set := make(map[int]bool)
	for _, part := range strings.Split(s, ",") {
		bounds := strings.Split(strings.TrimSpace(part), "-")
		if len(bounds) > 2 {
			return nil, bad
		}
		parse := func(s string) (int, error) {
			if s == "" {
				return 0, bad
			}
			for _, c := range s {
				if c < '0' || c > '9' {
					return 0, bad
				}
			}
			n, err := strconv.Atoi(s)
			if err != nil || n < 1 || n > 65535 {
				return 0, bad
			}
			return n, nil
		}
		lo, err := parse(bounds[0])
		if err != nil {
			return nil, bad
		}
		hi := lo
		if len(bounds) == 2 {
			hi, err = parse(bounds[1])
			if err != nil {
				return nil, bad
			}
		}
		if hi < lo || hi-lo+1 > onec.MaxProbePorts {
			return nil, bad
		}
		for p := lo; p <= hi; p++ {
			set[p] = true
			if len(set) > onec.MaxProbePorts {
				return nil, bad
			}
		}
	}
	ports := make([]int, 0, len(set))
	for p := range set {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}

func writePortTable(out io.Writer, report onec.PortProbeReport) error {
	address := report.ResolvedIP
	if report.DNSResolution == "remote" && address == "" {
		address = "resolved by proxy"
	}
	if _, err := fmt.Fprintf(out, "Host: %s; IPv4: %s; local ownership: %s\n", report.Host, address, report.LocalOwnership); err != nil {
		return err
	}
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PORT\tSTATE\tPROTOCOL\tLOCAL PROCESS (PID)\tRPC ROLE\tDETAIL")
	for _, p := range report.Results {
		processes, roles, details := []string{}, []string{}, []string{}
		for _, owner := range p.LocalProcesses {
			processes = append(processes, fmt.Sprintf("%s (%d)", owner.Name, owner.PID))
		}
		for _, check := range p.RoleChecks {
			if check.Matched {
				roles = append(roles, check.Role)
			}
			if check.ContextOpened && (!check.ContextReleased || !check.Closed) {
				details = append(details, "cleanup_unconfirmed")
			}
		}
		if len(p.RoleChecks) > 0 && len(roles) == 0 {
			details = append(details, "roles_unconfirmed")
		}
		if p.Observation != "" {
			details = append(details, p.Observation)
		}
		if len(roles) == 0 {
			roles = append(roles, "unknown")
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n", p.Port, p.State, p.Protocol, strings.Join(processes, ", "), strings.Join(roles, ", "), strings.Join(details, ", "))
	}
	return w.Flush()
}

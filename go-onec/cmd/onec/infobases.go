package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"onec"
	"os"
	"os/signal"
	"time"
)

type infobaseLister func(context.Context, onec.InfobaseListConfig) (onec.InfobaseListResult, error)

func runInfobases(args []string, out, diagnostic io.Writer) error {
	return runInfobasesWith(args, out, diagnostic, onec.ListInfobases)
}

func runInfobasesWith(args []string, out, diagnostic io.Writer, list infobaseLister) error {
	f := flag.NewFlagSet("onec infobases", flag.ContinueOnError)
	f.SetOutput(diagnostic)
	f.Usage = func() {
		fmt.Fprintln(diagnostic, "Usage: onec infobases --worker host:port [--transport anonymous|windows] [--execute]\nLists infobase names, IDs and descriptions through working-process administration; no infobase login.")
		printFlagGroups(f, diagnostic)
	}
	var cfg onec.InfobaseListConfig
	var proxy proxyOptions
	proxy.flags(f)
	var apply bool
	var transportPolicy string
	f.StringVar(&cfg.Worker, "worker", "", "required current rphost IPv4 host:port (not the manager or RAS)")
	f.StringVar(&cfg.Transport, "transport", "anonymous", "anonymous NTLM or explicitly selected current-session windows credentials; no fallback")
	f.StringVar(&cfg.Version, "client-version", "8.3.18.1208", "advertised build; compatibility with other builds is unverified")
	f.StringVar(&transportPolicy, "transport-policy", "plain", transportPolicyHelp)
	f.DurationVar(&cfg.Timeout, "timeout", 20*time.Second, "total operation timeout; cleanup has a separate bounded timeout")
	f.BoolVar(&apply, "apply", false, "perform the read-only network request")
	if help, err := parseCommandFlags(f, args); help || err != nil {
		return err
	}
	if cfg.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	cfg.TransportPolicy = onec.TransportPolicy(transportPolicy)
	var proxyErr error
	cfg.DialContext, proxyErr = proxy.dialer()
	if proxyErr != nil {
		return cliUsage(proxyErr)
	}
	if err := onec.ValidateInfobaseListConfig(cfg); err != nil {
		return err
	}
	if !apply {
		report := map[string]any{"mode": "preview", "operation": "infobases", "worker": cfg.Worker, "transport": cfg.Transport, "network_requests_sent": false, "infobase_login": false}
		proxy.report(report)
		if cfg.TransportPolicy != onec.TransportPlain {
			report["transport_policy"] = cfg.TransportPolicy
		}
		return writePreview(out, report)
	}
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(signalCtx, cfg.Timeout)
	defer cancel()
	result, operationErr := list(ctx, cfg)
	report := map[string]any{"mode": "apply", "operation": "infobases", "worker": cfg.Worker, "transport": cfg.Transport, "success": operationErr == nil, "infobases": result.Infobases, "stats": result.Stats}
	proxy.report(report)
	if cfg.TransportPolicy != onec.TransportPlain {
		report["transport_policy"] = cfg.TransportPolicy
	}
	return errors.Join(operationErr, writeCommandReport(out, report))
}

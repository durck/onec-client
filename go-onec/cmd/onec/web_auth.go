package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"onec/webauth"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
)

func runWebAuth(mode string, args []string, out, diagnostic io.Writer) error {
	f := flag.NewFlagSet("onec web "+mode, flag.ContinueOnError)
	f.SetOutput(diagnostic)
	f.Usage = func() {
		fmt.Fprintf(diagnostic, "Usage: onec web %s --url https://example.invalid/demo/ --user <known-user> [--execute]\nPassword is read from a hidden prompt or --password-stdin; never a command-line flag.\nlogin verifies one web-client attempt and logs out; basic-check verifies one HTTP Basic challenge.\n", mode)
		printFlagGroups(f, diagnostic)
	}
	var cfg webauth.Config
	var user, method, resource string
	var apply, stdin bool
	f.StringVar(&cfg.URL, "url", "", "known publication directory; login may use /ru_RU/, basic-check uses the publication root")
	f.StringVar(&user, "user", "", "known test/account username (required)")
	f.BoolVar(&stdin, "password-stdin", false, "read password from stdin (UTF-8, up to 4096 bytes); otherwise hidden terminal prompt")
	f.BoolVar(&apply, "apply", false, "perform one attempt; default preview does not read credentials or connect")
	f.BoolVar(&cfg.Insecure, "insecure", false, "explicitly disable server certificate verification for this run")
	f.BoolVar(&cfg.AllowHTTP, "allow-http", false, "explicitly permit unencrypted HTTP beyond literal loopback addresses")
	f.DurationVar(&cfg.Timeout, "timeout", 45*time.Second, "total operation timeout, up to 3m; logout gets a separate 15s")
	if mode == "login" {
		f.StringVar(&method, "auth", "auto", "auto (served web-client contract), legacy, v1, v3; no fallback")
	} else {
		f.StringVar(&resource, "resource", "odata/standard.odata/$metadata", "OData description/root, hs/, ws/ or ws/<name>?wsdl")
	}
	if help, err := parseCommandFlags(f, args); help || err != nil {
		if err != nil {
			return webUsage(err)
		}
		return nil
	}
	if cfg.Timeout <= 0 {
		return webUsage(errors.New("timeout must be positive"))
	}
	if err := webauth.ValidateConfig(cfg); err != nil {
		return webUsage(err)
	}
	if err := webauth.ValidateCredentials(webauth.Credentials{Username: user, Method: method}); err != nil {
		return webUsage(err)
	}
	if mode == "basic-check" {
		if err := webauth.ValidateBasicResource(resource); err != nil {
			return webUsage(err)
		}
	}
	if !apply {
		return writePreview(out, map[string]any{"mode": "preview", "operation": "web " + mode, "url": cfg.URL, "auth": method, "resource": resource, "network_requests_sent": false, "credentials_read": false, "tls_verification_disabled": cfg.Insecure, "logout_planned": mode == "login"})
	}
	password, err := readWebPassword(os.Stdin, diagnostic, stdin)
	if err != nil {
		return err
	}
	credentials := webauth.Credentials{Username: user, Password: password, Method: method}
	password = ""
	if err = webauth.ValidateCredentials(credentials); err != nil {
		return err
	}
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalCtx, cfg.Timeout)
	defer cancel()
	report := map[string]any{"operation": "web " + mode, "tls_verification_disabled": cfg.Insecure}
	if mode == "basic-check" {
		result, operationErr := webauth.CheckBasic(ctx, cfg, credentials, resource)
		credentials = webauth.Credentials{}
		report["result"] = result
		report["success"] = operationErr == nil
		addWebError(report, "error", operationErr)
		return errors.Join(operationErr, writeCommandReport(out, report))
	}
	c, operationErr := webauth.New(ctx, cfg)
	if operationErr != nil {
		credentials = webauth.Credentials{}
		report["success"] = false
		addWebError(report, "error", operationErr)
		return errors.Join(operationErr, writeCommandReport(out, report))
	}
	defer c.Close()
	result, operationErr := c.Login(ctx, credentials)
	credentials = webauth.Credentials{}
	needed := c.SessionPresent()
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
	cleanupErr := c.Logout(cleanupCtx)
	cleanupCancel()
	report["result"] = result
	report["logout_attempted"] = needed
	report["logout_confirmed"] = needed && cleanupErr == nil
	report["success"] = operationErr == nil && cleanupErr == nil
	addWebError(report, "error", operationErr)
	addWebError(report, "cleanup_error", cleanupErr)
	return errors.Join(operationErr, cleanupErr, writeCommandReport(out, report))
}

func addWebError(report map[string]any, key string, err error) {
	if err == nil {
		return
	}
	var e *webauth.Error
	if errors.As(err, &e) {
		report[key] = e
	} else {
		report[key] = "operation_failed"
	}
}

func readWebPassword(in *os.File, diagnostic io.Writer, stdin bool) (string, error) {
	if stdin {
		b, err := io.ReadAll(io.LimitReader(in, 4097))
		defer clear(b)
		if err != nil || len(b) > 4096 {
			return "", errors.New("password input limit or read error")
		}
		return strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r"), nil
	}
	if !term.IsTerminal(int(in.Fd())) {
		return "", errors.New("use an interactive terminal or --password-stdin")
	}
	fmt.Fprint(diagnostic, "1C password: ")
	b, err := term.ReadPassword(int(in.Fd()))
	fmt.Fprintln(diagnostic)
	defer clear(b)
	if err != nil || len(b) > 4096 {
		return "", errors.New("could not read hidden password")
	}
	return string(b), nil
}

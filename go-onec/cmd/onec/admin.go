package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"onec"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/term"
)

type adminRunner func(context.Context, onec.AdminConfig, onec.AdminRequest) (onec.AdminResult, error)

type adminAuthOptions struct {
	mode, user, passwordEnv string
}

type adminSecretInput struct {
	lookupEnv  func(string) (string, bool)
	readHidden func(string) (string, error)
}

func runAdmin(args []string, out, diagnostic io.Writer) error {
	return runAdminWith(args, out, diagnostic, onec.RunAdmin)
}

func runAdminWith(args []string, out, diagnostic io.Writer, execute adminRunner) error {
	return runAdminWithInput(args, out, diagnostic, execute, adminSecretInput{
		lookupEnv: os.LookupEnv,
		readHidden: func(scope string) (string, error) {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return "", fmt.Errorf("%s password needs an interactive terminal or --%s-password-env", scope, scope)
			}
			fmt.Fprintf(diagnostic, "1C %s administrator password: ", scope)
			password, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(diagnostic)
			defer clear(password)
			if err != nil || len(password) > 4096 {
				return "", errors.New("could not read hidden administration password")
			}
			return string(password), nil
		},
	})
}

func runAdminWithInput(args []string, out, diagnostic io.Writer, execute adminRunner, input adminSecretInput) error {
	if len(args) == 0 || isHelp(args[0]) {
		printGroupHelp(out, "admin", "Native server-agent administration. Agent and cluster identities are separate from transport authentication.", []helpCommand{
			{"clusters", "List clusters"},
			{"agent-admins", "List server administrators"},
			{"cluster-admins", "List cluster administrators"},
			{"servers", "List working servers"},
			{"processes", "List working processes"},
			{"bases", "List cluster infobases"},
			{"sessions", "List sessions"},
			{"terminate-session", "Terminate one explicit session"},
			{"set", "Change one supported cluster setting"},
		})
		return nil
	}
	operation := args[0]
	clusterScoped := false
	switch operation {
	case "clusters", "agent-admins":
	case "cluster-admins", "servers", "processes", "bases", "sessions", "terminate-session", "set":
		clusterScoped = true
	default:
		return cliUsage(errors.New("unknown administration command; use onec admin --help"))
	}
	f := flag.NewFlagSet("onec admin "+operation, flag.ContinueOnError)
	// flag errors echo invalid values. Never echo arbitrary argv, including an
	// accidentally supplied password, to either the diagnostic stream or main.
	f.SetOutput(io.Discard)
	f.Usage = func() {
		fmt.Fprintf(diagnostic, "Usage: onec admin %s [options]\nPreview performs no network, credential or security-provider access.\n", operation)
		f.SetOutput(diagnostic)
		printFlagGroups(f, diagnostic)
		f.SetOutput(io.Discard)
	}
	var cfg onec.AdminConfig
	var proxy proxyOptions
	proxy.flags(f)
	request := onec.AdminRequest{Operation: operation}
	var agent, cluster adminAuthOptions
	var apply bool
	var value string
	var transportPolicy string
	f.StringVar(&cfg.Agent, "agent", "127.0.0.1:1540", "server-agent IPv4 host:port (not the manager or RAS)")
	f.StringVar(&cfg.Version, "client-version", "8.3.18.1208", "advertised client build; administration schema is negotiated separately")
	defaultTransport := "windows"
	if runtime.GOOS != "windows" {
		defaultTransport = "anonymous"
	}
	f.StringVar(&cfg.Transport, "transport", defaultTransport, "windows current-session or anonymous transport; no fallback")
	f.StringVar(&transportPolicy, "transport-policy", "plain", transportPolicyHelp)
	f.DurationVar(&cfg.Timeout, "timeout", 20*time.Second, "operation timeout, positive and at most 5m; cleanup is separately bounded")
	f.BoolVar(&apply, "apply", false, "execute the selected request, including mutations; otherwise preview only")
	addAdminAuthFlags(f, "agent", &agent)
	if clusterScoped {
		f.StringVar(&request.ClusterID, "cluster", "", "required explicit cluster UUID; no default or wildcard selection")
		addAdminAuthFlags(f, "cluster", &cluster)
	} else {
		cluster.mode = "none"
	}
	if operation == "terminate-session" {
		f.StringVar(&request.SessionID, "session", "", "required internal session UUID from sessions output, not its numeric display ID")
		f.StringVar(&request.Message, "message", "", "optional termination message")
	}
	if operation == "set" {
		f.StringVar(&request.Setting, "setting", "", "security-level, recycle-lifetime, recycle-expiration, fault-tolerance, load-balancing-mode, kill-problem-processes, or kill-by-memory-with-dump")
		f.StringVar(&value, "value", "", "required decimal value; security-level 0..2; load-balancing/kill settings 0..1; lifetime/expiration/fault-tolerance 0..2147483647")
	}
	addReadableFlags(f)
	if err := f.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return cliUsage(errors.New("invalid administration options; use onec admin <command> --help"))
	}
	if err := validateFlagSpellings(f); err != nil {
		return cliUsage(err)
	}
	if f.NArg() != 0 {
		return cliUsage(errors.New("unexpected administration positional arguments"))
	}
	var emptyEnvName bool
	f.Visit(func(option *flag.Flag) {
		if strings.HasSuffix(option.Name, "-password-env") && option.Value.String() == "" {
			emptyEnvName = true
		}
	})
	if emptyEnvName {
		return errors.New("password environment options require a nonempty variable name")
	}
	if cfg.Timeout <= 0 || cfg.Timeout > 5*time.Minute {
		return errors.New("administration timeout must be positive and at most 5m")
	}
	cfg.TransportPolicy = onec.TransportPolicy(transportPolicy)
	var proxyErr error
	cfg.DialContext, proxyErr = proxy.dialer()
	if proxyErr != nil {
		return cliUsage(proxyErr)
	}
	if err := onec.ValidateAdminConfig(cfg); err != nil {
		return errors.New("invalid administration connection configuration; check agent endpoint, transport, transport policy and client version format")
	}
	if err := agent.validate("agent"); err != nil {
		return err
	}
	if err := cluster.validate("cluster"); err != nil {
		return err
	}
	if operation == "set" {
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil || strings.HasPrefix(value, "+") {
			return errors.New("set requires --value as an unsigned 32-bit decimal integer")
		}
		request.Value = uint32(parsed)
	}
	if err := onec.ValidateAdminRequest(request); err != nil {
		return errors.New("invalid administration request; check explicit target UUIDs and setting/value bounds")
	}
	report := map[string]any{
		"mode": "preview", "operation": "admin " + operation, "agent": cfg.Agent,
		"transport": cfg.Transport, "client_version": cfg.Version,
		"agent_auth": agent.mode, "cluster_auth": cluster.mode,
		"network_requests_sent": false, "credentials_read": false,
	}
	if cfg.TransportPolicy != onec.TransportPlain {
		report["transport_policy"] = cfg.TransportPolicy
	}
	proxy.report(report)
	if clusterScoped {
		report["cluster"] = request.ClusterID
	}
	if operation == "terminate-session" {
		report["session"] = request.SessionID
		report["message_set"] = request.Message != ""
	}
	if operation == "set" {
		report["setting"], report["value"] = request.Setting, request.Value
	}
	if !apply {
		return writePreview(out, report)
	}
	var err error
	request.AgentAuth, err = agent.credentials("agent", input)
	if err != nil {
		return err
	}
	request.ClusterAuth, err = cluster.credentials("cluster", input)
	if err != nil {
		return err
	}
	var secrets []string
	for _, credentials := range []*onec.AdminCredentials{request.AgentAuth, request.ClusterAuth} {
		if credentials != nil && credentials.Password != "" {
			secrets = append(secrets, credentials.Password)
		}
	}
	// Prefer the longer match when passwords overlap.
	sort.Slice(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(signalCtx, cfg.Timeout)
	defer cancel()
	result, operationErr := execute(ctx, cfg, request)
	request.AgentAuth, request.ClusterAuth = nil, nil
	report["mode"], report["success"] = "apply", operationErr == nil
	delete(report, "network_requests_sent")
	delete(report, "credentials_read")
	report["data"], report["stats"] = result.Data, result.Stats
	encodeErr := writeAdminReport(out, report, secrets)
	if err := errors.Join(operationErr, encodeErr); err != nil {
		return adminRedactedError{cause: err, message: redactAdminText(err.Error(), secrets)}
	}
	return nil
}

func addAdminAuthFlags(f *flag.FlagSet, scope string, options *adminAuthOptions) {
	f.StringVar(&options.mode, scope+"-auth", "none", "none (no call), default (empty credentials), or password (named administrator)")
	f.StringVar(&options.user, scope+"-user", "", "explicit administrator username, required only for password authentication")
	f.StringVar(&options.passwordEnv, scope+"-password-env", "", "environment variable NAME containing the password; otherwise hidden terminal prompt")
}

func (o adminAuthOptions) validate(scope string) error {
	switch o.mode {
	case "none", "default":
		if o.user != "" || o.passwordEnv != "" {
			return fmt.Errorf("--%s-user and --%s-password-env require --%s-auth password", scope, scope, scope)
		}
	case "password":
		if strings.TrimSpace(o.user) == "" || len(o.user) > 4096 || !utf8.ValidString(o.user) || strings.ContainsAny(o.user, "\x00\r\n") {
			return fmt.Errorf("--%s-auth password requires a nonempty administrator username", scope)
		}
	default:
		return fmt.Errorf("--%s-auth must be none, default or password", scope)
	}
	for i, r := range o.passwordEnv {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || i > 0 && r >= '0' && r <= '9') {
			return fmt.Errorf("--%s-password-env requires an environment variable name", scope)
		}
	}
	return nil
}

func (o adminAuthOptions) credentials(scope string, input adminSecretInput) (*onec.AdminCredentials, error) {
	if o.mode == "none" {
		return nil, nil
	}
	if o.mode == "default" {
		return &onec.AdminCredentials{}, nil
	}
	var password string
	if o.passwordEnv != "" {
		var ok bool
		password, ok = input.lookupEnv(o.passwordEnv)
		if !ok {
			return nil, fmt.Errorf("%s password environment variable is not set", scope)
		}
	} else {
		var err error
		password, err = input.readHidden(scope)
		if err != nil {
			return nil, fmt.Errorf("could not read %s password; use an interactive terminal or --%s-password-env", scope, scope)
		}
	}
	if len(password) > 4096 || !utf8.ValidString(password) || strings.ContainsRune(password, 0) {
		return nil, fmt.Errorf("%s password is invalid or exceeds 4096 bytes", scope)
	}
	return &onec.AdminCredentials{Username: o.user, Password: password}, nil
}

type adminRedactedError struct {
	cause   error
	message string
}

func (e adminRedactedError) Error() string { return e.message }
func (e adminRedactedError) Unwrap() error { return e.cause }

func redactAdminText(text string, secrets []string) string {
	for _, secret := range secrets {
		text = strings.ReplaceAll(text, secret, "[redacted]")
		quoted := strconv.Quote(secret)
		text = strings.ReplaceAll(text, quoted[1:len(quoted)-1], "[redacted]")
	}
	return text
}

func writeAdminReport(out io.Writer, report map[string]any, secrets []string) error {
	// Redact string values after serialization, preserving JSON numbers without
	// float conversion. This also protects future result types from echoing input.
	encoded, err := json.Marshal(report)
	if err != nil {
		return err
	}
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	// The report's fixed field names are protocol keys, not supplied input.
	// Preserve them even when a password happens to equal "success" or "data".
	for key, item := range value {
		value[key] = redactAdminValue(item, secrets)
	}
	return writeCommandReport(out, value)
}

func redactAdminValue(value any, secrets []string) any {
	switch value := value.(type) {
	case string:
		return redactAdminText(value, secrets)
	case []any:
		for i := range value {
			value[i] = redactAdminValue(value[i], secrets)
		}
		return value
	case map[string]any:
		redacted := make(map[string]any, len(value))
		for key, item := range value {
			redacted[redactAdminText(key, secrets)] = redactAdminValue(item, secrets)
		}
		return redacted
	default:
		return value
	}
}

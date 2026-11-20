package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"onec"
	"onec/internal/security"
	"onec/ntlmauth"
	"onec/ticketauth"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
)

const transportPolicyHelp = "plain, native27-n or native27-c; experimental native27 modes require explicit selection and have no native server acceptance proof"

// Connection and authentication options are shared by root and grouped commands.
type commandOptions struct {
	proxy                                                  proxyOptions
	server, worker, base, version, application, serverName string
	transportPolicy, transport                             string
	auth, user                                             string
	ticketFile, kerberosSPN, kdc                           string
	ntlm, ntlmDomain, ntlmUser                             string
	ntlmSecretStdin                                        bool
	passwordStdin, apply                                   bool
	timeout                                                time.Duration
}

func newCommandFlags(name string, diagnostic io.Writer) (*flag.FlagSet, *commandOptions) {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(diagnostic)
	f.Usage = func() {
		fmt.Fprintf(diagnostic, "Usage: %s [options]\n", name)
		if description := commandDescription(name); description != "" {
			printHelpText(diagnostic, description, "")
		}
		printFlagGroups(f, diagnostic)
	}
	o := &commandOptions{}
	o.proxy.flags(f)
	f.StringVar(&o.server, "server", "127.0.0.1:1541", "manager IPv4 host:port")
	f.StringVar(&o.worker, "worker", "", "worker IPv4 host:port; bypass manager")
	f.StringVar(&o.base, "base", "test", "infobase name")
	f.StringVar(&o.version, "client-version", "8.3.18.1208", "advertised platform build")
	f.StringVar(&o.transportPolicy, "transport-policy", "plain", transportPolicyHelp)
	f.StringVar(&o.application, "application", "", "application identity (v2 defaults to MobileClient)")
	f.StringVar(&o.serverName, "server-name", "", "server name in 1C headers")
	defaultAuth := "windows"
	if runtime.GOOS != "windows" {
		defaultAuth = "legacy"
	}
	f.StringVar(&o.auth, "auth", defaultAuth, "infobase login: windows, legacy, v1, v2 or v3")
	f.StringVar(&o.transport, "transport", "auto", "auto (Windows session on Windows; anonymous elsewhere), anonymous or windows")
	f.StringVar(&o.ticketFile, "ticket-file", "", "read .kirbi or ccache directly; no OS-cache import (requires --worker and --kerberos-spn)")
	f.StringVar(&o.kerberosSPN, "kerberos-spn", "", "exact service/host principal for file-backed Kerberos")
	f.StringVar(&o.kdc, "kdc", "", "explicit KDC IPv4 host:port for a TGT; optional with a service ticket")
	f.StringVar(&o.ntlm, "ntlm", "", "explicit NTLMv2 secret type: password or hash; requires --auth windows, --ntlm-domain and --ntlm-user")
	f.StringVar(&o.ntlmDomain, "ntlm-domain", "", "explicit account domain for NTLM; no local/current-user default")
	f.StringVar(&o.ntlmUser, "ntlm-user", "", "unqualified account name for NTLM (different from the infobase --user)")
	f.BoolVar(&o.ntlmSecretStdin, "ntlm-secret-stdin", false, "read NTLM password or 32-hex-character NT hash from stdin; otherwise hidden prompt")
	f.StringVar(&o.user, "user", "", "infobase username; otherwise prompt")
	f.BoolVar(&o.passwordStdin, "password-stdin", false, "read password from stdin (requires --user)")
	f.BoolVar(&o.apply, "apply", false, "perform the requested network operation")
	f.DurationVar(&o.timeout, "timeout", 45*time.Second, "total operation timeout")
	return f, o
}

func parseCommandFlags(f *flag.FlagSet, args []string) (bool, error) {
	addReadableFlags(f)
	// flag's default errors echo values, which may contain credentials or
	// terminal controls. Keep diagnostics fixed and show help only on request.
	usage, output := f.Usage, f.Output()
	f.Usage = func() {}
	f.SetOutput(io.Discard)
	err := f.Parse(args)
	f.Usage = usage
	f.SetOutput(output)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return true, nil
		}
		return false, cliUsage(fmt.Errorf("invalid options for %s; use %s --help", f.Name(), f.Name()))
	}
	if err := validateFlagSpellings(f); err != nil {
		return false, cliUsage(err)
	}
	if f.NArg() != 0 {
		return false, cliUsage(errors.New("unexpected positional arguments; options use --name value"))
	}
	return false, nil
}

func (o *commandOptions) config(login bool) (onec.Config, error) {
	if o.timeout <= 0 {
		return onec.Config{}, errors.New("timeout must be positive")
	}
	switch onec.AuthMethod(o.auth) {
	case onec.WindowsAuth, onec.LegacyAuth, onec.PasswordV1, onec.PasswordV2, onec.PasswordV3:
	default:
		return onec.Config{}, errors.New("unsupported authentication method")
	}
	if o.auth == "windows" && (o.user != "" || o.passwordStdin) {
		return onec.Config{}, errors.New("Windows authentication cannot be combined with password input")
	}
	if o.passwordStdin && o.user == "" {
		return onec.Config{}, errors.New("--password-stdin requires --user")
	}
	if !login && (o.user != "" || o.passwordStdin) {
		return onec.Config{}, errors.New("this command does not submit infobase credentials")
	}
	application := o.application
	if application == "" {
		application = "1CV8C"
		if o.auth == "v2" {
			application = "MobileClient"
		}
	}
	cfg := onec.Config{Server: o.server, Worker: o.worker, Infobase: o.base, ServerName: o.serverName, Profile: onec.Profile{Version: o.version, Application: application}, TransportPolicy: onec.TransportPolicy(o.transportPolicy), Timeout: o.timeout}
	var proxyErr error
	cfg.DialContext, proxyErr = o.proxy.dialer()
	if proxyErr != nil {
		return cfg, cliUsage(proxyErr)
	}
	if o.ticketFile != "" || o.kerberosSPN != "" || o.kdc != "" {
		if o.proxy.address != "" {
			return cfg, cliUsage(errors.New("SOCKS5 does not support file-backed Kerberos/KDC traffic; choose a supported native authentication provider explicitly"))
		}
		if o.auth != "windows" {
			return cfg, errors.New("ticket-file mode requires --auth windows")
		}
		cfg.Kerberos = &ticketauth.Options{File: o.ticketFile, SPN: o.kerberosSPN, KDC: o.kdc}
	}
	if o.ntlm != "" || o.ntlmDomain != "" || o.ntlmUser != "" || o.ntlmSecretStdin {
		if (o.ntlm != "password" && o.ntlm != "hash") || o.auth != "windows" || cfg.Kerberos != nil {
			return cfg, errors.New("--ntlm password|hash requires --auth windows and cannot be combined with ticket-file mode")
		}
		if err := ntlmauth.ValidateIdentity(ntlmauth.Identity{Domain: o.ntlmDomain, User: o.ntlmUser}); err != nil {
			return cfg, err
		}
	}
	if o.transport != "auto" && o.transport != "anonymous" && o.transport != "windows" && o.transport != "" {
		return cfg, errors.New("transport must be auto, anonymous or windows")
	}
	if cfg.Kerberos != nil || o.ntlm != "" {
		if o.transport != "auto" && o.transport != "" {
			return cfg, errors.New("explicit NTLM/Kerberos cannot be combined with a transport identity selector")
		}
	} else if o.transportIdentity() == "anonymous" {
		if login && o.auth == "windows" {
			return cfg, errors.New("Windows infobase login requires Windows transport or an explicit NTLM/Kerberos provider")
		}
		cfg.SecurityFactory = security.NewAnonymous
	}
	return cfg, onec.ValidateConfig(cfg)
}

func (o *commandOptions) transportIdentity() string {
	if o.transport == "anonymous" || o.transport == "windows" {
		return o.transport
	}
	if runtime.GOOS == "windows" || o.auth == "windows" {
		return "windows"
	}
	return "anonymous"
}

func (o *commandOptions) preview(operation string, cfg onec.Config) map[string]any {
	p := map[string]any{"mode": "preview", "operation": operation, "server": o.server, "worker": o.worker, "infobase": o.base, "authentication": o.auth, "profile": cfg.Profile, "network_requests_sent": false}
	o.proxy.report(p)
	if cfg.Kerberos == nil && o.ntlm == "" {
		p["transport"] = o.transportIdentity()
	}
	if cfg.TransportPolicy != "" && cfg.TransportPolicy != onec.TransportPlain {
		p["transport_policy"] = cfg.TransportPolicy
	}
	if cfg.Kerberos != nil {
		p["security_provider"] = "kerberos-file"
		p["kerberos_spn"] = o.kerberosSPN
		p["kdc"] = o.kdc
		p["credential_file_read"] = false
	}
	if o.ntlm != "" {
		p["security_provider"] = "ntlm-explicit"
		p["secret_type"] = o.ntlm
		p["secret_read"] = false
		p["ntlm_domain"], p["ntlm_user"] = o.ntlmDomain, o.ntlmUser
	}
	return p
}

func writePreview(out io.Writer, preview map[string]any) error {
	return writeCommandReport(out, preview)
}

func (o *commandOptions) credentials(cfg onec.Config, diagnostic io.Writer) (onec.Credentials, error) {
	credentials := onec.Credentials{Method: onec.AuthMethod(o.auth)}
	if o.auth == "windows" {
		return credentials, nil
	}
	if !o.passwordStdin && !term.IsTerminal(int(os.Stdin.Fd())) {
		return onec.Credentials{}, errors.New("password login needs an interactive terminal or --password-stdin")
	}
	reader := bufio.NewReader(os.Stdin)
	username := o.user
	if username == "" {
		var names []string
		if o.auth == "legacy" {
			listCtx, cancel := context.WithTimeout(context.Background(), o.timeout)
			client, err := onec.Dial(listCtx, cfg)
			if err == nil {
				names, err = client.Users(listCtx)
				err = errors.Join(err, client.Close())
			}
			cancel()
			if err != nil {
				fmt.Fprintln(diagnostic, "User selection list unavailable; enter a username manually.")
			} else {
				for i, name := range names {
					fmt.Fprintf(diagnostic, "%d. %q\n", i+1, name)
				}
			}
		}
		fmt.Fprint(diagnostic, "1C username or selection number: ")
		line, err := reader.ReadString('\n')
		if err != nil {
			return onec.Credentials{}, errors.New("could not read username")
		}
		username = strings.TrimSpace(line)
		if n, err := strconv.Atoi(username); err == nil && n >= 1 && n <= len(names) {
			username = names[n-1]
		}
	}
	credentials.Username = username
	if o.passwordStdin {
		line, err := io.ReadAll(io.LimitReader(reader, 4097))
		if err != nil || len(line) > 4096 {
			clear(line)
			return onec.Credentials{}, errors.New("password input limit or read error")
		}
		credentials.Password = strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
		clear(line)
	} else {
		fmt.Fprint(diagnostic, "1C password: ")
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(diagnostic)
		if err != nil {
			clear(password)
			return onec.Credentials{}, errors.New("could not read hidden password")
		}
		credentials.Password = string(password)
		clear(password)
	}
	return credentials, nil
}

// Session cleanup uses Client.Close's independent timeout even after the
// operation context expires. Each application action is attempted only once.
func executeCommand(cfg onec.Config, operation string, fields map[string]any, out io.Writer, action func(context.Context, *onec.Client) (any, error)) error {
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(signalCtx, cfg.Timeout)
	defer cancel()
	client, err := onec.Dial(ctx, cfg)
	if err != nil {
		return err
	}
	defer client.Close()
	result, operationErr := action(ctx, client)
	cleanupErr := client.Close()
	report := map[string]any{"mode": "apply", "operation": operation, "success": operationErr == nil && cleanupErr == nil, "stats": client.Stats()}
	if cfg.TransportPolicy != "" && cfg.TransportPolicy != onec.TransportPlain {
		report["transport_policy"] = cfg.TransportPolicy
	}
	if cfg.NTLM != nil {
		report["security_provider"] = "ntlm-explicit"
	}
	for key, value := range fields {
		report[key] = value
	}
	if result != nil {
		report["result"] = result
	}
	encodeErr := writeCommandReport(out, report)
	return errors.Join(operationErr, cleanupErr, encodeErr)
}

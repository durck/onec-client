package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"onec"
	"onec/wire"
	"os"
	"os/signal"
	"strings"
	"time"
)

const authCheckFixtureHash = "2db2c5998cd6e32fb40fb7593cb42370ef3a0b62802b4c526b646a64944a1f4d"

type authCheckResult struct {
	Event                    string          `json:"event"`
	Case                     string          `json:"case"`
	Method                   onec.AuthMethod `json:"method"`
	Application              string          `json:"application"`
	Phase                    string          `json:"phase"`
	Status                   string          `json:"status"`
	Diagnostic               string          `json:"diagnostic,omitempty"`
	HTTPStatus               int             `json:"http_status,omitempty"`
	RefusalConfirmed         bool            `json:"refusal_confirmed"`
	RetryEligible            bool            `json:"retry_eligible"`
	LoginConfirmed           bool            `json:"login_confirmed"`
	MethodsConfirmed         bool            `json:"methods_confirmed"`
	CallConfirmed            bool            `json:"call_confirmed"`
	EPFConfirmationRequired  bool            `json:"epf_confirmation_required"`
	EPFConfirmationSent      bool            `json:"epf_confirmation_sent"`
	EPFConfirmationSucceeded bool            `json:"epf_confirmation_succeeded"`
	FormClosed               bool            `json:"form_closed"`
	CleanupError             bool            `json:"cleanup_error"`
	Success                  bool            `json:"success"`
	Stats                    onec.Stats      `json:"stats"`
	DurationMS               int64           `json:"duration_ms"`
}

func checkMethods(raw string) ([]onec.AuthMethod, error) {
	seen := map[onec.AuthMethod]bool{}
	var out []onec.AuthMethod
	for _, name := range strings.Split(raw, ",") {
		method := onec.AuthMethod(name)
		switch method {
		case onec.LegacyAuth, onec.PasswordV1, onec.PasswordV2, onec.PasswordV3:
		default:
			return nil, errors.New("--methods accepts legacy,v1,v2,v3 only")
		}
		if seen[method] {
			return nil, errors.New("duplicate method in --methods")
		}
		seen[method] = true
		out = append(out, method)
	}
	return out, nil
}

// Only exact static library diagnostics can leave this boundary. Never emit
// arbitrary errors, server bodies, credentials, proofs or session headers.
func checkError(r *authCheckResult, err error) {
	r.Status, r.HTTPStatus, _ = batchLoginStatus(err)
	var approval *onec.ProcessingSecurityError
	if errors.As(err, &approval) {
		r.Status = "processing_confirmation_required"
	}
	var atom *wire.UnsupportedAtomError
	if errors.As(err, &atom) {
		r.Diagnostic = fmt.Sprintf("unsupported_binary_atom_at_%d_tag_%02x", atom.Offset, atom.Tag)
	}
	var native *wire.NativeRPCError
	if errors.As(err, &native) {
		r.Status = "server_rpc_error"
		r.Diagnostic = native.Code()
	}
	for code, message := range map[string]string{
		"deferred_security_rejected": "unexpected HTTP security renegotiation",
		"missing_final_proof":        "missing final application credential proof",
		"rejected_proof":             "credential proof rejected",
		"ambiguous_credential":       "ambiguous credential response",
		"routing_session_changed":    "routing session changed during authentication",
	} {
		if err != nil && err.Error() == message {
			r.Diagnostic = code
		}
	}
}

func authCheckCase(ctx context.Context, cfg onec.Config, credentials onec.Credentials,
	name string, reuse bool, fixture []byte, confirmEPF bool) (r authCheckResult) {
	started := time.Now()
	r = authCheckResult{Event: "case", Case: name, Method: credentials.Method,
		Application: cfg.Profile.Application, Phase: "dial", Status: "pending"}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	defer func() { r.DurationMS = time.Since(started).Milliseconds() }()
	c, err := onec.Dial(ctx, cfg)
	if err != nil {
		checkError(&r, err)
		return r
	}
	defer func() {
		closeErr := c.Close()
		r.Stats = c.Stats()
		r.CleanupError = r.CleanupError || closeErr != nil || !r.Stats.ContextReleased || !r.Stats.SecurityClosed ||
			!r.Stats.Closed || (r.Stats.Authenticated && !r.Stats.LogoutConfirmed)
		if r.CleanupError {
			r.Success = false
			if r.Status == "accepted" {
				r.Status = "cleanup_failed"
			}
		}
	}()
	if reuse {
		r.Phase = "generated_identity_refusal"
		id, err := wire.NewUUID()
		if err != nil {
			checkError(&r, err)
			return r
		}
		err = c.Login(ctx, onec.Credentials{Method: onec.LegacyAuth,
			Username: "GoCheckAbsent-" + id.String(), Password: "synthetic-noncredential"})
		var status *onec.StatusError
		r.RefusalConfirmed = errors.As(err, &status) && status.Operation == "login" &&
			(status.Status == 401 || status.Status == 402)
		r.RetryEligible = c.CanRetryLogin()
		if !r.RefusalConfirmed || !r.RetryEligible {
			if err == nil {
				err = errors.New("generated identity did not produce a clean refusal")
			}
			checkError(&r, err)
			return r
		}
	}
	r.Phase = "known_credential_login"
	if reuse {
		err = c.RetryLogin(ctx, credentials)
	} else {
		err = c.Login(ctx, credentials)
	}
	credentials = onec.Credentials{}
	if err != nil {
		checkError(&r, err)
		return r
	}
	r.LoginConfirmed = c.Stats().Authenticated
	if !r.LoginConfirmed {
		r.Status = "unconfirmed_login"
		return r
	}
	if fixture != nil {
		r.Phase = "control_epf_upload"
		p, err := c.UploadProcessing(ctx, fixture, "NativeFormProbe.epf")
		var challenge *onec.ProcessingSecurityError
		if errors.As(err, &challenge) {
			r.EPFConfirmationRequired = true
			if confirmEPF && challenge.EPFSHA256() == authCheckFixtureHash {
				r.Phase = "control_epf_confirmation"
				r.EPFConfirmationSent = true
				err = c.ConfirmProcessingSecurity(ctx, challenge)
				if err == nil {
					r.EPFConfirmationSucceeded = true
					r.Phase = "control_epf_upload_after_confirmation"
					p, err = c.UploadProcessing(ctx, fixture, "NativeFormProbe.epf")
				}
			}
		}
		if err != nil {
			checkError(&r, err)
			return r
		}
		r.Phase = "control_form_open"
		form, err := c.OpenForm(ctx, p)
		if err != nil {
			checkError(&r, err)
			return r
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			r.FormClosed = c.CloseForm(cleanup, form) == nil
			if !r.FormClosed {
				r.CleanupError = true
				r.Success = false
				if r.Status == "accepted" {
					r.Status = "form_cleanup_failed"
				}
			}
		}()
		r.Phase = "control_form_methods"
		methods, err := c.FormMethods(ctx, form)
		if err != nil {
			checkError(&r, err)
			return r
		}
		for _, method := range methods {
			r.MethodsConfirmed = r.MethodsConfirmed || method.Name == "ProtocolControl"
		}
		if !r.MethodsConfirmed {
			r.Status = "control_method_missing"
			return r
		}
		r.Phase = "control_form_call"
		v, err := c.CallNoContext(ctx, form, "ProtocolControl")
		if err != nil {
			checkError(&r, err)
			return r
		}
		r.CallConfirmed = v.Type == onec.StringType && v.Value == "PROBEFORM_CONTROL_20261019"
		if !r.CallConfirmed {
			r.Status = "control_return_mismatch"
			return r
		}
	}
	r.Phase, r.Status, r.Success = "complete", "accepted", true
	return r
}

func runAuthCheck(args []string, out, diagnostic io.Writer) (resultErr error) {
	flags, options := newCommandFlags("onec auth-check", diagnostic)
	options.auth = "legacy"
	flags.Lookup("auth").DefValue = "legacy"
	flags.Lookup("auth").Usage = "input prompt mode; leave legacy and select protocols with --methods"
	flags.Lookup("timeout").Usage = "timeout per acceptance case; cleanup has an independent deadline"
	var methodsRaw, reportPath, fixturePath string
	var extended, confirmEPF bool
	flags.StringVar(&methodsRaw, "methods", "legacy,v1,v2,v3", "distinct password methods to test with the same known credentials")
	flags.StringVar(&reportPath, "report-file", "", "new JSONL report path; required with --apply")
	flags.StringVar(&fixturePath, "control-epf", "", "optional pinned NativeFormProbe.epf; enables methods/call/form-close acceptance")
	flags.BoolVar(&extended, "extended", false, "after successful baselines: legacy refusal-to-success and two parallel successful logins")
	flags.BoolVar(&confirmEPF, "confirm-control-epf", false, "explicitly accept the pinned control EPF's opening warning once; the platform may retain this decision")
	if help, err := parseCommandFlags(flags, args); help || err != nil {
		return err
	}
	methods, err := checkMethods(methodsRaw)
	if err != nil {
		return err
	}
	if options.auth != "legacy" || options.ticketFile != "" || options.kerberosSPN != "" || options.kdc != "" ||
		options.ntlm != "" || options.ntlmUser != "" || options.ntlmDomain != "" || options.ntlmSecretStdin {
		return errors.New("auth-check accepts one infobase username/password; select protocols with --methods")
	}
	if options.worker == "" {
		return errors.New("auth-check requires an explicit --worker endpoint")
	}
	if confirmEPF && fixturePath == "" {
		return errors.New("--confirm-control-epf requires the pinned --control-epf")
	}
	cfg, err := options.config(true)
	if err != nil {
		return err
	}
	plan := options.preview("auth-check", cfg)
	plan["methods"], plan["extended"], plan["control_epf_planned"] = methods, extended, fixturePath != ""
	plan["confirm_control_epf"] = confirmEPF
	if cfg.Profile.Version == "8.3.18.1208" {
		plan["profile_compatibility_note"] = "The inspected build 18 login handler uses legacy query credentials; its first JSON 402 does not validate SecPswd v1/v2/v3 passwords."
	}
	plan["maximum_login_attempts"] = len(methods)
	if extended {
		plan["maximum_login_attempts"] = len(methods) + 4
	}
	plan["credential_count"], plan["credentials_read"] = 1, false
	if !options.apply {
		return writePreview(out, plan)
	}
	if reportPath == "" {
		return errors.New("--report-file is required with --apply")
	}
	var fixture []byte
	if fixturePath != "" {
		f, err := os.Open(fixturePath)
		if err != nil {
			return errors.New("cannot open pinned control fixture")
		}
		fixture, err = io.ReadAll(io.LimitReader(f, 1<<20))
		closeErr := f.Close()
		hash := sha256.Sum256(fixture)
		if err != nil || closeErr != nil || hex.EncodeToString(hash[:]) != authCheckFixtureHash {
			return errors.New("control fixture does not match pinned NativeFormProbe.epf")
		}
	}
	report, err := os.OpenFile(reportPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("cannot create report; select a nonexistent writable path")
	}
	defer func() { resultErr = errors.Join(resultErr, report.Close()) }()
	encoder := json.NewEncoder(report)
	plan["mode"] = "apply"
	plan["started_utc"] = time.Now().UTC().Format(time.RFC3339)
	if err := encoder.Encode(plan); err != nil {
		return errors.New("cannot write acceptance plan")
	}
	credentials, err := options.credentials(cfg, diagnostic)
	if err != nil {
		return errors.New("could not read local acceptance credentials")
	}
	defer func() { credentials = onec.Credentials{} }()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	var results []authCheckResult
	emit := func(r authCheckResult) error {
		results = append(results, r)
		fmt.Fprintf(diagnostic, "%s/%s: %s (login=%t, cleanup=%t)\n",
			r.Case, r.Method, r.Status, r.LoginConfirmed, !r.CleanupError)
		if err := encoder.Encode(r); err != nil {
			cancel()
			return errors.New("acceptance report write failed")
		}
		if err := report.Sync(); err != nil {
			cancel()
			return errors.New("acceptance report sync failed")
		}
		return nil
	}
	accepted := map[onec.AuthMethod]onec.Config{}
	stopped := false
	for _, method := range methods {
		if ctx.Err() != nil {
			stopped = true
			break
		}
		perMethod := *options
		perMethod.auth = string(method)
		methodCfg, err := perMethod.config(true)
		if err != nil {
			return err
		}
		credentials.Method = method
		r := authCheckCase(ctx, methodCfg, credentials, "baseline", false, fixture, confirmEPF)
		if err := emit(r); err != nil {
			return err
		}
		if r.LoginConfirmed && !r.CleanupError {
			accepted[method] = methodCfg
		}
		if r.CleanupError || r.Status == "policy_or_limit" {
			stopped = true
			break
		}
	}
	if extended && !stopped && ctx.Err() == nil {
		if methodCfg, ok := accepted[onec.LegacyAuth]; ok {
			credentials.Method = onec.LegacyAuth
			r := authCheckCase(ctx, methodCfg, credentials, "refusal_then_success", true, fixture, confirmEPF)
			if err := emit(r); err != nil {
				return err
			}
			stopped = r.CleanupError || r.Status == "policy_or_limit"
		}
		if !stopped && ctx.Err() == nil {
			for _, method := range methods {
				methodCfg, ok := accepted[method]
				if !ok {
					continue
				}
				credentials.Method = method
				completed := make(chan authCheckResult, 2)
				for i := 0; i < 2; i++ {
					go func(index int, credential onec.Credentials) {
						completed <- authCheckCase(ctx, methodCfg, credential, fmt.Sprintf("parallel_%d", index+1), false, nil, false)
					}(i, credentials)
				}
				var writeErr error
				for i := 0; i < 2; i++ {
					r := <-completed // Always join both workers, even after a report error.
					if writeErr == nil {
						writeErr = emit(r)
					}
				}
				if writeErr != nil {
					return writeErr
				}
				break
			}
		}
	}
	allPassed := len(results) >= len(methods) && !stopped && ctx.Err() == nil
	reuseChecked, parallelCases := false, 0
	for _, r := range results {
		allPassed = allPassed && r.Success
		reuseChecked = reuseChecked || r.Case == "refusal_then_success"
		if strings.HasPrefix(r.Case, "parallel_") {
			parallelCases++
		}
	}
	summary := map[string]any{"event": "summary", "cases": len(results), "completed": !stopped && ctx.Err() == nil,
		"all_cases_passed": allPassed, "successful_password_methods": len(accepted),
		"extended_prerequisites_available": !extended || len(accepted) > 0,
		"legacy_reuse_checked":             reuseChecked, "parallel_login_cases": parallelCases}
	if err := encoder.Encode(summary); err != nil {
		return errors.New("cannot write acceptance summary")
	}
	if !allPassed {
		return errors.New("acceptance has unresolved cases; inspect the sanitized report")
	}
	return nil
}

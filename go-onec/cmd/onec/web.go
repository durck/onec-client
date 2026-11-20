package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"onec/webprobe"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
)

type webUsageError = usageError

func webUsage(err error) error { return &webUsageError{err} }

type webEnumerator func(context.Context, webprobe.Config) (webprobe.Report, error)

func runWeb(args []string, out, diagnostic io.Writer) error {
	if len(args) > 0 && (args[0] == "login" || args[0] == "basic-check") {
		return runWebAuth(args[0], args[1:], out, diagnostic)
	}
	return runWebWith(args, out, diagnostic, webprobe.Enumerate)
}
func runWebWith(args []string, out, diagnostic io.Writer, enumerate webEnumerator) error {
	if len(args) == 0 || isHelp(args[0]) {
		printGroupHelp(out, "web", "Inventory a known publication or verify one explicit login and logout.", []helpCommand{
			{"enum", "Inspect an anonymous publication"},
			{"login", "Verify web-client login and log out"},
			{"basic-check", "Check an HTTP Basic challenge"},
			{"completion", "Print web-only shell completion"},
		})
		return nil
	}
	if args[0] == "completion" {
		return webCompletion(args[1:], out)
	}
	if args[0] != "enum" {
		return webUsage(errors.New("use onec web enum or onec web completion"))
	}
	f := flag.NewFlagSet("onec web enum", flag.ContinueOnError)
	f.SetOutput(diagnostic)
	f.Usage = func() {
		fmt.Fprintln(diagnostic, "Usage: onec web enum --url https://example.invalid/demo/ru_RU/ [options]\nAnonymous fixed profile: GET metadata plus one empty POST for authentication settings.\nNo login, redirects, cookie reuse, record queries or downloaded script execution.\nExample: onec web enum --url https://example.invalid/demo/ru_RU/ --execute --out first.json\nCompare: add --baseline first.json --out second.json --fail-on-findings")
		printFlagGroups(f, diagnostic)
	}
	var c webprobe.Config
	var apply, jsonOutput, fail bool
	var outPath, baselinePath string
	f.StringVar(&c.URL, "url", "", "known publication directory, optionally ending in /ru_RU/; origin alone is insufficient")
	f.BoolVar(&c.Assets, "assets", false, "also inspect seven known HTML/JS/localization assets as data; no crawling")
	f.BoolVar(&c.Insecure, "insecure", false, "explicitly disable TLS verification for this run and flag the result")
	f.DurationVar(&c.Timeout, "timeout", 3*time.Minute, "total timeout including DNS; positive, at most 3m")
	f.BoolVar(&apply, "apply", false, "send the previewed profile (otherwise no network or report files)")
	f.BoolVar(&jsonOutput, "json", false, "write a JSON report to stdout instead of a table")
	f.StringVar(&outPath, "out", "", "also save JSON to a new file; existing files are refused")
	f.StringVar(&baselinePath, "baseline", "", "compare a complete JSON report from the same URL/profile/assets option")
	f.BoolVar(&fail, "fail-on-findings", false, "exit 1 when any warn finding exists; default findings do not fail a complete run")
	if help, err := parseCommandFlags(f, args[1:]); help || err != nil {
		if err != nil {
			return webUsage(err)
		}
		return nil
	}
	if c.Timeout <= 0 {
		return webUsage(errors.New("timeout must be positive"))
	}
	p, err := webprobe.NewPlan(c)
	if err != nil {
		return webUsage(err)
	}
	if !apply {
		return writePreview(out, map[string]any{"mode": "preview", "operation": "web enum", "network_requests_sent": false, "plan": p, "tls_verification_disabled": c.Insecure, "baseline": baselinePath, "out": outPath, "limits": map[string]any{"request_timeout": "15s", "interval": "250ms", "total_bytes": 32 << 20, "body_bytes_default": 1 << 20, "body_bytes_with_assets": 8 << 20}, "note": "sysver is added from the entry page when recognized; no redirects followed"})
	}
	var baseline webprobe.Report
	if baselinePath != "" {
		if baseline, err = readWebBaseline(baselinePath); err != nil {
			return err
		}
		if err = webprobe.CompatibleBaseline(p, baseline); err != nil {
			return webUsage(err)
		}
	}
	var file *os.File
	if outPath != "" {
		file, err = os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		defer file.Close()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	report, operationErr := enumerate(ctx, c)
	if baselinePath != "" && report.Complete {
		operationErr = errors.Join(operationErr, webprobe.Compare(&report, baseline))
	}
	if file != nil {
		operationErr = errors.Join(operationErr, json.NewEncoder(file).Encode(report), file.Sync())
	}
	if jsonOutput || wantsJSON(out) {
		operationErr = errors.Join(operationErr, json.NewEncoder(out).Encode(report))
	} else {
		operationErr = errors.Join(operationErr, writeWebReport(out, report))
	}
	if fail {
		for _, f := range report.Findings {
			if f.Severity == "warn" {
				operationErr = errors.Join(operationErr, errors.New("warning findings present; inspect the report"))
				break
			}
		}
	}
	return operationErr
}

func readWebBaseline(path string) (webprobe.Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return webprobe.Report{}, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, (4<<20)+1))
	if err != nil {
		return webprobe.Report{}, err
	}
	if len(b) > 4<<20 {
		return webprobe.Report{}, errors.New("baseline exceeds 4 MiB")
	}
	var r webprobe.Report
	if err = json.Unmarshal(b, &r); err != nil {
		return r, errors.New("baseline is not a JSON web enumeration report")
	}
	return r, nil
}

func writeWebReport(out io.Writer, r webprobe.Report) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Publication: %q\nResolved IP: %q; complete: %v; bytes: %d\n", r.Plan.Publication, r.ResolvedIP, r.Complete, r.TotalBytes)
	if r.TLS != nil {
		fmt.Fprintf(&b, "TLS: %s; verified: %v; certificate subject: %q\n", r.TLS.Version, r.TLS.Verified, r.TLS.Subject)
	}
	w := tabwriter.NewWriter(&b, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ENDPOINT\tHTTP\tKIND\tBYTES\tAUTH")
	for _, x := range r.Results {
		fmt.Fprintf(w, "%s\t%d\t%s\t%d\t%s\n", x.Request.ID, x.Status, x.Kind, x.Bytes, strings.Join(x.AuthSchemes, ","))
	}
	w.Flush()
	for _, x := range r.Results {
		if x.Request.ID == "entry" {
			fmt.Fprintf(&b, "HTTP server: %q; X-Powered-By: %q\n", x.Server, x.PoweredBy)
		}
		if x.BasicRealm != "" {
			fmt.Fprintf(&b, "%s: Basic realm=%q\n", x.Request.ID, x.BasicRealm)
		}
		if len(x.Summary) > 0 {
			data, _ := json.Marshal(x.Summary)
			fmt.Fprintf(&b, "%s: %s\n", x.Request.ID, data)
		}
		if x.Error != "" {
			fmt.Fprintf(&b, "ERROR [%s]: %q\n", x.Request.ID, x.Error)
		}
	}
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "%s %s [%s]: %s\n", strings.ToUpper(f.Severity), f.Code, f.Endpoint, f.Message)
	}
	fmt.Fprintln(&b, "Findings are observations, not vulnerability verdicts. HTTP 401/403 does not establish whether a service exists.")
	_, err := io.WriteString(out, b.String())
	return err
}

func webCompletion(args []string, out io.Writer) error {
	if len(args) != 1 {
		return webUsage(errors.New("use onec web completion bash, zsh, fish or powershell"))
	}
	flags := "--url --assets --insecure --timeout --execute --apply --json --out --baseline --fail-on-findings --user --auth --password-stdin --resource --allow-http --help"
	var script string
	switch args[0] {
	case "bash":
		script = "_onec_web_complete() { if [[ ${COMP_WORDS[1]} == web ]]; then COMPREPLY=( $(compgen -W 'enum login basic-check completion " + flags + "' -- \"${COMP_WORDS[COMP_CWORD]}\") ); else COMPREPLY=( $(compgen -W 'web' -- \"${COMP_WORDS[COMP_CWORD]}\") ); fi; }; complete -F _onec_web_complete onec\n"
	case "zsh":
		script = "#compdef onec\n_onec_web_complete() { if [[ $words[2] == web ]]; then compadd -- enum login basic-check completion " + flags + "; else compadd -- web; fi; }; compdef _onec_web_complete onec\n"
	case "fish":
		script = "complete -c onec -f -a web\ncomplete -c onec -f -n '__fish_seen_subcommand_from web' -a 'enum login basic-check completion " + flags + "'\n"
	case "powershell":
		script = "Register-ArgumentCompleter -Native -CommandName onec,onec.exe -ScriptBlock { param($wordToComplete, $commandAst, $cursorPosition) ('web enum login basic-check completion " + flags + "').Split(' ') | Where-Object { $_.StartsWith($wordToComplete) } }\n"
	default:
		return webUsage(errors.New("supported completion shells: bash, zsh, fish, powershell"))
	}
	_, err := io.WriteString(out, script)
	return err
}

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/term"
)

type wizardAction struct {
	title                         string
	command                       []string
	connection, login, processing bool
}

var wizardActions = []wizardAction{
	{"Audit empty credentials", []string{"checklist"}, false, false, false},
	{"Verify an infobase login", []string{"login"}, true, true, false},
	{"List prelogin users", []string{"users"}, true, false, false},
	{"List infobases", []string{"infobases"}, false, false, false},
	{"Check one port", []string{"ports", "check"}, false, false, false},
	{"Discover 1C ports", []string{"ports", "scan"}, false, false, false},
	{"List EPF server methods", []string{"epf", "methods"}, true, true, true},
	{"Call an EPF server function", []string{"epf", "run"}, true, true, true},
	{"List clusters", []string{"admin", "clusters"}, false, false, false},
	{"Inspect a web publication", []string{"web", "enum"}, false, false, false},
}

var errWizardCancel = errors.New("wizard cancelled")

func runWizard(args []string, out, diagnostic io.Writer) error {
	if len(args) == 1 && isHelp(args[0]) {
		fmt.Fprintln(out, "Usage: onec wizard\nGuided command setup. Shows the exact command and an offline plan before execution.\nRequires terminal input; q cancels any step. Passwords use the existing hidden prompt.\nPresentation options go before wizard: onec --color never wizard.")
		return nil
	}
	if len(args) != 0 {
		return cliUsage(errors.New("wizard takes no arguments; use onec wizard --help"))
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return cliUsage(errors.New("wizard requires an interactive terminal; use onec --help for scriptable commands"))
	}
	return wizardWith(os.Stdin, out, diagnostic, run)
}

type wizardPrompt struct {
	input  io.Reader
	output io.Writer
}

// Read one byte at a time so no type-ahead password is buffered before the
// existing hidden terminal prompt takes ownership of stdin.
func (p wizardPrompt) line(label, fallback string, required bool) (string, error) {
	for {
		fmt.Fprint(p.output, "  "+label)
		if fallback != "" {
			fmt.Fprint(p.output, " ["+terminalText(fallback)+"]")
		}
		fmt.Fprint(p.output, ": ")
		var b strings.Builder
		var one [1]byte
		for {
			n, err := p.input.Read(one[:])
			if n == 1 {
				if one[0] == '\n' {
					break
				}
				b.WriteByte(one[0])
				if b.Len() > 4096 {
					return "", cliUsage(errors.New("wizard input exceeds 4096 bytes"))
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					return "", errWizardCancel
				}
				return "", err
			}
		}
		value := strings.TrimSuffix(b.String(), "\r")
		if strings.EqualFold(strings.TrimSpace(value), "q") {
			return "", errWizardCancel
		}
		if !utf8.ValidString(value) || strings.ContainsFunc(value, func(r rune) bool {
			return unicode.IsControl(r) || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069
		}) {
			fmt.Fprintln(p.output, "  Enter plain text without control characters.")
			continue
		}
		if value == "" {
			value = fallback
		}
		if required && strings.TrimSpace(value) == "" {
			fmt.Fprintln(p.output, "  This field is required.")
			continue
		}
		return value, nil
	}
}

func (p wizardPrompt) choice(label string, count, def int) (int, error) {
	for {
		value, err := p.line(label, strconv.Itoa(def), true)
		if err != nil {
			return 0, err
		}
		number, err := strconv.Atoi(value)
		if err == nil && number >= 0 && number <= count {
			return number, nil
		}
		fmt.Fprintf(p.output, "  Choose a number from 0 to %d.\n", count)
	}
}

func wizardWith(input io.Reader, out, diagnostic io.Writer, invoke func([]string, io.Writer, io.Writer) error) (resultErr error) {
	defer func() {
		if errors.Is(resultErr, errWizardCancel) {
			fmt.Fprintln(diagnostic, "\n  Wizard closed. No new operation was started.")
			resultErr = nil
		}
	}()
	p := wizardPrompt{input, diagnostic}
	for {
		fmt.Fprintln(diagnostic, "\n"+terminalAccent(diagnostic, "1;96", "  onec / Command wizard"))
		fmt.Fprintln(diagnostic, "  q cancels any step. Passwords are excluded from the reusable command.\n\n  1 / Choose a task")
		for i, action := range wizardActions {
			fmt.Fprintf(diagnostic, "  %d  %s\n", i+1, action.title)
		}
		fmt.Fprintln(diagnostic, "  0  Exit")
		selected, err := p.choice("Choice", len(wizardActions), 0)
		if err != nil {
			return err
		}
		if selected == 0 {
			return nil
		}
		action := wizardActions[selected-1]
		fmt.Fprintln(diagnostic, "\n  2 / Configure")
		args, err := wizardArguments(p, action)
		if err != nil {
			return err
		}
		fmt.Fprintln(diagnostic, "\n  3 / Review\n\n  Reusable command:")
		fmt.Fprintln(diagnostic, "  "+wizardCommand(append(append([]string(nil), args...), "--execute"), runtime.GOOS))
		fmt.Fprintln(diagnostic, "\n  Offline preview:")
		if err = invoke(args, out, diagnostic); err != nil {
			printCommandError(diagnostic, err)
			fmt.Fprintln(diagnostic, "  Select the task again to correct its parameters.")
			continue
		}
		fmt.Fprintln(diagnostic, "\n  1  Execute once\n  2  Configure another command\n  0  Finish without execution")
		choice, err := p.choice("Next", 2, 0)
		if err != nil {
			return err
		}
		if choice == 0 {
			return nil
		}
		if choice == 2 {
			continue
		}
		fmt.Fprintln(diagnostic, "\n  Running...")
		return invoke(append(args, "--execute"), out, diagnostic)
	}
}

func wizardArguments(p wizardPrompt, action wizardAction) ([]string, error) {
	args := append([]string(nil), action.command...)
	ask := func(flag, label, fallback string, required bool) error {
		value, err := p.line(label, fallback, required)
		if err == nil && value != "" {
			args = append(args, flag, value)
		}
		return err
	}
	if action.connection {
		fmt.Fprintln(p.output, "  Connection: 1 - working process, 2 - cluster manager")
		route, err := p.choice("Route", 2, 1)
		if err != nil {
			return nil, err
		}
		if route == 0 {
			return nil, errWizardCancel
		}
		if route == 1 {
			err = ask("--worker", "Worker endpoint", "127.0.0.1:1560", true)
		} else {
			err = ask("--manager", "Manager endpoint", "127.0.0.1:1541", true)
		}
		if err != nil {
			return nil, err
		}
		if err = ask("--database", "Infobase name", "", true); err != nil {
			return nil, err
		}
	}
	if action.login {
		defaultMethod := 1
		if runtime.GOOS == "windows" {
			fmt.Fprintln(p.output, "  Login: 1 - current Windows identity, 2 - infobase username/password")
		} else {
			defaultMethod = 2
			fmt.Fprintln(p.output, "  Login: 2 - infobase username/password (current Windows identity is unavailable)")
		}
		auth, err := p.choice("Login method", 2, defaultMethod)
		if err != nil {
			return nil, err
		}
		if auth == 0 {
			return nil, errWizardCancel
		}
		if auth == 1 && runtime.GOOS != "windows" {
			return nil, cliUsage(errors.New("current Windows identity is unavailable; choose infobase password login"))
		}
		if auth == 2 {
			args = append(args, "--auth", "legacy")
			if err = ask("--user", "Infobase username", "", true); err != nil {
				return nil, err
			}
		} else {
			args = append(args, "--auth", "windows")
		}
	}
	if action.processing {
		if err := ask("--file", "EPF path (without surrounding quotes)", "", true); err != nil {
			return nil, err
		}
		if err := ask("--form", "Form name (Enter for default)", "", false); err != nil {
			return nil, err
		}
		if action.command[1] == "run" {
			if err := ask("--method", "Exported server function without context", "", true); err != nil {
				return nil, err
			}
			if err := ask("--args-json", "Arguments as a JSON array", "[]", true); err != nil {
				return nil, err
			}
		}
		fmt.Fprintln(p.output, "  Opening an EPF can run its server handlers. Platform trust prompts are not approved automatically.")
	}
	switch strings.Join(action.command, " ") {
	case "checklist":
		fmt.Fprintln(p.output, "  Targets: 1 - one IP/domain, 2 - UTF-8 host list")
		source, err := p.choice("Target source", 2, 1)
		if err != nil {
			return nil, err
		}
		if source == 0 {
			return nil, errWizardCancel
		}
		if source == 1 {
			err = ask("--target", "Target IP or domain", "", true)
		} else {
			err = ask("--targets-file", "Target file path", "", true)
		}
		if err != nil {
			return nil, err
		}
		if err = ask("--report-file", "New report path (Enter for timestamped name)", "", false); err != nil {
			return nil, err
		}
		fmt.Fprintln(p.output, "  Coverage is limited to discovered objects. Login checks can affect lockout counters.")
	case "infobases":
		if err := ask("--worker", "Worker endpoint", "127.0.0.1:1560", true); err != nil {
			return nil, err
		}
	case "ports check":
		if err := ask("--host", "Server host", "127.0.0.1", true); err != nil {
			return nil, err
		}
		if err := ask("--port", "Port", "1560", true); err != nil {
			return nil, err
		}
	case "ports scan":
		if err := ask("--host", "Server host", "127.0.0.1", true); err != nil {
			return nil, err
		}
		if err := ask("--ports", "Ports or range", "1540-1591", true); err != nil {
			return nil, err
		}
	case "admin clusters":
		if err := ask("--agent", "Server-agent endpoint", "127.0.0.1:1540", true); err != nil {
			return nil, err
		}
	case "web enum":
		if err := ask("--url", "Publication directory URL", "", true); err != nil {
			return nil, err
		}
	}
	if action.command[0] != "web" {
		value, err := p.line("SOCKS5 proxy URL (Enter for direct)", "", false)
		if err != nil {
			return nil, err
		}
		if value != "" {
			// Validate before printing a reusable command: credentials are forbidden in URLs.
			if _, err = (proxyOptions{address: value}).dialer(); err != nil {
				return nil, cliUsage(err)
			}
			args = append(args, "--proxy", value)
			if err = ask("--proxy-auth-env", "Proxy credential environment variable (optional)", "", false); err != nil {
				return nil, err
			}
		}
	}
	return args, nil
}

func wizardCommand(args []string, platform string) string {
	words := []string{"onec"}
	for _, arg := range args {
		if arg != "" && !strings.ContainsFunc(arg, func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("-_=.,:/\\", r)
		}) {
			words = append(words, arg)
			continue
		}
		if platform == "windows" {
			words = append(words, "'"+strings.ReplaceAll(arg, "'", "''")+"'")
		} else {
			words = append(words, "'"+strings.ReplaceAll(arg, "'", `'\''`)+"'")
		}
	}
	return strings.Join(words, " ")
}

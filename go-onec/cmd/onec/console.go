package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/term"
)

type consoleWriter struct {
	io.Writer
	mode, color       string
	verbose, terminal bool
	width             int
}

func (w *consoleWriter) human() bool { return w.mode == "text" || w.mode == "auto" && w.terminal }

type usageError struct{ err error }

func (e *usageError) Error() string { return e.err.Error() }
func (e *usageError) Unwrap() error { return e.err }
func cliUsage(err error) error {
	if err == nil {
		return nil
	}
	return &usageError{err}
}

func commandExitCode(err error) int {
	if err == nil {
		return 0
	}
	var usage *usageError
	if errors.As(err, &usage) {
		return 2
	}
	return 1
}

// Global presentation switches precede the command. Never scan arbitrary argv:
// a method argument or filename may itself be named --output or --color.
func consoleArgs(args []string) ([]string, consoleWriter, error) {
	options := consoleWriter{mode: "auto", color: "auto", width: 80}
	for len(args) > 0 && strings.HasPrefix(args[0], "-") && !isHelp(args[0]) {
		name, value, hasValue := strings.Cut(args[0], "=")
		args = args[1:]
		if name == "--verbose" {
			options.verbose = true
			if hasValue {
				var err error
				options.verbose, err = strconv.ParseBool(value)
				if err != nil {
					return nil, options, cliUsage(errors.New("--verbose expects true or false"))
				}
			}
			continue
		}
		if name != "--output" && name != "--color" {
			return nil, options, cliUsage(errors.New("unknown global option; use onec --help"))
		}
		if !hasValue {
			if len(args) == 0 {
				return nil, options, cliUsage(fmt.Errorf("%s requires a value", name))
			}
			value, args = args[0], args[1:]
		}
		switch name {
		case "--output":
			if value != "auto" && value != "text" && value != "json" {
				return nil, options, cliUsage(errors.New("--output must be auto, text or json"))
			}
			options.mode = value
		case "--color":
			if value != "auto" && value != "always" && value != "never" {
				return nil, options, cliUsage(errors.New("--color must be auto, always or never"))
			}
			options.color = value
		}
	}
	return args, options, nil
}

func consoleStream(out io.Writer, options consoleWriter) *consoleWriter {
	options.Writer = out
	if file, ok := out.(*os.File); ok {
		options.terminal = term.IsTerminal(int(file.Fd()))
		if width, _, err := term.GetSize(int(file.Fd())); err == nil && width >= 40 {
			options.width = width
		}
	}
	return &options
}

func wantsJSON(out io.Writer) bool     { w, ok := out.(*consoleWriter); return ok && w.mode == "json" }
func verboseOutput(out io.Writer) bool { w, ok := out.(*consoleWriter); return !ok || w.verbose }

func terminalAccent(out io.Writer, code, text string) string {
	enabled := false
	if w, ok := out.(*consoleWriter); ok {
		enabled = w.color == "always" || w.color == "auto" && w.terminal
		if w.color == "auto" {
			_, noColor := os.LookupEnv("NO_COLOR")
			enabled = enabled && !noColor && os.Getenv("TERM") != "dumb"
		}
	} else if file, ok := out.(*os.File); ok {
		_, noColor := os.LookupEnv("NO_COLOR")
		enabled = term.IsTerminal(int(file.Fd())) && !noColor && os.Getenv("TERM") != "dumb"
	}
	if !enabled {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

// Application strings must never become terminal control sequences or forged lines.
func terminalText(text string) string {
	var b strings.Builder
	for _, r := range text {
		switch r {
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if unicode.IsControl(r) || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

func printCommandError(out io.Writer, err error) {
	fmt.Fprintln(out, "\n"+terminalAccent(out, "91", "ERROR")+"  "+terminalText(err.Error()))
	if commandExitCode(err) == 2 {
		fmt.Fprintln(out, "  Use onec help <command> for options, or onec wizard for guided setup.")
	}
}

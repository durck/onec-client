// Command onec exercises the observed native 1C protocol subset.
package main

import (
	"context"
	"fmt"
	"io"
	"onec"
	"os"
	"strings"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, options, _ := consoleArgs(os.Args[1:])
		printCommandError(consoleStream(os.Stderr, options), err)
		os.Exit(commandExitCode(err))
	}
}

func run(args []string, out, diagnostic io.Writer) error {
	if _, wrapped := out.(*consoleWriter); wrapped {
		return runCommand(args, out, diagnostic)
	}
	args, options, err := consoleArgs(args)
	if err != nil {
		return err
	}
	return runCommand(args, consoleStream(out, options), consoleStream(diagnostic, options))
}

func runCommand(args []string, out, diagnostic io.Writer) error {
	if len(args) > 1 && args[0] == "help" {
		for _, topic := range args[1:] {
			if strings.HasPrefix(topic, "-") {
				return cliUsage(fmt.Errorf("help accepts command names only; use onec help login"))
			}
		}
		topic := append([]string(nil), args[1:]...)
		return run(append(topic, "--help"), out, diagnostic)
	}
	if len(args) == 0 || isHelp(args[0]) {
		printRootHelp(out)
		return nil
	}
	switch args[0] {
	case "wizard":
		return runWizard(args[1:], out, diagnostic)
	case "completion":
		return runCompletion(args[1:], out)
	case "__complete":
		return runCompletionQuery(args[1:], out)
	case "web":
		return runWeb(args[1:], out, diagnostic)
	case "ports":
		return runPorts(args[1:], out, diagnostic)
	case "infobases":
		return runInfobases(args[1:], out, diagnostic)
	case "admin":
		return runAdmin(args[1:], out, diagnostic)
	case "auth-check":
		return runAuthCheck(args[1:], out, diagnostic)
	case "checklist":
		return runChecklist(args[1:], out, diagnostic)
	case "login-batch":
		return runLoginBatch(args[1:], out, diagnostic)
	case "inspect":
		return runInspect(args[1:], out, diagnostic)
	case "epf":
		return runEPF(args[1:], out, diagnostic)
	case "methods", "run":
		return cliUsage(fmt.Errorf("%s moved; use onec epf %s", args[0], args[0]))
	case "users", "settings", "login":
		return runRootCommand(args[0], args[1:], out, diagnostic)
	default:
		return cliUsage(fmt.Errorf("unknown command; use onec --help"))
	}
}

func isHelp(arg string) bool {
	return arg == "help" || arg == "--help" || arg == "-h"
}

func runRootCommand(command string, args []string, out, diagnostic io.Writer) error {
	flags, options := newCommandFlags("onec "+command, diagnostic)
	if help, err := parseCommandFlags(flags, args); help || err != nil {
		return err
	}
	cfg, err := options.config(command == "login")
	if err != nil {
		return err
	}
	if !options.apply {
		return writePreview(out, options.preview(command, cfg))
	}
	cleanup, err := options.prepareSecurity(&cfg, diagnostic)
	if err != nil {
		return err
	}
	defer cleanup()
	var credentials onec.Credentials
	if command == "login" {
		credentials, err = options.credentials(cfg, diagnostic)
		if err != nil {
			return err
		}
	}
	return executeCommand(cfg, command, nil, out, func(ctx context.Context, client *onec.Client) (any, error) {
		switch command {
		case "users":
			return client.Users(ctx)
		case "settings":
			body, err := client.AuthenticationSettings(ctx)
			return map[string]any{"decoded_bytes": len(body)}, err
		default:
			err := client.Login(ctx, credentials)
			credentials = onec.Credentials{}
			return nil, err
		}
	})
}

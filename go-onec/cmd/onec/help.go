package main

import (
	"flag"
	"fmt"
	"io"
	"strings"
)

// Both spellings share the original flag.Value, including boolean semantics.
// Keep the wire configuration and machine-readable reports unchanged.
var readableFlags = []struct{ original, preferred string }{
	{"server", "manager"},
	{"base", "database"},
	{"epf", "file"},
	{"upload", "upload-mode"},
	{"interactive", "allow-edit"},
	{"duration", "session-timeout"},
	{"apply", "execute"},
}

func addReadableFlags(f *flag.FlagSet) {
	for _, alias := range readableFlags {
		if original := f.Lookup(alias.original); original != nil && f.Lookup(alias.preferred) == nil {
			f.Var(original.Value, alias.preferred, original.Usage)
			f.Lookup(alias.preferred).DefValue = original.DefValue
		}
	}
}

func validateFlagSpellings(f *flag.FlagSet) error {
	used := map[string]bool{}
	f.Visit(func(option *flag.Flag) { used[option.Name] = true })
	for _, alias := range readableFlags {
		if used[alias.original] && used[alias.preferred] {
			return fmt.Errorf("use either --%s or --%s, not both", alias.preferred, alias.original)
		}
	}
	return nil
}

func printFlagGroups(f *flag.FlagSet, out io.Writer) {
	if capture, ok := out.(interface{ captureFlags(*flag.FlagSet) }); ok {
		capture.captureFlags(f)
		return
	}
	groups := []struct{ title, names string }{
		{"Processing", "epf form upload interactive param method arg args-json expect confirm-open"},
		{"Connection", "server worker base url agent host target targets-file agent-port manager-port worker-ports ports port resource proxy proxy-auth-env"},
		{"Authentication", "auth transport user password-stdin agent-auth agent-user agent-password-env cluster-auth cluster-user cluster-password-env"},
		{"Windows credentials", "ticket-file kerberos-spn kdc ntlm ntlm-domain ntlm-user ntlm-secret-stdin"},
		{"Target and changes", "cluster session setting value message"},
		{"Input", "input elements mode users-file passwords-file methods control-epf"},
		{"Session", "duration language timeout total-timeout"},
		{"Execution", "apply concurrency workers interval max-attempts connection-mode extended confirm-control-epf"},
		{"Output", "json format out report-file baseline fail-on-findings"},
		{"Advanced", "transport-policy client-version application server-name roles local-process assets insecure allow-http max-input-bytes max-record-bytes max-atoms max-events"},
	}
	seen := map[string]bool{}
	for _, alias := range readableFlags {
		seen[alias.preferred] = true
	}
	printOption := func(option *flag.Flag) {
		name, legacy := option.Name, ""
		for _, alias := range readableFlags {
			if name == alias.original {
				name, legacy = alias.preferred, "alias: --"+alias.original
				break
			}
		}
		kind, usage := flag.UnquoteUsage(option)
		if value := map[string]string{"server": "HOST:PORT", "worker": "HOST:PORT", "agent": "HOST:PORT", "base": "NAME", "epf": "PATH", "form": "NAME", "auth": "MODE", "upload": "MODE", "param": "NAME=VALUE", "method": "NAME", "user": "NAME", "ntlm": "password|hash", "target": "HOST", "host": "HOST", "targets-file": "PATH", "report-file": "PATH", "proxy": "URL", "proxy-auth-env": "NAME", "worker-ports": "RANGES", "agent-port": "PORT", "manager-port": "PORT", "transport": "MODE"}[option.Name]; value != "" {
			kind = value
		}
		label := "--" + name
		if kind != "" {
			label += " " + strings.ToUpper(kind)
		}
		fmt.Fprintln(out, "  "+terminalAccent(out, "96", label))
		printHelpText(out, usage, "      ")
		var details []string
		if option.DefValue != "" && option.DefValue != "false" && option.DefValue != "0" {
			details = append(details, "default: "+option.DefValue)
		}
		if legacy != "" {
			details = append(details, legacy)
		}
		if len(details) > 0 {
			fmt.Fprintln(out, "      "+terminalAccent(out, "90", strings.Join(details, " · ")))
		}
	}
	for _, group := range groups {
		if !verboseOutput(out) && (group.title == "Windows credentials" || group.title == "Advanced") {
			for _, name := range strings.Fields(group.names) {
				seen[name] = true
			}
			continue
		}
		if f.Name() == "onec epf ui" {
			if group.title == "Connection" {
				group.names = strings.ReplaceAll(group.names, " port ", " ")
			} else if group.title == "Session" {
				group.names += " port"
			}
		}
		started := false
		for _, name := range strings.Fields(group.names) {
			if option := f.Lookup(name); option != nil {
				if !started {
					fmt.Fprintln(out, "\n"+terminalAccent(out, "1", group.title))
					started = true
				}
				seen[name] = true
				printOption(option)
			}
		}
	}
	started := false
	f.VisitAll(func(option *flag.Flag) {
		if !seen[option.Name] {
			if !started {
				fmt.Fprintln(out, "\n"+terminalAccent(out, "1", "Other options"))
				started = true
			}
			printOption(option)
		}
	})
	fmt.Fprintln(out, "\n  -h, --help\n      Show this command's options.")
	if !verboseOutput(out) {
		fmt.Fprintf(out, "\nAll options: onec --verbose help %s\n", strings.TrimPrefix(f.Name(), "onec "))
	}
	if f.Lookup("apply") != nil {
		fmt.Fprintln(out, terminalAccent(out, "93", "Preview by default. Add --execute (alias: --apply) to perform the operation."))
	}
	if example := commandExample(f.Name()); example != "" {
		title := "Example"
		if f.Lookup("apply") != nil {
			title += " / preview"
		}
		fmt.Fprintln(out, "\n"+terminalAccent(out, "1", title))
		fmt.Fprintln(out, "  "+example)
	}
}

func printHelpText(out io.Writer, text, indent string) {
	line := indent
	for _, word := range strings.Fields(text) {
		if len(line)+len(word)+1 > 86 && line != indent {
			fmt.Fprintln(out, line)
			line = indent
		}
		if line != indent {
			line += " "
		}
		line += word
	}
	fmt.Fprintln(out, line)
}

func commandExample(name string) string {
	switch name {
	case "onec checklist":
		return name + " --target 192.0.2.10"
	case "onec login", "onec users", "onec settings":
		return name + " --worker 127.0.0.1:1560 --database demo"
	case "onec epf ui", "onec epf methods", "onec epf modules":
		return name + " --worker 127.0.0.1:1560 --database demo --file sample.epf"
	case "onec epf run":
		return name + " --worker 127.0.0.1:1560 --database demo --file sample.epf --method Echo --arg hello"
	case "onec ports scan":
		return name + " --host 127.0.0.1 --ports 1540-1591"
	case "onec ports check":
		return name + " --host 127.0.0.1 --port 1560"
	case "onec admin clusters", "onec admin agent-admins":
		return name + " --agent 127.0.0.1:1540"
	case "onec admin cluster-admins", "onec admin servers", "onec admin processes", "onec admin bases", "onec admin sessions":
		return name + " --agent 127.0.0.1:1540 --cluster 00000000-0000-0000-0000-000000000001"
	case "onec admin terminate-session":
		return name + " --cluster 00000000-0000-0000-0000-000000000001 --session 00000000-0000-0000-0000-000000000002"
	case "onec admin set":
		return name + " --cluster 00000000-0000-0000-0000-000000000001 --setting security-level --value 0"
	case "onec infobases":
		return name + " --worker 127.0.0.1:1560"
	case "onec auth-check":
		return name + " --worker 127.0.0.1:1560 --database demo --methods legacy"
	case "onec login-batch":
		return name + " --worker 127.0.0.1:1560 --database demo --auth legacy --mode paired --users-file users.txt --passwords-file passwords.txt"
	case "onec web enum":
		return name + " --url https://example.invalid/demo/ru_RU/"
	case "onec web login":
		return name + " --url https://example.invalid/demo/ru_RU/ --user tester"
	case "onec web basic-check":
		return name + " --url https://example.invalid/demo/ --user tester"
	case "onec epf lifecycle":
		return name + " --elements docs/examples/form-lifecycle/elements.json"
	case "onec inspect":
		return name + " test-results/client-stream.bin"
	default:
		return ""
	}
}

func printRootHelp(out io.Writer) {
	fmt.Fprintln(out, terminalAccent(out, "1;96", "onec / 1C protocol client"))
	fmt.Fprintln(out, "Audit endpoints, inspect services and work with supported 1C protocols.")
	fmt.Fprintln(out, "\nUsage: onec [global-options] <command> [options]")
	for _, group := range []struct{ title, commands string }{
		{"Audit and discovery", "  checklist      Empty-credential checks across hosts, clusters and databases\n  ports          Discover ports or check one endpoint\n  infobases      List databases on a working process\n  users          Read the prelogin user selection list\n  settings       Read infobase authentication settings"},
		{"Authentication and administration", "  login          Verify one native login and log out\n  auth-check     Compare login methods for a known test account\n  login-batch    Check supplied credentials with bounded workers\n  admin          Cluster inventory and explicit management operations\n  web            Web publication inventory and authentication"},
		{"Processing and offline tools", "  epf            Server methods, module images and form workbench\n  inspect        Inspect a saved TCP stream offline"},
		{"Getting started", "  wizard         Task -> parameters -> preview -> execute\n  help <command> Command help and examples\n  completion     Shell integration: PowerShell, Bash, Zsh, Fish"},
	} {
		fmt.Fprintln(out, "\n"+terminalAccent(out, "1", group.title))
		fmt.Fprintln(out, group.commands)
	}
	fmt.Fprintln(out, "\n"+terminalAccent(out, "93", "Network commands preview by default. Add --execute to run them."))
	fmt.Fprintln(out, "Checklist coverage: discovered objects only; a refusal does not prove a nonempty password.")
	fmt.Fprintln(out, "\n"+terminalAccent(out, "1", "Global options / before the command"))
	fmt.Fprintln(out, "  --output auto|text|json    Readable terminal output; JSON for scripts\n  --color auto|always|never  Color policy; auto respects NO_COLOR\n  --verbose                 All help options and report details\n  -h, --help                Show this help")
	fmt.Fprintln(out, "\n"+terminalAccent(out, "1", "Examples"))
	fmt.Fprintln(out, "  onec checklist --target audit-host.example\n  onec checklist --targets-file targets.txt --execute --report-file audit.json\n  onec checklist --target audit-host.example --proxy socks5://127.0.0.1:1080\n  onec --verbose help checklist\n  onec wizard\n\nUse onec <command> --help for options. --apply remains an alias for --execute.")
}

type helpCommand struct{ name, description string }

func printGroupHelp(out io.Writer, group, description string, commands []helpCommand) {
	fmt.Fprintf(out, "Usage: onec %s <command> [options]\n", group)
	printHelpText(out, description, "")
	fmt.Fprintln(out, "\n"+terminalAccent(out, "1", "Commands"))
	for _, command := range commands {
		fmt.Fprintf(out, "  %-20s %s\n", command.name, command.description)
	}
	fmt.Fprintf(out, "\nHelp: onec help %s <command>\nAll options: onec --verbose help %s <command>\n", group, group)
	fmt.Fprintln(out, "Network commands preview by default. Add --execute to run them.")
}

func commandDescription(name string) string {
	switch name {
	case "onec login":
		return "Verify one infobase login and confirm logout and resource cleanup."
	case "onec users":
		return "Read the prelogin user selection list. Hidden users may be absent; this is not a complete account inventory."
	case "onec settings":
		return "Read supported infobase authentication settings without application login."
	case "onec auth-check":
		return "Compare explicit password methods for one known test account, recording login and cleanup separately."
	case "onec login-batch":
		return "Check supplied credentials with bounded workers, dispatch pacing and explicit result reporting."
	case "onec epf methods":
		return "Open an EPF form and discover server method metadata. Opening may run server handlers."
	case "onec epf modules":
		return "Retrieve compiled client images from an EPF without executing client code. Opening may run server handlers."
	case "onec epf run":
		return "Open an EPF and call one supported server function without context."
	case "onec epf ui":
		return "Open a local browser workbench for the supported EPF form subset."
	}
	return ""
}

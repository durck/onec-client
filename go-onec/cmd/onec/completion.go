package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
)

var commandTree = map[string][]string{
	"":           {"wizard", "login", "users", "settings", "infobases", "ports", "epf", "admin", "web", "inspect", "auth-check", "checklist", "login-batch", "completion", "help"},
	"epf":        {"methods", "modules", "run", "ui", "lifecycle"},
	"ports":      {"scan", "check"},
	"admin":      {"clusters", "agent-admins", "cluster-admins", "servers", "processes", "bases", "sessions", "terminate-session", "set"},
	"web":        {"enum", "login", "basic-check", "completion"},
	"completion": {"powershell", "bash", "zsh", "fish"},
}

type flagCapture struct{ set *flag.FlagSet }

func (*flagCapture) Write(p []byte) (int, error)    { return len(p), nil }
func (c *flagCapture) captureFlags(f *flag.FlagSet) { c.set = f }

// Ask the ordinary, offline help path for its actual flag set. Completions do
// not maintain a second option catalog and never initialize providers or dial.
func completionFlagSet(command []string) *flag.FlagSet {
	capture := &flagCapture{}
	args := append(append([]string(nil), command...), "--help")
	if runCommand(args, io.Discard, capture) != nil {
		return nil
	}
	return capture.set
}

func completionCandidates(words []string, current string) []string {
	values := map[string][]string{
		"output": {"auto", "text", "json"}, "color": {"auto", "always", "never"}, "auth": {"windows", "legacy", "v1", "v2", "v3"},
		"transport": {"windows", "anonymous"}, "upload": {"open-document", "extmd"}, "upload-mode": {"open-document", "extmd"},
		"ntlm": {"password", "hash"}, "agent-auth": {"none", "default", "password"}, "cluster-auth": {"none", "default", "password"},
		"transport-policy": {"plain", "native27-n", "native27-c"},
	}
	filter := func(options []string, prefix string) []string {
		var found []string
		for _, option := range options {
			if strings.HasPrefix(option, prefix) {
				found = append(found, option)
			}
		}
		sort.Strings(found)
		return found
	}
	for len(words) > 0 && strings.HasPrefix(words[0], "-") {
		name, _, equal := strings.Cut(words[0], "=")
		words = words[1:]
		if (name == "--output" || name == "--color") && !equal {
			if len(words) == 0 {
				return filter(values[strings.TrimPrefix(name, "--")], current)
			}
			words = words[1:]
		}
	}
	if len(words) == 0 {
		if name, prefix, equal := strings.Cut(current, "="); equal && (name == "--output" || name == "--color") {
			found := filter(values[strings.TrimPrefix(name, "--")], prefix)
			for i := range found {
				found[i] = name + "=" + found[i]
			}
			return found
		}
		return filter(append(append([]string(nil), commandTree[""]...), "--help", "--output", "--color", "--verbose"), current)
	}
	if words[0] == "help" {
		if len(words) == 1 {
			return filter(commandTree[""], current)
		}
		return filter(commandTree[strings.Join(words[1:], " ")], current)
	}
	command := []string{words[0]}
	words = words[1:]
	if group, ok := commandTree[command[0]]; ok {
		if len(words) == 0 {
			return filter(group, current)
		}
		command = append(command, words[0])
		words = words[1:]
	}
	f := completionFlagSet(command)
	if f == nil {
		return nil
	}
	if len(command) > 1 && command[0] == "web" {
		values["auth"] = []string{"auto", "legacy", "v1", "v3"}
	}
	if option := f.Lookup("transport"); option != nil && option.DefValue == "auto" {
		values["transport"] = []string{"auto", "windows", "anonymous"}
	}
	if command[0] == "checklist" {
		values["auth"] = []string{"legacy", "v1", "v2", "v3"}
	}
	for i := 0; i < len(words); i++ {
		name, _, equal := strings.Cut(strings.TrimLeft(words[i], "-"), "=")
		option := f.Lookup(name)
		if option == nil || equal {
			continue
		}
		boolean, ok := option.Value.(interface{ IsBoolFlag() bool })
		if ok && boolean.IsBoolFlag() {
			continue
		}
		if i == len(words)-1 {
			return filter(values[name], current)
		}
		i++
	}
	if name, prefix, equal := strings.Cut(current, "="); equal && strings.HasPrefix(name, "--") {
		if f.Lookup(strings.TrimPrefix(name, "--")) == nil {
			return nil
		}
		found := filter(values[strings.TrimPrefix(name, "--")], prefix)
		for i := range found {
			found[i] = name + "=" + found[i]
		}
		return found
	}
	options := []string{"--help"}
	f.VisitAll(func(option *flag.Flag) { options = append(options, "--"+option.Name) })
	return filter(options, current)
}

func runCompletionQuery(args []string, out io.Writer) error {
	if len(args) == 0 || len(args) > 256 || !strings.HasPrefix(args[0], "--current=") {
		return cliUsage(errors.New("invalid completion query"))
	}
	for _, arg := range args {
		if len(arg) > 4096 {
			return cliUsage(errors.New("completion word too long"))
		}
	}
	for _, candidate := range completionCandidates(args[1:], strings.TrimPrefix(args[0], "--current=")) {
		if _, err := fmt.Fprintln(out, candidate); err != nil {
			return err
		}
	}
	return nil
}

func runCompletion(args []string, out io.Writer) error {
	if len(args) == 0 || len(args) == 1 && isHelp(args[0]) {
		fmt.Fprintln(out, "Usage: onec completion <powershell|bash|zsh|fish>\nPrint an opt-in completion script for every command; no profile is modified.\nPowerShell: onec completion powershell | Out-String | Invoke-Expression\nBash/Zsh: source <(onec completion bash) # use zsh for Zsh; compinit must be loaded\nFish: onec completion fish | source")
		return nil
	}
	if len(args) != 1 {
		return cliUsage(errors.New("choose completion powershell, bash, zsh or fish"))
	}
	var script string
	switch args[0] {
	case "powershell":
		script = `Register-ArgumentCompleter -Native -CommandName onec,onec.exe -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $parts = @($commandAst.CommandElements | Select-Object -Skip 1 | Where-Object { $_.Extent.EndOffset -lt $cursorPosition -or ($wordToComplete -eq '' -and $_.Extent.EndOffset -le $cursorPosition) } | ForEach-Object {
        if ($_ -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $_.Value } else { $_.Extent.Text }
    })
    $exe = $commandAst.CommandElements[0].Value
    & $exe __complete "--current=$wordToComplete" @parts | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}
`
	case "bash":
		script = `_onec_complete() {
    local current="${COMP_WORDS[COMP_CWORD]}" candidate
    COMPREPLY=()
    while IFS= read -r candidate; do COMPREPLY+=("$candidate"); done < <("${COMP_WORDS[0]}" __complete "--current=$current" "${COMP_WORDS[@]:1:COMP_CWORD-1}")
}
complete -o default -F _onec_complete onec
`
	case "zsh":
		script = `_onec_complete() {
    local -a candidates context
    local i
    for (( i=2; i<CURRENT; i++ )); do context+=("${words[i]}"); done
    candidates=("${(@f)$("${words[1]}" __complete "--current=$PREFIX" "${context[@]}")}")
    if (( ${#candidates} )) && [[ -n "${candidates[1]}" ]]; then
        compadd -- "${candidates[@]}"
    else
        _files
    fi
}
compdef _onec_complete onec
`
	case "fish":
		script = `function __onec_complete
    set -l words (commandline -xpc)
    set -l current (commandline -ct)
    command $words[1] __complete "--current=$current" $words[2..-1]
end
complete -c onec -a '(__onec_complete)'
`
	default:
		return cliUsage(errors.New("supported completion shells: powershell, bash, zsh, fish"))
	}
	_, err := io.WriteString(out, script)
	return err
}

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestReadableFlagAliasesPreservePreview(t *testing.T) {
	old := []string{"epf", "ui", "--server", "192.0.2.1:1541", "--base", "example", "--epf", "missing.epf", "--upload", "extmd", "--interactive", "--duration", "10m"}
	modern := []string{"epf", "ui", "--manager", "192.0.2.1:1541", "--database", "example", "--file", "missing.epf", "--upload-mode", "extmd", "--allow-edit", "--session-timeout", "10m", "--execute=false"}
	var results [2]bytes.Buffer
	for i, args := range [][]string{old, modern} {
		var diagnostic bytes.Buffer
		if err := run(args, &results[i], &diagnostic); err != nil {
			t.Fatal(err)
		}
	}
	if results[0].String() != results[1].String() {
		t.Fatalf("aliases changed preview:\n%s\n%s", results[0].String(), results[1].String())
	}
	var preview map[string]any
	if err := json.Unmarshal(results[1].Bytes(), &preview); err != nil || preview["network_requests_sent"] != false {
		t.Fatal("preview must remain machine-readable and offline")
	}
}

func TestFlagAliasesRejectAmbiguousSpellings(t *testing.T) {
	for _, args := range [][]string{
		{"login", "--database", "example", "--base", "other"},
		{"login", "--execute=false", "--apply"},
		{"admin", "clusters", "--execute=false", "--apply"},
	} {
		var out, diagnostic bytes.Buffer
		if err := run(args, &out, &diagnostic); err == nil || out.Len() != 0 {
			t.Fatalf("ambiguous options accepted: %v", args)
		}
	}
}

func TestHelpTopicAndGroupedFlags(t *testing.T) {
	var out, diagnostic bytes.Buffer
	if err := run([]string{"--verbose", "help", "epf", "ui"}, &out, &diagnostic); err != nil {
		t.Fatal(err)
	}
	help := out.String() + diagnostic.String()
	last := -1
	for _, heading := range []string{"Processing", "Connection", "Authentication", "Windows credentials", "Session", "Execution"} {
		i := strings.Index(help, heading+"\n")
		if i <= last {
			t.Fatalf("missing or unordered group %q in %s", heading, help)
		}
		last = i
	}
	for _, want := range []string{"--file", "--database", "--allow-edit", "--execute", "--epf", "--interactive", "--apply", "20m0s"} {
		if !strings.Contains(help, want) {
			t.Errorf("help missing %s", want)
		}
	}
	if strings.Contains(help, "\x1b[") {
		t.Fatal("redirected help must not contain ANSI escapes")
	}
}

func TestAllHelpRemainsOffline(t *testing.T) {
	for _, command := range []string{"login", "users", "settings", "login-batch", "auth-check", "epf ui", "epf run", "epf methods", "epf modules", "epf lifecycle", "admin clusters", "admin set", "infobases", "web enum", "web login", "web basic-check", "ports scan", "ports check", "inspect"} {
		t.Run(command, func(t *testing.T) {
			var out, diagnostic bytes.Buffer
			if err := run(append(strings.Fields(command), "--help"), &out, &diagnostic); err != nil {
				t.Fatal(err)
			}
			help := out.String() + diagnostic.String()
			if !strings.Contains(help, "Usage: onec "+command) || !strings.Contains(help, "--help") {
				t.Fatalf("incomplete help: %s", help)
			}
		})
	}
}

func TestHelpRejectsOperationFlags(t *testing.T) {
	var out, diagnostic bytes.Buffer
	if err := run([]string{"help", "epf", "lifecycle", "--elements"}, &out, &diagnostic); err == nil || out.Len() != 0 {
		t.Fatal("help topic accepted operation flags")
	}
}

func TestEveryCommandHelpIsOfflineAndComplete(t *testing.T) {
	for group, commands := range commandTree {
		if group == "completion" {
			continue
		}
		for _, name := range commands {
			if name == "help" || name == "completion" {
				continue
			}
			command := strings.Fields(strings.TrimSpace(group + " " + name))
			for _, verbose := range []bool{false, true} {
				args := []string{"help"}
				if verbose {
					args = []string{"--verbose", "help"}
				}
				var out, diagnostic bytes.Buffer
				if err := run(append(args, command...), &out, &diagnostic); err != nil {
					t.Fatal(command, err)
				}
				help := out.String() + diagnostic.String()
				if !strings.Contains(help, "Usage: onec "+strings.Join(command, " ")) || strings.Contains(help, "\x1b[") {
					t.Fatalf("invalid help for %v: %s", command, help)
				}
			}
		}
	}
}

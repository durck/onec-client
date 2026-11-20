package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

func TestConsoleFormatsAndPreviewBoundary(t *testing.T) {
	for _, format := range []string{"auto", "text", "json"} {
		var out, diagnostic bytes.Buffer
		err := run([]string{"--output", format, "login", "--worker", "192.0.2.1:1560", "--database", "example"}, &out, &diagnostic)
		if err != nil {
			t.Fatal(err)
		}
		if format == "text" {
			for _, want := range []string{"PREVIEW", "example", "192.0.2.1:1560", "--execute", "No network"} {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("missing %s: %s", want, out.String())
				}
			}
		} else {
			var value map[string]any
			if json.Unmarshal(out.Bytes(), &value) != nil || value["network_requests_sent"] != false {
				t.Fatal("JSON preview changed", out.String())
			}
		}
		if strings.Contains(out.String(), "\x1b") || diagnostic.Len() != 0 {
			t.Fatal("noise in redirected output")
		}
	}
}

func TestChecklistHumanFormattingPreservesMachineReport(t *testing.T) {
	for _, tc := range []struct {
		key   string
		value any
		want  string
		ok    bool
	}{
		{"operation_timeout_ns", json.Number("20000000000"), "20s", true},
		{"total_timeout_ns", json.Number("1800000000000"), "30m0s", true},
		{"worker_ports", []any{json.Number("1560"), json.Number("1561"), json.Number("1563")}, "1560-1561, 1563", true},
		{"worker_ports", []any{json.Number("1560"), json.Number("1560")}, "1560, 1560", true},
		{"worker_ports", []any{}, "none", true},
		{"worker_ports", []any{json.Number("0")}, "", false},
		{"worker_ports", []any{"invalid"}, "", false},
	} {
		got, ok := reportField(tc.key, tc.value)
		if got != tc.want || ok != tc.ok {
			t.Fatal(tc.key, got, ok)
		}
	}
	for _, mode := range []string{"text", "json"} {
		var out, diagnostic bytes.Buffer
		if err := run([]string{"--output", mode, "checklist", "--target", "server.example", "--report-file", "audit.json"}, &out, &diagnostic); err != nil {
			t.Fatal(err)
		}
		if mode == "text" {
			for _, want := range []string{"20s", "1560-1591", "partial inventory", "audit.json"} {
				if !strings.Contains(out.String(), want) {
					t.Fatal("missing", want)
				}
			}
		} else {
			var report map[string]any
			if err := json.Unmarshal(out.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if report["report_file"] != "audit.json" || report["options"].(map[string]any)["operation_timeout_ns"] != float64(20000000000) {
				t.Fatal("machine report changed", out.String())
			}
		}
	}
}

func TestConsoleOutputIsLosslessAndEscapesTerminalControls(t *testing.T) {
	var out bytes.Buffer
	w := &consoleWriter{Writer: &out, mode: "text", verbose: true, width: 80}
	value := map[string]any{"operation": "fixture", "success": true, "result": []map[string]any{{"name": "one\x1b[31m\rspoof", "value": json.Number("9007199254740993")}}}
	if err := writeCommandReport(w, value); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"9007199254740993", `\u001b`, `\r`, "SUCCESS"} {
		if !strings.Contains(out.String(), want) {
			t.Fatal(out.String())
		}
	}
	if strings.Contains(out.String(), "\x1b") || strings.Contains(out.String(), "\r") {
		t.Fatal("terminal control injection")
	}
	out.Reset()
	w.mode = "json"
	if err := writeCommandReport(w, value); err != nil || !json.Valid(out.Bytes()) || !strings.Contains(out.String(), "9007199254740993") {
		t.Fatal(err, out.String())
	}
}

func TestConsolePresentationOptionsAreValidatedBeforeDispatch(t *testing.T) {
	for _, args := range [][]string{{"--color", "bad", "login", "--execute"}, {"--output", "bad", "login", "--execute"}, {"--output"}, {"--bogus"}} {
		var out, diagnostic bytes.Buffer
		err := run(args, &out, &diagnostic)
		if err == nil || commandExitCode(err) != 2 || out.Len() != 0 {
			t.Fatalf("invalid presentation accepted: %v %v", args, err)
		}
	}
}

func TestConsoleColorModesAndMachineOutput(t *testing.T) {
	var out bytes.Buffer
	w := &consoleWriter{Writer: &out, color: "always"}
	if !strings.Contains(terminalAccent(w, "96", "Title"), "\x1b[") {
		t.Fatal("explicit color ignored")
	}
	w.color = "never"
	if terminalAccent(w, "96", "Title") != "Title" {
		t.Fatal("color never ignored")
	}
	out.Reset()
	if err := run([]string{"--color=always", "--output=json", "login"}, &out, io.Discard); err != nil || !json.Valid(out.Bytes()) {
		t.Fatal("JSON was colored", err, out.String())
	}
}

func TestConsoleWriteFailurePropagates(t *testing.T) {
	sentinel := errors.New("write failed")
	err := writeCommandReport(&consoleWriter{Writer: consoleFailedWriter{sentinel}, mode: "text"}, map[string]any{"success": true})
	if !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
}

type consoleFailedWriter struct{ err error }

func (w consoleFailedWriter) Write([]byte) (int, error) { return 0, w.err }

// Exercise main's actual stdout/stderr and exit behavior with closed stdin.
// Every invocation is help, a preview, or rejected before execution.
func TestCLIProcessContract(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		code int
		json bool
	}{
		{nil, 0, false},
		{[]string{"--output=json", "login", "--database", "demo"}, 0, true},
		{[]string{"login", "--database", "demo"}, 0, true},
		{[]string{"--output=text", "login", "--database", "demo"}, 0, false},
		{[]string{"wizard"}, 2, false},
		{[]string{"wizard", "--help"}, 0, false},
		{[]string{"unknown-command"}, 2, false},
		{[]string{"epf", "unknown-command"}, 2, false},
		{[]string{"ports", "unknown-command"}, 2, false},
		{[]string{"admin", "unknown-command"}, 2, false},
		{[]string{"login", "--timeout", "do-not-echo-secret", "--execute"}, 2, false},
		{[]string{"login", "--do-not-echo-secret", "--execute"}, 2, false},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			cmd := exec.Command(executable, append([]string{"-test.run=^TestCLIProcessHelper$", "--"}, tc.args...)...)
			cmd.Env = append(os.Environ(), "ONEC_CLI_TEST_HELPER=1")
			var out, diagnostic bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &diagnostic
			err := cmd.Run()
			code := 0
			if err != nil {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) {
					t.Fatal(err)
				}
				code = exitErr.ExitCode()
			}
			if code != tc.code || tc.json && !json.Valid(out.Bytes()) {
				t.Fatalf("exit %d; stdout %s; stderr %s", code, out.String(), diagnostic.String())
			}
			if tc.code != 0 && (out.Len() != 0 || !strings.Contains(diagnostic.String(), "ERROR")) {
				t.Fatal("error did not stay on stderr", out.String(), diagnostic.String())
			}
			if strings.Contains(out.String()+diagnostic.String(), "\x1b") || strings.Contains(diagnostic.String(), "do-not-echo-secret") {
				t.Fatal("unsafe or colored pipe output")
			}
		})
	}
}

func TestCLIProcessHelper(t *testing.T) {
	if os.Getenv("ONEC_CLI_TEST_HELPER") != "1" {
		return
	}
	separator := slices.Index(os.Args, "--")
	if separator < 0 {
		os.Exit(99)
	}
	os.Args = append([]string{"onec"}, os.Args[separator+1:]...)
	main()
	os.Exit(0)
}

func TestConsoleTableFallsBackWithoutTruncatingValues(t *testing.T) {
	var out bytes.Buffer
	long := strings.Repeat("я", 100)
	w := &consoleWriter{Writer: &out, mode: "text", width: 60}
	if err := writeCommandReport(w, map[string]any{"result": []any{map[string]any{"name": long, "id": "full-identifier"}}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), long) || !strings.Contains(out.String(), "full-identifier") || !strings.Contains(out.String(), "[1]") {
		t.Fatal("wide record truncated", out.String())
	}
	out.Reset()
	if err := writeCommandReport(w, map[string]any{"result": []any{map[string]any{"a\x1b": 1, "b": 2}}}); err != nil || strings.Contains(out.String(), "\x1b") {
		t.Fatal("unsafe table header", err, out.String())
	}
}

func TestHumanAdminReportKeepsRedactionAndExactNumbers(t *testing.T) {
	var out bytes.Buffer
	w := &consoleWriter{Writer: &out, mode: "text", width: 80}
	err := writeAdminReport(w, map[string]any{
		"operation": "admin clusters", "success": false,
		"data": map[string]any{"note": "echo sensitive-value", "number": uint64(9007199254740993)},
	}, []string{"sensitive-value"})
	if err != nil || strings.Contains(out.String(), "sensitive-value") || !strings.Contains(out.String(), "[redacted]") || !strings.Contains(out.String(), "9007199254740993") || !strings.Contains(out.String(), "FAILED") {
		t.Fatal(err, out.String())
	}
}

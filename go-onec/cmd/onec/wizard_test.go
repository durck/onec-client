package main

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestWizardPreviewCancelAndExplicitExecution(t *testing.T) {
	for _, end := range []string{"0\n", "\n", "q\n", "", "1\n"} {
		var out, diagnostic bytes.Buffer
		var calls [][]string
		err := wizardWith(strings.NewReader("2\n1\n\ndemo\n2\nfixture-user\n\n"+end), &out, &diagnostic, func(args []string, _, _ io.Writer) error {
			calls = append(calls, append([]string(nil), args...))
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		want := 1
		if end == "1\n" {
			want = 2
		}
		if len(calls) != want {
			t.Fatal(calls)
		}
		if strings.Contains(strings.Join(calls[0], " "), "--execute") {
			t.Fatal("preview executed")
		}
		if want == 2 && calls[1][len(calls[1])-1] != "--execute" {
			t.Fatal("confirmed operation did not execute")
		}
	}
}

func TestWizardBuildsProcessingCommandWithoutTrustOrPasswordFlags(t *testing.T) {
	var out bytes.Buffer
	args, err := wizardArguments(wizardPrompt{strings.NewReader("2\n\ndemo\n2\nTester\nC:\\my files\\sample.epf\n\nEcho\n[\"hello\"]\n\n"), &out}, wizardActions[7])
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(args, []string{"epf", "run", "--manager", "127.0.0.1:1541", "--database", "demo", "--auth", "legacy", "--user", "Tester", "--file", `C:\my files\sample.epf`, "--method", "Echo", "--args-json", `["hello"]`}) {
		t.Fatal(args)
	}
	for _, arg := range args {
		if arg == "--confirm-open" || arg == "--password" || arg == "--execute" {
			t.Fatal("implicit trust/secret/execution", args)
		}
	}
}

func TestWizardDoesNotPrefetchPasswordOrExecuteInvalidPlan(t *testing.T) {
	input := strings.NewReader("line\npassword\n")
	if line, err := (wizardPrompt{input, io.Discard}).line("input", "", true); err != nil || line != "line" {
		t.Fatal(line, err)
	}
	remaining, _ := io.ReadAll(input)
	if string(remaining) != "password\n" {
		t.Fatal("wizard consumed type-ahead password")
	}
	count := 0
	err := wizardWith(strings.NewReader("2\n1\n\ndemo\n2\nfixture-user\n\n0\n"), io.Discard, io.Discard, func([]string, io.Writer, io.Writer) error { count++; return errors.New("invalid config") })
	if err != nil || count != 1 {
		t.Fatal(count, err)
	}
}

func TestWizardRejectsControlSequencesAndQuotesShellArguments(t *testing.T) {
	value, err := (wizardPrompt{strings.NewReader("\x1b[31m\nvalid\n"), io.Discard}).line("input", "", true)
	if err != nil || value != "valid" {
		t.Fatal(value, err)
	}
	command := wizardCommand([]string{"login", "--database", "x'; Write-Output evil; '", "--user", "$(whoami)"}, "windows")
	if command != `onec login --database 'x''; Write-Output evil; ''' --user '$(whoami)'` {
		t.Fatal(command)
	}
}

func TestWizardExecutionEOFIsNotCancellation(t *testing.T) {
	called := 0
	err := wizardWith(strings.NewReader("2\n1\n\ndemo\n2\nfixture-user\n\n1\n"), io.Discard, io.Discard, func([]string, io.Writer, io.Writer) error {
		called++
		if called == 2 {
			return io.EOF
		}
		return nil
	})
	if !errors.Is(err, io.EOF) || called != 2 {
		t.Fatal("execution error was swallowed", called, err)
	}
}

func TestEveryWizardActionProducesAValidOfflinePreview(t *testing.T) {
	inputs := map[string]string{
		"checklist":      "1\naudit-host.example\n\n\n",
		"login":          "1\n\ndemo\n2\nfixture-user\n\n",
		"users":          "1\n\ndemo\n\n",
		"infobases":      "\n\n",
		"ports check":    "\n\n\n",
		"ports scan":     "\n\n\n",
		"epf methods":    "1\n\ndemo\n2\nfixture-user\nmissing.epf\n\n\n",
		"epf run":        "1\n\ndemo\n2\nTester\nmissing.epf\n\nEcho\n[\"hello\"]\n\n",
		"admin clusters": "\n\n",
		"web enum":       "https://example.invalid/demo/ru_RU/\n",
	}
	for i, action := range wizardActions {
		t.Run(action.title, func(t *testing.T) {
			var out, diagnostic bytes.Buffer
			calls := 0
			err := wizardWith(strings.NewReader(strconv.Itoa(i+1)+"\n"+inputs[strings.Join(action.command, " ")]+"0\n"), &out, &diagnostic, func(args []string, out, diagnostic io.Writer) error {
				calls++
				for _, arg := range args {
					if arg == "--execute" || arg == "--apply" {
						t.Fatal("preview attempted execution")
					}
				}
				return run(args, out, diagnostic)
			})
			if err != nil || calls != 1 || !strings.Contains(out.String(), `"mode":"preview"`) || !strings.Contains(out.String(), `"network_requests_sent":false`) {
				t.Fatal("invalid wizard preview", err, calls, out.String(), diagnostic.String())
			}
		})
	}
}

func TestWizardChecklistProxyAndSecretBoundary(t *testing.T) {
	var out bytes.Buffer
	action := wizardActions[0]
	args, err := wizardArguments(wizardPrompt{strings.NewReader("2\ntargets.txt\nnew-audit.json\nsocks5://127.0.0.1:1080\nPROXY_AUTH\n"), &out}, action)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"checklist", "--targets-file", "targets.txt", "--report-file", "new-audit.json", "--proxy", "socks5://127.0.0.1:1080", "--proxy-auth-env", "PROXY_AUTH"}
	if !reflect.DeepEqual(args, want) {
		t.Fatal(args)
	}
	out.Reset()
	_, err = wizardArguments(wizardPrompt{strings.NewReader("1\nserver.example\n\nsocks5://user:secret@127.0.0.1:1080\n"), &out}, action)
	if err == nil || strings.Contains(out.String()+err.Error(), "user:secret") {
		t.Fatal("proxy credentials were accepted or echoed")
	}
}

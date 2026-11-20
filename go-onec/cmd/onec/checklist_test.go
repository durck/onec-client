package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"onec"
	"onec/wire"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestChecklistTargets(t *testing.T) {
	got, err := readChecklistTargets(strings.NewReader("\ufeff# hosts\r\n192.0.2.1\r\nExample.test\nexample.test.\n\n"))
	if err != nil || strings.Join(got, ",") != "192.0.2.1,example.test" {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"", "# none", "https://example.test", "a:1540", "192.0.2.0/24", "999.1.2.3", "::1", "a\x1bb", "-bad.test", "a..b", strings.Repeat("a", 64) + ".test", "good.test\n\xff"} {
		if _, err := readChecklistTargets(strings.NewReader(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func checklistTestOptions() checklistOptions {
	return checklistOptions{Targets: []string{"lab.test"}, AgentPort: 1540, ManagerPort: 1541, Version: "8.3.18.1208", Auth: onec.LegacyAuth, Transport: "anonymous", Timeout: time.Second, TotalTimeout: time.Minute, MaxAttempts: 100, Interval: 0}
}

func checklistTestDeps() checklistDeps {
	return checklistDeps{
		resolve: func(context.Context, string) (string, error) { return "192.0.2.1", nil },
		admin: func(context.Context, onec.AdminConfig, onec.AdminRequest) (onec.AdminResult, error) {
			return onec.AdminResult{}, errors.New("fixture unavailable")
		},
		users: func(context.Context, onec.Config) ([]string, onec.Stats, error) {
			return nil, onec.Stats{}, errors.New("fixture unavailable")
		},
		login: func(context.Context, onec.Config, onec.Credentials) checklistLogin {
			return checklistLogin{Err: errors.New("fixture unavailable")}
		},
		probe: func(context.Context, onec.PortProbeConfig) (onec.PortProbeReport, error) {
			return onec.PortProbeReport{}, nil
		},
		bases: func(context.Context, onec.InfobaseListConfig) (onec.InfobaseListResult, error) {
			return onec.InfobaseListResult{}, nil
		},
	}
}

func cleanChecklistStats() onec.Stats {
	return onec.Stats{ContextReleased: true, SecurityClosed: true, Closed: true}
}
func cleanChecklistAdmin() onec.AdminStats {
	return onec.AdminStats{ContextReleased: true, SecurityClosed: true, Closed: true}
}

func TestChecklistWalksClustersAndPartialUsersOnce(t *testing.T) {
	o := checklistTestOptions()
	d := checklistTestDeps()
	const cluster = "11111111-2222-3333-4444-555555555555"
	var operations []string
	var attempts []string
	d.admin = func(_ context.Context, c onec.AdminConfig, r onec.AdminRequest) (onec.AdminResult, error) {
		if c.Agent != "192.0.2.1:1540" || c.Transport != "anonymous" {
			t.Fatalf("scope: %+v", c)
		}
		operations = append(operations, r.Operation)
		result := onec.AdminResult{Stats: cleanChecklistAdmin()}
		if r.AgentAuth != nil {
			result.Stats.AgentAuthenticated = true
		}
		if r.ClusterAuth != nil {
			result.Stats.AuthenticatedClusters = []string{cluster}
		}
		switch r.Operation {
		case "agent-admins":
			result.Data = []onec.AdminUser{}
		case "clusters":
			result.Data = []onec.AdminCluster{{ID: cluster, Name: "test", Endpoints: []wire.AdminEndpoint{{Host: "untrusted.example", Port: 1641}}}}
		case "cluster-admins":
			result.Data = []onec.AdminUser{{Name: "operator", PasswordAuthAllowed: true}, {Name: "os-only", SysAuthAllowed: true}}
		case "bases":
			result.Data = []onec.AdminInfoBase{{ID: "db1", Name: "Demo"}, {ID: "db1", Name: "Demo"}}
		default:
			t.Fatalf("unexpected operation %s", r.Operation)
		}
		return result, nil
	}
	d.users = func(_ context.Context, c onec.Config) ([]string, onec.Stats, error) {
		if c.Server != "192.0.2.1:1641" || c.Infobase != "Demo" || c.ServerName != "lab.test" {
			t.Fatalf("scope: %+v", c)
		}
		return []string{"alice", "ALICE", "bob"}, cleanChecklistStats(), nil
	}
	d.login = func(_ context.Context, c onec.Config, cred onec.Credentials) checklistLogin {
		if cred.Password != "" || cred.Method != onec.LegacyAuth || !c.DisableContextRecovery {
			t.Fatal("not an exact empty-password attempt")
		}
		attempts = append(attempts, cred.Username)
		stats := cleanChecklistStats()
		if cred.Username == "alice" {
			stats.Authenticated = true
			stats.LogoutConfirmed = true
			return checklistLogin{Stats: stats, Attempted: true}
		}
		return checklistLogin{Stats: stats, Attempted: true, Err: &onec.StatusError{Operation: "login", Status: 401}}
	}
	r := executeChecklist(context.Background(), o, d, nil)
	if !r.Completed || strings.Join(attempts, ",") != "alice,bob" || r.Summary.Users != 2 || r.Summary.Databases != 1 {
		t.Fatalf("attempts=%v summary=%+v", attempts, r.Summary)
	}
	if !strings.Contains(strings.Join(r.Limitations, " "), "prelogin") {
		t.Fatal("missing coverage limitation")
	}
	if len(operations) == 0 || r.Summary.Findings == 0 {
		t.Fatal("missing findings")
	}
	for _, v := range r.Results {
		if v.User == "bob" && v.Status != "not_accepted" {
			t.Fatalf("incorrect refusal: %+v", v)
		}
	}
}

func TestChecklistFindingSurvivesCleanupFailure(t *testing.T) {
	o := checklistTestOptions()
	o.WorkerPorts = []int{1560}
	d := checklistTestDeps()
	d.probe = func(_ context.Context, c onec.PortProbeConfig) (onec.PortProbeReport, error) {
		return onec.PortProbeReport{Results: []onec.PortProbeResult{{Port: 1560, Address: "203.0.113.99:1", Protocol: "onec-native", State: "open", RoleChecks: []onec.PortRoleCheck{{Role: "working-process-administration", Matched: true, ContextOpened: true, ContextReleased: true, Closed: true}}}}}, nil
	}
	d.bases = func(_ context.Context, c onec.InfobaseListConfig) (onec.InfobaseListResult, error) {
		if c.Worker != "192.0.2.1:1560" {
			t.Fatal("followed returned address")
		}
		return onec.InfobaseListResult{Infobases: []onec.InfobaseInfo{{ID: "db1", Name: "Demo"}}}, nil
	}
	d.users = func(context.Context, onec.Config) ([]string, onec.Stats, error) {
		return []string{"alice"}, cleanChecklistStats(), nil
	}
	d.login = func(context.Context, onec.Config, onec.Credentials) checklistLogin {
		return checklistLogin{Attempted: true, Stats: onec.Stats{Authenticated: true}, CleanupErr: errors.New("fixture cleanup")}
	}
	r := executeChecklist(context.Background(), o, d, nil)
	for _, v := range r.Results {
		if v.Check == "infobase_empty_password" {
			if v.Status != "finding" || !v.CleanupFailed {
				t.Fatalf("lost finding: %+v", v)
			}
			return
		}
	}
	t.Fatal("no password finding")
}

func TestChecklistLimitsCancellationAndResolutionFailure(t *testing.T) {
	o := checklistTestOptions()
	o.Targets = []string{"bad.test", "good.test"}
	o.MaxAttempts = 1
	d := checklistTestDeps()
	var calls int
	d.resolve = func(_ context.Context, s string) (string, error) {
		if s == "bad.test" {
			return "", errors.New("secret raw DNS diagnostic")
		}
		return "192.0.2.2", nil
	}
	d.admin = func(context.Context, onec.AdminConfig, onec.AdminRequest) (onec.AdminResult, error) {
		calls++
		return onec.AdminResult{Data: []onec.AdminUser{{Name: "one", PasswordAuthAllowed: true}}, Stats: cleanChecklistAdmin()}, nil
	}
	r := executeChecklist(context.Background(), o, d, nil)
	if r.Completed || r.Summary.CredentialAttempts > 1 || calls == 0 {
		t.Fatalf("%+v", r.Summary)
	}
	b, _ := json.Marshal(r)
	if bytes.Contains(b, []byte("secret raw")) {
		t.Fatal("raw error leaked")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls = 0
	r = executeChecklist(ctx, o, d, nil)
	if calls != 0 || r.Completed {
		t.Fatal("cancellation did not stop work")
	}
}

func TestChecklistPreviewAndExclusiveReport(t *testing.T) {
	d := checklistTestDeps()
	d.resolve = func(context.Context, string) (string, error) { t.Fatal("network in preview/preflight"); return "", nil }
	var out bytes.Buffer
	path := filepath.Join(t.TempDir(), "report.json")
	args := []string{"--target", "192.0.2.1", "--report-file", path}
	if err := runChecklistWith(args, &out, io.Discard, d); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("preview wrote report")
	}
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runChecklistWith(append(args, "--execute"), io.Discard, io.Discard, d); err == nil {
		t.Fatal("overwrote report")
	}
	b, _ := os.ReadFile(path)
	if string(b) != "keep" {
		t.Fatal("existing report changed")
	}
}

func TestChecklistWritesReportAfterFailedTarget(t *testing.T) {
	d := checklistTestDeps()
	d.resolve = func(context.Context, string) (string, error) { return "", &net.DNSError{Err: "fixture", Name: "host"} }
	path := filepath.Join(t.TempDir(), "report.json")
	var out, progress bytes.Buffer
	err := runChecklistWith([]string{"lab.test", "--execute", "--report-file", path}, &out, &progress, d)
	if err == nil {
		t.Fatal("incomplete run reported success")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var r checklistReport
	if e = json.Unmarshal(b, &r); e != nil || r.Completed || len(r.Results) == 0 {
		t.Fatalf("%s %v", b, e)
	}
	if !strings.Contains(progress.String(), "resolve") || out.Len() == 0 {
		t.Fatal("console output absent")
	}
}

func TestChecklistDatabaseStopsAndReportsUnattemptedUsers(t *testing.T) {
	for _, tc := range []struct {
		name           string
		result         checklistLogin
		wantStatus     string
		calls, skipped int
	}{
		{"refusal", checklistLogin{Attempted: true, Stats: cleanChecklistStats(), Err: &onec.StatusError{Operation: "login", Status: 401}}, "not_accepted", 2, 0},
		{"policy", checklistLogin{Attempted: true, Stats: cleanChecklistStats(), Err: &onec.StatusError{Operation: "login", Status: 423}}, "error", 1, 1},
		{"dial", checklistLogin{Err: errors.New("fixture")}, "error", 1, 1},
		{"unconfirmed", checklistLogin{Attempted: true, Stats: cleanChecklistStats()}, "error", 1, 1},
		{"cleanup", checklistLogin{Attempted: true, Stats: onec.Stats{Authenticated: true}, CleanupErr: errors.New("fixture")}, "finding", 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, d := checklistTestOptions(), checklistTestDeps()
			o.Auth = onec.PasswordV2
			calls := 0
			d.users = func(context.Context, onec.Config) ([]string, onec.Stats, error) {
				return []string{"alice", "ALICE", "bob"}, cleanChecklistStats(), nil
			}
			d.login = func(_ context.Context, c onec.Config, cred onec.Credentials) checklistLogin {
				if c.Profile.Application != "MobileClient" || c.SecurityFactory == nil || !c.DisableContextRecovery || cred.Method != onec.PasswordV2 || cred.Password != "" {
					t.Fatal("incorrect password login configuration")
				}
				calls++
				return tc.result
			}
			s := checklistRun{ctx: context.Background(), o: o, d: d, r: newChecklistReport(o)}
			s.database(checklistDatabase{base: checklistResult{Target: "lab.test", Database: "Demo"}, worker: "192.0.2.1:1560"})
			if calls != tc.calls || s.r.Summary.Users != 2 || s.r.Summary.Skipped != tc.skipped {
				t.Fatalf("calls=%d summary=%+v", calls, s.r.Summary)
			}
			if s.r.Results[1].Status != tc.wantStatus {
				t.Fatalf("%+v", s.r.Results)
			}
			if tc.skipped > 0 {
				last := s.r.Results[len(s.r.Results)-1]
				if last.Count != 1 || last.Attempted {
					t.Fatalf("missing remaining-user coverage: %+v", last)
				}
			}
		})
	}
}

func TestChecklistSkippedUserDoesNotInheritPreviousAttempt(t *testing.T) {
	o, d := checklistTestOptions(), checklistTestDeps()
	d.users = func(context.Context, onec.Config) ([]string, onec.Stats, error) {
		return []string{"alice", "bad\x1bname"}, cleanChecklistStats(), nil
	}
	d.login = func(context.Context, onec.Config, onec.Credentials) checklistLogin {
		return checklistLogin{Attempted: true, Stats: cleanChecklistStats(), Err: &onec.StatusError{Operation: "login", Status: 401}}
	}
	s := checklistRun{ctx: context.Background(), o: o, d: d, r: newChecklistReport(o)}
	s.database(checklistDatabase{base: checklistResult{Target: "lab.test", Database: "Demo"}, worker: "192.0.2.1:1560"})
	last := s.r.Results[len(s.r.Results)-1]
	if last.Attempted || last.HTTPStatus != 0 || last.Status != "skipped" {
		t.Fatalf("%+v", last)
	}
}

func TestChecklistAdminAuthenticationEvidenceSurvivesReadFailure(t *testing.T) {
	o, d := checklistTestOptions(), checklistTestDeps()
	d.admin = func(context.Context, onec.AdminConfig, onec.AdminRequest) (onec.AdminResult, error) {
		stats := cleanChecklistAdmin()
		stats.AgentAuthenticated = true
		return onec.AdminResult{Stats: stats}, &wire.AdminRPCError{}
	}
	s := checklistRun{ctx: context.Background(), o: o, d: d, r: newChecklistReport(o)}
	_, accepted := s.adminCredential(checklistResult{Target: "lab.test", ResolvedIP: "192.0.2.1"}, onec.AdminRequest{Operation: "agent-admins", AgentAuth: &onec.AdminCredentials{}}, "agent_empty_default")
	if !accepted || s.r.Summary.Findings != 1 || s.r.Summary.Errors != 1 || s.r.Summary.NotAccepted != 0 {
		t.Fatalf("lost accepted credential: %+v", s.r)
	}
}

func TestChecklistResolvedAliasesDoNotRepeatChecks(t *testing.T) {
	o, d := checklistTestOptions(), checklistTestDeps()
	o.Targets = []string{"one.test", "two.test", "192.0.2.1"}
	calls := 0
	d.admin = func(context.Context, onec.AdminConfig, onec.AdminRequest) (onec.AdminResult, error) {
		calls++
		return onec.AdminResult{}, errors.New("fixture")
	}
	r := executeChecklist(context.Background(), o, d, nil)
	if calls != 3 || r.Summary.Targets != 3 || r.Summary.CredentialAttempts != 1 {
		t.Fatalf("calls=%d summary=%+v", calls, r.Summary)
	}
	aliases := 0
	for _, row := range r.Results {
		if row.Check == "target_alias" {
			aliases++
		}
	}
	if aliases != 2 {
		t.Fatal("missing alias coverage")
	}
}

func TestChecklistWorkerDiscoveryRetainsUncertainty(t *testing.T) {
	o, d := checklistTestOptions(), checklistTestDeps()
	o.WorkerPorts = []int{1560, 1561, 1562}
	d.probe = func(context.Context, onec.PortProbeConfig) (onec.PortProbeReport, error) {
		return onec.PortProbeReport{Results: []onec.PortProbeResult{
			{Port: 1560, State: "timeout"},
			{Port: 1561, State: "open", Protocol: "onec-native", RoleChecks: []onec.PortRoleCheck{{Role: "working-process-administration", Matched: true, ContextOpened: true}}},
			{Port: 1562, State: "open", Protocol: "onec-native"},
		}}, nil
	}
	d.bases = func(context.Context, onec.InfobaseListConfig) (onec.InfobaseListResult, error) {
		t.Fatal("enumerated unconfirmed or unclean worker")
		return onec.InfobaseListResult{}, nil
	}
	s := checklistRun{ctx: context.Background(), o: o, d: d, r: newChecklistReport(o)}
	if found := s.workerDatabases(checklistResult{Target: "lab.test", ResolvedIP: "192.0.2.1"}); len(found) != 0 || s.r.Summary.Errors != 2 || s.r.Summary.Skipped != 1 {
		t.Fatalf("%+v", s.r.Summary)
	}
}

func TestChecklistWorkerListRetainsCleanupEvidenceAndData(t *testing.T) {
	o, d := checklistTestOptions(), checklistTestDeps()
	o.WorkerPorts = []int{1560}
	d.probe = func(context.Context, onec.PortProbeConfig) (onec.PortProbeReport, error) {
		return onec.PortProbeReport{Results: []onec.PortProbeResult{{Port: 1560, State: "open", Protocol: "onec-native", RoleChecks: []onec.PortRoleCheck{{Role: "working-process-administration", Matched: true, ContextOpened: true, ContextReleased: true, Closed: true}}}}}, nil
	}
	d.bases = func(context.Context, onec.InfobaseListConfig) (onec.InfobaseListResult, error) {
		return onec.InfobaseListResult{Infobases: []onec.InfobaseInfo{{ID: "db1", Name: "Demo"}}, Stats: onec.Stats{Connections: []string{"192.0.2.1:1560"}, Closed: true, SecurityClosed: true}}, errors.New("fixture release failure")
	}
	s := checklistRun{ctx: context.Background(), o: o, d: d, r: newChecklistReport(o)}
	found := s.workerDatabases(checklistResult{Target: "lab.test", ResolvedIP: "192.0.2.1"})
	last := s.r.Results[len(s.r.Results)-1]
	if len(found) != 1 || last.Status != "error" || !last.CleanupFailed {
		t.Fatalf("lost data or cleanup evidence: found=%v row=%+v", found, last)
	}
}

func TestChecklistInputAndOfflineCLIValidation(t *testing.T) {
	for _, input := range []string{strings.Repeat("a", 1<<20+1), strings.Repeat("host.test\n", 120000)} {
		if _, err := readChecklistTargets(strings.NewReader(input)); err == nil {
			t.Fatal("accepted oversized list")
		}
	}
	d := checklistTestDeps()
	d.resolve = func(context.Context, string) (string, error) { t.Fatal("network before valid execute"); return "", nil }
	for _, args := range [][]string{
		{}, {"--target", "a.test", "--targets-file", "unused"}, {"a.test", "--target", "b.test"},
		{"--target", "a.test", "--auth", "windows"}, {"--target", "a.test", "--transport", "auto"},
		{"--target", "a.test", "--transport="},
		{"--target", "a.test", "--agent-port", "0"}, {"--target", "a.test", "--worker-ports", "1-65535"},
		{"--target", "a.test", "--max-attempts", "0"}, {"--target", "a.test", "--interval", "-1s"},
		{"--target", "a.test", "--timeout", "0"}, {"--target", "a.test", "--total-timeout", "25h"},
		{"--target", "a.test", "--execute", "--apply"},
	} {
		if err := runChecklistWith(args, io.Discard, io.Discard, d); err == nil || commandExitCode(err) != 2 {
			t.Fatalf("args=%v err=%v", args, err)
		}
	}
	path := filepath.Join(t.TempDir(), "hosts.txt")
	if err := os.WriteFile(path, []byte("# scope\n192.0.2.1\nExample.test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runChecklistWith([]string{"--targets-file", path, "--worker-ports", "none"}, &out, io.Discard, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "example.test") {
		t.Fatal("missing file target")
	}
	flags := completionFlagSet([]string{"checklist"})
	if flags == nil || flags.Lookup("targets-file") == nil || flags.Lookup("execute") == nil {
		t.Fatal("checklist not connected to help/completion")
	}
}

func TestChecklistCompleteReportAndFindingExitCodes(t *testing.T) {
	for _, failOnFindings := range []bool{false, true} {
		d := checklistTestDeps()
		const cluster = "11111111-2222-3333-4444-555555555555"
		d.admin = func(_ context.Context, _ onec.AdminConfig, r onec.AdminRequest) (onec.AdminResult, error) {
			result := onec.AdminResult{Stats: cleanChecklistAdmin()}
			if r.AgentAuth != nil {
				result.Stats.AgentAuthenticated = true
			}
			if r.ClusterAuth != nil {
				result.Stats.AuthenticatedClusters = []string{cluster}
			}
			switch r.Operation {
			case "agent-admins", "cluster-admins":
				result.Data = []onec.AdminUser{}
			case "clusters":
				result.Data = []onec.AdminCluster{{ID: cluster}}
			case "bases":
				result.Data = []onec.AdminInfoBase{{ID: "db1", Name: "Demo"}}
			default:
				t.Fatal("unexpected administrative operation")
			}
			return result, nil
		}
		d.users = func(context.Context, onec.Config) ([]string, onec.Stats, error) {
			return []string{"alice"}, cleanChecklistStats(), nil
		}
		d.login = func(context.Context, onec.Config, onec.Credentials) checklistLogin {
			stats := cleanChecklistStats()
			stats.Authenticated, stats.LogoutConfirmed = true, true
			return checklistLogin{Attempted: true, Stats: stats}
		}
		path := filepath.Join(t.TempDir(), "report.json")
		args := []string{"--target", "lab.test", "--worker-ports", "none", "--interval", "0", "--report-file", path, "--execute"}
		if failOnFindings {
			args = append(args, "--fail-on-findings")
		}
		var out, progress bytes.Buffer
		err := runChecklistWith(args, &out, &progress, d)
		if (err != nil) != failOnFindings || err != nil && commandExitCode(err) != 1 {
			t.Fatalf("finding exit: %v", err)
		}
		var r checklistReport
		if err := json.Unmarshal(out.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		if !r.Completed || r.Summary.Findings != 3 || r.Summary.Users != 1 || !strings.Contains(progress.String(), "[finding]") {
			t.Fatalf("%+v", r.Summary)
		}
		file, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var saved checklistReport
		if err := json.Unmarshal(file, &saved); err != nil || saved.Summary != r.Summary {
			t.Fatalf("saved and console report differ: %v", err)
		}
	}
}

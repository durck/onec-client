package main

import (
	"context"
	"errors"
	"net"
	"onec"
	"onec/wire"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type checklistOptions struct {
	Proxy        string `json:"proxy,omitempty"`
	ProxyAuth    bool   `json:"proxy_auth_configured,omitempty"`
	dial         proxyDialFunc
	Targets      []string             `json:"targets"`
	AgentPort    int                  `json:"agent_port"`
	ManagerPort  int                  `json:"manager_port"`
	WorkerPorts  []int                `json:"worker_ports"`
	Version      string               `json:"advertised_client_version"`
	Auth         onec.AuthMethod      `json:"infobase_auth"`
	Transport    string               `json:"transport_identity"`
	Policy       onec.TransportPolicy `json:"transport_policy"`
	Timeout      time.Duration        `json:"operation_timeout_ns"`
	TotalTimeout time.Duration        `json:"total_timeout_ns"`
	Interval     time.Duration        `json:"credential_interval_ns"`
	MaxAttempts  int                  `json:"max_credential_attempts"`
}

type checklistResult struct {
	Target        string `json:"target"`
	ResolvedIP    string `json:"resolved_ip,omitempty"`
	Endpoint      string `json:"endpoint,omitempty"`
	Cluster       string `json:"cluster_id,omitempty"`
	Database      string `json:"database,omitempty"`
	DatabaseID    string `json:"database_id,omitempty"`
	User          string `json:"user,omitempty"`
	Check         string `json:"check"`
	Status        string `json:"status"`
	Detail        string `json:"detail"`
	Count         int    `json:"count,omitempty"`
	HTTPStatus    int    `json:"http_status,omitempty"`
	Attempted     bool   `json:"authentication_requested"`
	CleanupFailed bool   `json:"cleanup_failed"`
}

type checklistSummary struct {
	Targets            int `json:"targets"`
	Clusters           int `json:"clusters"`
	Databases          int `json:"databases"`
	Users              int `json:"users"`
	CredentialAttempts int `json:"credential_checks"`
	Findings           int `json:"findings"`
	NotAccepted        int `json:"not_accepted"`
	Errors             int `json:"errors"`
	Skipped            int `json:"skipped"`
}

type checklistReport struct {
	SchemaVersion int               `json:"schema_version"`
	Operation     string            `json:"operation"`
	Mode          string            `json:"mode"`
	Started       string            `json:"started_at"`
	Finished      string            `json:"finished_at,omitempty"`
	Completed     bool              `json:"completed"`
	Coverage      string            `json:"coverage"`
	Options       checklistOptions  `json:"options"`
	ReportFile    string            `json:"report_file,omitempty"`
	Limitations   []string          `json:"limitations"`
	Summary       checklistSummary  `json:"summary"`
	Results       []checklistResult `json:"results"`
}

type checklistLogin struct {
	Stats           onec.Stats
	Attempted       bool
	Err, CleanupErr error
}

type checklistDeps struct {
	resolve func(context.Context, string) (string, error)
	admin   adminRunner
	users   func(context.Context, onec.Config) ([]string, onec.Stats, error)
	login   func(context.Context, onec.Config, onec.Credentials) checklistLogin
	probe   portProber
	bases   func(context.Context, onec.InfobaseListConfig) (onec.InfobaseListResult, error)
}

type checklistRun struct {
	ctx         context.Context
	o           checklistOptions
	d           checklistDeps
	r           checklistReport
	emit        func(checklistResult)
	lastAttempt time.Time
	halted      bool
}

func newChecklistReport(o checklistOptions) checklistReport {
	report := checklistReport{SchemaVersion: 1, Operation: "checklist", Mode: "execute", Started: time.Now().UTC().Format(time.RFC3339), Coverage: "discovered_objects_only", Options: o, Results: []checklistResult{}, Limitations: []string{
		"Users are the prelogin selection list, not a complete account inventory; hidden users are outside coverage.",
		"DNS selects one IPv4 address per target. Agent, advertised manager and manager-selected worker connections stay on that IP; additional worker discovery uses configured ports.",
		"Empty-credential acceptance is an observation under the selected transport identity; it does not prove that every administrator lacks a password.",
		"A refusal does not prove a nonempty password: policy, account state, licensing and protocol compatibility can prevent login.",
		"The advertised build is not server version detection. Native live compatibility is bounded to 8.3.18.1208; other profiles require separate qualification.",
		"Credential checks count scheduled candidates, including connection failures. Successful empty administrative credentials are reused for inventory, requiring additional authentication exchanges.",
	}}
	if o.Proxy != "" {
		report.Limitations[1] = "Target DNS is delegated to SOCKS5 for each connection. Connections retain the supplied target name; resolved IPs and alias deduplication are unavailable. Use literal IP targets for address pinning."
	}
	return report
}

func executeChecklist(ctx context.Context, o checklistOptions, d checklistDeps, emit func(checklistResult)) checklistReport {
	s := checklistRun{ctx: ctx, o: o, d: d, r: newChecklistReport(o), emit: emit}
	seenIPs := map[string]string{}
	for _, host := range o.Targets {
		if s.stopped() {
			break
		}
		s.r.Summary.Targets++
		if o.Proxy != "" {
			base := checklistResult{Target: host}
			if ip := net.ParseIP(host); ip != nil {
				base.ResolvedIP = ip.String()
			}
			s.record(base, "resolve", "info", "Target passed to SOCKS5; no local target DNS lookup", false)
			s.host(base)
			continue
		}
		c, cancel := context.WithTimeout(ctx, o.Timeout)
		ip, err := d.resolve(c, host)
		cancel()
		base := checklistResult{Target: host, ResolvedIP: ip}
		if err != nil || net.ParseIP(ip) == nil || net.ParseIP(ip).To4() == nil {
			s.record(base, "resolve", "error", "IPv4 resolution failed", false)
			continue
		}
		s.record(base, "resolve", "info", "Target resolved and pinned for this run", false)
		if first, ok := seenIPs[ip]; ok {
			s.record(base, "target_alias", "info", "Duplicate resolved IP; checks are recorded under "+first, false)
			continue
		}
		seenIPs[ip] = host
		s.host(base)
	}
	if ctx.Err() != nil {
		s.record(checklistResult{}, "run", "error", "Cancelled or total timeout reached; remaining targets were not checked", false)
	}
	s.r.Completed = !s.halted && ctx.Err() == nil && s.r.Summary.Errors == 0 && s.r.Summary.Skipped == 0
	s.r.Finished = time.Now().UTC().Format(time.RFC3339)
	return s.r
}

func (s *checklistRun) stopped() bool { return s.halted || s.ctx.Err() != nil }

func (r checklistResult) routeHost() string {
	if r.ResolvedIP != "" {
		return r.ResolvedIP
	}
	return r.Target
}

func (s *checklistRun) record(base checklistResult, check, status, detail string, cleanup bool) {
	base.Check, base.Status, base.Detail, base.CleanupFailed = check, status, detail, cleanup
	s.r.Results = append(s.r.Results, base)
	switch status {
	case "finding":
		s.r.Summary.Findings++
	case "not_accepted":
		s.r.Summary.NotAccepted++
	case "error":
		s.r.Summary.Errors++
	case "skipped":
		s.r.Summary.Skipped++
	}
	if cleanup && status != "error" {
		s.r.Summary.Errors++
	}
	if s.emit != nil {
		s.emit(base)
	}
}

func (s *checklistRun) attempt(base checklistResult, check string) bool {
	if s.stopped() {
		return false
	}
	if s.r.Summary.CredentialAttempts >= s.o.MaxAttempts {
		s.record(base, check, "skipped", "Global credential-attempt limit reached; remaining checks were not run", false)
		s.halted = true
		return false
	}
	if wait := time.Until(s.lastAttempt.Add(s.o.Interval)); !s.lastAttempt.IsZero() && wait > 0 {
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-s.ctx.Done():
			timer.Stop()
			return false
		}
	}
	s.lastAttempt = time.Now()
	s.r.Summary.CredentialAttempts++
	return true
}

func checklistAdminCleanup(r onec.AdminResult) bool {
	return len(r.Stats.Connections) > 0 && (!r.Stats.ContextReleased || !r.Stats.SecurityClosed || !r.Stats.Closed)
}

func checklistFailure(err error) (string, string) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "error", "Cancelled or operation timeout"
	}
	var rpc *wire.AdminRPCError
	if errors.As(err, &rpc) {
		return "not_accepted", "Administrative RPC request was refused; password configuration is not established"
	}
	return "error", "Network, unsupported protocol or operation failure; no password conclusion"
}

func (s *checklistRun) admin(base checklistResult, r onec.AdminRequest, check string) (onec.AdminResult, bool) {
	if s.stopped() {
		return onec.AdminResult{}, false
	}
	c, cancel := context.WithTimeout(s.ctx, s.o.Timeout)
	defer cancel()
	cfg := onec.AdminConfig{Agent: net.JoinHostPort(base.routeHost(), strconv.Itoa(s.o.AgentPort)), Version: s.o.Version, Transport: s.o.Transport, TransportPolicy: s.o.Policy, Timeout: s.o.Timeout, DialContext: s.o.dial}
	result, err := s.d.admin(c, cfg, r)
	base.Endpoint = cfg.Agent
	cleanup := checklistAdminCleanup(result)
	if err != nil {
		status, detail := checklistFailure(err)
		if !base.Attempted || checklistAdminAuthenticated(result, r) || r.ClusterAuth != nil && r.AgentAuth != nil && !result.Stats.AgentAuthenticated {
			status = "error"
		}
		// Successfully decoded data remains usable even if final cleanup failed.
		s.record(base, check, status, detail, cleanup)
		return result, result.Data != nil
	}
	if cleanup {
		s.record(base, check, "error", "Operation returned data but cleanup was not confirmed", true)
	}
	return result, true
}

func checklistAdminAuthenticated(result onec.AdminResult, request onec.AdminRequest) bool {
	if request.ClusterAuth == nil {
		return result.Stats.AgentAuthenticated
	}
	for _, id := range result.Stats.AuthenticatedClusters {
		if strings.EqualFold(id, request.ClusterID) {
			return true
		}
	}
	return false
}

// Credential outcomes are separate from the following read and cleanup: an
// authenticated flag remains evidence even when either later stage fails.
func (s *checklistRun) adminCredential(base checklistResult, r onec.AdminRequest, check string) (onec.AdminResult, bool) {
	if !s.attempt(base, check) {
		return onec.AdminResult{}, false
	}
	base.Endpoint = net.JoinHostPort(base.routeHost(), strconv.Itoa(s.o.AgentPort))
	base.Attempted = true
	result, ok := s.admin(base, r, check+"_operation")
	accepted := checklistAdminAuthenticated(result, r)
	if accepted {
		s.record(base, check, "finding", "Explicit empty credentials accepted under the selected transport identity", checklistAdminCleanup(result))
	} else if ok {
		s.record(base, check, "error", "Authentication success was not confirmed", false)
	}
	return result, accepted
}

func (s *checklistRun) administrators(base checklistResult, agent *onec.AdminCredentials) *onec.AdminCredentials {
	op, scope := "agent-admins", "agent"
	if base.Cluster != "" {
		op, scope = "cluster-admins", "cluster"
	}
	request := onec.AdminRequest{Operation: op, ClusterID: base.Cluster, AgentAuth: agent}
	result, ok := s.admin(base, request, scope+"_admin_list")
	admins, listed := result.Data.([]onec.AdminUser)
	if ok && listed {
		row := base
		row.Count = len(admins)
		s.record(row, scope+"_admin_list", "info", "Administrator records read; listing alone does not establish administrative access", false)
	}
	var access *onec.AdminCredentials
	defaultRequest := request
	if scope == "agent" {
		defaultRequest.AgentAuth = &onec.AdminCredentials{}
	} else {
		defaultRequest.ClusterAuth = &onec.AdminCredentials{}
	}
	def, accepted := s.adminCredential(base, defaultRequest, scope+"_empty_default")
	if accepted {
		access = &onec.AdminCredentials{}
	}
	if values, yes := def.Data.([]onec.AdminUser); yes {
		admins, listed = values, true
	}
	if !listed {
		s.record(base, scope+"_named_empty_passwords", "skipped", "Administrator list unavailable; named empty-password checks could not run", false)
		return access
	}
	seen := map[string]bool{}
	for _, user := range admins {
		if s.stopped() {
			break
		}
		key := strings.ToUpper(user.Name)
		if seen[key] {
			continue
		}
		seen[key] = true
		row := base
		row.User = user.Name
		if !user.PasswordAuthAllowed {
			s.record(row, scope+"_empty_password", "info", "Password authentication is disabled for this administrator", false)
			continue
		}
		if !checklistUserName(user.Name) {
			s.record(row, scope+"_empty_password", "skipped", "Unsupported administrator name", false)
			continue
		}
		cred := &onec.AdminCredentials{Username: user.Name}
		req := request
		if scope == "agent" {
			req.AgentAuth = cred
		} else {
			req.ClusterAuth = cred
		}
		_, accepted := s.adminCredential(row, req, scope+"_empty_password")
		if accepted && access == nil {
			access = cred
		}
	}
	return access
}

type checklistDatabase struct {
	base            checklistResult
	manager, worker string
}

func (s *checklistRun) host(base checklistResult) {
	agent := s.administrators(base, nil)
	result, ok := s.admin(base, onec.AdminRequest{Operation: "clusters", AgentAuth: agent}, "clusters")
	databases := []checklistDatabase{}
	seenClusters := map[string]bool{}
	if clusters, yes := result.Data.([]onec.AdminCluster); yes && ok {
		row := base
		row.Count = len(clusters)
		s.record(row, "clusters", "info", "Clusters discovered", false)
		for _, cluster := range clusters {
			if s.stopped() {
				break
			}
			if seenClusters[cluster.ID] {
				continue
			}
			seenClusters[cluster.ID] = true
			row := base
			row.Cluster = cluster.ID
			if err := onec.ValidateAdminRequest(onec.AdminRequest{Operation: "bases", ClusterID: cluster.ID}); err != nil {
				s.record(row, "cluster", "error", "Invalid cluster identifier", false)
				continue
			}
			s.r.Summary.Clusters++
			access := s.administrators(row, agent)
			res, read := s.admin(row, onec.AdminRequest{Operation: "bases", ClusterID: cluster.ID, AgentAuth: agent, ClusterAuth: access}, "databases")
			if bases, yes := res.Data.([]onec.AdminInfoBase); yes && read {
				port := s.o.ManagerPort
				if len(cluster.Endpoints) > 0 {
					port = int(cluster.Endpoints[0].Port)
				}
				if port < 1 || port > 65535 {
					s.record(row, "databases", "error", "Invalid manager port; cluster databases were not scheduled", false)
					continue
				}
				for _, db := range bases {
					item := row
					item.Database, item.DatabaseID = db.Name, db.ID
					databases = append(databases, checklistDatabase{base: item, manager: net.JoinHostPort(base.routeHost(), strconv.Itoa(port))})
				}
				row.Count = len(bases)
				s.record(row, "databases", "info", "Cluster database names discovered; manager connections stay on the input target", false)
			} else {
				s.record(row, "databases", "skipped", "Cluster database inventory unavailable", false)
			}
		}
	} else {
		s.record(base, "clusters", "skipped", "Cluster inventory unavailable; configured worker-port discovery can still proceed", false)
	}
	if !s.stopped() && len(s.o.WorkerPorts) > 0 {
		databases = append(databases, s.workerDatabases(base)...)
	}
	seen := map[string]bool{}
	for _, db := range databases {
		if s.stopped() {
			break
		}
		key := strings.ToUpper(db.base.DatabaseID)
		if key == "" {
			key = "name:" + strings.ToUpper(db.base.Database)
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		s.database(db)
	}
	if len(databases) == 0 && !s.stopped() {
		s.record(base, "database_coverage", "skipped", "No accessible databases discovered; infobase password checks did not run", false)
	}
}

func (s *checklistRun) workerDatabases(base checklistResult) []checklistDatabase {
	c, cancel := context.WithTimeout(s.ctx, s.o.Timeout*time.Duration(len(s.o.WorkerPorts)))
	defer cancel()
	probe, err := s.d.probe(c, onec.PortProbeConfig{Host: base.routeHost(), Ports: s.o.WorkerPorts, Timeout: min(s.o.Timeout, 5*time.Second), Concurrency: 4, Version: s.o.Version, SkipLocalProcess: true, DialContext: s.o.dial, RemoteDNS: s.o.Proxy != ""})
	if err != nil {
		s.record(base, "worker_discovery", "error", "Worker discovery incomplete", false)
	}
	var found []checklistDatabase
	allowed := map[int]bool{}
	for _, p := range s.o.WorkerPorts {
		allowed[p] = true
	}
	for _, p := range probe.Results {
		if s.stopped() {
			break
		}
		if !allowed[p.Port] {
			continue
		}
		row := base
		row.Endpoint = net.JoinHostPort(base.routeHost(), strconv.Itoa(p.Port))
		worker, cleanup := false, false
		for _, role := range p.RoleChecks {
			worker = worker || role.Role == "working-process-administration" && role.Matched
			cleanup = cleanup || role.ContextOpened && (!role.ContextReleased || !role.Closed)
		}
		switch {
		case cleanup:
			s.record(row, "worker_probe", "error", "Port role probe cleanup was not confirmed; this worker was not enumerated", true)
		case p.State == "timeout" || p.State == "error" || p.State == "canceled":
			s.record(row, "worker_probe", "error", "Port probe did not establish whether a worker is available", false)
		case p.Protocol == "onec-native" && !worker:
			s.record(row, "worker_probe", "skipped", "1C endpoint found but worker interface was not confirmed", false)
		case worker:
			s.record(row, "worker_probe", "info", "Working-process administration interface confirmed", false)
		default:
			s.record(row, "worker_probe", "info", "Port closed or no recognized 1C worker greeting", false)
		}
		if !worker || cleanup {
			continue
		}
		ctx, stop := context.WithTimeout(s.ctx, s.o.Timeout)
		res, e := s.d.bases(ctx, onec.InfobaseListConfig{Worker: row.Endpoint, Transport: s.o.Transport, Version: s.o.Version, TransportPolicy: s.o.Policy, Timeout: s.o.Timeout, DialContext: s.o.dial})
		stop()
		cleanup = len(res.Stats.Connections) > 0 && (!res.Stats.ContextReleased || !res.Stats.SecurityClosed || !res.Stats.Closed)
		if e != nil || cleanup {
			s.record(row, "worker_databases", "error", "Worker database enumeration or cleanup failed", cleanup)
		}
		for _, db := range res.Infobases {
			item := row
			item.Database, item.DatabaseID = db.Name, db.ID
			found = append(found, checklistDatabase{base: item, worker: row.Endpoint})
		}
		if e == nil && !cleanup {
			row.Count = len(res.Infobases)
			s.record(row, "worker_databases", "info", "Worker database names discovered", false)
		}
	}
	return found
}

func checklistUserName(name string) bool {
	if name == "" || !utf8.ValidString(name) || len([]rune(name)) > 256 {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func (s *checklistRun) database(db checklistDatabase) {
	s.r.Summary.Databases++
	row := db.base
	row.Endpoint = db.manager
	if db.worker != "" {
		row.Endpoint = db.worker
	}
	cfg := onec.Config{Server: db.manager, Worker: db.worker, ServerName: row.Target, Infobase: row.Database, Profile: onec.Profile{Version: s.o.Version, Application: "1CV8C"}, TransportPolicy: s.o.Policy, Timeout: s.o.Timeout, DisableContextRecovery: true, DialContext: s.o.dial}
	if s.o.Auth == onec.PasswordV2 {
		cfg.Profile.Application = "MobileClient"
	}
	if err := onec.ValidateConfig(cfg); err != nil {
		s.record(row, "users", "error", "Database name or route unsupported by the current client", false)
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, s.o.Timeout)
	users, stats, err := s.d.users(ctx, checklistSecurity(cfg, s.o.Transport))
	cancel()
	cleanup := len(stats.Connections) > 0 && (!stats.Closed || !stats.SecurityClosed || !stats.ContextReleased)
	if err != nil {
		s.record(row, "users", "error", "Prelogin user-list request failed; this database was not checked", cleanup)
		return
	}
	row.Count = len(users)
	s.record(row, "users", "info", "Prelogin selection list only; hidden users are outside coverage", cleanup)
	row.Count = 0
	if len(users) == 0 {
		s.record(row, "infobase_empty_password", "skipped", "No usernames returned; empty list does not establish password protection", false)
		return
	}
	seen := map[string]bool{}
	unique := make([]string, 0, len(users))
	for _, user := range users {
		key := strings.ToUpper(user)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, user)
		}
	}
	s.r.Summary.Users += len(unique)
	for i, user := range unique {
		if s.stopped() {
			break
		}
		row.User = user
		row.Attempted, row.HTTPStatus = false, 0
		if !checklistUserName(user) {
			s.record(row, "infobase_empty_password", "skipped", "Unsupported username in selection list", false)
			continue
		}
		if !s.attempt(row, "infobase_empty_password") {
			break
		}
		ctx, stop := context.WithTimeout(s.ctx, s.o.Timeout)
		res := s.d.login(ctx, checklistSecurity(cfg, s.o.Transport), onec.Credentials{Method: s.o.Auth, Username: user, Password: ""})
		stop()
		row.Attempted = res.Attempted
		state, code, proceed := batchLoginStatus(res.Err)
		row.HTTPStatus = code
		cleanup := res.CleanupErr != nil || res.Attempted && (!res.Stats.ContextReleased || !res.Stats.SecurityClosed || !res.Stats.Closed || res.Stats.Authenticated && !res.Stats.LogoutConfirmed)
		switch {
		case res.Attempted && res.Err == nil && res.Stats.Authenticated:
			s.record(row, "infobase_empty_password", "finding", "Password login with an explicitly empty password succeeded", cleanup)
		case res.Attempted && state == "not_accepted":
			s.record(row, "infobase_empty_password", "not_accepted", "Empty-password login was refused; account password state is not established", cleanup)
		default:
			s.record(row, "infobase_empty_password", "error", state+"; remaining users in this database were not attempted", cleanup)
			proceed = false
		}
		if !proceed || cleanup {
			if i+1 < len(unique) {
				remaining := row
				remaining.User = ""
				remaining.Attempted = false
				remaining.HTTPStatus = 0
				remaining.Count = len(unique) - i - 1
				s.record(remaining, "infobase_empty_password", "skipped", "Remaining usernames were not attempted after an operational, policy or cleanup failure", false)
			}
			break
		}
	}
}

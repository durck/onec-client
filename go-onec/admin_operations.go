package onec

import (
	"context"
	"errors"
	"onec/wire"
)

// AdminCluster represents the materialized cluster descriptor returned by the
// agent. Endpoint addresses are informational and are never followed implicitly.
type AdminCluster struct {
	ID                string               `json:"id"`
	Name              string               `json:"name"`
	Endpoints         []wire.AdminEndpoint `json:"endpoints"`
	Settings          AdminClusterSettings `json:"settings"`
	SettingsAvailable bool                 `json:"settings_available"`
	layout            int
	recyclingSchedule string
	legacyRecycling   [7]int64
}

type AdminClusterSettings struct {
	SecurityLevel        uint32 `json:"security_level"`
	LifeTimeLimit        uint32 `json:"lifetime_limit"`
	ExpirationTimeout    uint32 `json:"expiration_timeout"`
	FaultToleranceLevel  uint32 `json:"fault_tolerance_level"`
	LoadBalancingMode    uint32 `json:"load_balancing_mode"`
	KillProblemProcesses bool   `json:"kill_problem_processes"`
	KillByMemoryWithDump bool   `json:"kill_by_memory_with_dump"`
	RecyclingSchedule    string `json:"recycling_schedule,omitempty"`
}

// AdminMutationError reports failure after a mutation was sent. OutcomeUnknown
// means the connection/reply did not establish whether the server applied it.
// Callers must inspect state instead of automatically retrying the operation.
type AdminMutationError struct {
	Operation      string
	OutcomeUnknown bool
	cause          error
}

func (e *AdminMutationError) Error() string {
	if e.OutcomeUnknown {
		return "administrative mutation outcome unknown; inspect server state before retrying"
	}
	return "administrative mutation rejected"
}
func (e *AdminMutationError) Unwrap() error { return e.cause }

// AdminMutationResult confirms a native acknowledgment. A later administrator
// can change the same settings; this is not an atomic compare-and-swap receipt.
type AdminMutationResult struct {
	Operation string `json:"operation"`
	ClusterID string `json:"cluster_id"`
	SessionID string `json:"session_id,omitempty"`
	Setting   string `json:"setting,omitempty"`
	Value     uint32 `json:"value"`
	Confirmed bool   `json:"confirmed"`
}

func adminString(s string) []any { return []any{"S", wire.WideString(s)} }
func adminScalar(n uint32) []any { return []any{"#", wire.ScalarType, n} }
func adminBool(b bool) []any {
	n := 0
	if b {
		n = 1
	}
	return []any{"B", n}
}

func (c *AdminClient) invoke(ctx context.Context, method, flags uint32, args ...any) (any, error) {
	if method == 30 || method == 32 {
		want := 6
		if method == 32 {
			want = 4
		}
		if c.stats.InterfaceMethods == 68 {
			want = 8
			if method == 32 {
				want = 3
			}
		}
		if len(args) != want {
			return nil, errors.New("operation signature does not match the negotiated administration interface")
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	n, err := c.connection.next()
	if err != nil {
		return nil, err
	}
	p, err := wire.AdminCall(c.connection.target, n, method, flags, args...)
	if err != nil {
		return nil, err
	}
	defer clear(p)
	r, err := c.connection.exchange(ctx, p)
	if err != nil {
		return nil, err
	}
	defer clear(r)
	modes := make([]uint32, len(args))
	for i, arg := range args {
		if _, ok := arg.(wire.AdminOutput); ok {
			modes[i] = 1
		}
	}
	return wire.ParseAdminReply(r, flags, modes, wire.AdminReplyMarker(c.connection.target, n, 4, method))
}

func (c *AdminClient) authenticateAgent(ctx context.Context, credentials AdminCredentials) error {
	c.stats.AgentAuthenticated = false
	_, err := c.invoke(ctx, 19, 3, adminString(credentials.Username), adminString(credentials.Password))
	if err == nil {
		c.stats.AgentAuthenticated = true
	}
	return err
}

func (c *AdminClient) authenticateCluster(ctx context.Context, id wire.UUID, credentials AdminCredentials) error {
	for i, old := range c.stats.AuthenticatedClusters {
		if old == id.String() {
			c.stats.AuthenticatedClusters = append(c.stats.AuthenticatedClusters[:i], c.stats.AuthenticatedClusters[i+1:]...)
			break
		}
	}
	_, err := c.invoke(ctx, 9, 3, wire.TypedUUID(id), adminString(credentials.Username), adminString(credentials.Password))
	if err == nil {
		c.stats.AuthenticatedClusters = append(c.stats.AuthenticatedClusters, id.String())
	}
	return err
}

// AuthenticateAgent makes exactly one request. Empty credentials are explicit
// default authentication, with no automatic retry under the Windows identity.
func (c *AdminClient) AuthenticateAgent(ctx context.Context, credentials AdminCredentials) error {
	if !validAdminCredentials(&credentials) {
		return errors.New("invalid administrative credentials")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("administration client is closed")
	}
	return c.authenticateAgent(ctx, credentials)
}

// AuthenticateCluster authenticates only the named cluster in this context.
func (c *AdminClient) AuthenticateCluster(ctx context.Context, clusterID string, credentials AdminCredentials) error {
	id, err := adminUUID(clusterID)
	if err != nil {
		return err
	}
	if !validAdminCredentials(&credentials) {
		return errors.New("invalid administrative credentials")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("administration client is closed")
	}
	return c.authenticateCluster(ctx, id, credentials)
}

func (c *AdminClient) mutate(ctx context.Context, operation string, method uint32, args ...any) error {
	c.stats.MutationAttempted = false
	c.stats.MutationConfirmed = false
	before := c.connection.sent
	_, err := c.invoke(ctx, method, 3, args...)
	c.stats.MutationAttempted = c.connection.sent > before
	if err != nil && c.stats.MutationAttempted {
		var rejected *wire.AdminRPCError
		return &AdminMutationError{Operation: operation, OutcomeUnknown: !errors.As(err, &rejected), cause: err}
	}
	if err == nil {
		c.stats.MutationConfirmed = true
	}
	return err
}

func (c *AdminClient) setCluster(ctx context.Context, r AdminRequest, id wire.UUID) (any, error) {
	clusters, err := c.clusters(ctx)
	if err != nil {
		return nil, err
	}
	var current *AdminClusterSettings
	var descriptor *AdminCluster
	for i := range clusters {
		if clusters[i].ID == id.String() {
			if current != nil {
				return nil, errors.New("ambiguous cluster descriptor")
			}
			current = &clusters[i].Settings
			descriptor = &clusters[i]
		}
	}
	if current == nil {
		return nil, errors.New("target cluster was not returned by this agent")
	}
	method := uint32(30)
	args := []any{wire.TypedUUID(id)}
	switch r.Setting {
	case "security-level":
		method = 23
		args = append(args, adminScalar(r.Value))
	case "fault-tolerance":
		method = 39
		args = append(args, adminScalar(r.Value))
	default:
		if descriptor.layout == 12 {
			legacy := descriptor.legacyRecycling
			switch r.Setting {
			case "recycle-lifetime":
				legacy[0] = int64(r.Value)
			case "recycle-expiration":
				legacy[1] = int64(r.Value)
			case "load-balancing-mode":
				legacy[4] = int64(r.Value)
			case "kill-problem-processes":
				legacy[6] = int64(r.Value)
			default:
				return nil, errors.New("setting is unavailable in the negotiated legacy cluster layout")
			}
			for _, n := range legacy[:6] {
				args = append(args, []any{"#", wire.ScalarType, n})
			}
			args = append(args, adminBool(legacy[6] != 0))
			break
		}
		if !descriptor.SettingsAvailable {
			return nil, errors.New("composite settings are unavailable for this cluster layout")
		}
		if descriptor.layout == 15 && r.Setting == "recycle-lifetime" {
			return nil, errors.New("this cluster uses a recycling schedule instead of a lifetime setting")
		}
		s := *current
		switch r.Setting {
		case "recycle-lifetime":
			s.LifeTimeLimit = r.Value
		case "recycle-expiration":
			s.ExpirationTimeout = r.Value
		case "load-balancing-mode":
			s.LoadBalancingMode = r.Value
		case "kill-problem-processes":
			s.KillProblemProcesses = r.Value == 1
		case "kill-by-memory-with-dump":
			s.KillByMemoryWithDump = r.Value == 1
		default:
			return nil, errors.New("unsupported cluster setting")
		}
		if s.LifeTimeLimit > 0x7fffffff || s.ExpirationTimeout > 0x7fffffff || s.LoadBalancingMode > 0x7fffffff {
			return nil, errors.New("cluster settings exceed the supported signed range")
		}
		var recycling any = adminScalar(s.LifeTimeLimit)
		if descriptor.layout == 15 {
			recycling = adminString(descriptor.recyclingSchedule)
		}
		args = append(args, recycling, adminScalar(s.ExpirationTimeout), adminScalar(s.LoadBalancingMode), adminBool(s.KillProblemProcesses), adminBool(s.KillByMemoryWithDump))
	}
	if err := c.mutate(ctx, r.Operation, method, args...); err != nil {
		return nil, err
	}
	return AdminMutationResult{Operation: r.Operation, ClusterID: id.String(), Setting: r.Setting, Value: r.Value, Confirmed: true}, nil
}

func (c *AdminClient) clusters(ctx context.Context) ([]AdminCluster, error) {
	v, err := c.invoke(ctx, 0, 1)
	if err != nil {
		return nil, err
	}
	descriptors, err := wire.ParseAdminClusters(v)
	if err != nil {
		return nil, err
	}
	result := make([]AdminCluster, 0, len(descriptors))
	for _, d := range descriptors {
		if c.stats.InterfaceMethods == 68 && d.Layout != 12 || (c.stats.InterfaceMethods == 79 || c.stats.InterfaceMethods == 80) && d.Layout != 10 || (c.stats.InterfaceMethods == 89 || c.stats.InterfaceMethods == 96) && d.Layout != 15 {
			return nil, errors.New("cluster layout does not match the negotiated administration interface")
		}
		result = append(result, AdminCluster{ID: d.ID.String(), Name: d.Name, Endpoints: d.Endpoints, SettingsAvailable: d.Layout != 12, layout: d.Layout, recyclingSchedule: d.RecyclingSchedule, legacyRecycling: d.LegacyRecycling, Settings: AdminClusterSettings{
			RecyclingSchedule: d.RecyclingSchedule,
			SecurityLevel:     d.Settings[0], LifeTimeLimit: d.Settings[1], ExpirationTimeout: d.Settings[2], FaultToleranceLevel: d.Settings[3], LoadBalancingMode: d.Settings[4], KillProblemProcesses: d.Settings[5] != 0, KillByMemoryWithDump: d.Settings[6] != 0,
		}})
	}
	return result, nil
}

func (c *AdminClient) sessions(ctx context.Context, cluster wire.UUID) ([]wire.AdminSessionDescriptor, error) {
	v, err := c.invoke(ctx, 31, 3, wire.TypedUUID(cluster), wire.TypedUUID(wire.UUID{}), wire.AdminOutput{})
	if err != nil {
		return nil, err
	}
	return wire.ParseAdminSessions(v)
}

func (c *AdminClient) terminateSession(ctx context.Context, r AdminRequest, cluster wire.UUID) (any, error) {
	if c.stats.InterfaceMethods == 68 && r.Message != "" {
		return nil, errors.New("the negotiated legacy termination method does not support a message")
	}
	sessions, err := c.sessions(ctx, cluster)
	if err != nil {
		return nil, err
	}
	target, _ := adminUUID(r.SessionID)
	var selected *wire.AdminSessionDescriptor
	for i := range sessions {
		if sessions[i].ID == target.String() {
			if selected != nil {
				return nil, errors.New("ambiguous session target")
			}
			selected = &sessions[i]
		}
	}
	if selected == nil {
		return nil, errors.New("target session was not returned for this cluster")
	}
	base, err := adminUUID(selected.InfoBaseID)
	if err != nil {
		return nil, errors.New("session has no verified infobase route")
	}
	args := []any{wire.TypedUUID(cluster), wire.TypedUUID(base), wire.TypedUUID(target)}
	if c.stats.InterfaceMethods != 68 {
		args = append(args, adminString(r.Message))
	}
	if err = c.mutate(ctx, r.Operation, 32, args...); err != nil {
		return nil, err
	}
	return AdminMutationResult{Operation: r.Operation, ClusterID: cluster.String(), SessionID: target.String(), Confirmed: true}, nil
}

// Clusters reads descriptors without claiming administrator authorization.
func (c *AdminClient) Clusters(ctx context.Context) ([]AdminCluster, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("administration client is closed")
	}
	return c.clusters(ctx)
}

// Execute runs one operation on the existing context. Authentication at each
// requested scope precedes the operation and failures stop execution.
func (c *AdminClient) Execute(ctx context.Context, r AdminRequest) (any, error) {
	if err := ValidateAdminRequest(r); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("administration client is closed")
	}
	c.stats.MutationAttempted, c.stats.MutationConfirmed = false, false
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.AgentAuth != nil {
		if err := c.authenticateAgent(ctx, *r.AgentAuth); err != nil {
			return nil, err
		}
	}
	id, _ := wire.ParseUUID(r.ClusterID)
	if r.ClusterAuth != nil {
		if err := c.authenticateCluster(ctx, id, *r.ClusterAuth); err != nil {
			return nil, err
		}
	}
	switch r.Operation {
	case "clusters":
		return c.clusters(ctx)
	case "set":
		return c.setCluster(ctx, r, id)
	case "sessions":
		return c.sessions(ctx, id)
	case "terminate-session":
		return c.terminateSession(ctx, r, id)
	case "processes":
		v, err := c.invoke(ctx, 3, 1, wire.TypedUUID(id))
		if err != nil {
			return nil, err
		}
		return wire.ParseAdminProcesses(v)
	case "agent-admins":
		v, err := c.invoke(ctx, 20, 1)
		if err != nil {
			return nil, err
		}
		return wire.ParseAdminUsers(v)
	case "cluster-admins":
		v, err := c.invoke(ctx, 10, 1, wire.TypedUUID(id))
		if err != nil {
			return nil, err
		}
		return wire.ParseAdminUsers(v)
	case "servers":
		v, err := c.invoke(ctx, 13, 1, wire.TypedUUID(id))
		if err != nil {
			return nil, err
		}
		return wire.ParseAdminWorkingServers(v)
	case "bases":
		v, err := c.invoke(ctx, 5, 1, wire.TypedUUID(id))
		if err != nil {
			return nil, err
		}
		return wire.ParseAdminInfoBases(v)
	default:
		return nil, errors.New("unsupported administration operation")
	}
}

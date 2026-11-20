package onec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"onec/internal/security"
	"onec/wire"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// AdminConfig connects to a server agent, normally port 1540. No infobase or
// application login is required. Transport identity and administrator identity
// are independent. The default transport uses the current Windows account.
type AdminConfig struct {
	Agent, Version, Transport string
	TransportPolicy           TransportPolicy // Empty/plain preserves existing record framing.
	Timeout                   time.Duration   // Per exchange; caller context bounds the whole operation.
	SecurityFactory           func() (SecurityContext, error)
	DialContext               func(context.Context, string, string) (net.Conn, error)
}

// AdminCredentials belongs to one administrative scope. Empty strings request
// default authentication. They do not assert that the administrator list is empty.
type AdminCredentials struct {
	Username, Password string `json:"-"`
}

func (AdminCredentials) String() string     { return "administrative credentials (redacted)" }
func (c AdminCredentials) GoString() string { return c.String() }

// AdminRequest selects one operation. Nil credentials mean no authentication
// attempt; an empty credentials value is an explicit default-auth attempt.
// A setting request changes exactly one setting. No operation is retried.
type AdminRequest struct {
	Operation   string            `json:"operation"`
	ClusterID   string            `json:"cluster_id,omitempty"`
	SessionID   string            `json:"session_id,omitempty"`
	Setting     string            `json:"setting,omitempty"`
	Value       uint32            `json:"value,omitempty"`
	Message     string            `json:"-"`
	AgentAuth   *AdminCredentials `json:"-"`
	ClusterAuth *AdminCredentials `json:"-"`
}

// AdminStats separates transport, administrator authorization and cleanup.
// Mutation flags describe the last validated Execute request, including failures
// in its prerequisites. Locally invalid requests leave previous state unchanged.
type AdminStats struct {
	Connections             []string              `json:"connections"`
	RPCRounds               int                   `json:"rpc_rounds"`
	BytesSent               int64                 `json:"bytes_sent"`
	BytesReceived           int64                 `json:"bytes_received"`
	SecurityContexts        []SecurityObservation `json:"security_contexts"`
	AgentAuthenticated      bool                  `json:"agent_authenticated"`
	AuthenticatedClusters   []string              `json:"authenticated_clusters"`
	ContextReleased         bool                  `json:"context_released"`
	SecurityClosed          bool                  `json:"security_closed"`
	Closed                  bool                  `json:"closed"`
	MutationAttempted       bool                  `json:"mutation_attempted"`
	MutationConfirmed       bool                  `json:"mutation_confirmed"`
	InterfaceMethods        uint32                `json:"interface_methods"`
	AdvertisedClientVersion string                `json:"advertised_client_version"`
}

type AdminResult struct {
	Data  any        `json:"data"`
	Stats AdminStats `json:"stats"`
}

// AdminClient owns one serialized server-agent connection. Close it even after
// an authentication error. It never falls back to another identity or reconnects.
type AdminClient struct {
	mu         sync.Mutex
	cfg        Config
	connection *connection
	stats      AdminStats
	closed     bool
	closeErr   error
}

func (*AdminClient) String() string     { return "1C administration client (context redacted)" }
func (c *AdminClient) GoString() string { return c.String() }

func (c AdminConfig) normalized() (Config, error) {
	if _, _, err := policyOptions(c.TransportPolicy); err != nil {
		return Config{}, err
	}
	if c.Agent == "" {
		c.Agent = "127.0.0.1:1540"
	}
	host, port, err := net.SplitHostPort(c.Agent)
	p, pe := strconv.Atoi(port)
	if err != nil || pe != nil || p < 1 || p > 65535 || !namePattern.MatchString(host) || strings.Contains(host, ":") {
		return Config{}, errors.New("administration requires an agent IPv4 host:port endpoint")
	}
	if c.Version == "" {
		c.Version = "8.3.18.1208"
	}
	if !versionPattern.MatchString(c.Version) {
		return Config{}, errors.New("invalid platform version")
	}
	if c.Timeout == 0 {
		c.Timeout = 20 * time.Second
	}
	if c.Timeout < 0 {
		return Config{}, errors.New("timeout must be positive")
	}
	if c.Transport == "" {
		c.Transport = "windows"
	}
	if c.Transport != "windows" && c.Transport != "anonymous" {
		return Config{}, errors.New("transport must be windows or anonymous")
	}
	if c.SecurityFactory == nil {
		c.SecurityFactory = security.New
		if c.Transport == "anonymous" {
			c.SecurityFactory = security.NewAnonymous
		}
	}
	if c.DialContext == nil {
		c.DialContext = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	return Config{Server: c.Agent, Profile: Profile{Version: c.Version, Application: "COMConsole"}, TransportPolicy: c.TransportPolicy, Timeout: c.Timeout, SecurityFactory: c.SecurityFactory, DialContext: c.DialContext}, nil
}

// ValidateAdminConfig does not acquire credentials or contact a server.
func ValidateAdminConfig(c AdminConfig) error { _, err := c.normalized(); return err }

func adminUUID(s string) (wire.UUID, error) {
	id, err := wire.ParseUUID(s)
	if err != nil || id == (wire.UUID{}) {
		return wire.UUID{}, errors.New("a nonzero administrative UUID is required")
	}
	return id, nil
}

func validAdminCredentials(c *AdminCredentials) bool {
	if c == nil {
		return true
	}
	return len(c.Username) <= 4096 && len(c.Password) <= 4096 && utf8.ValidString(c.Username) && utf8.ValidString(c.Password) &&
		!strings.ContainsRune(c.Username, 0) && !strings.ContainsRune(c.Password, 0) && (c.Username != "" || c.Password == "")
}

// ValidateAdminRequest validates the exact target before connecting, including
// for a preview. Wildcards and an omitted mutation target are never accepted.
func ValidateAdminRequest(r AdminRequest) error {
	needsCluster := false
	switch r.Operation {
	case "clusters", "agent-admins":
	case "cluster-admins", "servers", "processes", "bases", "sessions", "terminate-session", "set":
		needsCluster = true
	default:
		return errors.New("unsupported administration operation")
	}
	if needsCluster || r.ClusterAuth != nil {
		if _, err := adminUUID(r.ClusterID); err != nil {
			return errors.New("operation requires an explicit cluster UUID")
		}
	} else if r.ClusterID != "" {
		return errors.New("this operation does not take a cluster UUID")
	}
	if r.Operation == "terminate-session" {
		if _, err := adminUUID(r.SessionID); err != nil {
			return errors.New("termination requires an explicit session UUID")
		}
		if len(r.Message) > 4096 || !utf8.ValidString(r.Message) || strings.ContainsRune(r.Message, 0) {
			return errors.New("invalid termination message")
		}
	} else if r.SessionID != "" || r.Message != "" {
		return errors.New("session and message are only valid for termination")
	}
	if r.Operation == "set" {
		switch r.Setting {
		case "security-level":
			if r.Value > 2 {
				return errors.New("security-level must be 0, 1 or 2")
			}
		case "kill-problem-processes", "kill-by-memory-with-dump", "load-balancing-mode":
			if r.Value > 1 {
				return errors.New("boolean/mode setting must be 0 or 1")
			}
		case "recycle-lifetime", "recycle-expiration", "fault-tolerance":
			if r.Value > 0x7fffffff {
				return errors.New("setting exceeds signed 32-bit range")
			}
		default:
			return errors.New("unsupported cluster setting")
		}
	} else if r.Setting != "" || r.Value != 0 {
		return errors.New("setting and value are only valid for set")
	}
	if !validAdminCredentials(r.AgentAuth) || !validAdminCredentials(r.ClusterAuth) {
		return errors.New("invalid administrative credentials")
	}
	return nil
}

func DialAdmin(ctx context.Context, options AdminConfig) (*AdminClient, error) {
	c, err := dialAdmin(ctx, options)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// dialAdmin retains a closed client on post-bootstrap failure so RunAdmin can
// report its cleanup evidence. Public DialAdmin never exposes a failed client.
func dialAdmin(ctx context.Context, options AdminConfig) (_ *AdminClient, err error) {
	cfg, err := options.normalized()
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	process, err := wire.NewUUID()
	if err != nil {
		return nil, err
	}
	conn, err := openConnection(ctx, cfg, cfg.Server, wire.ServerAgentContext, wire.AdminProcessSelector, wire.UUID{}, process)
	if err != nil {
		return nil, fmt.Errorf("server-agent administration: %w", err)
	}
	c := &AdminClient{cfg: cfg, connection: conn, stats: AdminStats{AdvertisedClientVersion: cfg.Profile.Version, Connections: []string{cfg.Server}, SecurityContexts: []SecurityObservation{{Stage: "agent", Mechanism: conn.mechanism}}, AuthenticatedClusters: []string{}}}
	defer func() {
		if err != nil {
			err = errors.Join(err, c.Close())
		}
	}()
	n, err := conn.next()
	if err != nil {
		return c, err
	}
	p, err := wire.QueryRequest(conn.target, n, wire.ServerAgentInterface)
	if err != nil {
		return c, err
	}
	reply, err := conn.exchange(ctx, p)
	if err != nil {
		return c, err
	}
	if c.stats.InterfaceMethods, err = wire.ParseServerAgentProfile(reply, wire.AdminReplyMarker(conn.target, n, 1, 0)); err != nil {
		return c, err
	}
	return c, nil
}

func (c *AdminClient) Stats() AdminStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	if c.connection != nil {
		s.RPCRounds = c.connection.rounds
		s.BytesSent = c.connection.sent
		s.BytesReceived = c.connection.received
		s.ContextReleased = c.connection.released
		s.SecurityClosed = c.connection.securityClosed
	}
	s.Connections = append([]string{}, s.Connections...)
	s.SecurityContexts = append([]SecurityObservation{}, s.SecurityContexts...)
	s.AuthenticatedClusters = append([]string{}, s.AuthenticatedClusters...)
	s.Closed = c.closed
	return s
}

func (c *AdminClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return c.closeErr
	}
	c.closed = true
	if c.connection == nil {
		return nil
	}
	var releaseErr error
	if c.connection.sync {
		ctx, cancel := context.WithTimeout(context.Background(), min(c.cfg.Timeout, 5*time.Second))
		releaseErr = c.connection.release(ctx)
		cancel()
	} else {
		releaseErr = errors.New("administrative context release unconfirmed after interrupted exchange")
	}
	c.closeErr = errors.Join(releaseErr, c.connection.closeSocket())
	return c.closeErr
}

// RunAdmin opens, executes and closes one administration connection. Partial
// data is preserved if remote-context cleanup fails. Auth failures stop the
// requested operation; caller-supplied credentials are not retained in results.
func RunAdmin(ctx context.Context, cfg AdminConfig, request AdminRequest) (result AdminResult, err error) {
	if err = ValidateAdminRequest(request); err != nil {
		return result, err
	}
	c, err := dialAdmin(ctx, cfg)
	if err != nil {
		if c != nil {
			result.Stats = c.Stats()
		}
		return result, err
	}
	defer func() { err = errors.Join(err, c.Close()); result.Stats = c.Stats() }()
	result.Data, err = c.Execute(ctx, request)
	return result, err
}

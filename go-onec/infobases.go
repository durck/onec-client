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
	"time"
)

// InfobaseListConfig selects a working-process administration endpoint. It
// needs no infobase name and never performs application login or discovery.
type InfobaseListConfig struct {
	Worker          string
	Version         string
	Transport       string          // "anonymous" (default) or explicit current-session "windows".
	TransportPolicy TransportPolicy // Empty/plain preserves existing record framing.
	Timeout         time.Duration   // Per exchange; the caller context can bound the whole operation.
	SecurityFactory func() (SecurityContext, error)
	DialContext     func(context.Context, string, string) (net.Conn, error)
}

type InfobaseInfo struct {
	Name        string `json:"name"`
	ID          string `json:"id"`
	Description string `json:"description"`
}

type InfobaseListResult struct {
	Infobases []InfobaseInfo `json:"infobases"`
	Stats     Stats          `json:"stats"`
}

func (c InfobaseListConfig) normalized() (Config, error) {
	if _, _, err := policyOptions(c.TransportPolicy); err != nil {
		return Config{}, err
	}
	host, port, err := net.SplitHostPort(c.Worker)
	p, pe := strconv.Atoi(port)
	if err != nil || pe != nil || p < 1 || p > 65535 || !namePattern.MatchString(host) || strings.Contains(host, ":") {
		return Config{}, errors.New("infobase listing requires a worker IPv4 host:port endpoint")
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
		c.Transport = "anonymous"
	}
	if c.Transport != "anonymous" && c.Transport != "windows" {
		return Config{}, errors.New("transport must be anonymous or windows")
	}
	if c.SecurityFactory == nil {
		c.SecurityFactory = security.NewAnonymous
		if c.Transport == "windows" {
			c.SecurityFactory = security.New
		}
	}
	if c.DialContext == nil {
		c.DialContext = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	return Config{Worker: c.Worker, Profile: Profile{Version: c.Version, Application: "COMConsole"}, TransportPolicy: c.TransportPolicy, Timeout: c.Timeout, SecurityFactory: c.SecurityFactory, DialContext: c.DialContext}, nil
}

// ValidateInfobaseListConfig validates options without acquiring credentials,
// loading a vendor library, or opening a network connection.
func ValidateInfobaseListConfig(cfg InfobaseListConfig) error {
	_, err := cfg.normalized()
	return err
}

// ListInfobases makes one bounded read-only request and releases its remote
// context. It never retries with a different identity. A non-nil error can
// accompany a retrieved list when cleanup fails; consult Stats separately.
// Live compatibility is established only for the documented build/endpoint.
func ListInfobases(ctx context.Context, options InfobaseListConfig) (result InfobaseListResult, err error) {
	cfg, err := options.normalized()
	if err != nil {
		return result, err
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	process, err := wire.NewUUID()
	if err != nil {
		return result, err
	}
	c, err := openConnection(ctx, cfg, cfg.Worker, wire.AdminProcessContext, wire.AdminProcessSelector, wire.UUID{}, process)
	if err != nil {
		return result, fmt.Errorf("working-process administration: %w", err)
	}
	result.Stats.Connections = []string{cfg.Worker}
	result.Stats.SecurityContexts = []SecurityObservation{{"administration", c.mechanism}}
	defer func() {
		var releaseErr error
		if c.sync {
			cleanup, cancel := context.WithTimeout(context.Background(), min(cfg.Timeout, 5*time.Second))
			releaseErr = c.release(cleanup)
			cancel()
		} else {
			releaseErr = errors.New("administrative context release unconfirmed after interrupted exchange")
		}
		closeErr := c.closeSocket()
		result.Stats.ContextReleased = c.released
		result.Stats.SecurityClosed = c.securityClosed
		result.Stats.Closed = true
		result.Stats.RPCRounds = c.rounds
		result.Stats.BytesSent = c.sent
		result.Stats.BytesReceived = c.received
		err = errors.Join(err, releaseErr, closeErr)
	}()
	n, err := c.next()
	if err != nil {
		return result, err
	}
	request, err := wire.QueryRequest(c.target, n, wire.InfobaseListInterface)
	if err != nil {
		return result, err
	}
	reply, err := c.exchange(ctx, request)
	if err != nil {
		return result, err
	}
	if err = wire.ParseInfobaseInterface(reply); err != nil {
		return result, err
	}
	n, err = c.next()
	if err != nil {
		return result, err
	}
	request, err = wire.InfobaseListRequest(c.target, n)
	if err != nil {
		return result, err
	}
	reply, err = c.exchange(ctx, request)
	if err != nil {
		return result, err
	}
	bases, err := wire.ParseInfobases(reply)
	if err != nil {
		return result, err
	}
	result.Infobases = make([]InfobaseInfo, 0, len(bases))
	for _, base := range bases {
		result.Infobases = append(result.Infobases, InfobaseInfo{Name: base.Name, ID: base.ID.String(), Description: base.Description})
	}
	return result, nil
}

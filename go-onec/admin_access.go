package onec

import (
	"context"
	"onec/wire"
)

type AdminUser = wire.AdminUserDescriptor
type AdminWorkingServer = wire.WorkingServerDescriptor
type AdminWorkingProcess = wire.AdminProcessDescriptor
type AdminInfoBase = wire.AdminInfoBaseDescriptor
type AdminSession = wire.AdminSessionDescriptor

// Sessions returns the verified core fields of every session in one cluster.
// It uses the authentication already established on this client context.
func (c *AdminClient) Sessions(ctx context.Context, clusterID string) ([]AdminSession, error) {
	v, err := c.Execute(ctx, AdminRequest{Operation: "sessions", ClusterID: clusterID})
	if err != nil {
		return nil, err
	}
	return v.([]AdminSession), nil
}

// SetClusterSetting reads the cluster descriptor and changes one supported
// setting. A valid acknowledgment confirms execution, not an atomic transaction
// with the preceding read. Neither failures nor uncertain outcomes are retried.
func (c *AdminClient) SetClusterSetting(ctx context.Context, clusterID, setting string, value uint32) (AdminMutationResult, error) {
	v, err := c.Execute(ctx, AdminRequest{Operation: "set", ClusterID: clusterID, Setting: setting, Value: value})
	if err != nil {
		return AdminMutationResult{}, err
	}
	return v.(AdminMutationResult), nil
}

// TerminateSession resolves the infobase route from a fresh session listing and
// terminates exactly one internal session UUID. Numeric display IDs do not match.
func (c *AdminClient) TerminateSession(ctx context.Context, clusterID, sessionID, message string) (AdminMutationResult, error) {
	v, err := c.Execute(ctx, AdminRequest{Operation: "terminate-session", ClusterID: clusterID, SessionID: sessionID, Message: message})
	if err != nil {
		return AdminMutationResult{}, err
	}
	return v.(AdminMutationResult), nil
}

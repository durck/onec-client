package onec

import (
	"context"
	"errors"
	"fmt"
	"onec/wire"
	"reflect"
	"time"
)

// Only simpleLogin's credential-free initial request enters this function.
// Users, AuthenticationSettings, credential exchanges and application calls
// retain their existing behavior. Inner-security continuation is outside the
// recovery boundary, even if it returns the same native exception.
func (c *Client) preliminaryLogin(ctx context.Context, passwordMode bool) (*wire.HTTP, error) {
	request := func() ([]byte, error) {
		return c.pdu("POST", c.loginTarget(nil, passwordMode), nil, "", "application/xml", "", 0)
	}
	pdu, err := request()
	if err != nil {
		return nil, err
	}
	reply, err := c.sendHTTP(ctx, pdu, nil, false)
	if err != nil && c.canRecoverContext(ctx, err) {
		original := err
		if err = c.recoverContext(ctx); err != nil {
			return nil, errors.Join(original, err)
		}
		// A fresh client ID belongs in the new request. Never replay the old PDU.
		pdu, err = request()
		if err == nil {
			reply, err = c.sendHTTP(ctx, pdu, nil, false)
		}
		if err != nil {
			return nil, errors.Join(original, err)
		}
	}
	if err != nil {
		return nil, err
	}
	return c.completeHTTP(ctx, pdu, reply)
}

func (c *Client) canRecoverContext(ctx context.Context, err error) bool {
	var native *wire.NativeRPCError
	return !c.cfg.DisableContextRecovery && c.stats.ContextRecoveryAttempts == 0 &&
		ctx.Err() == nil && c.usable() == nil && c.workerAddress != "" &&
		!c.loginCredentialsSent && c.inner == nil && c.session == nil &&
		!c.authenticated && !c.stats.Authenticated && c.lastSync == 0 &&
		errors.As(err, &native) && native.Code() == "infobase_context_releasing" &&
		native.Class() == wire.MustUUID("05a83ab3-14ea-4d74-aef1-3128b035c350")
}

// A custom context can have an uncomparable dynamic type. Only compare values
// when Go permits it; the factory contract still requires fresh independent
// state, which cannot be inferred for arbitrary caller implementations.
func sameSecurityContext(a, b SecurityContext) bool {
	left, right := reflect.ValueOf(a), reflect.ValueOf(b)
	return left.IsValid() && right.IsValid() && left.Type() == right.Type() &&
		left.Comparable() && right.Comparable() && a == b
}

// The caller holds c.mu. The rejected context is fully disposed before any new
// security provider or socket is acquired. Cleanup errors are never suppressed.
func (c *Client) recoverContext(ctx context.Context) error {
	c.stats.ContextRecoveryAttempts++
	retired := c.connection
	previousProvider, previousIdentity := retired.outer, retired.identity
	cleanup, cancel := context.WithTimeout(ctx, 5*time.Second)
	cleanupErr := c.closeLocked(cleanup)
	cancel()
	c.stats.RetiredContextReleased = c.stats.ContextReleased
	c.stats.RetiredSecurityClosed = c.stats.SecurityClosed
	c.stats.RetiredConnectionClosed = cleanupErr == nil && c.stats.Closed
	c.retiredRounds += retired.rounds
	c.retiredSent += retired.sent
	c.retiredReceived += retired.received
	c.connection = nil
	if cleanupErr != nil {
		return fmt.Errorf("retired context cleanup: %w", cleanupErr)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	process, err := wire.NewUUID()
	if err != nil {
		return err
	}
	last, err := wire.NewUUID()
	if err != nil {
		return err
	}
	clientID, err := wire.NewUUID()
	if err != nil {
		return err
	}

	// c.cfg is already normalized. Re-normalizing would reinterpret explicit
	// NTLM/Kerberos options and their generated factory as conflicting providers.
	cfg := c.cfg
	factory := cfg.SecurityFactory
	cfg.SecurityFactory = func() (SecurityContext, error) {
		fresh, err := factory()
		if sameSecurityContext(fresh, previousProvider) {
			return nil, errors.Join(errors.New("context recovery requires a fresh security context"), err)
		}
		if fresh == nil && err == nil {
			err = errors.New("context recovery requires a fresh security context")
		}
		// Preserve a partially constructed provider alongside its error so the
		// owning connection closes it, exactly as on an ordinary initial Dial.
		return fresh, err
	}
	c.closed, c.httpStarted, c.httpComplete = false, false, false
	c.closeErr = nil
	c.clientID = clientID
	c.stats.ContextReleased, c.stats.SecurityClosed, c.stats.Closed = false, false, false
	c.connection, err = openConnectionOwned(ctx, cfg, c.workerAddress, wire.WorkerContext, cfg.Infobase+":"+cfg.Infobase, last, process, &previousIdentity)
	if err != nil {
		// The failed bootstrap has already closed its local resources. Retain
		// its counters and actual security cleanup outcome, without claiming a
		// remote context release that never completed.
		c.closed, c.stats.Closed = true, true
		c.stats.SecurityClosed = c.connection.securityClosed
		c.closeErr = err
		return fmt.Errorf("replacement worker: %w", err)
	}
	c.stats.Connections = append(c.stats.Connections, c.workerAddress)
	c.stats.SecurityContexts = append(c.stats.SecurityContexts, SecurityObservation{"worker", c.connection.mechanism})
	if err = c.connection.query(ctx, wire.HTTPInterface); err != nil {
		cleanup, cancel := context.WithTimeout(ctx, 5*time.Second)
		closeErr := c.closeLocked(cleanup)
		cancel()
		return errors.Join(err, closeErr)
	}
	c.stats.ContextRecoveries++
	return nil
}

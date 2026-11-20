package onec

import (
	"context"
	"errors"
)

// Optional interfaces keep existing SecurityFactory implementations compatible.
func securityStep(ctx context.Context, provider SecurityContext, target string, input []byte) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if p, ok := provider.(interface {
		StepContext(context.Context, string, []byte) ([]byte, bool, error)
	}); ok {
		return p.StepContext(ctx, target, input)
	}
	return provider.Step(target, input)
}

// Peer completion does not replace the provider's own completion rules, including
// server-proof verification for Kerberos. NTLM does not provide that mutual proof.
// No additional client token can be sent after the peer has completed the exchange.
func finishSecurity(ctx context.Context, provider SecurityContext, target string, complete bool, token []byte) error {
	defer clear(token)
	if len(token) != 0 {
		out, done, err := securityStep(ctx, provider, target, token)
		defer clear(out)
		if err != nil {
			return err
		}
		if !done || len(out) != 0 {
			return errors.New("final security proof requires an unsupported continuation")
		}
		complete = done
	}
	if !complete {
		return errors.New("server completed without a verified security context")
	}
	return nil
}

// SecurityObservation reports an established transport or inner context. It
// does not imply infobase login, authorization or encrypted application data.
type SecurityObservation struct {
	Stage     string `json:"stage"`
	Mechanism string `json:"mechanism"`
}

func securityMechanism(provider SecurityContext) string {
	if p, ok := provider.(interface{ Mechanism() (string, error) }); ok {
		if name, err := p.Mechanism(); err == nil && (name == "Kerberos" || name == "NTLM" || name == "NTLM-anonymous") {
			return name
		}
	}
	return "unknown"
}

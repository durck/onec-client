package onec

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"onec/internal/transportpolicy27"
	"onec/wire"
	"time"
)

type connection struct {
	conn                net.Conn
	cfg                 Config
	decoder             *wire.Decoder
	counter             uint32
	target              wire.UUID
	outer               SecurityContext
	policy              *transportpolicy27.Client
	identity, mechanism string
	sync                bool
	released            bool
	securityClosed      bool
	rounds              int
	sent, received      int64
}

func (c *connection) operation(ctx context.Context, fn func() error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	deadline := time.Now().Add(c.cfg.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if e := c.conn.SetDeadline(deadline); e != nil {
		return e
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { c.conn.SetDeadline(time.Now()); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
	}()
	e := fn()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return e
}
func (c *connection) send(p []byte) error {
	for len(p) > 0 {
		n, e := c.conn.Write(p)
		c.sent += int64(n)
		p = p[n:]
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
func (c *connection) exchange(ctx context.Context, p []byte) (out []byte, err error) {
	if !c.sync {
		return nil, errors.New("connection is not synchronized")
	}
	if len(p) > 1024*1024 {
		return nil, errors.New("RPC request limit exceeded")
	}
	c.sync = false
	c.rounds++
	defer func() {
		if !c.sync && c.policy != nil {
			c.policy.Close()
		}
	}()
	err = c.operation(ctx, func() error {
		payload := p
		if c.policy != nil {
			var e error
			payload, e = c.policy.EncodeRequest(p)
			if e != nil {
				return e
			}
			defer clear(payload)
		}
		if e := c.send(wire.EncodeRecord(payload)); e != nil {
			return e
		}
		buf := make([]byte, 8192)
		total := 0
		for {
			n, e := c.conn.Read(buf)
			if n > 0 {
				total += n
				c.received += int64(n)
				if total > 2*1024*1024 {
					return errors.New("RPC response limit exceeded")
				}
				events, de := c.decoder.Feed(buf[:n])
				if de != nil {
					return de
				}
				if len(events) > 0 {
					if len(events) != 1 || events[0].Kind != "record" {
						return errors.New("unexpected outstanding RPC event")
					}
					if de = c.decoder.Finish(); de != nil {
						return de
					}
					out = events[0].Payload
					if c.policy != nil {
						out, de = c.policy.DecodeResponse(events[0].Payload)
						clear(events[0].Payload)
						if de != nil {
							return de
						}
					}
					// A fully consumed record restores framing even if cancellation wins
					// the operation result. Policy state must also be advanced before
					// restoring sync. Never drain or replay an incomplete exchange.
					c.sync = true
					return nil
				}
			}
			if e != nil {
				return e
			}
		}
	})
	return
}
func (c *connection) next() (uint32, error) {
	if c.counter == ^uint32(0) {
		return 0, errors.New("RPC sequence exhausted")
	}
	c.counter++
	return c.counter, nil
}
func openConnection(ctx context.Context, cfg Config, address string, kind wire.UUID, selector string, last, process wire.UUID) (*connection, error) {
	c, err := openConnectionOwned(ctx, cfg, address, kind, selector, last, process, nil)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// openConnectionOwned retains its already-closed partial connection on failure
// so recovery can account for failed bootstrap traffic and cleanup. Ordinary
// callers keep openConnection's nil-on-error contract. The optional identity is
// checked against the exact name used in the introduction, before any dial.
func openConnectionOwned(ctx context.Context, cfg Config, address string, kind wire.UUID, selector string, last, process wire.UUID, expectedIdentity *string) (c *connection, err error) {
	c = &connection{cfg: cfg, sync: true}
	c.decoder, _ = wire.NewDecoder(1024 * 1024)
	defer func(owned *connection) {
		if err != nil {
			err = errors.Join(err, owned.closeSocket())
			c = owned
		}
	}(c)
	options, enabled, err := policyOptions(cfg.TransportPolicy)
	if err != nil {
		return nil, err
	}
	if enabled {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		c.policy, err = transportpolicy27.NewClient(options)
		if err != nil {
			return nil, err
		}
	}
	c.outer, err = cfg.SecurityFactory()
	if err != nil {
		return nil, err
	}
	name, err := c.outer.Name()
	if err != nil {
		return nil, err
	}
	if expectedIdentity != nil && name != *expectedIdentity {
		return nil, errors.New("context recovery security identity changed")
	}
	c.identity = name
	intro, err := wire.Introduction(name)
	if err != nil {
		return nil, err
	}
	c.conn, err = cfg.DialContext(ctx, "tcp4", address)
	if err != nil {
		return nil, err
	}
	err = c.operation(ctx, func() error {
		b := make([]byte, 5)
		n, e := io.ReadFull(c.conn, b)
		c.received += int64(n)
		if e != nil {
			return e
		}
		if !bytes.Equal(b, wire.Greeting) {
			return errors.New("unexpected server greeting")
		}
		p := append(append([]byte{}, wire.Control3...), process.LittleEndian()...)
		return c.send(p)
	})
	if err != nil {
		return nil, err
	}
	var seed [4]byte
	if _, err = rand.Read(seed[:]); err != nil {
		return nil, err
	}
	c.counter = 1000 + binary.LittleEndian.Uint32(seed[:])%30000
	sendToken := func(token []byte) (wire.BootstrapResult, error) {
		p, e := wire.BootstrapRequest(c.counter, kind, computerName(), token, selector, last, cfg.Profile.Version, cfg.Profile.Application)
		if e != nil {
			return wire.BootstrapResult{}, e
		}
		r, e := c.exchange(ctx, p)
		if e != nil {
			return wire.BootstrapResult{}, e
		}
		return wire.ParseBootstrap(r)
	}
	r, err := sendToken(intro)
	if err != nil {
		return nil, fmt.Errorf("bootstrap introduction: %w", err)
	}
	if r.Completed {
		return nil, errors.New("premature bootstrap completion")
	}
	target, packageName, err := wire.IntroductionAck(r.Token)
	if err != nil {
		return nil, err
	}
	if packageName != "Negotiate" {
		return nil, errors.New("unsupported security package")
	}
	var input []byte
	for leg := 0; leg < 3; leg++ {
		token, complete, e := securityStep(ctx, c.outer, target, input)
		clear(input)
		if e != nil {
			return nil, e
		}
		if _, e = c.next(); e != nil {
			return nil, e
		}
		r, e = sendToken(token)
		clear(token)
		if e != nil {
			return nil, fmt.Errorf("bootstrap security: %w", e)
		}
		if r.Completed {
			if !r.HasTarget {
				return nil, errors.New("bootstrap did not return a completed remote context")
			}
			if e := finishSecurity(ctx, c.outer, target, complete, r.Token); e != nil {
				return nil, e
			}
			c.target = r.Target
			c.mechanism = securityMechanism(c.outer)
			return c, nil
		}
		input = r.Token
		if len(input) == 0 {
			return nil, errors.New("missing bootstrap security token")
		}
	}
	return nil, errors.New("bootstrap security round limit")
}
func (c *connection) query(ctx context.Context, iid wire.UUID) error {
	n, e := c.next()
	if e != nil {
		return e
	}
	p, e := wire.QueryRequest(c.target, n, iid)
	if e != nil {
		return e
	}
	r, e := c.exchange(ctx, p)
	if e != nil {
		return e
	}
	return wire.ParseQuery(r)
}
func (c *connection) release(ctx context.Context) error {
	if c.released {
		return nil
	}
	if !c.sync {
		return errors.New("cannot release unsynchronized context")
	}
	n, e := c.next()
	if e != nil {
		return e
	}
	p, e := wire.ReleaseRequest(c.target, n)
	if e != nil {
		return e
	}
	r, e := c.exchange(ctx, p)
	if e != nil {
		return e
	}
	if e = wire.ParseRelease(r); e == nil {
		c.released = true
	}
	return e
}
func (c *connection) closeSocket() error {
	if c == nil {
		return nil
	}
	var errs []error
	if c.policy != nil {
		c.policy.Close()
		c.policy = nil
	}
	if c.conn != nil {
		errs = append(errs, c.conn.Close())
		c.conn = nil
	}
	if c.outer != nil {
		e := c.outer.Close()
		errs = append(errs, e)
		c.securityClosed = e == nil
		c.outer = nil
	}
	return errors.Join(errs...)
}

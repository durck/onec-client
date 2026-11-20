package secpswd

import (
	"crypto/rand"
	"errors"
	"io"
	"time"
)

type Version int

const (
	V1 Version = 1
	V2 Version = 2
	V3 Version = 3
)

func (v Version) NativeSelector() int { return int(v) - 1 }

type State string

const (
	New      State = "new"
	WaitS2   State = "wait_s2"
	WaitS4   State = "wait_s4"
	WaitS6   State = "wait_s6"
	Accepted State = "accepted"
	Rejected State = "rejected"
	Failed   State = "failed"
	Closed   State = "closed"
)

type Options struct {
	Random io.Reader
	Now    func() time.Time
	MaxAge time.Duration
}

// Step either carries the next credential, or a final result. Do not log Credential.
type Step struct {
	Credential         string `json:"-"`
	Completed, Success bool
}

func (s Step) String() string {
	if s.Completed {
		if s.Success {
			return "SecPswd accepted"
		}
		return "SecPswd rejected"
	}
	return "SecPswd continuation (redacted)"
}

type Client struct {
	version               Version
	state                 State
	rng                   io.Reader
	now                   func() time.Time
	maxAge                time.Duration
	started               time.Time
	password, rcc, rc, rs []byte
	keys                  [][]byte
}

func (s Step) GoString() string    { return s.String() }
func (c *Client) String() string   { return "SecPswd state machine (redacted)" }
func (c *Client) GoString() string { return c.String() }

// NewClient creates a single-use exchange. MaxAge zero means 18 seconds;
// a negative MaxAge disables expiry for deterministic offline tests.
func NewClient(version Version, opt *Options) (*Client, error) {
	if version < V1 || version > V3 {
		return nil, errors.New("SecPswd version must be 1, 2 or 3")
	}
	c := &Client{version: version, state: New, rng: rand.Reader, now: time.Now, maxAge: 18 * time.Second}
	if opt != nil {
		if opt.Random != nil {
			c.rng = opt.Random
		}
		if opt.Now != nil {
			c.now = opt.Now
		}
		if opt.MaxAge != 0 {
			c.maxAge = opt.MaxAge
		}
	}
	return c, nil
}
func (c *Client) Version() Version    { return c.version }
func (c *Client) State() State        { return c.state }
func (c *Client) Authenticated() bool { return c.state == Accepted }
func (c *Client) wipe() {
	clear(c.password)
	clear(c.rcc)
	clear(c.rc)
	clear(c.rs)
	for _, k := range c.keys {
		clear(k)
	}
	c.password = nil
	c.rcc = nil
	c.rc = nil
	c.rs = nil
	c.keys = nil
}
func (c *Client) Close() { c.wipe(); c.state = Closed }
func (c *Client) Start(user, password string) (out string, err error) {
	if c.state != New {
		return "", errors.New("credential exchange already started")
	}
	defer func() {
		if err != nil {
			c.wipe()
			c.state = Failed
		}
	}()
	if err = validText(user); err != nil {
		return
	}
	if err = validText(password); err != nil {
		return
	}
	c.password = []byte(password)
	var packet []byte
	switch c.version {
	case V3:
		noise, e := random(c.rng, 16)
		if e != nil {
			return "", e
		}
		body := append(append([]byte{1}, b8(noise)...), b32([]byte(user))...)
		packet, err = encrypt(envelopeKey, addCRC(body), envelopeIV, c.rng)
	case V2:
		c.rc, err = random(c.rng, 32)
		if err != nil {
			return
		}
		normal, e := PasswordKey(password, 0, nil, true)
		if e != nil {
			return "", e
		}
		defer clear(normal)
		upper, e := PasswordKey(password, 0, nil, false)
		if e != nil {
			return "", e
		}
		defer clear(upper)
		a, e := encrypt(normal, c.rc, messageIV, c.rng)
		if e != nil {
			return "", e
		}
		b, e := encrypt(upper, c.rc, messageIV, c.rng)
		if e != nil {
			return "", e
		}
		body := append(append(append([]byte{1}, b8(a)...), b8(b)...), b32([]byte(user))...)
		packet = addCRC(body)
	case V1:
		c.rcc, err = random(c.rng, 32)
		if err != nil {
			return
		}
		normal, e := PasswordKey(password, 0, nil, true)
		if e != nil {
			return "", e
		}
		upper, e := PasswordKey(password, 0, nil, false)
		if e != nil {
			clear(normal)
			return "", e
		}
		c.keys = append(c.keys, normal)
		if !sameKey(normal, upper) {
			c.keys = append(c.keys, upper)
		} else {
			clear(upper)
		}
		packet = addCRC(append(append([]byte{1}, b32([]byte(user))...), b8(c.rcc)...))
	}
	if err != nil {
		return
	}
	out, err = encode(packet)
	if err == nil {
		c.started = c.now()
		c.state = WaitS2
	}
	return
}
func (c *Client) Receive(credential string) (result Step, err error) {
	if c.state != WaitS2 && c.state != WaitS4 && c.state != WaitS6 {
		return result, errors.New("no credential expected in this state")
	}
	defer func() {
		if err != nil {
			c.wipe()
			c.state = Failed
		}
	}()
	if c.maxAge > 0 && c.now().Sub(c.started) >= c.maxAge {
		return result, errors.New("credential exchange expired")
	}
	packet, e := decode(credential)
	if e != nil {
		return result, e
	}
	if c.version == V1 {
		return c.receiveV1(packet)
	}
	if c.version == V3 && c.state == WaitS2 {
		return c.receiveV3(packet)
	}
	if c.state == WaitS6 || c.version == V2 && c.state == WaitS4 {
		return c.complete(equal(packet, []byte("suc"))), nil
	}
	return c.receiveServerKey(packet)
}
func (c *Client) complete(success bool) Step {
	c.wipe()
	c.state = Rejected
	if success {
		c.state = Accepted
	}
	return Step{Completed: true, Success: success}
}
func (c *Client) receiveV3(packet []byte) (Step, error) {
	r, e := encryptedReader(envelopeKey, packet, envelopeIV)
	if e != nil {
		return Step{}, e
	}
	defer clear(r.data)
	r.b8()
	mode := int(r.u8())
	salt := r.b8()
	strong := r.u8()
	if e = r.finish(); e != nil {
		return Step{}, e
	}
	if mode > 3 || strong > 1 {
		return Step{}, errors.New("invalid V3 hash parameters")
	}
	key, e := PasswordKey(string(c.password), mode, salt, strong == 1)
	if e != nil {
		return Step{}, e
	}
	defer clear(key)
	rc, e := random(c.rng, 32)
	if e != nil {
		return Step{}, e
	}
	encrypted, e := encrypt(key, rc, messageIV, c.rng)
	if e != nil {
		clear(rc)
		return Step{}, e
	}
	out, e := encode(addCRC(append([]byte{3}, b8(encrypted)...)))
	if e != nil {
		clear(rc)
		return Step{}, e
	}
	c.rc = rc
	c.state = WaitS4
	return Step{Credential: out}, nil
}
func (c *Client) receiveServerKey(packet []byte) (Step, error) {
	b, e := checkCRC(packet)
	if e != nil {
		return Step{}, e
	}
	r := reader{data: b}
	encrypted := r.b8()
	strong := r.u8()
	if e = r.finish(); e != nil {
		return Step{}, e
	}
	if strong != '0' && strong != '1' {
		return Step{}, errors.New("invalid strong-password flag")
	}
	rs, e := decrypt(c.rc, encrypted, messageIV)
	if e != nil {
		return Step{}, e
	}
	defer clear(rs)
	if len(rs) != 32 {
		return Step{}, errors.New("invalid server key length")
	}
	noise, e := random(c.rng, 32)
	if e != nil {
		return Step{}, e
	}
	body := append(b8(noise), b32(c.password)...)
	defer clear(body)
	encrypted, e = encrypt(rs, addCRC(body), messageIV, c.rng)
	if e != nil {
		return Step{}, e
	}
	out, e := encode(encrypted)
	if e != nil {
		return Step{}, e
	}
	c.wipe()
	c.state = WaitS4
	if c.version == V3 {
		c.state = WaitS6
	}
	return Step{Credential: out}, nil
}
func (c *Client) receiveV1(packet []byte) (Step, error) {
	if c.state == WaitS4 {
		r, e := encryptedReader(c.rs, packet, messageIV)
		if e != nil {
			return Step{}, e
		}
		defer clear(r.data)
		result := r.b8()
		r.b8()
		if e = r.finish(); e != nil {
			return Step{}, e
		}
		return c.complete(equal(result, []byte("suc"))), nil
	}
	var noise, rs []byte
	count := 0
	for _, key := range c.keys {
		r, e := encryptedReader(key, packet, messageIV)
		if e != nil {
			continue
		}
		n, s, echo := r.b8(), r.b8(), r.b8()
		if r.finish() == nil && len(s) == 32 && equal(echo, c.rcc) {
			count++
			noise = append([]byte(nil), n...)
			rs = append([]byte(nil), s...)
		}
		clear(r.data)
	}
	if count != 1 {
		return Step{}, errors.New("invalid or ambiguous V1 server challenge")
	}
	defer clear(noise)
	body := append(b32(c.password), b8(noise)...)
	defer clear(body)
	encrypted, e := encrypt(rs, addCRC(body), messageIV, c.rng)
	if e != nil {
		clear(rs)
		return Step{}, e
	}
	out, e := encode(encrypted)
	if e != nil {
		clear(rs)
		return Step{}, e
	}
	c.wipe()
	c.rs = rs
	c.state = WaitS4
	return Step{Credential: out}, nil
}

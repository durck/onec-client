package transportpolicy27

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
)

// Options is explicit protocol selection, independent of a claimed version.
// Requested and Minimum are separate values; a higher reply can be accepted.
type Options struct {
	Requested Level
	Minimum   Level
	// MaxRecordSize bounds encoded requests and received policy records.
	// Zero selects 1 MiB. Values outside 256 bytes..16 MiB are rejected.
	MaxRecordSize int
}

type phase byte

const (
	fresh phase = iota
	initialPending
	ready
	replyPending
	closed
)

// Client owns one serialized policy exchange. It must not be copied and is not
// concurrency safe.
// Every error irreversibly closes it; an I/O failure after EncodeRequest must
// also call Close. A caller must not retry, rewind the IV or reuse this state
// on a reconnected socket. Outer record framing remains the caller's job.
type Client struct {
	options Options
	phase   phase
	private *rsa.PrivateKey
	data    material
}

func (Client) String() string     { return "1C transport policy (redacted)" }
func (c Client) GoString() string { return c.String() }

// NewClient creates fresh local RSA material. It performs no I/O or native calls.
func NewClient(options Options) (*Client, error) {
	if !supported(options.Requested) || !supported(options.Minimum) {
		return nil, errPolicy
	}
	if options.MaxRecordSize == 0 {
		options.MaxRecordSize = 1 << 20
	}
	if options.MaxRecordSize < 256 || options.MaxRecordSize > 16<<20 {
		return nil, errLimit
	}
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, errors.New("transport policy key generation failed")
	}
	return &Client{options: options, private: key}, nil
}

// EncodeRequest adds the initial public-key header, or the negotiated transform.
// The returned bytes are a record payload, without outer transport markers.
func (c *Client) EncodeRequest(body []byte) (out []byte, err error) {
	defer func() {
		if err != nil {
			c.Close()
		}
	}()
	if c == nil || (c.phase != fresh && c.phase != ready) {
		return nil, errState
	}
	if len(body) == 0 || len(body) > c.options.MaxRecordSize {
		return nil, errLimit
	}
	switch {
	case c.phase == fresh:
		out = requestHeader(c.options.Requested, &c.private.PublicKey)
		out = append(out, body...)
		c.phase = initialPending
	case c.data.level == None:
		out = bytes.Clone(body)
		c.phase = replyPending
	default:
		c.data.advance()
		plain := make([]byte, len(body)+1)
		plain[0] = '0' + byte(c.data.level)
		copy(plain[1:], body)
		out, err = c.data.encrypt(plain)
		clear(plain)
		c.phase = replyPending
	}
	if err == nil && len(out) > c.options.MaxRecordSize {
		clear(out)
		return nil, errLimit
	}
	return out, err
}

// DecodeResponse consumes exactly one response payload. Malformed input,
// refusal, unsupported policy and insufficient level expose one generic error.
func (c *Client) DecodeResponse(record []byte) (body []byte, err error) {
	defer func() {
		if err != nil {
			c.Close()
		}
	}()
	if c == nil || (c.phase != initialPending && c.phase != replyPending) {
		return nil, errState
	}
	if len(record) == 0 || len(record) > c.options.MaxRecordSize {
		return nil, errLimit
	}
	if c.phase == initialPending {
		body, err = c.initialResponse(record)
	} else if c.data.level == None {
		body = bytes.Clone(record)
	} else {
		body, err = c.data.decrypt(record)
		if err == nil {
			// rtrsrvc 016de0/019470: markers 0/1/2, then minimum check.
			// The reply marker does not replace the negotiated effective level.
			if len(body) == 0 || body[0] < '0' || body[0] > '2' || Level(body[0]-'0') < c.options.Minimum {
				clear(body)
				return nil, errPolicy
			}
			body[0] = 0
			body = body[1:]
		}
	}
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, errPolicy
	}
	c.phase = ready
	return body, nil
}

func (c *Client) initialResponse(record []byte) ([]byte, error) {
	header, encryptedBody, err := splitHeader(record)
	if err != nil {
		return nil, errPolicy
	}
	defer clear(header)
	if !bytes.HasPrefix(header, []byte("\xef\xbb\xbf")) {
		return nil, errPolicy
	}
	encrypted, rest, err := readBinaryField(header[3:], 128)
	if err != nil || len(rest) != 0 {
		clear(encrypted)
		return nil, errPolicy
	}
	defer clear(encrypted)
	// inet 020940: mode zero is RSAES-PKCS1-v1_5. Neither malformed RSA
	// nor a malformed decrypted policy can be interpreted as application data.
	plain, err := rsa.DecryptPKCS1v15(nil, c.private, encrypted)
	c.private = nil
	if err != nil {
		return nil, errPolicy
	}
	defer clear(plain)
	policy, remainder, err := splitHeader(plain)
	if err != nil {
		return nil, errPolicy
	}
	defer clear(policy)
	if len(remainder) != 0 {
		return nil, errPolicy
	}
	c.data, err = readMaterial(policy, c.options.Minimum)
	if err != nil {
		return nil, errPolicy
	}
	return c.data.decrypt(encryptedBody)
}

// EffectiveLevel reports a completed negotiation, never an unverified reply.
func (c *Client) EffectiveLevel() (Level, bool) {
	if c == nil || (c.phase != ready && c.phase != replyPending) {
		return None, false
	}
	return c.data.level, true
}

// Close discards owned material and makes further use fail. It is idempotent.
// Go's RSA internals and garbage collector do not guarantee physical erasure.
func (c *Client) Close() {
	if c != nil {
		c.data.clear()
		c.private = nil
		c.phase = closed
	}
}

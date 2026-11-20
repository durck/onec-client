package ntlmauth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"
)

const (
	unicodeFlag      uint32 = 0x00000001
	requestTarget    uint32 = 0x00000004
	signFlag         uint32 = 0x00000010
	ntlmFlag         uint32 = 0x00000200
	alwaysSign       uint32 = 0x00008000
	extendedSecurity uint32 = 0x00080000
	targetInfoFlag   uint32 = 0x00800000
	versionFlag      uint32 = 0x02000000
	strength128      uint32 = 0x20000000
	keyExchange      uint32 = 0x40000000
	requiredFlags           = unicodeFlag | ntlmFlag | extendedSecurity | targetInfoFlag | strength128
	clientFlags             = requiredFlags | requestTarget | signFlag | alwaysSign | keyExchange
	maxToken                = 65536
)

var signature = []byte("NTLMSSP\x00")
var errChallenge = errors.New("invalid or unsupported NTLMv2 challenge")

// Context is one exchange. Step emits raw NTLMSSP tokens for a Negotiate acceptor.
// A complete client token is not proof of server identity: NTLM is not mutual auth.
// Every error permanently fails this context. Methods are safe for concurrent use.
type Context struct{ state *contextState }
type contextState struct {
	mu        sync.Mutex
	identity  Identity
	key       [16]byte
	target    string
	negotiate []byte
	phase     int // 0 initial, 1 challenge expected, 2 final token emitted, 3 closed/failed
}

func (Context) String() string     { return "NTLMv2 context (secret redacted)" }
func (c Context) GoString() string { return c.String() }
func (c *Context) Name() (string, error) {
	if c == nil || c.state == nil {
		return "", errClosed
	}
	s := c.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == 3 {
		return "", errClosed
	}
	return s.identity.Domain + "\\" + s.identity.User, nil
}
func (c *Context) Mechanism() (string, error) {
	if c == nil || c.state == nil {
		return "", errClosed
	}
	s := c.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != 2 {
		return "", errors.New("NTLM exchange not complete")
	}
	return "NTLM", nil
}
func (c *Context) Close() error {
	if c == nil || c.state == nil {
		return nil
	}
	s := c.state
	s.mu.Lock()
	defer s.mu.Unlock()
	s.close()
	return nil
}
func (s *contextState) close() {
	clear(s.key[:])
	clear(s.negotiate)
	s.negotiate = nil
	s.phase = 3
}
func (c *Context) Step(target string, input []byte) ([]byte, bool, error) {
	return c.StepContext(context.Background(), target, input)
}
func (c *Context) StepContext(ctx context.Context, target string, input []byte) (out []byte, complete bool, err error) {
	if c == nil || c.state == nil {
		return nil, false, errClosed
	}
	s := c.state
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() {
		if err != nil {
			s.close()
			clear(out)
			out = nil
			complete = false
		}
	}()
	if err = ctx.Err(); err != nil {
		return
	}
	if s.phase == 3 {
		return nil, false, errClosed
	}
	if len(target) == 0 || len(target) > 4096 || (s.phase != 0 && target != s.target) {
		return nil, false, errors.New("NTLM target missing or changed within the exchange")
	}
	if s.phase == 0 {
		if len(input) != 0 {
			return nil, false, errors.New("unexpected initial NTLM token")
		}
		s.target = target
		s.negotiate = make([]byte, 32)
		copy(s.negotiate, signature)
		binary.LittleEndian.PutUint32(s.negotiate[8:], 1)
		binary.LittleEndian.PutUint32(s.negotiate[12:], clientFlags)
		s.phase = 1
		return bytes.Clone(s.negotiate), false, nil
	}
	if s.phase != 1 {
		return nil, false, errors.New("NTLM exchange cannot be restarted or continued after type 3")
	}
	out, err = authenticate(s.identity, s.key[:], s.negotiate, input, rand.Reader, time.Now())
	clear(s.key[:])
	clear(s.negotiate)
	s.negotiate = nil
	if err != nil {
		return nil, false, err
	}
	if err = ctx.Err(); err != nil {
		return
	}
	s.phase = 2
	return out, true, nil
}

func mac(key []byte, data ...[]byte) []byte {
	h := hmac.New(md5.New, key)
	for _, b := range data {
		_, _ = h.Write(b)
	}
	return h.Sum(nil)
}

func authenticate(id Identity, key, negotiate, input []byte, random io.Reader, now time.Time) ([]byte, error) {
	c, err := parseChallenge(input)
	if err != nil {
		return nil, err
	}
	clientNonce := make([]byte, 8)
	defer clear(clientNonce)
	if _, err := io.ReadFull(random, clientNonce); err != nil {
		return nil, errors.New("NTLM random source failed")
	}
	stamp := c.timestamp
	if !c.hasTimestamp {
		binary.LittleEndian.PutUint64(stamp[:], uint64(now.Unix()+11644473600)*10000000+uint64(now.Nanosecond()/100))
	}
	info := c.responseInfo()
	defer clear(info)
	response, sessionKey := computeResponse(key, c.nonce[:], clientNonce, stamp[:], info)
	defer clear(response)
	defer clear(sessionKey)
	exported := bytes.Clone(sessionKey)
	defer clear(exported)
	flags := c.flags & clientFlags
	var encrypted []byte
	if flags&signFlag == 0 {
		flags &^= keyExchange
	}
	if flags&keyExchange != 0 {
		if _, err := io.ReadFull(random, exported); err != nil {
			return nil, errors.New("NTLM random source failed")
		}
		cipher, err := rc4.NewCipher(sessionKey)
		if err != nil {
			return nil, errors.New("NTLM session key setup failed")
		}
		encrypted = make([]byte, 16)
		defer clear(encrypted)
		cipher.XORKeyStream(encrypted, exported)
		cipher.Reset()
	}
	// Version is an all-zero reserved field (VERSION is not advertised). MIC is
	// always at offset 72; all offsets account for its 16 bytes before payload.
	out := make([]byte, 88)
	copy(out, signature)
	binary.LittleEndian.PutUint32(out[8:], 3)
	binary.LittleEndian.PutUint32(out[60:], flags)
	fields := [][]byte{make([]byte, 24), response, utf16Bytes(id.Domain), utf16Bytes(id.User), nil, encrypted}
	for i, b := range fields {
		at := 12 + 8*i
		if i >= 2 && i <= 4 && len(out)%2 != 0 {
			out = append(out, 0)
		}
		binary.LittleEndian.PutUint16(out[at:], uint16(len(b)))
		binary.LittleEndian.PutUint16(out[at+2:], uint16(len(b)))
		binary.LittleEndian.PutUint32(out[at+4:], uint32(len(out)))
		out = append(out, b...)
	}
	mic := mac(exported, negotiate, input, out)
	copy(out[72:88], mic)
	clear(mic)
	return out, nil
}

func computeResponse(key, serverNonce, clientNonce, timestamp, info []byte) ([]byte, []byte) {
	blob := make([]byte, 28, 32+len(info))
	blob[0], blob[1] = 1, 1
	copy(blob[8:16], timestamp)
	copy(blob[16:24], clientNonce)
	blob = append(blob, info...)
	blob = append(blob, 0, 0, 0, 0)
	defer clear(blob)
	proof := mac(key, serverNonce, blob)
	defer clear(proof)
	sessionKey := mac(key, proof)
	return append(append([]byte(nil), proof...), blob...), sessionKey
}

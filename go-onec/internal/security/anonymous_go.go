package security

import (
	stdcontext "context"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
)

// Unicode, NTLM, target information, extended-session negotiation and the
// mandatory ALWAYS_SIGN compatibility flag are offered. Anonymous NTLM provides
// no signing, sealing or peer authentication.
// MS-NLMP 3.3.2: empty user/password => empty NT response and a single zero LM byte.
const anonymousGoFlags uint32 = 0x00888205
const anonymousFlag uint32 = 0x00000800

type anonymousGoContext struct {
	mu     sync.Mutex
	phase  int // 0 initial, 1 challenge expected, 2 token emitted, 3 closed/failed
	target string
}

func newAnonymousGo() Context { return &anonymousGoContext{} }

func (c *anonymousGoContext) Name() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.phase == 3 {
		return "", errors.New("anonymous NTLM context is closed")
	}
	return "ANONYMOUS LOGON", nil
}

func (c *anonymousGoContext) Mechanism() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.phase != 2 {
		return "", errors.New("anonymous NTLM exchange is not complete")
	}
	return "NTLM-anonymous", nil
}

func (c *anonymousGoContext) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.phase, c.target = 3, ""
	return nil
}

func (c *anonymousGoContext) Step(target string, input []byte) ([]byte, bool, error) {
	return c.StepContext(stdcontext.Background(), target, input)
}

func (c *anonymousGoContext) StepContext(ctx stdcontext.Context, target string, input []byte) (out []byte, complete bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer func() {
		if err != nil {
			c.phase, c.target = 3, ""
			clear(out)
			out = nil
			complete = false
		}
	}()
	if err = ctx.Err(); err != nil {
		return
	}
	if c.phase > 1 {
		return nil, false, errors.New("anonymous NTLM exchange cannot be reused")
	}
	if target == "" || len(target) > 4096 || strings.ContainsRune(target, 0) || c.phase == 1 && target != c.target {
		return nil, false, errors.New("anonymous NTLM target missing, invalid or changed")
	}
	if c.phase == 0 {
		if len(input) != 0 {
			return nil, false, errors.New("anonymous NTLM initial input must be empty")
		}
		out = make([]byte, 32)
		copy(out, "NTLMSSP\x00")
		binary.LittleEndian.PutUint32(out[8:], 1)
		binary.LittleEndian.PutUint32(out[12:], anonymousGoFlags)
		c.phase, c.target = 1, target
		return out, false, nil
	}
	if err = validateAnonymousChallenge(input); err != nil {
		return
	}
	flags := binary.LittleEndian.Uint32(input[20:24])
	if flags&0x201 != 0x201 {
		return nil, false, errors.New("anonymous NTLM requires Unicode and NTLM negotiation")
	}
	out = make([]byte, 65)
	copy(out, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(out[8:], 3)
	// Domain, username, workstation, NT response and session key are all empty.
	for at := 12; at <= 52; at += 8 {
		binary.LittleEndian.PutUint32(out[at+4:], 64)
	}
	binary.LittleEndian.PutUint16(out[12:], 1)
	binary.LittleEndian.PutUint16(out[14:], 1)
	binary.LittleEndian.PutUint32(out[60:], flags&anonymousGoFlags|anonymousFlag)
	c.phase = 2
	return out, true, nil
}

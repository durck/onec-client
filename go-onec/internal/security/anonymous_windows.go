//go:build windows

package security

import (
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

type anonymousIdentity struct {
	User           *uint16
	UserLength     uint32
	Domain         *uint16
	DomainLength   uint32
	Password       *uint16
	PasswordLength uint32
	Flags          uint32
}

type anonymousContext struct {
	context
	empty    uint16
	identity anonymousIdentity
	target   string
	started  bool
}

// NewAnonymous creates fresh, explicitly empty NTLM credentials. It never uses
// the current account, the credential cache, or an alternate security provider.
// Its two-leg exchange is restricted to an anonymous token and NULL_SESSION.
func NewAnonymous() (Context, error) {
	c := &anonymousContext{}
	c.identity = anonymousIdentity{User: &c.empty, Domain: &c.empty, Password: &c.empty, Flags: 2}
	name, err := windows.UTF16PtrFromString("NTLM")
	if err != nil {
		return nil, err
	}
	var expiry int64
	// OUTBOUND | AUTOLOGON_RESTRICTED, with nonnull empty Unicode identity.
	s, _, _ := acquire.Call(0, uintptr(unsafe.Pointer(name)), 0x12, 0, uintptr(unsafe.Pointer(&c.identity)), 0, 0, uintptr(unsafe.Pointer(&c.credentials)), uintptr(unsafe.Pointer(&expiry)))
	runtime.KeepAlive(name)
	runtime.KeepAlive(c)
	if uint32(s) != 0 {
		return nil, statusError("anonymous acquire", s)
	}
	c.hasCredentials = true
	return c, nil
}

func (c *anonymousContext) Name() (string, error) {
	if c.closed {
		return "", errors.New("anonymous SSPI is closed")
	}
	// This is an introduction label, not an OS account-name query or account proof.
	return "ANONYMOUS LOGON", nil
}

func (c *anonymousContext) Mechanism() (string, error) {
	if c.closed || !c.established {
		return "", errors.New("anonymous SSPI context is not established")
	}
	return "NTLM-anonymous", nil
}

func (c *anonymousContext) Step(target string, input []byte) (out []byte, complete bool, err error) {
	if c.closed {
		return nil, false, errors.New("anonymous SSPI is closed")
	}
	defer func() {
		if err != nil {
			clear(out)
			out = nil
			complete = false
			err = errors.Join(err, c.Close())
		}
	}()
	if c.established {
		return nil, false, errors.New("anonymous SSPI exchange is already complete")
	}
	if target == "" || c.started && target != c.target {
		return nil, false, errors.New("invalid or changed anonymous SSPI target")
	}
	if c.started {
		if err := validateAnonymousChallenge(input); err != nil {
			return nil, false, err
		}
	} else if len(input) != 0 {
		return nil, false, errors.New("anonymous SSPI initial input must be empty")
	}
	spn, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return nil, false, errors.New("invalid anonymous SSPI target")
	}
	var old, inptr uintptr
	if c.hasContext {
		old = uintptr(unsafe.Pointer(&c.context.context))
	}
	ib := secBuffer{Size: uint32(len(input)), Type: 2}
	id := descriptor{Count: 1, Buffers: &ib}
	if len(input) > 0 {
		ib.Data = unsafe.Pointer(&input[0])
		inptr = uintptr(unsafe.Pointer(&id))
	}
	ob := secBuffer{Type: 2}
	od := descriptor{Count: 1, Buffers: &ob}
	var attrs uint32
	var expiry int64
	s, _, _ := initialize.Call(uintptr(unsafe.Pointer(&c.credentials)), old, uintptr(unsafe.Pointer(spn)), 0x113|anonymousNullSession, 0, 0x10, inptr, 0, uintptr(unsafe.Pointer(&c.context.context)), uintptr(unsafe.Pointer(&od)), uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Pointer(&expiry)))
	runtime.KeepAlive(input)
	runtime.KeepAlive(spn)
	runtime.KeepAlive(id)
	runtime.KeepAlive(c)
	defer func() {
		if ob.Data != nil {
			freeBuffer.Call(uintptr(ob.Data))
		}
	}()
	code := uint32(s)
	if code&0x80000000 != 0 {
		return nil, false, statusError("anonymous initialize", s)
	}
	c.hasContext = true
	if code == 0x90313 || code == 0x90314 {
		st, _, _ := completeToken.Call(uintptr(unsafe.Pointer(&c.context.context)), uintptr(unsafe.Pointer(&od)))
		if uint32(st) != 0 {
			return nil, false, statusError("anonymous complete token", st)
		}
	}
	if od.Version != 0 || od.Count != 1 || od.Buffers != &ob || ob.Type != 2 || ob.Size == 0 || ob.Size > anonymousTokenLimit || ob.Data == nil {
		return nil, false, errors.New("invalid anonymous SSPI output buffer")
	}
	token := unsafe.Slice((*byte)(ob.Data), int(ob.Size))
	complete, err = validateAnonymousStep(c.started, code, attrs, token)
	if err != nil {
		return nil, false, err
	}
	c.started, c.target, c.established = true, target, complete
	return append([]byte(nil), token...), c.established, nil
}

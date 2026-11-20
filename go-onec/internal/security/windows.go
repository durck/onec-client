//go:build windows

package security

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"runtime"
	"unsafe"
)

var dll = windows.NewLazySystemDLL("secur32.dll")
var acquire = dll.NewProc("AcquireCredentialsHandleW")
var query = dll.NewProc("QueryCredentialsAttributesW")
var queryContext = dll.NewProc("QueryContextAttributesW")
var initialize = dll.NewProc("InitializeSecurityContextW")
var completeToken = dll.NewProc("CompleteAuthToken")
var deleteContext = dll.NewProc("DeleteSecurityContext")
var freeCredentials = dll.NewProc("FreeCredentialsHandle")
var freeBuffer = dll.NewProc("FreeContextBuffer")

type handle struct{ Lower, Upper uintptr }
type secBuffer struct {
	Size, Type uint32
	Data       unsafe.Pointer
}
type descriptor struct {
	Version, Count uint32
	Buffers        *secBuffer
}
type context struct {
	credentials, context               handle
	hasCredentials, hasContext, closed bool
	established                        bool
}

// Mechanism queries the negotiated package after completion; an offered
// Negotiate package or an output token alone is not proof of Kerberos.
func (c *context) Mechanism() (string, error) {
	if c.closed || !c.established {
		return "", errors.New("SSPI context is not established")
	}
	type packageInfo struct {
		Capabilities   uint32
		Version, RPCID uint16
		MaxToken       uint32
		Name, Comment  *uint16
	}
	var result struct {
		Package *packageInfo
		State   uint32
	}
	s, _, _ := queryContext.Call(uintptr(unsafe.Pointer(&c.context)), 12, uintptr(unsafe.Pointer(&result)))
	if uint32(s) != 0 {
		return "", statusError("negotiated package", s)
	}
	if result.Package == nil {
		return "", errors.New("SSPI returned no negotiated package")
	}
	defer freeBuffer.Call(uintptr(unsafe.Pointer(result.Package)))
	if result.State != 0 {
		return "", errors.New("SSPI negotiation is not complete")
	}
	return windows.UTF16PtrToString(result.Package.Name), nil
}

func statusError(op string, s uintptr) error {
	return fmt.Errorf("SSPI %s failed (0x%08x)", op, uint32(s))
}
func New() (Context, error) {
	c := &context{}
	name, e := windows.UTF16PtrFromString("Negotiate")
	if e != nil {
		return nil, e
	}
	var expiry int64
	s, _, _ := acquire.Call(0, uintptr(unsafe.Pointer(name)), 2, 0, 0, 0, 0, uintptr(unsafe.Pointer(&c.credentials)), uintptr(unsafe.Pointer(&expiry)))
	runtime.KeepAlive(name)
	if uint32(s) != 0 {
		return nil, statusError("acquire", s)
	}
	c.hasCredentials = true
	return c, nil
}
func (c *context) Name() (string, error) {
	if c.closed {
		return "", errors.New("SSPI is closed")
	}
	var p *uint16
	s, _, _ := query.Call(uintptr(unsafe.Pointer(&c.credentials)), 1, uintptr(unsafe.Pointer(&p)))
	if uint32(s) != 0 {
		return "", statusError("credential name", s)
	}
	if p == nil {
		return "", errors.New("SSPI returned an empty credential name")
	}
	defer freeBuffer.Call(uintptr(unsafe.Pointer(p)))
	return windows.UTF16PtrToString(p), nil
}
func (c *context) Step(target string, input []byte) ([]byte, bool, error) {
	if c.closed {
		return nil, false, errors.New("SSPI is closed")
	}
	if len(input) > 65535 {
		return nil, false, errors.New("SSPI token limit")
	}
	spn, e := windows.UTF16PtrFromString(target)
	if e != nil {
		return nil, false, errors.New("invalid SSPI target")
	}
	var old uintptr
	if c.hasContext {
		old = uintptr(unsafe.Pointer(&c.context))
	}
	var inptr uintptr
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
	// Same native flags as the reference, plus OS-managed output allocation.
	s, _, _ := initialize.Call(uintptr(unsafe.Pointer(&c.credentials)), old, uintptr(unsafe.Pointer(spn)), 0x113, 0, 0x10, inptr, 0, uintptr(unsafe.Pointer(&c.context)), uintptr(unsafe.Pointer(&od)), uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Pointer(&expiry)))
	runtime.KeepAlive(input)
	runtime.KeepAlive(spn)
	runtime.KeepAlive(id)
	code := uint32(s)
	if ob.Data != nil {
		defer freeBuffer.Call(uintptr(ob.Data))
	}
	if code&0x80000000 != 0 {
		return nil, false, statusError("initialize", s)
	}
	c.hasContext = true
	if code == 0x90313 || code == 0x90314 {
		st, _, _ := completeToken.Call(uintptr(unsafe.Pointer(&c.context)), uintptr(unsafe.Pointer(&od)))
		if uint32(st) != 0 {
			return nil, false, statusError("complete token", st)
		}
	}
	if code != 0 && code != 0x90312 && code != 0x90313 && code != 0x90314 {
		return nil, false, statusError("unexpected status", s)
	}
	if ob.Size > 65535 || ob.Size > 0 && ob.Data == nil {
		return nil, false, errors.New("invalid SSPI output buffer")
	}
	var out []byte
	if ob.Size > 0 {
		out = append([]byte(nil), unsafe.Slice((*byte)(ob.Data), int(ob.Size))...)
	}
	c.established = code == 0 || code == 0x90313
	return out, c.established, nil
}
func (c *context) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	var errs []error
	if c.hasContext {
		s, _, _ := deleteContext.Call(uintptr(unsafe.Pointer(&c.context)))
		if uint32(s) != 0 {
			errs = append(errs, statusError("delete context", s))
		}
		c.hasContext = false
	}
	if c.hasCredentials {
		s, _, _ := freeCredentials.Call(uintptr(unsafe.Pointer(&c.credentials)))
		if uint32(s) != 0 {
			errs = append(errs, statusError("free credentials", s))
		}
		c.hasCredentials = false
	}
	return errors.Join(errs...)
}

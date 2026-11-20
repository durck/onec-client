// Package ntlmauth implements explicit, connection-oriented NTLMv2 credentials
// for the 1C authentication exchanges. It never accesses OS credentials or caches.
// It provides authentication tokens, not application message signing or sealing.
package ntlmauth

import (
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/crypto/md4"
)

var errClosed = errors.New("NTLM credentials or context closed")

// Identity is explicit. Domain is the account domain, not a server-discovered
// default. User is the unqualified account name; no current-user fallback exists.
type Identity struct{ Domain, User string }

func ValidateIdentity(id Identity) error {
	for _, s := range []string{id.Domain, id.User} {
		if s == "" || len(s) > 256 || !utf8.ValidString(s) || strings.ContainsAny(s, "\\/\x00") || strings.TrimSpace(s) != s {
			return errors.New("NTLM requires an explicit domain and unqualified username")
		}
		for _, r := range s {
			if unicode.IsControl(r) {
				return errors.New("invalid NTLM identity")
			}
		}
	}
	return nil
}

// Credentials owns a derived NTLMv2 response key, never a retained password or
// NT hash. Close it after all clients using it have closed. NewContext copies the
// response key; closing Credentials does not revoke already-created contexts.
// Erasure is best-effort: Go, hashing implementations and callers can retain copies.
// Copies of Credentials share ownership; constructors leave caller buffers intact.
type Credentials struct{ state *credentialState }
type credentialState struct {
	mu       sync.Mutex
	identity Identity
	key      [16]byte
	closed   bool
}

func (Credentials) String() string     { return "NTLMv2 credentials (secret redacted)" }
func (c Credentials) GoString() string { return c.String() }

// NewPassword accepts UTF-8 password bytes. Clear the caller-owned input after
// this call. An empty password is explicit and never means the current session.
func NewPassword(id Identity, password []byte) (*Credentials, error) {
	if err := ValidateIdentity(id); err != nil {
		return nil, err
	}
	if len(password) > 4096 || !utf8.Valid(password) {
		return nil, errors.New("NTLM password must be valid UTF-8, at most 4096 bytes")
	}
	encoded := utf16Bytes(string(password))
	defer clear(encoded)
	h := md4.New()
	_, _ = h.Write(encoded)
	hash := h.Sum(nil)
	defer clear(hash)
	h.Reset()
	return NewHash(id, hash)
}

// NewHash accepts exactly 16 binary bytes of the NT hash, not a NetNTLM response,
// hexadecimal text or an LM:NT pair. It does not retain or modify the input.
func NewHash(id Identity, hash []byte) (*Credentials, error) {
	if err := ValidateIdentity(id); err != nil {
		return nil, err
	}
	if len(hash) != 16 {
		return nil, errors.New("NT hash must contain exactly 16 bytes")
	}
	key := mac(hash, utf16Bytes(strings.ToUpper(id.User)+id.Domain))
	defer clear(key)
	s := &credentialState{identity: id}
	copy(s.key[:], key)
	return &Credentials{state: s}, nil
}

func (c *Credentials) Validate() error {
	if c == nil || c.state == nil {
		return errClosed
	}
	s := c.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errClosed
	}
	return nil
}
func (c *Credentials) Close() error {
	if c == nil || c.state == nil {
		return nil
	}
	s := c.state
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.key[:])
	s.closed = true
	return nil
}

func (c *Credentials) NewContext() (*Context, error) {
	if c == nil || c.state == nil {
		return nil, errClosed
	}
	s := c.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errClosed
	}
	return &Context{state: &contextState{identity: s.identity, key: s.key}}, nil
}

func utf16Bytes(s string) []byte {
	units := utf16.Encode([]rune(s))
	defer clear(units)
	b := make([]byte, len(units)*2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(b[2*i:], u)
	}
	return b
}

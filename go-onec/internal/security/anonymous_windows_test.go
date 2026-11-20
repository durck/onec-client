//go:build windows

package security

import (
	"os"
	"testing"
	"unsafe"
)

func TestAnonymousIdentityABI(t *testing.T) {
	pointerSize := unsafe.Sizeof(uintptr(0))
	wantSize, wantDomain, wantFlags := uintptr(48), uintptr(16), uintptr(44)
	if pointerSize == 4 {
		wantSize, wantDomain, wantFlags = 28, 8, 24
	}
	if unsafe.Sizeof(anonymousIdentity{}) != wantSize || unsafe.Offsetof(anonymousIdentity{}.Domain) != wantDomain || unsafe.Offsetof(anonymousIdentity{}.Flags) != wantFlags {
		t.Fatal("unexpected Unicode credential identity ABI")
	}
}

func TestAnonymousInvalidStateClosesWithoutNegotiating(t *testing.T) {
	for _, tc := range []struct {
		name, target string
		input        []byte
		started      bool
	}{
		{"empty target", "", nil, false},
		{"initial input", "fixture/server", []byte("private-token-marker"), false},
		{"changed target", "fixture/changed", nil, true},
		{"invalid challenge", "fixture/server", []byte("private-token-marker"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &anonymousContext{started: tc.started, target: "fixture/server"}
			out, done, err := c.Step(tc.target, tc.input)
			if err == nil || len(out) != 0 || done || !c.closed {
				t.Fatal("invalid input did not fail closed")
			}
			if _, err := c.Name(); err == nil {
				t.Fatal("closed context returned a name")
			}
			if _, err := c.Mechanism(); err == nil {
				t.Fatal("closed context returned a mechanism")
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Optional local OS test: fresh explicit empty credentials and a public
// synthetic challenge only. No network, vendor DLL, account or captured token.
func TestAnonymousSSPISyntheticChallenge(t *testing.T) {
	if os.Getenv("ONEC_ANONYMOUS_SSPI_SELFTEST") != "1" {
		t.Skip("requires explicit synthetic OS-SSPI opt-in")
	}
	c, err := NewAnonymous()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if name, err := c.Name(); err != nil || name != "ANONYMOUS LOGON" {
		t.Fatalf("anonymous introduction name: %v", err)
	}
	if _, err := c.(*anonymousContext).Mechanism(); err == nil {
		t.Fatal("mechanism reported before completion")
	}
	first, done, err := c.Step("fixture/server", nil)
	defer clear(first)
	if err != nil || done || validateAnonymousNegotiate(first) != nil {
		t.Fatalf("anonymous negotiation: %v", err)
	}
	final, done, err := c.Step("fixture/server", syntheticAnonymousChallenge())
	defer clear(final)
	if err != nil || !done || validateAnonymousAuthenticate(final) != nil {
		t.Fatalf("anonymous completion: %v", err)
	}
	if mechanism, err := c.(*anonymousContext).Mechanism(); err != nil || mechanism != "NTLM-anonymous" {
		t.Fatalf("anonymous mechanism: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Step("fixture/server", nil); err == nil {
		t.Fatal("closed context accepted a new exchange")
	}
}

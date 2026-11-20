package security

import (
	"encoding/binary"
	"strings"
	"testing"
)

func syntheticAnonymousAuthenticate() []byte {
	b := make([]byte, 65)
	copy(b, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(b[8:], 3)
	for at := 12; at <= 52; at += 8 {
		binary.LittleEndian.PutUint32(b[at+4:], 64)
	}
	binary.LittleEndian.PutUint16(b[12:], 1)
	binary.LittleEndian.PutUint16(b[14:], 1)
	return b
}

func syntheticAnonymousChallenge() []byte {
	// Public synthetic names and nonce; no captured or account material.
	info := []byte{2, 0, 12, 0, 'D', 0, 'o', 0, 'm', 0, 'a', 0, 'i', 0, 'n', 0, 1, 0, 12, 0, 'S', 0, 'e', 0, 'r', 0, 'v', 0, 'e', 0, 'r', 0, 0, 0, 0, 0}
	b := make([]byte, 56+len(info))
	copy(b, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(b[8:], 2)
	binary.LittleEndian.PutUint32(b[16:], 56)
	binary.LittleEndian.PutUint32(b[20:], 0xe28a8235)
	copy(b[24:32], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	binary.LittleEndian.PutUint16(b[40:], uint16(len(info)))
	binary.LittleEndian.PutUint16(b[42:], uint16(len(info)))
	binary.LittleEndian.PutUint32(b[44:], 56)
	copy(b[56:], info)
	b[48], b[55] = 10, 15
	return b
}

func TestAnonymousAuthenticateRejectsAccountProofAndMalformedBuffers(t *testing.T) {
	if err := validateAnonymousAuthenticate(syntheticAnonymousAuthenticate()); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func([]byte){
		"nonzero LM response":                        func(b []byte) { b[64] = 1 },
		"empty LM response outside supported subset": func(b []byte) { binary.LittleEndian.PutUint16(b[12:], 0) },
		"local-call":            func(b []byte) { binary.LittleEndian.PutUint32(b[60:], ntlmLocalCall) },
		"truncated version":     func(b []byte) { binary.LittleEndian.PutUint32(b[60:], ntlmVersion) },
		"NT response":           func(b []byte) { b[20], b[22] = 1, 1 },
		"domain":                func(b []byte) { b[28], b[30] = 1, 1 },
		"user":                  func(b []byte) { b[36], b[38] = 1, 1 },
		"overflow offset":       func(b []byte) { binary.LittleEndian.PutUint32(b[16:], 0xffffffff) },
		"header overlap":        func(b []byte) { binary.LittleEndian.PutUint32(b[16:], 63) },
		"short capacity":        func(b []byte) { binary.LittleEndian.PutUint16(b[14:], 0) },
		"wrong message":         func(b []byte) { binary.LittleEndian.PutUint32(b[8:], 2) },
		"SPNEGO wrapper":        func(b []byte) { b[0] = 0x60 },
		"unbounded empty field": func(b []byte) { binary.LittleEndian.PutUint32(b[56:], 0xffffffff) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b := syntheticAnonymousAuthenticate()
			mutate(b)
			if err := validateAnonymousAuthenticate(b); err == nil {
				t.Fatal("accepted account proof or malformed token")
			}
		})
	}
	b := syntheticAnonymousAuthenticate()
	for n := 0; n < len(b); n++ {
		if err := validateAnonymousAuthenticate(b[:n]); err == nil {
			t.Fatalf("accepted truncated token of length %d", n)
		}
	}
	if err := validateAnonymousAuthenticate(append(b, make([]byte, anonymousTokenLimit)...)); err == nil {
		t.Fatal("accepted oversized token")
	}
}

func TestAnonymousChallengeBoundsAndLocalCall(t *testing.T) {
	b := syntheticAnonymousChallenge()
	if err := validateAnonymousChallenge(b); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < len(b); n++ {
		if err := validateAnonymousChallenge(b[:n]); err == nil {
			t.Fatalf("accepted truncated challenge of length %d", n)
		}
	}
	for name, mutate := range map[string]func([]byte){
		"local-call":                 func(b []byte) { binary.LittleEndian.PutUint32(b[20:], 0xe28ac235) },
		"target info offset":         func(b []byte) { binary.LittleEndian.PutUint32(b[44:], 0xffffffff) },
		"target info header overlap": func(b []byte) { binary.LittleEndian.PutUint32(b[44:], 47) },
		"target info capacity":       func(b []byte) { binary.LittleEndian.PutUint16(b[42:], 0) },
	} {
		t.Run(name, func(t *testing.T) {
			b := syntheticAnonymousChallenge()
			mutate(b)
			if err := validateAnonymousChallenge(b); err == nil {
				t.Fatal("accepted malformed or local-call challenge")
			}
		})
	}
}

func TestAnonymousNegotiateBounds(t *testing.T) {
	b := make([]byte, 32)
	copy(b, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(b[8:], 1)
	if err := validateAnonymousNegotiate(b); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < len(b); n++ {
		if err := validateAnonymousNegotiate(b[:n]); err == nil {
			t.Fatalf("accepted truncated negotiate of length %d", n)
		}
	}
	binary.LittleEndian.PutUint32(b[12:], ntlmLocalCall)
	if err := validateAnonymousNegotiate(b); err == nil {
		t.Fatal("accepted local-call negotiate")
	}
	const private = "private-token-marker"
	if err := validateAnonymousAuthenticate([]byte(private)); err == nil || strings.Contains(err.Error(), private) {
		t.Fatal("missing rejection or token disclosed in error")
	}
}

func TestAnonymousCompletionRequiresTokenAndNullSession(t *testing.T) {
	negotiate := make([]byte, 32)
	copy(negotiate, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(negotiate[8:], 1)
	authenticate := syntheticAnonymousAuthenticate()
	for _, tc := range []struct {
		name                string
		started             bool
		status, attributes  uint32
		token               []byte
		wantDone, wantError bool
	}{
		{"negotiate", false, 0x90312, 0, negotiate, false, false},
		{"completed negotiate token", false, 0x90314, 0, negotiate, false, false},
		{"premature completion", false, 0, anonymousNullSession, authenticate, false, true},
		{"wrong initial token", false, 0x90312, 0, authenticate, false, true},
		{"anonymous completion", true, 0, anonymousNullSession, authenticate, true, false},
		{"completed authenticate token", true, 0x90313, anonymousNullSession, authenticate, true, false},
		{"missing null session", true, 0, 0, authenticate, false, true},
		{"unexpected continuation", true, 0x90312, anonymousNullSession, authenticate, false, true},
		{"missing authenticate", true, 0, anonymousNullSession, nil, false, true},
		{"wrong final token", true, 0, anonymousNullSession, negotiate, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			done, err := validateAnonymousStep(tc.started, tc.status, tc.attributes, tc.token)
			if done != tc.wantDone || (err != nil) != tc.wantError {
				t.Fatalf("completion %t, error %v", done, err)
			}
		})
	}
}

func FuzzAnonymousNTLMBounds(f *testing.F) {
	f.Add(syntheticAnonymousAuthenticate())
	f.Add(syntheticAnonymousChallenge())
	f.Add([]byte("NTLMSSP\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = validateAnonymousNegotiate(b)
		_ = validateAnonymousChallenge(b)
		_ = validateAnonymousAuthenticate(b)
	})
}

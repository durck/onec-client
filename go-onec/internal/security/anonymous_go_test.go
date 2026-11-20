package security

import (
	stdcontext "context"
	"encoding/binary"
	"strings"
	"testing"
)

func TestPortableAnonymousExchange(t *testing.T) {
	c := newAnonymousGo().(*anonymousGoContext)
	defer c.Close()
	if name, err := c.Name(); name != "ANONYMOUS LOGON" || err != nil {
		t.Fatal(name, err)
	}
	first, done, err := c.Step("service/fixture", nil)
	if err != nil || done || validateAnonymousNegotiate(first) != nil {
		t.Fatal("invalid negotiate", err)
	}
	if binary.LittleEndian.Uint32(first[12:16])&0x8000 == 0 {
		t.Fatal("mandatory ALWAYS_SIGN flag missing")
	}
	if _, err := c.Mechanism(); err == nil {
		t.Fatal("premature completion")
	}
	challenge := syntheticAnonymousChallenge()
	final, done, err := c.Step("service/fixture", challenge)
	if err != nil || !done || validateAnonymousAuthenticate(final) != nil {
		t.Fatal("invalid authenticate", err)
	}
	// Independent wire assertions: no identity, account proof, workstation or key.
	if len(final) != 65 || final[64] != 0 || binary.LittleEndian.Uint16(final[12:14]) != 1 {
		t.Fatal("not a null-session response")
	}
	for at := 20; at <= 52; at += 8 {
		if binary.LittleEndian.Uint16(final[at:at+2]) != 0 {
			t.Fatal("nonempty identity/proof/key field", at)
		}
	}
	flags := binary.LittleEndian.Uint32(final[60:64])
	if flags&0x8000 == 0 || flags&anonymousFlag == 0 || flags&(0x10|0x20|0x40000000|ntlmVersion|ntlmLocalCall) != 0 {
		t.Fatal("unsupported session security claimed")
	}
	if mechanism, err := c.Mechanism(); mechanism != "NTLM-anonymous" || err != nil {
		t.Fatal(mechanism, err)
	}
	if _, _, err := c.Step("service/fixture", challenge); err == nil {
		t.Fatal("exchange replay accepted")
	}
}

func TestPortableAnonymousRejectsInvalidExchange(t *testing.T) {
	for _, mode := range []string{"initial-token", "changed-target", "local-call", "missing-unicode", "truncated", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			c := newAnonymousGo().(*anonymousGoContext)
			target := "service/fixture"
			input := syntheticAnonymousChallenge()
			ctx := stdcontext.Background()
			if mode != "initial-token" {
				if _, _, err := c.Step(target, nil); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "initial-token":
				input = []byte("private-token-marker")
			case "changed-target":
				target = "service/other"
			case "local-call":
				binary.LittleEndian.PutUint32(input[20:], binary.LittleEndian.Uint32(input[20:])|ntlmLocalCall)
			case "missing-unicode":
				input[20] &^= 1
			case "truncated":
				input = input[:20]
			case "cancelled":
				var cancel stdcontext.CancelFunc
				ctx, cancel = stdcontext.WithCancel(ctx)
				cancel()
			}
			out, done, err := c.StepContext(ctx, target, input)
			if err == nil || done || len(out) != 0 || strings.Contains(err.Error(), "private-token-marker") {
				t.Fatal("invalid exchange accepted or disclosed")
			}
			if _, err := c.Name(); err == nil {
				t.Fatal("failed context remained reusable")
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

//go:build !windows

package security

import "testing"

func TestAnonymousAvailableWithoutWindows(t *testing.T) {
	provider, err := NewAnonymous()
	if err != nil || provider == nil {
		t.Fatal("pure Go provider unavailable", err)
	}
	defer provider.Close()
	if _, ok := provider.(*anonymousGoContext); !ok {
		t.Fatal("non-Windows anonymous provider must not depend on OS credentials")
	}
}

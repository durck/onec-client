//go:build !windows

package security

// NewAnonymous uses a fresh pure Go null-session exchange on non-Windows hosts.
func NewAnonymous() (Context, error) {
	return newAnonymousGo(), nil
}

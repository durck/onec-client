// Package security isolates operating-system security providers.
package security

// Context owns credentials for one fresh exchange. Tokens are opaque and private.
type Context interface {
	Name() (string, error)
	Step(target string, input []byte) (output []byte, complete bool, err error)
	Close() error
}

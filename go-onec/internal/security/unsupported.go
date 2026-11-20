//go:build !windows

package security

import "errors"

func New() (Context, error) {
	return nil, errors.New("native Windows SSPI requires Windows; supply a compatible security provider on this OS")
}

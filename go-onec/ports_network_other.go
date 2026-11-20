//go:build !windows

package onec

import (
	"errors"
	"syscall"
)

func portConnectionRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }

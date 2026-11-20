package onec

import (
	"errors"
	"golang.org/x/sys/windows"
)

func portConnectionRefused(err error) bool { return errors.Is(err, windows.WSAECONNREFUSED) }

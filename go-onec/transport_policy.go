package onec

import (
	"errors"
	"onec/internal/transportpolicy27"
)

// TransportPolicy explicitly selects native record processing, independently
// of the advertised client version and transport authentication provider.
type TransportPolicy string

const (
	TransportPlain     TransportPolicy = "plain"
	TransportNative27N TransportPolicy = "native27-n" // Experimental n request, minimum n; can accept c.
	TransportNative27C TransportPolicy = "native27-c" // Experimental c request and minimum c.
)

func policyOptions(selection TransportPolicy) (options transportpolicy27.Options, enabled bool, err error) {
	switch selection {
	case "", TransportPlain:
		return options, false, nil
	case TransportNative27N:
		return options, true, nil
	case TransportNative27C:
		options.Requested = transportpolicy27.Encrypted
		options.Minimum = transportpolicy27.Encrypted
		return options, true, nil
	default:
		return options, false, errors.New("transport policy must be plain, native27-n or native27-c")
	}
}

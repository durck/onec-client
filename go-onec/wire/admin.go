package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Native server-agent administration identifiers shared by the inspected
// installed clients. This is independent
// of the working-process AdminProcess context and application manager context.
var ServerAgentContext = MustUUID("bc9113bc-5b88-4c9f-9fc0-ff7ade5450f0")
var ServerAgentInterface = MustUUID("73cdaa77-2afc-436c-b738-58c772e3a0bf")
var ClusterListType = MustUUID("41344e9c-168a-4c10-8df4-0a3700dbd815")

const MaxAdminObjects = 4096

// AdminOutput marks a pure output parameter in a verified method contract.
type AdminOutput struct{}

// AdminRPCError retains only the native class and numeric code. Exception
// descriptions, server paths and stack strings are never exposed.
type AdminRPCError struct {
	Class UUID   `json:"class"`
	Code  uint32 `json:"code"`
}

func (e *AdminRPCError) Error() string {
	return fmt.Sprintf("administrative RPC exception (code %d)", e.Code)
}

// AdminReplyMarker implements the exact-build transport's additive call marker.
// It identifies the target/interface/call; it is not a security authenticator.
func AdminReplyMarker(target UUID, sequence, operation, method uint32) uint32 {
	sum := func(u UUID) uint32 {
		n := binary.BigEndian.Uint32(u[:4]) + uint32(binary.BigEndian.Uint16(u[4:6])) + uint32(binary.BigEndian.Uint16(u[6:8]))
		for _, b := range u[8:] {
			n += uint32(b)
		}
		return n
	}
	n := sum(target) + uint32(uint16(sequence)) + uint32(uint16(operation))
	if operation != 0 {
		n += sum(ServerAgentInterface)
		if operation != 1 {
			n += uint32(uint16(method))
		}
	}
	return n
}

// ParseServerAgentProfile accepts only independently recovered interface tables.
// Method counts identify contracts, not platform version strings.
func ParseServerAgentProfile(p []byte, expectedMarker ...uint32) (uint32, error) {
	top, err := ParseText(p)
	if err == nil && len(top) == 1 {
		if r, ok := List(top[0], 3); ok && textIs(r[0], 1) {
			count, e := TextNumber(r[2])
			if e != nil || (count != 68 && count != 79 && count != 80 && count != 89 && count != 96) {
				return 0, errors.New("unsupported server-agent administration interface")
			}
			if n, e := TextNumber(r[1]); e == nil && n >= 0 && n <= 0xffffffff && (len(expectedMarker) == 0 || len(expectedMarker) == 1 && uint32(n) == expectedMarker[0]) {
				return uint32(count), nil
			}
		}
	}
	return 0, errors.New("unsupported server-agent administration interface")
}

func ParseServerAgentInterface(p []byte, expectedMarker ...uint32) error {
	_, err := ParseServerAgentProfile(p, expectedMarker...)
	return err
}

// AdminCall encodes input arguments as generic values. Call flags and parameter
// directions are supplied by the exact method contract, not inferred from a name.
func AdminCall(target UUID, sequence, method, flags uint32, args ...any) ([]byte, error) {
	if target == (UUID{}) || sequence == 0 || method >= 79 || len(args) > 16 {
		return nil, errors.New("invalid administration call")
	}
	values := []any{0, target, sequence, 4, ServerAgentInterface, method, flags, len(args)}
	for _, arg := range args {
		if _, output := arg.(AdminOutput); output {
			values = append(values, 1)
		} else {
			values = append(values, 0, arg)
		}
	}
	return Pack(values)
}

func parseAdminException(r []any) *AdminRPCError {
	if len(r) != 4 || !IsNumber(r[0], 2) || !IsNumber(r[3], 0) {
		return nil
	}
	class, err := GUID(r[1])
	if err != nil {
		return nil
	}
	wrapper, ok := List(r[2], 2)
	if !ok {
		return nil
	}
	detail, ok := List(wrapper[0], 6)
	if !ok || !IsGUID(detail[0], class) || !IsNumber(detail[5], 0) {
		return nil
	}
	nested, ok := List(detail[2], 1)
	if !ok || !IsNumber(nested[0], 0) {
		return nil
	}
	for _, i := range []int{1, 3, 4} {
		if _, err := String(detail[i]); err != nil {
			return nil
		}
	}
	code, err := Number(wrapper[1])
	if err != nil {
		return nil
	}
	return &AdminRPCError{Class: class, Code: code}
}

// ParseAdminValue validates a zero-argument getter. The reply marker is a native
// checksum of the call identity, not an echo of the client's sequence number.
func ParseAdminValue(p []byte) (any, error) {
	return ParseAdminReply(p, 1, nil)
}

// ParseAdminReply validates return mode and every parameter direction. It returns
// either the generic return value or the one output value. The supported build's
// administration methods never combine a generic return with output parameters.
func ParseAdminReply(p []byte, returnMode uint32, modes []uint32, expectedMarker ...uint32) (any, error) {
	bad := errors.New("invalid administration reply")
	if (returnMode != 1 && returnMode != 3) || len(modes) > 16 {
		return nil, bad
	}
	if len(p) > MaxText {
		return nil, errors.New("administration reply exceeds record limit")
	}
	top, err := DecodeTree(p)
	if err != nil {
		return nil, err
	}
	if len(top) != 2 || !IsNumber(top[1], 2) {
		return nil, bad
	}
	r, ok := List(top[0], -1)
	if !ok {
		return nil, bad
	}
	if e := parseAdminException(r); e != nil {
		return nil, e
	}
	if len(r) < 5 || !IsNumber(r[0], 1) || !IsNumber(r[2], returnMode) {
		return nil, bad
	}
	if marker, err := Number(r[1]); err != nil || len(expectedMarker) > 1 || len(expectedMarker) == 1 && marker != expectedMarker[0] {
		return nil, bad
	}
	pos := 3
	var value any
	if returnMode == 1 {
		value = r[pos]
		pos++
	}
	if pos >= len(r) || !IsNumber(r[pos], uint32(len(modes))) {
		return nil, bad
	}
	pos++
	for _, mode := range modes {
		if mode > 1 || pos >= len(r) || !IsNumber(r[pos], mode) {
			return nil, bad
		}
		pos++
		if mode == 1 {
			if value != nil || pos >= len(r) {
				return nil, bad
			}
			value = r[pos]
			pos++
		}
	}
	if pos != len(r)-1 || !IsNumber(r[pos], 0) {
		return nil, bad
	}
	return value, nil
}

type AdminEndpoint struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
}
type ClusterDescriptor struct {
	ID        UUID
	Name      string
	Endpoints []AdminEndpoint
	Settings  [7]uint32
	// RecyclingSchedule is present in the verified 15-field native layout.
	RecyclingSchedule string
	Layout            int
	// LegacyRecycling preserves the seven scalar arguments after the cluster
	// UUID in the older eight-parameter recycling operation.
	LegacyRecycling [7]int64
}

func adminCollection(value any, kind UUID) ([]any, error) {
	bad := errors.New("unsupported administration collection layout")
	typed, ok := List(value, 3)
	if !ok || !IsString(typed[0], "#") || !IsGUID(typed[1], kind) {
		return nil, bad
	}
	items, ok := List(typed[2], -1)
	if !ok || len(items) == 0 {
		return nil, bad
	}
	n, err := Number(items[0])
	if err != nil || n > MaxAdminObjects || int(n) != len(items)-1 {
		return nil, bad
	}
	return items[1:], nil
}

func ParseAdminClusters(value any) ([]ClusterDescriptor, error) {
	items, err := adminCollection(value, ClusterListType)
	if err != nil {
		return nil, err
	}
	result := make([]ClusterDescriptor, 0, len(items))
	bad := errors.New("unsupported cluster descriptor layout")
	for _, item := range items {
		f, ok := List(item, -1)
		if !ok || (len(f) != 10 && len(f) != 12 && len(f) != 15) {
			return nil, bad
		}
		id, e1 := GUID(f[0])
		name, e2 := String(f[1])
		endpoints, ok := List(f[2], -1)
		if e1 != nil || id == (UUID{}) || e2 != nil || len(name) > 262144 || !ok || len(endpoints) == 0 {
			return nil, bad
		}
		n, e := Number(endpoints[0])
		if e != nil || n > 256 || int(n) != len(endpoints)-1 {
			return nil, bad
		}
		d := ClusterDescriptor{ID: id, Name: name, Endpoints: make([]AdminEndpoint, 0, n), Layout: len(f)}
		for _, endpoint := range endpoints[1:] {
			pair, ok := List(endpoint, 2)
			if !ok {
				return nil, bad
			}
			h, e1 := String(pair[0])
			port, e2 := Number(pair[1])
			if e1 != nil || len(h) > 4096 || e2 != nil || port < 1 || port > 65535 {
				return nil, bad
			}
			d.Endpoints = append(d.Endpoints, AdminEndpoint{Host: h, Port: uint16(port)})
		}
		indices := []int{3, 4, 5, 6, 7, 8, 9}
		if len(f) == 12 {
			// The older native descriptor has a different settings order. Its
			// identity and endpoints remain usable; do not invent field names.
			if !adminFields(f[3:], "i i i i i u i i b") {
				return nil, bad
			}
			indices = nil
			for i, pos := range []int{4, 5, 6, 7, 9, 10, 11} {
				d.LegacyRecycling[i], _ = SignedNumber64(f[pos])
			}
		}
		if len(f) == 15 {
			indices = []int{3, -1, 4, 5, 6, 7, 8}
			if !adminFields(f[3:], "i i u i b b b b i i b s") {
				return nil, bad
			}
			d.RecyclingSchedule, _ = String(f[14])
		}
		for i, pos := range indices {
			if pos < 0 {
				continue
			}
			v, e := Number(f[pos])
			if e != nil {
				return nil, bad
			}
			d.Settings[i] = v
		}
		if d.Settings[5] > 1 || d.Settings[6] > 1 {
			return nil, bad
		}
		result = append(result, d)
	}
	return result, nil
}

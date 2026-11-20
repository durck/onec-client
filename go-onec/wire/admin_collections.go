package wire

import (
	"errors"
	"math"
)

var AdminUsersType = MustUUID("9d95bd82-b4c3-49d5-9077-bc703bd7dc09")
var WorkingServersType = MustUUID("85ae4176-e9f6-4dda-8927-4ebdaea01e3a")
var AdminInfoBasesType = MustUUID("59654aab-c9d2-49e0-ab3b-32f2a3595c5b")

// AdminUserDescriptor contains only properties independently mapped through
// the exact-build native receiver. The opaque password-related third string
// is validated and discarded, never retained in a result or diagnostic.
type AdminUserDescriptor struct {
	Name                string `json:"name"`
	Description         string `json:"description"`
	SysUserName         string `json:"sys_user_name"`
	SysAuthAllowed      bool   `json:"sys_auth_allowed"`
	PasswordAuthAllowed bool   `json:"password_auth_allowed"`
}

type AdminPortRange struct {
	From uint16 `json:"from"`
	To   uint16 `json:"to"`
}

// WorkingServerDescriptor exposes the mapped identity, name, endpoint and
// port-range properties. Remaining fields are schema-checked and omitted.
// Endpoints are informational; these parsers do not connect to them.
type WorkingServerDescriptor struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	MainPort   uint16           `json:"main_port"`
	HostName   string           `json:"host_name"`
	PortRanges []AdminPortRange `json:"port_ranges"`
}

type AdminInfoBaseDescriptor struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func adminCollectionText(value any) (string, error) {
	s, err := String(value)
	if err != nil || len(s) > 262144 {
		return "", errors.New("invalid administration string")
	}
	return s, nil
}

func adminCollectionU16(value any) (uint16, error) {
	n, err := Number(value)
	if err != nil || n > math.MaxUint16 {
		return 0, errors.New("invalid administration uint16")
	}
	return uint16(n), nil
}

// ParseAdminUsers decodes the five-field build-18 administrator rows while
// deliberately excluding the opaque password-related string. Native getter
// probes establish flag masks 1 (password) and 2 (OS); other bits are omitted.
func ParseAdminUsers(value any) ([]AdminUserDescriptor, error) {
	items, err := adminCollection(value, AdminUsersType)
	if err != nil {
		return nil, err
	}
	result := make([]AdminUserDescriptor, 0, len(items))
	bad := errors.New("unsupported administrator descriptor layout")
	for _, item := range items {
		fields, ok := List(item, 5)
		if !ok {
			return nil, bad
		}
		name, e0 := adminCollectionText(fields[0])
		description, e1 := adminCollectionText(fields[1])
		_, e2 := adminCollectionText(fields[2])
		sysUser, e3 := adminCollectionText(fields[3])
		flags, e4 := SignedNumber64(fields[4])
		if e0 != nil || e1 != nil || e2 != nil || e3 != nil || e4 != nil || flags < math.MinInt32 || flags > math.MaxInt32 {
			return nil, bad
		}
		result = append(result, AdminUserDescriptor{Name: name, Description: description, SysUserName: sysUser, PasswordAuthAllowed: flags&1 != 0, SysAuthAllowed: flags&2 != 0})
	}
	return result, nil
}

// ParseAdminWorkingServers validates the variable-width build-18 row. The
// port-range count is followed by exactly that many pairs, then ten tail fields.
// Zero ports are preserved without interpreting them or following endpoints.
func ParseAdminWorkingServers(value any) ([]WorkingServerDescriptor, error) {
	items, err := adminCollection(value, WorkingServersType)
	if err != nil {
		return nil, err
	}
	result := make([]WorkingServerDescriptor, 0, len(items))
	bad := errors.New("unsupported working-server descriptor layout")
	for _, item := range items {
		fields, ok := List(item, -1)
		if !ok || len(fields) < 16 {
			return nil, bad
		}
		id, e0 := GUID(fields[0])
		name, e1 := adminCollectionText(fields[1])
		port, e2 := adminCollectionU16(fields[2])
		host, e3 := adminCollectionText(fields[3])
		_, e4 := SignedNumber64(fields[4])
		rangeCount, e5 := Number(fields[5])
		if e0 != nil || id == (UUID{}) || e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || rangeCount > MaxAdminObjects || len(fields) < 16+int(rangeCount) || len(fields) > 18+int(rangeCount) {
			return nil, bad
		}
		row := WorkingServerDescriptor{ID: id.String(), Name: name, MainPort: port, HostName: host, PortRanges: make([]AdminPortRange, 0, rangeCount)}
		for _, field := range fields[6 : 6+int(rangeCount)] {
			pair, ok := List(field, 2)
			if !ok {
				return nil, bad
			}
			from, e0 := adminCollectionU16(pair[0])
			to, e1 := adminCollectionU16(pair[1])
			if e0 != nil || e1 != nil || from > to {
				return nil, bad
			}
			row.PortRanges = append(row.PortRanges, AdminPortRange{From: from, To: to})
		}
		tail := fields[6+int(rangeCount):]
		for _, i := range []int{0, 1} {
			if _, err := adminCollectionText(tail[i]); err != nil {
				return nil, bad
			}
		}
		for _, i := range []int{2, 3} {
			if _, err := Number(tail[i]); err != nil {
				return nil, bad
			}
		}
		for _, i := range []int{4, 5} {
			if n, err := Number(tail[i]); err != nil || n > 1 {
				return nil, bad
			}
		}
		if _, err := adminCollectionU16(tail[6]); err != nil {
			return nil, bad
		}
		for _, i := range []int{7, 8, 9} {
			if _, err := SignedNumber64(tail[i]); err != nil {
				return nil, bad
			}
		}
		// Later native writers add one or two required strings. The known
		// shapes are distinct; extra primitive or structured fields are refused.
		for _, v := range tail[10:] {
			if _, err := adminCollectionText(v); err != nil {
				return nil, bad
			}
		}
		result = append(result, row)
	}
	return result, nil
}

// ParseAdminInfoBases returns the identity, Name and Descr properties of the
// agent's short infobase descriptors, not detailed working-process objects.
func ParseAdminInfoBases(value any) ([]AdminInfoBaseDescriptor, error) {
	items, err := adminCollection(value, AdminInfoBasesType)
	if err != nil {
		return nil, err
	}
	result := make([]AdminInfoBaseDescriptor, 0, len(items))
	bad := errors.New("unsupported short-infobase descriptor layout")
	for _, item := range items {
		fields, ok := List(item, 3)
		if !ok {
			return nil, bad
		}
		id, e0 := GUID(fields[0])
		name, e1 := adminCollectionText(fields[1])
		description, e2 := adminCollectionText(fields[2])
		if e0 != nil || id == (UUID{}) || e1 != nil || e2 != nil {
			return nil, bad
		}
		result = append(result, AdminInfoBaseDescriptor{ID: id.String(), Name: name, Description: description})
	}
	return result, nil
}

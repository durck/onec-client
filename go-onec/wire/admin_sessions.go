package wire

import "errors"

var AdminProcessListType = MustUUID("ace040f2-4e7e-422a-ac4c-03662bafb6d7")
var AdminSessionListType = MustUUID("a3b238cc-3fa5-406b-a1eb-5347bcae06e2")

// AdminProcessDescriptor projects verified fields. License records and metrics
// whose meaning is not established are validated structurally but not exposed.
type AdminProcessDescriptor struct {
	ID            string `json:"id"`
	HostName      string `json:"host_name"`
	Port          uint16 `json:"port"`
	Enabled       bool   `json:"enabled"`
	Running       int64  `json:"running"`
	PID           string `json:"pid"`
	StartedAtRaw  uint64 `json:"started_at_raw"`
	Connections   uint64 `json:"connections"`
	MemorySize    uint32 `json:"memory_size"`
	SelectionSize uint32 `json:"selection_size"`
}

// AdminSessionDescriptor contains the stable core of the build-18 descriptor.
// InfoBaseID supplies the eraseSeance route; it is never guessed by the caller.
// Optional statistics, time-zone and license extensions are not projected.
type AdminSessionDescriptor struct {
	ID                  string `json:"id"`
	InfoBaseID          string `json:"infobase_id"`
	InfoBaseName        string `json:"infobase_name"`
	InfoBaseDescription string `json:"infobase_description"`
	SessionID           uint32 `json:"session_id"`
	HostName            string `json:"host_name"`
	UserName            string `json:"user_name"`
	Application         string `json:"application"`
	StartedAtRaw        uint64 `json:"started_at_raw"`
	LastActiveAtRaw     uint64 `json:"last_active_at_raw"`
}

func nullableAdminUUID(v any) (UUID, error) {
	if IsNumber(v, 0) {
		return UUID{}, nil
	}
	return GUID(v)
}

func ParseAdminProcesses(value any) ([]AdminProcessDescriptor, error) {
	rows, err := adminCollection(value, AdminProcessListType)
	if err != nil {
		return nil, err
	}
	result := make([]AdminProcessDescriptor, 0, len(rows))
	bad := errors.New("unsupported working-process descriptor layout")
	for _, raw := range rows {
		r, ok := List(raw, -1)
		if !ok || len(r) < 13 || len(r) > MaxAdminObjects+13 {
			return nil, bad
		}
		id, e1 := GUID(r[0])
		host, e2 := String(r[1])
		_, e3 := nullableAdminUUID(r[2])
		port, e4 := Number(r[3])
		enabled, e5 := Number(r[4])
		running, e6 := SignedNumber64(r[5])
		connections, e7 := UnsignedNumber64(r[6])
		started, e8 := UnsignedNumber64(r[7])
		if e1 != nil || id == (UUID{}) || e2 != nil || e3 != nil || e4 != nil || port > 65535 || e5 != nil || enabled > 1 || e6 != nil || running < -2147483648 || running > 2147483647 || e7 != nil || e8 != nil {
			return nil, bad
		}
		stats, ok := List(r[8], 16)
		if !ok {
			return nil, bad
		}
		for i, v := range stats {
			var e error
			switch i {
			case 0, 1, 2, 3, 4, 6, 7, 14:
				_, e = FloatNumber(v)
			case 9:
				n, ne := SignedNumber64(v)
				e = ne
				if n < -2147483648 || n > 2147483647 {
					e = bad
				}
			case 13, 15:
				_, e = UnsignedNumber64(v)
			default:
				_, e = Number(v)
			}
			if e != nil {
				return nil, bad
			}
		}
		pid, e1 := String(r[9])
		_, e2 = SignedNumber64(r[10])
		count, e3 := Number(r[11])
		if e1 != nil || e2 != nil || e3 != nil || count > MaxAdminObjects || len(r) != 13+int(count) {
			return nil, bad
		}
		for _, license := range r[12 : 12+int(count)] {
			if !validAdminLicense(license) {
				return nil, bad
			}
		}
		last, e := Number(r[len(r)-1])
		if e != nil || last > 1 {
			return nil, bad
		}
		memory, _ := Number(stats[8])
		selection, _ := Number(stats[5])
		result = append(result, AdminProcessDescriptor{ID: id.String(), HostName: host, Port: uint16(port), Enabled: enabled == 1, Running: running, PID: pid, StartedAtRaw: started, Connections: connections, MemorySize: memory, SelectionSize: selection})
	}
	return result, nil
}

func ParseAdminSessions(value any) ([]AdminSessionDescriptor, error) {
	rows, err := adminCollection(value, AdminSessionListType)
	if err != nil {
		return nil, err
	}
	result := make([]AdminSessionDescriptor, 0, len(rows))
	bad := errors.New("unsupported session descriptor layout")
	for _, raw := range rows {
		entry, ok := List(raw, -1)
		if !ok || len(entry) < 2 {
			return nil, bad
		}
		// A missing core record cannot provide a safe mutation target.
		if !IsNumber(entry[0], 1) || len(entry) < 3 {
			return nil, bad
		}
		r, ok := List(entry[1], -1)
		if !ok || len(r) < 22 || len(r) > 4096 {
			return nil, bad
		}
		license, e := Number(entry[2])
		if e != nil || license > 1 || len(entry) != 3+int(license) {
			return nil, bad
		}
		if license == 1 && !validAdminLicense(entry[3]) {
			return nil, bad
		}
		ids := make(map[int]UUID, 6)
		for _, i := range []int{0, 1, 13, 15, 16, 19} {
			u, e := nullableAdminUUID(r[i])
			if e != nil {
				return nil, bad
			}
			ids[i] = u
		}
		if ids[0] == (UUID{}) || ids[1] == (UUID{}) {
			return nil, bad
		}
		str := make(map[int]string, 9)
		for _, i := range []int{2, 3, 7, 8, 9, 11, 12, 17, 18} {
			s, e := String(r[i])
			if e != nil {
				return nil, bad
			}
			str[i] = s
		}
		display, e1 := Number(r[4])
		started, e2 := UnsignedNumber64(r[5])
		active, e3 := UnsignedNumber64(r[6])
		port, e4 := Number(r[10])
		_, e5 := Number(r[14])
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || port > 65535 || e5 != nil {
			return nil, bad
		}
		// The first optional statistics representation has unresolved list
		// boundaries and is refused. The second and all extension groups have
		// a recovered structural schema, but are not exposed as named metrics.
		presence, e := Number(r[20])
		if e != nil || presence > 1 {
			return nil, bad
		}
		if presence != 0 {
			return nil, errors.New("first session statistics representation is unsupported")
		}
		second, e := Number(r[21])
		if e != nil || second > 1 {
			return nil, bad
		}
		tail := 22
		if second == 1 {
			if len(r) < 23 || !validAdminSessionStats(r[22]) {
				return nil, bad
			}
			tail++
		}
		if !validAdminSessionExtensions(r[tail:]) {
			return nil, bad
		}
		result = append(result, AdminSessionDescriptor{ID: ids[0].String(), InfoBaseID: ids[1].String(), InfoBaseName: str[2], InfoBaseDescription: str[3], SessionID: display, HostName: str[7], UserName: str[8], Application: str[12], StartedAtRaw: started, LastActiveAtRaw: active})
	}
	return result, nil
}

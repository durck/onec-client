package wire

import "errors"

// These identifiers and layouts are observed on 8.3.18.1208. They describe
// working-process administration, not the application's HTTP RPC interface.
var AdminProcessContext = MustUUID("a2c6af52-7d8b-46ef-9a69-cb1fa650e4f5")
var InfobaseListInterface = MustUUID("7607aa1f-f87e-47a2-8a6b-701c7105ca63")
var InfobaseListType = MustUUID("33f42b5a-58eb-482c-a6b0-9f92260e5c2b")

const AdminProcessSelector = "##AdminProcess##:##AdminProcess##"
const MaxInfobases = 4096

type InfobaseInfo struct {
	Name, Description string
	ID                UUID
}

func ParseInfobaseInterface(p []byte) error {
	top, err := ParseText(p)
	if err != nil {
		return err
	}
	if len(top) == 1 {
		r, ok := List(top[0], 3)
		if ok && textIs(r[0], 1) && textIs(r[2], 15) {
			if n, e := TextNumber(r[1]); e == nil && n >= 0 && n <= 0xffffffff {
				return nil
			}
		}
	}
	return errors.New("unsupported working-process administration interface")
}

func InfobaseListRequest(target UUID, counter uint32) ([]byte, error) {
	return Pack([]any{0, target, counter, 4, InfobaseListInterface, 1, 1, 0})
}

// ParseInfobases validates the complete response before returning any entries.
// The observed response materializes value records; it does not create one
// remote object or additional property-get request per infobase.
func ParseInfobases(p []byte) ([]InfobaseInfo, error) {
	bad := errors.New("invalid infobase-list reply")
	if len(p) > 1024*1024 {
		return nil, errors.New("infobase-list reply exceeds record limit")
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
	if native := parseNativeRPCError(r); native != nil {
		return nil, native
	}
	if len(r) != 6 || !IsNumber(r[0], 1) || !IsNumber(r[2], 1) || !IsNumber(r[4], 0) || !IsNumber(r[5], 0) {
		return nil, bad
	}
	if _, err := Number(r[1]); err != nil {
		return nil, bad
	}
	typed, ok := List(r[3], 3)
	if !ok || !IsString(typed[0], "#") || !IsGUID(typed[1], InfobaseListType) {
		return nil, bad
	}
	values, ok := List(typed[2], -1)
	if !ok || len(values) == 0 {
		return nil, bad
	}
	count, err := Number(values[0])
	if err != nil || count > MaxInfobases || int(count) != len(values)-1 {
		return nil, bad
	}
	result := make([]InfobaseInfo, 0, count)
	for _, value := range values[1:] {
		fields, ok := List(value, 3)
		if !ok {
			return nil, bad
		}
		name, e1 := String(fields[0])
		id, e2 := GUID(fields[1])
		description, e3 := String(fields[2])
		if e1 != nil || e2 != nil || e3 != nil || len(name) > 262144 || len(description) > 262144 {
			return nil, bad
		}
		result = append(result, InfobaseInfo{Name: name, Description: description, ID: id})
	}
	return result, nil
}

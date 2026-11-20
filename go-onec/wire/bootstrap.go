package wire

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"unicode/utf8"
)

var Root = MustUUID("e23134a2-14ff-4160-ba5f-ccef04e3786f")
var ConnectInterface = MustUUID("7f58f27d-5ad8-43a1-aa1e-c982f41bed5c")
var SelectInterface = MustUUID("73b7d3a3-fe0b-4fdf-ba70-b74b3589ffc3")
var ManagerContext = MustUUID("4ecea39c-b4c9-453e-aed0-ce8a24cc71c2")
var WorkerContext = MustUUID("1e01900d-82fd-413a-bfe5-571a4c30a685")
var UUIDType = MustUUID("ae135932-4f94-44df-92c1-c91f15a92848")
var BlobType = MustUUID("671507fd-50a9-4b63-b70e-58b3d364f48f")
var RemoteType = MustUUID("3ace6d91-51bb-4344-9388-c8105ad4ad11")
var ScalarType = MustUUID("ba5edc33-8936-4212-9ed2-485e759203aa")
var URLType = MustUUID("dd5dcb0e-62b5-4d01-8305-6f87bbc772c6")

func Introduction(name string) ([]byte, error) {
	b := []byte(name)
	if len(b) == 0 || len(b) > 65535 || strings.ContainsRune(name, 0) || !utf8.Valid(b) {
		return nil, errors.New("invalid credential name")
	}
	out := append([]byte("V8IntroTicketReq"), byte(len(b)), byte(len(b)>>8))
	out = append(out, b...)
	return append(out, 0), nil
}
func IntroductionAck(p []byte) (string, string, error) {
	bad := errors.New("invalid introduction acknowledgement")
	marker := []byte("V8IntroTicketAck")
	if !bytes.HasPrefix(p, marker) {
		return "", "", bad
	}
	p = p[len(marker):]
	values := []string{}
	for i := 0; i < 2; i++ {
		if len(p) < 2 {
			return "", "", bad
		}
		n := int(binary.BigEndian.Uint16(p))
		p = p[2:]
		if n == 0 || n > len(p) || !utf8.Valid(p[:n]) || bytes.IndexByte(p[:n], 0) >= 0 {
			return "", "", bad
		}
		values = append(values, string(p[:n]))
		p = p[n:]
	}
	if len(p) != 0 {
		return "", "", bad
	}
	return values[0], values[1], nil
}
func TypedUUID(u UUID) []any { return []any{"#", UUIDType, []any{1, u}} }
func BootstrapRequest(counter uint32, context UUID, computer string, token []byte, selector string, last UUID, version, app string) ([]byte, error) {
	blob := []any{}
	if len(token) > 0 {
		blob = append(blob, Raw(base64.StdEncoding.EncodeToString(token)))
	}
	return EncodeText([]any{[]any{0, Root, counter, 4, ConnectInterface, 0, 1, 11, 0, []any{"S", selector}, 0, TypedUUID(context), 0, []any{"S", app}, 0, []any{"S", computer}, 2, []any{"#", BlobType, blob}, 1, 0, []any{"S", version}, 0, []any{"S", "1ru_RU"}, 0, []any{"S", "1ru_RU"}, 0, TypedUUID(last), 1}})
}

type BootstrapResult struct {
	Completed bool
	Token     []byte
	Target    UUID
	HasTarget bool
}

func textIs(v any, n int64) bool { x, e := TextNumber(v); return e == nil && x == n }
func textTyped(v any, u UUID) (any, error) {
	x, ok := List(v, 3)
	if !ok || x[0] != "#" {
		return nil, errors.New("invalid typed text value")
	}
	r, ok := x[1].(Raw)
	if !ok {
		return nil, errors.New("invalid typed UUID")
	}
	id, e := ParseUUID(string(r))
	if e != nil || id != u {
		return nil, errors.New("unexpected typed UUID")
	}
	return x[2], nil
}
func isUndefined(v any) bool { x, ok := List(v, 1); return ok && x[0] == "U" }
func ParseBootstrap(p []byte) (BootstrapResult, error) {
	var result BootstrapResult
	bad := errors.New("invalid bootstrap reply")
	top, e := ParseText(p)
	if e != nil {
		return result, e
	}
	if len(top) != 2 || !textIs(top[1], 0) {
		return result, bad
	}
	r, ok := List(top[0], -1)
	if !ok || (len(r) != 20 && len(r) != 21) {
		return result, bad
	}
	for i, n := range map[int]int64{0: 1, 2: 1, 4: 11, 5: 0, 6: 0, 7: 0, 8: 0, 9: 2, 11: 1, 13: 0, 14: 0, 15: 0, 16: 0, 17: 1} {
		if !textIs(r[i], n) {
			return result, bad
		}
	}
	tail := int64(0)
	if len(r) == 21 {
		tail = 1
	}
	if !textIs(r[19], tail) {
		return result, bad
	}
	body, e := textTyped(r[10], BlobType)
	if e != nil {
		return result, e
	}
	blob, ok := List(body, -1)
	if !ok || len(blob) > 1 {
		return result, bad
	}
	if len(blob) == 1 {
		b, ok := blob[0].(Raw)
		if !ok {
			return result, bad
		}
		if strings.ContainsAny(string(b), "\r\n") {
			return result, bad
		}
		result.Token, e = base64.StdEncoding.Strict().DecodeString(string(b))
		if e != nil {
			return result, bad
		}
	}
	flag, ok := List(r[12], 2)
	if !ok || flag[0] != "B" || (!textIs(flag[1], 0) && !textIs(flag[1], 1)) {
		return result, bad
	}
	result.Completed = textIs(flag[1], 1)
	if result.Completed {
		if !isUndefined(r[3]) {
			v, e := textTyped(r[3], RemoteType)
			if e != nil {
				return result, e
			}
			l, ok := List(v, 1)
			if !ok {
				return result, bad
			}
			raw, ok := l[0].(Raw)
			if !ok {
				return result, bad
			}
			result.Target, e = ParseUUID(string(raw))
			if e != nil {
				return result, bad
			}
			result.HasTarget = true
		}
		v, e := textTyped(r[18], ScalarType)
		if e != nil {
			return result, e
		}
		if _, e = TextNumber(v); e != nil {
			return result, bad
		}
	} else if !isUndefined(r[3]) || !isUndefined(r[18]) {
		return result, bad
	}
	return result, nil
}
func SelectRequest(target UUID, counter uint32, base string, client UUID, app string) ([]byte, error) {
	return Pack([]any{0, target, counter, 4, SelectInterface, 0, 3, 7, 0, []any{"S", ""}, 0, []any{"S", ""}, 0, []any{"S", base}, 0, []any{"S", app}, 0, TypedUUID(client), 1, 1})
}
func ParseSelection(p []byte) (string, error) {
	top, e := DecodeTree(p)
	bad := errors.New("invalid worker selection reply")
	if e != nil {
		return "", e
	}
	if len(top) != 2 || !IsNumber(top[1], 2) {
		return "", bad
	}
	r, ok := List(top[0], 14)
	if !ok {
		return "", bad
	}
	for i, n := range map[int]uint32{0: 1, 2: 3, 3: 7, 4: 0, 5: 0, 6: 0, 7: 0, 8: 0, 9: 1, 11: 1, 13: 0} {
		if !IsNumber(r[i], n) {
			return "", bad
		}
	}
	t, ok := List(r[12], 3)
	if !ok || !IsString(t[0], "#") || !IsGUID(t[1], URLType) {
		return "", bad
	}
	b, ok := List(t[2], 2)
	if !ok || !IsNumber(b[0], 1) {
		return "", bad
	}
	if _, e := String(b[1]); e != nil {
		return "", e
	}
	return GenericString(r[10])
}
func QueryRequest(target UUID, counter uint32, iid UUID) ([]byte, error) {
	return EncodeText([]any{[]any{0, target, counter, 1, iid}})
}
func ParseQuery(p []byte) error {
	top, e := ParseText(p)
	if e != nil {
		return e
	}
	if len(top) == 1 {
		r, ok := List(top[0], 3)
		if ok && textIs(r[0], 1) && textIs(r[2], 1) {
			return nil
		}
	}
	return errors.New("interface query rejected")
}
func ReleaseRequest(target UUID, counter uint32) ([]byte, error) {
	return Pack([]any{0, target, counter, 0, 0})
}
func ParseRelease(p []byte) error {
	top, e := DecodeTree(p)
	if e != nil {
		return e
	}
	if len(top) == 1 {
		r, ok := List(top[0], 2)
		if ok && IsNumber(r[0], 1) {
			return nil
		}
	}
	return errors.New("invalid context release reply")
}

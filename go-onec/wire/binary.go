package wire

import (
	"encoding/binary"
	"errors"
	"math"
	"unicode/utf16"
	"unicode/utf8"
)

type Atom struct {
	Offset, End int
	Tag         byte
	Kind        string
	Value       any
}
type SecurityBlob []byte

// WideString requests native UTF-16 ListStream encoding without changing the
// existing narrow-string encoding used by application protocol callers.
type WideString string

// UnsupportedAtomError exposes only the format tag and its record offset.
// It never includes payload bytes, which can contain credentials.
type UnsupportedAtomError struct {
	Offset int
	Tag    byte
}

func (*UnsupportedAtomError) Error() string { return "unsupported binary atom type" }

func DecodeAtoms(p []byte) ([]Atom, error) {
	if len(p) > 16*1024*1024 {
		return nil, errors.New("binary record limit exceeded")
	}
	pos := 0
	out := []Atom{}
	take := func(n int) ([]byte, error) {
		if n < 0 || n > len(p)-pos {
			return nil, errors.New("truncated binary value")
		}
		b := p[pos : pos+n]
		pos += n
		return b, nil
	}
	for pos < len(p) {
		start := pos
		tag := p[pos]
		pos++
		code := tag & 31
		a := Atom{Offset: start, Tag: tag}
		switch {
		case code == 0:
			if tag == 0 {
				return nil, errors.New("empty binary token")
			}
			a.Kind = "structure"
		case code <= 10:
			a.Kind = "small"
			a.Value = uint32(code - 1)
		case code == 11:
			b, e := take(1)
			if e != nil {
				return nil, e
			}
			a.Kind = "octet"
			a.Value = append([]byte(nil), b...)
		case code == 13 || code == 15:
			b, e := take(int(code) - 11)
			if e != nil {
				return nil, e
			}
			a.Kind = "unsigned"
			if code == 13 {
				a.Value = uint32(binary.LittleEndian.Uint16(b))
			} else {
				a.Value = binary.LittleEndian.Uint32(b)
			}
		case code == 17:
			b, e := take(8)
			if e != nil {
				return nil, e
			}
			a.Kind, a.Value = "unsigned64", binary.LittleEndian.Uint64(b)
		case code == 12 || code == 14 || code == 16 || code == 18:
			width := 1 << ((code - 12) / 2)
			b, e := take(width)
			if e != nil {
				return nil, e
			}
			var magnitude uint64
			for i, v := range b {
				magnitude |= uint64(v) << (8 * i)
			}
			if magnitude > 1<<63 {
				return nil, errors.New("signed integer overflow")
			}
			a.Kind, a.Value = "signed", -int64(magnitude)
		case code == 19 || code == 20:
			width := 4
			if code == 20 {
				width = 8
			}
			b, e := take(width)
			if e != nil {
				return nil, e
			}
			x := float64(0)
			if code == 19 {
				x = float64(math.Float32frombits(binary.LittleEndian.Uint32(b)))
			} else {
				x = math.Float64frombits(binary.LittleEndian.Uint64(b))
			}
			a.Kind, a.Value = "float", x
		case code == 21:
			b, e := take(16)
			if e != nil {
				return nil, e
			}
			u, _ := UUIDFromLE(b)
			a.Kind = "guid"
			a.Value = u
		case code >= 23 && code <= 25:
			// Native ListStream lengths count UTF-16 code units. The long
			// variant has an eight-byte length, not a four-byte length.
			width := map[byte]int{23: 1, 24: 2, 25: 8}[code]
			b, e := take(width)
			if e != nil {
				return nil, e
			}
			n := uint64(b[0])
			if code == 24 {
				n = uint64(binary.LittleEndian.Uint16(b))
			} else if code == 25 {
				n = binary.LittleEndian.Uint64(b)
			}
			// Check before multiplication and int conversion, including on
			// 32-bit systems. The outer record bound also limits allocation.
			if n > uint64((len(p)-pos)/2) {
				return nil, errors.New("truncated binary wide string")
			}
			b, _ = take(int(n) * 2)
			units := make([]uint16, int(n))
			for i := range units {
				units[i] = binary.LittleEndian.Uint16(b[i*2:])
			}
			// Reject malformed Unicode locally rather than silently replace
			// it. Native handling of unpaired surrogates is not established.
			for i := 0; i < len(units); i++ {
				u := units[i]
				if u >= 0xd800 && u <= 0xdbff {
					if i+1 == len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
						return nil, errors.New("invalid binary UTF-16 string")
					}
					i++
				} else if u >= 0xdc00 && u <= 0xdfff {
					return nil, errors.New("invalid binary UTF-16 string")
				}
			}
			a.Kind = "wide-string"
			a.Value = string(utf16.Decode(units))
		case code == 26 || code == 27:
			b, e := take(int(code) - 25)
			if e != nil {
				return nil, e
			}
			n := int(b[0])
			if code == 27 {
				n = int(binary.LittleEndian.Uint16(b))
			}
			b, e = take(n)
			if e != nil {
				return nil, e
			}
			a.Kind = "bytes"
			a.Value = append([]byte{}, b...)
		default:
			return nil, &UnsupportedAtomError{Offset: start, Tag: tag}
		}
		a.End = pos
		out = append(out, a)
	}
	return out, nil
}
func BuildTree(atoms []Atom) ([]any, error) {
	root := []any{}
	stack := []*[]any{&root}
	for _, a := range atoms {
		if a.Tag&32 != 0 {
			if len(stack) == 1 {
				return nil, errors.New("unmatched binary list end")
			}
			stack = stack[:len(stack)-1]
		}
		if a.Tag&64 != 0 {
			if len(stack) > 64 {
				return nil, errors.New("binary nesting limit")
			}
			child := []any{}
			parent := stack[len(stack)-1]
			*parent = append(*parent, &child)
			stack = append(stack, &child)
		}
		if a.Kind != "structure" {
			dst := stack[len(stack)-1]
			*dst = append(*dst, a)
		}
	}
	if len(stack) != 1 {
		return nil, errors.New("unclosed binary list")
	}
	var flatten func([]any) []any
	flatten = func(xs []any) []any {
		for i, x := range xs {
			if p, ok := x.(*[]any); ok {
				xs[i] = flatten(*p)
			}
		}
		return xs
	}
	return flatten(root), nil
}
func DecodeTree(p []byte) ([]any, error) {
	a, e := DecodeAtoms(p)
	if e != nil {
		return nil, e
	}
	return BuildTree(a)
}
func Number(v any) (uint32, error) {
	a, ok := v.(Atom)
	if !ok {
		return 0, errors.New("expected integer atom")
	}
	if n, ok := a.Value.(uint32); ok && (a.Kind == "small" || a.Kind == "unsigned") {
		return n, nil
	}
	if a.Kind == "octet" {
		return uint32(a.Value.([]byte)[0]), nil
	}
	return 0, errors.New("expected integer atom")
}
func IsNumber(v any, n uint32) bool { x, e := Number(v); return e == nil && x == n }

func UnsignedNumber64(v any) (uint64, error) {
	if n, err := Number(v); err == nil {
		return uint64(n), nil
	}
	if a, ok := v.(Atom); ok && a.Kind == "unsigned64" {
		return a.Value.(uint64), nil
	}
	return 0, errors.New("expected unsigned integer atom")
}

func SignedNumber64(v any) (int64, error) {
	if n, err := UnsignedNumber64(v); err == nil && n <= math.MaxInt64 {
		return int64(n), nil
	}
	if a, ok := v.(Atom); ok && a.Kind == "signed" {
		return a.Value.(int64), nil
	}
	return 0, errors.New("expected signed integer atom")
}

func FloatNumber(v any) (float64, error) {
	if a, ok := v.(Atom); ok && a.Kind == "float" {
		x := a.Value.(float64)
		if !math.IsNaN(x) && !math.IsInf(x, 0) {
			return x, nil
		}
	}
	return 0, errors.New("expected finite floating-point atom")
}
func Bytes(v any) ([]byte, error) {
	a, ok := v.(Atom)
	if !ok {
		return nil, errors.New("expected byte atom")
	}
	if a.Kind == "bytes" || a.Kind == "octet" {
		return a.Value.([]byte), nil
	}
	if a.Kind == "small" && a.Value == uint32(0) {
		return []byte{}, nil
	}
	return nil, errors.New("unsupported byte atom")
}
func String(v any) (string, error) {
	if a, ok := v.(Atom); ok && a.Kind == "wide-string" {
		return a.Value.(string), nil
	}
	b, e := Bytes(v)
	if e != nil {
		return "", e
	}
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r), nil
}
func IsString(v any, s string) bool { x, e := String(v); return e == nil && x == s }
func GUID(v any) (UUID, error) {
	a, ok := v.(Atom)
	if ok && a.Kind == "guid" {
		return a.Value.(UUID), nil
	}
	return UUID{}, errors.New("expected GUID atom")
}
func IsGUID(v any, u UUID) bool       { x, e := GUID(v); return e == nil && x == u }
func List(v any, n int) ([]any, bool) { x, ok := v.([]any); return x, ok && (n < 0 || len(x) == n) }
func GenericString(v any) (string, error) {
	x, ok := List(v, 2)
	if !ok || !IsString(x[0], "S") {
		return "", errors.New("expected generic string")
	}
	return String(x[1])
}

func Pack(v any) ([]byte, error) { return pack(v, 0, 0) }
func pack(v any, prefix byte, depth int) ([]byte, error) {
	if depth > 64 {
		return nil, errors.New("binary nesting limit")
	}
	switch x := v.(type) {
	case SecurityBlob:
		if len(x) > 65535 {
			return nil, errors.New("security blob limit")
		}
		a, _ := pack("#", 0, depth+1)
		b, _ := pack(BlobType, 128, depth+1)
		n, _ := pack(len(x), 0, depth+1)
		data, e := pack([]byte(x), 0, depth+1)
		if e != nil {
			return nil, e
		}
		out := []byte{prefix | 64}
		out = append(out, a...)
		out = append(out, b...)
		out = append(out, 192)
		out = append(out, n...)
		out = append(out, data...)
		return append(out, 32, 32), nil
	case httpFileChunks:
		out := []byte{prefix | 64}
		for _, chunk := range x {
			b, err := pack(chunk, 0, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, b...)
		}
		return append(out, 32), nil
	case []any:
		out := []byte{prefix | 64}
		for i, item := range x {
			p := byte(0)
			if i > 0 {
				p = 128
			}
			b, e := pack(item, p, depth+1)
			if e != nil {
				return nil, e
			}
			if len(out)+len(b) > 16*1024*1024 {
				return nil, errors.New("binary size limit")
			}
			out = append(out, b...)
		}
		return append(out, 32), nil
	case int:
		if x < 0 || uint64(x) > 0xffffffff {
			return nil, errors.New("integer outside uint32")
		}
		return pack(uint32(x), prefix, depth)
	case uint32:
		if x < 10 {
			return []byte{prefix | byte(x+1)}, nil
		}
		if x < 256 {
			return []byte{prefix | 11, byte(x)}, nil
		}
		if x < 65536 {
			return []byte{prefix | 13, byte(x), byte(x >> 8)}, nil
		}
		return []byte{prefix | 15, byte(x), byte(x >> 8), byte(x >> 16), byte(x >> 24)}, nil
	case uint64:
		if x <= math.MaxUint32 {
			return pack(uint32(x), prefix, depth)
		}
		out := make([]byte, 9)
		out[0] = prefix | 17
		binary.LittleEndian.PutUint64(out[1:], x)
		return out, nil
	case int64:
		if x >= 0 {
			return pack(uint64(x), prefix, depth)
		}
		magnitude := uint64(-(x + 1)) + 1
		width, code := 8, byte(18)
		if magnitude < 256 {
			width, code = 1, 12
		} else if magnitude < 65536 {
			width, code = 2, 14
		} else if magnitude <= math.MaxUint32 {
			width, code = 4, 16
		}
		out := make([]byte, width+1)
		out[0] = prefix | code
		for i := 0; i < width; i++ {
			out[i+1] = byte(magnitude >> (8 * i))
		}
		return out, nil
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return nil, errors.New("non-finite binary float")
		}
		out := make([]byte, 9)
		out[0] = prefix | 20
		binary.LittleEndian.PutUint64(out[1:], math.Float64bits(x))
		return out, nil
	case UUID:
		return append([]byte{prefix | 21}, x.LittleEndian()...), nil
	case WideString:
		if !utf8.ValidString(string(x)) || len(x) > MaxText/2 {
			return nil, errors.New("invalid or oversized binary wide string")
		}
		units := utf16.Encode([]rune(x))
		var out []byte
		if len(units) < 256 {
			out = []byte{prefix | 23, byte(len(units))}
		} else if len(units) < 65536 {
			out = []byte{prefix | 24, byte(len(units)), byte(len(units) >> 8)}
		} else {
			out = make([]byte, 9)
			out[0] = prefix | 25
			binary.LittleEndian.PutUint64(out[1:], uint64(len(units)))
		}
		for _, unit := range units {
			out = append(out, byte(unit), byte(unit>>8))
		}
		return out, nil
	case string:
		if !utf8.ValidString(x) {
			return nil, errors.New("invalid UTF-8 string")
		}
		b := []byte{}
		for _, r := range x {
			if r > 255 {
				return nil, errors.New("wide ListStream strings are not implemented")
			}
			b = append(b, byte(r))
		}
		return pack(b, prefix, depth)
	case []byte:
		n := len(x)
		if n == 0 {
			return []byte{prefix | 1}, nil
		}
		if n == 1 {
			return []byte{prefix | 11, x[0]}, nil
		}
		if n > 65535 {
			return nil, errors.New("binary string limit")
		}
		head := []byte{prefix | 26, byte(n)}
		if n >= 256 {
			head = []byte{prefix | 27, byte(n), byte(n >> 8)}
		}
		return append(head, x...), nil
	default:
		return nil, errors.New("unsupported binary value")
	}
}

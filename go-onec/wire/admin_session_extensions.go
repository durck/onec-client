package wire

import (
	"math"
	"strings"
)

// Structural schemas below come from the exact build's persistence writers.
// u/U are uint32/uint64, i/I are int32/int64, b bool, s string, g nullable UUID.
func adminFields(values []any, schema string) bool {
	types := strings.Fields(schema)
	if len(values) != len(types) {
		return false
	}
	for i, kind := range types {
		v := values[i]
		switch kind {
		case "u":
			if _, e := Number(v); e != nil {
				return false
			}
		case "U":
			if _, e := UnsignedNumber64(v); e != nil {
				return false
			}
		case "i":
			n, e := SignedNumber64(v)
			if e != nil || n < math.MinInt32 || n > math.MaxInt32 {
				return false
			}
		case "I":
			if _, e := SignedNumber64(v); e != nil {
				return false
			}
		case "b":
			n, e := Number(v)
			if e != nil || n > 1 {
				return false
			}
		case "s":
			if _, e := adminCollectionText(v); e != nil {
				return false
			}
		case "g":
			if _, e := nullableAdminUUID(v); e != nil {
				return false
			}
		case "h":
			if _, e := adminCollectionU16(v); e != nil {
				return false
			}
		case "attributes":
			r, ok := List(v, -1)
			if !ok || len(r) < 1 {
				return false
			}
			n, e := Number(r[0])
			if e != nil || n > MaxAdminObjects || len(r) != int(n)+1 {
				return false
			}
			for _, item := range r[1:] {
				p, ok := List(item, 3)
				if !ok || !adminFields(p, "s s u") {
					return false
				}
			}
		case "timezone":
			r, ok := List(v, -1)
			if !ok || len(r) < 2 || !adminFields(r[:2], "b s") {
				return false
			}
			fixed, _ := Number(r[0])
			if len(r) != 2+int(fixed) {
				return false
			}
			if fixed == 1 && !adminFields(r[2:], "I") {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func validAdminLicense(v any) bool {
	x, ok := List(v, 2)
	if !ok {
		return false
	}
	kind, e := Number(x[0])
	p, ok := List(x[1], -1)
	if e != nil || kind > 1 || !ok {
		return false
	}
	if kind == 0 {
		return adminFields(p, "s i")
	}
	if len(p) < 17 || !adminFields(p[:7], "i b s i s i b") {
		return false
	}
	present, _ := Number(p[6])
	tail := 7 + 14*int(present)
	if len(p) != tail+10 {
		return false
	}
	for _, field := range p[7:tail] {
		if !adminFields([]any{field}, "s") {
			return false
		}
	}
	return adminFields(p[tail:], "s b i i s b s U U u")
}

func validAdminSessionStats(v any) bool {
	r, ok := List(v, -1)
	if !ok || len(r) < 48 {
		return false
	}
	if !adminFields(r[:48], "u U U U U U u U u b u U u U u U U U U b u U u U U s u s u u I I I U U U U U U b u U u s I U U i") {
		return false
	}
	n, e := SignedNumber64(r[47])
	if e != nil || n < 0 || n > MaxAdminObjects || len(r) != 48+2*int(n) {
		return false
	}
	for i := 48; i < len(r); i += 2 {
		if !adminFields(r[i:i+1], "s") {
			return false
		}
		metrics, ok := List(r[i+1], 17)
		if !ok || !adminFields(metrics, "u U U u u U U I I U U U U U I u u") {
			return false
		}
	}
	return true
}

// The native reader permits ending at these group boundaries. Optional payloads
// must be complete before any core record becomes eligible for a mutation.
func validAdminSessionExtensions(r []any) bool {
	groups := []string{"i", "u b", "s", "g", "u s", "s", "U", "u", "i", "attributes", "timezone", "b", "b", "b", "b u u", "b", "U", "g", "s h", "u", "s", "s", "u"}
	for _, group := range groups {
		if len(r) == 0 {
			return true
		}
		n := len(strings.Fields(group))
		if len(r) < n || !adminFields(r[:n], group) {
			return false
		}
		r = r[n:]
	}
	return len(r) == 0
}

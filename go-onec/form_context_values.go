package onec

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
)

func contextNumber(raw any) (uint64, error) {
	text, ok := snapshotScalarText(raw)
	if !ok {
		return 0, errors.New("invalid form state counter")
	}
	n, err := strconv.ParseUint(text, 10, 53)
	if err != nil {
		return 0, errors.New("invalid form state counter")
	}
	return n, nil
}

func contextValues(raw any, fields []contextField, previous []any, initial bool) ([]any, error) {
	props, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("invalid context property data")
	}
	for key := range props {
		if key != "fields" && key != "v" && key != "#v" && key != "##sequence" {
			return nil, errors.New("unsupported context property member")
		}
	}
	values, ok := props["v"].([]any)
	if !ok {
		return nil, errors.New("invalid context property values")
	}
	positions := make([]int, len(fields))
	for i := range positions {
		positions[i] = i
	}
	if raw, exists := props["fields"]; exists {
		s, ok := raw.(string)
		if !ok {
			return nil, errors.New("invalid context property positions")
		}
		parts := strings.Fields(s)
		positions = make([]int, len(parts))
		for i, p := range parts {
			n, err := strconv.Atoi(p)
			if err != nil || n < 0 || n >= len(fields) {
				return nil, errors.New("invalid context property position")
			}
			positions[i] = n
		}
	}
	if len(positions) != len(values) {
		return nil, errors.New("context property count mismatch")
	}
	var types []any
	if raw, exists := props["#v"]; exists {
		types, ok = raw.([]any)
		if !ok || len(types) != len(values) {
			return nil, errors.New("invalid context property type list")
		}
	}
	out := append([]any(nil), previous...)
	if initial {
		out = make([]any, len(fields))
	}
	if len(out) != len(fields) {
		return nil, errors.New("invalid context property base")
	}
	seen := map[int]bool{}
	for i, pos := range positions {
		if seen[pos] {
			return nil, errors.New("duplicate context property position")
		}
		seen[pos] = true
		field := fields[pos]
		if field.object {
			if !initial && !reflect.DeepEqual(out[pos], values[i]) {
				return nil, errors.New("nested context changes are unsupported")
			}
			out[pos] = values[i]
			continue
		}
		if types != nil {
			typ, ok := types[i].(string)
			if !ok || (typ != "undefined" && !strings.EqualFold(typ, field.scalarType())) {
				return nil, errors.New("unsupported context property type")
			}
		}
		value, err := decodeFormScalar(field.scalarType(), values[i])
		if err != nil {
			return nil, err
		}
		out[pos], err = encodeFormValue(value)
		if err != nil {
			return nil, err
		}
	}
	if initial {
		for i, field := range fields {
			if !seen[i] && !field.object {
				return nil, errors.New("missing initial scalar context value")
			}
		}
	}
	return out, nil
}

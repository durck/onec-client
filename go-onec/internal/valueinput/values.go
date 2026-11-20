// Package valueinput decodes explicit scalar user input without float coercion.
package valueinput

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"onec"
	"strings"
)

// JSONString rejects malformed Unicode instead of replacing it with U+FFFD.
type JSONString string

func (s *JSONString) UnmarshalJSON(data []byte) error {
	value, err := (onec.FormValueCodec{}).Unmarshal(onec.StringType, data)
	if err != nil {
		return err
	}
	*s = JSONString(value.Value.(string))
	return nil
}

// Arguments accepts strings for backwards compatibility and typed objects:
// {"type":"number","value":"12.50"}, {"type":"boolean","value":true}, and
// {"type":"date","value":"2026-10-20T12:34:56"}.
func Arguments(data []byte) ([]onec.Value, error) {
	if len(data) > 256<<10 {
		return nil, errors.New("argument input limit")
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil || raw == nil || len(raw) > 32 {
		return nil, errors.New("arguments require an array of at most 32 values")
	}
	out := make([]onec.Value, len(raw))
	for i, item := range raw {
		var text JSONString
		if len(item) > 0 && item[0] == '"' {
			if err := json.Unmarshal(item, &text); err != nil {
				return nil, errors.New("invalid string argument")
			}
			value, err := Text(onec.StringType, string(text))
			if err != nil {
				return nil, err
			}
			out[i] = value
			continue
		}
		input, err := typedArgument(item)
		if err != nil {
			return nil, errors.New("invalid typed argument")
		}
		switch strings.ToLower(input.Type) {
		case "string", "number", "date":
			if len(input.Value) == 0 || input.Value[0] != '"' || json.Unmarshal(input.Value, &text) != nil {
				return nil, errors.New("string, number and date values require JSON strings")
			}
		case "boolean":
			if bytes.Equal(input.Value, []byte("true")) {
				text = "true"
			} else if bytes.Equal(input.Value, []byte("false")) {
				text = "false"
			} else {
				return nil, errors.New("Boolean value requires true or false")
			}
		default:
			return nil, errors.New("unsupported argument type")
		}
		value, err := Text(input.Type, string(text))
		if err != nil {
			return nil, err
		}
		out[i] = value
	}
	return out, nil
}

type argumentInput struct {
	Type  string
	Value json.RawMessage
}

// Decode the two-field object explicitly: encoding/json otherwise accepts
// duplicate fields and silently keeps their last value.
func typedArgument(data []byte) (argumentInput, error) {
	var out argumentInput
	d := json.NewDecoder(bytes.NewReader(data))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return out, errors.New("typed argument requires an object")
	}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return out, err
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return out, errors.New("duplicate argument field")
		}
		seen[name] = true
		switch name {
		case "type":
			var value JSONString
			if err := d.Decode(&value); err != nil {
				return out, err
			}
			out.Type = string(value)
		case "value":
			if err := d.Decode(&out.Value); err != nil {
				return out, err
			}
		default:
			return out, errors.New("unknown argument field")
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || len(seen) != 2 || d.Decode(new(any)) != io.EOF {
		return out, errors.New("incomplete typed argument")
	}
	return out, nil
}

// Text converts a field's text using its server-declared type.
func Text(typeID, text string) (onec.Value, error) {
	switch strings.ToUpper(typeID) {
	case "STRING", onec.StringType:
		value := onec.StringValue(text)
		if _, err := (onec.FormValueCodec{}).Marshal(value); err != nil {
			return onec.Value{}, err
		}
		return value, nil
	case "NUMBER", onec.NumberType:
		return onec.NumberValue(text)
	case "DATE", onec.DateType:
		return onec.DateValue(text)
	case "BOOLEAN", onec.BooleanType:
		if text != "true" && text != "false" {
			return onec.Value{}, errors.New("Boolean field requires true or false")
		}
		return onec.BooleanValue(text == "true"), nil
	default:
		return onec.Value{}, errors.New("unsupported field type")
	}
}

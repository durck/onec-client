package onec

import (
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf16"
)

// Native replies can contain JSON Number tokens even though the inspected
// client writer emits decimal text. strictJSON retains each token as
// json.Number; this conversion never passes through binary floating point.
func contextReturnedArguments(prm map[string]any, count int) ([]Value, error) {
	raw, present := prm["param"]
	tags, tagged := prm["#param"]
	if !present && !tagged {
		return nil, nil
	}
	values, ok := raw.([]any)
	types, typeOK := tags.([]any)
	if !ok || !typeOK || len(values) != count || len(types) != count {
		return nil, errors.New("invalid returned argument list")
	}
	result := make([]Value, count)
	for i, raw := range values {
		typ, ok := types[i].(string)
		if !ok {
			return nil, errors.New("invalid returned argument type")
		}
		if strings.EqualFold(typ, NumberType) {
			if n, ok := raw.(json.Number); ok {
				raw = n.String()
			}
		}
		value, err := decodeFormScalar(typ, raw)
		if err != nil {
			return nil, err
		}
		result[i] = value
	}
	return result, nil
}

// Qualifier names/defaults are observed in 18 loader 2869-2870. The shipped
// client can round or clamp values; this API rejects edits requiring either
// operation, so the caller never silently loses precision.
func contextScalarQualifiers(field *contextField, typ map[string]any) error {
	allowed := map[string]bool{"__content": true}
	switch field.typeID {
	case NumberType:
		allowed["digits"], allowed["precision"], allowed["unsigned"] = true, true, true
		field.digits = 10
		for _, entry := range []struct {
			name string
			dest *int
		}{{"digits", &field.digits}, {"precision", &field.precision}} {
			if raw, exists := typ[entry.name]; exists {
				n, err := contextNumber(raw)
				if err != nil || n > MaxFormDecimalDigits {
					return errors.New("invalid Number qualifier")
				}
				*entry.dest = int(n)
			}
		}
		if field.digits < 1 || field.precision > field.digits {
			return errors.New("invalid Number precision")
		}
		if raw, exists := typ["unsigned"]; exists {
			var ok bool
			field.unsigned, ok = raw.(bool)
			if !ok {
				return errors.New("invalid Number sign qualifier")
			}
		}
	case BooleanType, DateType:
		// Date-only/time-only restrictions are not yet admitted. This profile
		// accepts only the default full civil date/time descriptor.
	default:
		return errors.New("unsupported monotype scalar context field")
	}
	for key := range typ {
		if !allowed[key] {
			return errors.New("unsupported scalar qualifier")
		}
	}
	return nil
}

func (field contextField) validateEdit(value Value, payload any) error {
	if value.Type != field.scalarType() {
		return errors.New("context edit type does not match its field")
	}
	switch field.scalarType() {
	case StringType:
		text, ok := payload.(string)
		if !ok || (field.length > 0 && len(utf16.Encode([]rune(text))) > field.length) {
			return errors.New("context String exceeds its declared length")
		}
	case NumberType:
		text, ok := payload.(string)
		if !ok {
			return errors.New("invalid context decimal")
		}
		if field.unsigned && strings.HasPrefix(text, "-") {
			return errors.New("context Number does not permit negative values")
		}
		parts := strings.Split(strings.TrimPrefix(text, "-"), ".")
		whole := len(strings.TrimLeft(parts[0], "0"))
		fraction := 0
		if len(parts) == 2 {
			fraction = len(parts[1])
		}
		if whole > field.digits-field.precision || fraction > field.precision {
			return errors.New("context Number exceeds declared digits or precision")
		}
	case BooleanType, DateType:
		// encodeFormValue has already validated the payload.
	default:
		return errors.New("unsupported context edit")
	}
	return nil
}

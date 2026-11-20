package onec

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

// These IDs and payloads come from the shipped 8.3.18.1208 scalar constructors.
// These encodings do not establish support on other server builds.
const (
	NumberType    = "B0BE78F2-0EE6-4D31-A3BB-77DD32BA5BEC"
	BooleanType   = "5D4125AD-F6E7-4313-BE32-F71D0AB60915"
	DateType      = "AAE38C48-A877-411C-A6D3-FBAA1F83C4BD"
	UndefinedType = "EE8D3E7C-F930-4A76-8AAD-4FF9083A6EA6"
	NullType      = "AF40A278-63BC-478E-91A8-19E0D16B10B5"

	MaxFormStringUnits   = 65536
	MaxFormDecimalDigits = 38
	MaxFormValueBytes    = 512 * 1024
	formDateLayout       = "2006-01-02T15:04:05"
	emptyFormDate        = "0001-01-01T00:00:00"
	emptyFormReference   = "00000000-0000-0000-0000-000000000000"
)

// Decimal is canonical decimal text. No codec operation uses binary floats.
// Construct it with NumberValue; Marshal validates manually created values.
type Decimal string

// FormDate is a civil date and time with second precision and no time zone.
type FormDate string

func NumberValue(text string) (Value, error) {
	text, err := normalizeFormDecimal(text)
	if err != nil {
		return Value{}, err
	}
	return Value{NumberType, Decimal(text)}, nil
}

func BooleanValue(v bool) Value { return Value{BooleanType, v} }
func UndefinedValue() Value     { return Value{UndefinedType, nil} }
func NullValue() Value          { return Value{NullType, nil} }

// DateValue accepts the emitted format, compact YYYYMMDD[hhmm[ss]], or the
// empty string for the empty date. Calendar overflow and time zones are rejected.
func DateValue(text string) (Value, error) {
	text, err := normalizeFormDate(text)
	if err != nil {
		return Value{}, err
	}
	return Value{DateType, FormDate(text)}, nil
}

// ReferenceValue constructs a UUID-payload reference. The codec must separately
// register typeID as a confirmed yr/Ar-derived type; enum references use another
// wire representation and must not be registered.
func ReferenceValue(typeID, id string) (Value, error) {
	typeID = strings.ToUpper(typeID)
	if !formUUID(typeID) || builtinFormType(typeID) || !formReference(id) {
		return Value{}, errors.New("invalid form reference")
	}
	if id == emptyFormReference {
		id = ""
	}
	return Value{typeID, id}, nil
}

// FormValueCodec is immutable after construction. Its zero value supports only
// String, Number, Boolean, Date, Undefined and Null. The registry is deliberately
// explicit: a syntactically valid type UUID alone does not establish its codec.
type FormValueCodec struct{ references map[string]bool }

func NewFormValueCodec(referenceTypeIDs ...string) (FormValueCodec, error) {
	if len(referenceTypeIDs) > 2048 {
		return FormValueCodec{}, errors.New("too many form reference types")
	}
	c := FormValueCodec{references: make(map[string]bool, len(referenceTypeIDs))}
	for _, id := range referenceTypeIDs {
		id = strings.ToUpper(id)
		if !formUUID(id) || builtinFormType(id) || c.references[id] {
			return FormValueCodec{}, errors.New("invalid or duplicate form reference type")
		}
		c.references[id] = true
	}
	return c, nil
}

// Marshal encodes one scalar payload. Undefined is the literal undefined in the
// platform's JSON-like dialect, so the result is not always standard JSON.
// Number payloads are JSON strings, never JSON numbers.
func (c FormValueCodec) Marshal(v Value) ([]byte, error) {
	switch strings.ToUpper(v.Type) {
	case StringType:
		s, ok := v.Value.(string)
		if !ok || !formString(s) {
			return nil, errors.New("invalid form string")
		}
		return json.Marshal(s)
	case NumberType:
		s, ok := formDecimalText(v.Value)
		if !ok {
			return nil, errors.New("form number requires decimal text")
		}
		s, err := normalizeFormDecimal(s)
		if err != nil {
			return nil, err
		}
		return json.Marshal(s)
	case BooleanType:
		b, ok := v.Value.(bool)
		if !ok {
			return nil, errors.New("invalid form boolean")
		}
		if b {
			return []byte("true"), nil
		}
		return []byte("false"), nil
	case DateType:
		var s string
		switch x := v.Value.(type) {
		case FormDate:
			s = string(x)
		case string:
			s = x
		default:
			return nil, errors.New("form date requires civil date text")
		}
		s, err := normalizeFormDate(s)
		if err != nil {
			return nil, err
		}
		return json.Marshal(s)
	case UndefinedType:
		if v.Value != nil {
			return nil, errors.New("invalid undefined form value")
		}
		return []byte("undefined"), nil
	case NullType:
		if v.Value != nil {
			return nil, errors.New("invalid null form value")
		}
		return []byte("null"), nil
	default:
		if !c.references[strings.ToUpper(v.Type)] {
			return nil, errors.New("unsupported form value type")
		}
		s, ok := v.Value.(string)
		if !ok || !formReference(s) {
			return nil, errors.New("invalid form reference payload")
		}
		if s == emptyFormReference {
			s = ""
		}
		return json.Marshal(s)
	}
}

// Unmarshal decodes a payload using a known concrete type. The shipped JS
// serializer emits Number strings; the native server also emits numeric tokens.
// Both are decoded as exact decimal text without any float64 conversion.
func (c FormValueCodec) Unmarshal(typeID string, data []byte) (Value, error) {
	if len(data) > MaxFormValueBytes {
		return Value{}, errors.New("form value exceeds size limit")
	}
	data = bytes.TrimSpace(data)
	typeID = strings.ToUpper(typeID)
	switch typeID {
	case UndefinedType:
		if !bytes.Equal(data, []byte("undefined")) {
			return Value{}, errors.New("invalid undefined form payload")
		}
		return UndefinedValue(), nil
	case NullType:
		if !bytes.Equal(data, []byte("null")) {
			return Value{}, errors.New("invalid null form payload")
		}
		return NullValue(), nil
	case BooleanType:
		if bytes.Equal(data, []byte("true")) {
			return BooleanValue(true), nil
		}
		if bytes.Equal(data, []byte("false")) {
			return BooleanValue(false), nil
		}
		return Value{}, errors.New("invalid form boolean payload")
	case StringType, NumberType, DateType:
	default:
		if !c.references[typeID] {
			return Value{}, errors.New("unsupported form value type")
		}
	}
	if typeID == NumberType && len(data) > 0 && data[0] != '"' {
		if !json.Valid(data) {
			return Value{}, errors.New("invalid numeric form token")
		}
		return NumberValue(string(data))
	}
	s, err := decodeFormJSONString(data)
	if err != nil {
		return Value{}, err
	}
	switch typeID {
	case StringType:
		if !formString(s) {
			return Value{}, errors.New("form string exceeds size limit")
		}
		return StringValue(s), nil
	case NumberType:
		return NumberValue(s)
	case DateType:
		return DateValue(s)
	default:
		return ReferenceValue(typeID, s)
	}
}

// MarshalTagged emits the fh(value,"value",object) envelope in source order.
// Undefined omits #value, exactly as Ce.rha() does.
func (c FormValueCodec) MarshalTagged(v Value) ([]byte, error) {
	payload, err := c.Marshal(v)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(v.Type, UndefinedType) {
		return []byte(`{"value":undefined}`), nil
	}
	id, _ := json.Marshal(strings.ToUpper(v.Type))
	out := append([]byte(`{"#value":`), id...)
	out = append(out, []byte(`,"value":`)...)
	out = append(out, payload...)
	return append(out, '}'), nil
}

// UnmarshalTagged accepts only the scalar envelope, with exactly one value and
// at most one type tag. It does not silently infer untagged strings or numbers.
func (c FormValueCodec) UnmarshalTagged(data []byte) (Value, error) {
	if len(data) > MaxFormValueBytes {
		return Value{}, errors.New("form envelope exceeds size limit")
	}
	p := formScalarParser{data: data}
	if !p.consume('{') {
		return Value{}, errors.New("invalid form envelope")
	}
	var payload []byte
	var typeID string
	seen := map[string]bool{}
	for {
		keyRaw, err := p.scalar()
		if err != nil {
			return Value{}, err
		}
		key, err := decodeFormJSONString(keyRaw)
		if err != nil || (key != "#value" && key != "value") || seen[key] || !p.consume(':') {
			return Value{}, errors.New("invalid form envelope member")
		}
		seen[key] = true
		raw, err := p.scalar()
		if err != nil {
			return Value{}, err
		}
		if key == "#value" {
			typeID, err = decodeFormJSONString(raw)
			if err != nil {
				return Value{}, err
			}
		} else {
			payload = raw
		}
		if p.consume('}') {
			break
		}
		if !p.consume(',') {
			return Value{}, errors.New("invalid form envelope separator")
		}
	}
	p.space()
	if p.pos != len(p.data) || !seen["value"] {
		return Value{}, errors.New("invalid form envelope end")
	}
	if !seen["#value"] {
		typeID = UndefinedType
	} else if typeID == "" {
		return Value{}, errors.New("empty form type tag")
	}
	return c.Unmarshal(typeID, payload)
}

func builtinFormType(id string) bool {
	switch id {
	case StringType, NumberType, BooleanType, DateType, UndefinedType, NullType, BinaryType:
		return true
	}
	return false
}

func formUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, ch := range []byte(s) {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if ch != '-' {
				return false
			}
		} else if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return false
		}
	}
	return s != emptyFormReference
}

func formReference(s string) bool { return s == "" || s == emptyFormReference || formUUID(s) }

func formString(s string) bool {
	return utf8.ValidString(s) && len(s) <= MaxFormStringUnits*4 &&
		formUTF16Length(s) <= MaxFormStringUnits
}

func formUTF16Length(s string) int {
	n := 0
	for _, r := range s {
		n += utf16.RuneLen(r)
	}
	return n
}

func formDecimalText(v any) (string, bool) {
	switch x := v.(type) {
	case Decimal:
		return string(x), true
	case string:
		return x, true
	default:
		return "", false
	}
}

func normalizeFormDecimal(s string) (string, error) {
	// A small lexical bound is checked before normalization or allocation.
	if len(s) == 0 || len(s) > 2*MaxFormDecimalDigits+4 {
		return "", errors.New("invalid form decimal length")
	}
	negative := s[0] == '-'
	if negative || s[0] == '+' {
		s = s[1:]
	}
	parts := strings.Split(s, ".")
	if len(parts) > 2 || parts[0] == "" || (len(parts) == 2 && parts[1] == "") {
		return "", errors.New("invalid form decimal syntax")
	}
	for _, part := range parts {
		for _, ch := range []byte(part) {
			if ch < '0' || ch > '9' {
				return "", errors.New("invalid form decimal syntax")
			}
		}
	}
	integer := strings.TrimLeft(parts[0], "0")
	fraction := ""
	if len(parts) == 2 {
		fraction = strings.TrimRight(parts[1], "0")
	}
	if len(integer)+len(fraction) > MaxFormDecimalDigits {
		return "", errors.New("form decimal exceeds precision limit")
	}
	if integer == "" {
		integer = "0"
	}
	if fraction != "" {
		integer += "." + fraction
	}
	if negative && integer != "0" {
		integer = "-" + integer
	}
	return integer, nil
}

func normalizeFormDate(s string) (string, error) {
	if s == "" {
		return emptyFormDate, nil
	}
	switch len(s) {
	case 8, 12, 14:
		for _, ch := range []byte(s) {
			if ch < '0' || ch > '9' {
				return "", errors.New("invalid compact form date")
			}
		}
		s += strings.Repeat("0", 14-len(s))
		s = s[:4] + "-" + s[4:6] + "-" + s[6:8] + "T" + s[8:10] + ":" + s[10:12] + ":" + s[12:14]
	case 19:
	default:
		return "", errors.New("invalid form date length")
	}
	t, err := time.Parse(formDateLayout, s)
	if err != nil || t.Year() < 1 || t.Year() > 9999 || t.Format(formDateLayout) != s {
		return "", errors.New("invalid form calendar date")
	}
	return s, nil
}

// encoding/json replaces malformed UTF-8 and unpaired UTF-16 surrogates.
// Reject them first so the codec never silently changes a supplied string.
func decodeFormJSONString(data []byte) (string, error) {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' || !utf8.Valid(data) {
		return "", errors.New("form payload requires a JSON string")
	}
	for i := 1; i < len(data)-1; i++ {
		if data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data)-1 {
			return "", errors.New("invalid form string escape")
		}
		if data[i] != 'u' {
			continue
		}
		u, ok := formHex4(data[i+1:])
		if !ok {
			return "", errors.New("invalid form unicode escape")
		}
		i += 4
		if u >= 0xdc00 && u <= 0xdfff {
			return "", errors.New("unpaired form unicode surrogate")
		}
		if u >= 0xd800 && u <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return "", errors.New("unpaired form unicode surrogate")
			}
			low, ok := formHex4(data[i+3:])
			if !ok || low < 0xdc00 || low > 0xdfff {
				return "", errors.New("unpaired form unicode surrogate")
			}
			i += 6
		}
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return "", errors.New("invalid form JSON string")
	}
	return s, nil
}

func formHex4(b []byte) (uint16, bool) {
	if len(b) < 4 {
		return 0, false
	}
	var n uint16
	for _, ch := range b[:4] {
		n <<= 4
		switch {
		case ch >= '0' && ch <= '9':
			n += uint16(ch - '0')
		case ch >= 'a' && ch <= 'f':
			n += uint16(ch-'a') + 10
		case ch >= 'A' && ch <= 'F':
			n += uint16(ch-'A') + 10
		default:
			return 0, false
		}
	}
	return n, true
}

type formScalarParser struct {
	data []byte
	pos  int
}

func (p *formScalarParser) space() {
	for p.pos < len(p.data) && (p.data[p.pos] == ' ' || p.data[p.pos] == '\n' || p.data[p.pos] == '\r' || p.data[p.pos] == '\t') {
		p.pos++
	}
}

func (p *formScalarParser) consume(ch byte) bool {
	p.space()
	if p.pos < len(p.data) && p.data[p.pos] == ch {
		p.pos++
		return true
	}
	return false
}

func (p *formScalarParser) scalar() ([]byte, error) {
	p.space()
	start := p.pos
	if p.pos == len(p.data) {
		return nil, errors.New("missing form scalar")
	}
	if p.data[p.pos] == '"' {
		p.pos++
		for p.pos < len(p.data) {
			ch := p.data[p.pos]
			p.pos++
			if ch == '"' {
				return p.data[start:p.pos], nil
			}
			if ch == '\\' {
				p.pos++
			}
		}
		return nil, errors.New("unterminated form string")
	}
	for p.pos < len(p.data) {
		ch := p.data[p.pos]
		if ch == ',' || ch == '}' || ch == ':' || ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t' {
			break
		}
		p.pos++
	}
	if p.pos == start {
		return nil, errors.New("missing form scalar")
	}
	return p.data[start:p.pos], nil
}

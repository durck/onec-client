package wire

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const MaxText = 1024 * 1024

var bom = []byte{239, 187, 191}

type Raw string
type textParser struct {
	s string
	p int
}

func (p *textParser) space() {
	for p.p < len(p.s) && strings.ContainsRune(" \r\n\t", rune(p.s[p.p])) {
		p.p++
	}
}
func (p *textParser) value(depth int) (any, error) {
	p.space()
	if p.p == len(p.s) {
		return nil, errors.New("missing text value")
	}
	switch p.s[p.p] {
	case '{':
		if depth >= 32 {
			return nil, errors.New("text depth exceeded")
		}
		p.p++
		p.space()
		if p.p < len(p.s) && p.s[p.p] == '}' {
			p.p++
			return []any{}, nil
		}
		v, e := p.sequence(depth + 1)
		if e != nil {
			return nil, e
		}
		if p.p == len(p.s) || p.s[p.p] != '}' {
			return nil, errors.New("unclosed text list")
		}
		p.p++
		return v, nil
	case '"':
		p.p++
		var out strings.Builder
		for p.p < len(p.s) {
			c := p.s[p.p]
			p.p++
			if c == '"' {
				if p.p < len(p.s) && p.s[p.p] == '"' {
					p.p++
					out.WriteByte(c)
				} else {
					return out.String(), nil
				}
			} else {
				out.WriteByte(c)
			}
		}
		return nil, errors.New("unclosed text string")
	default:
		start := p.p
		for p.p < len(p.s) && !strings.ContainsRune(",{}\" \r\n\t", rune(p.s[p.p])) {
			p.p++
		}
		if start == p.p {
			return nil, errors.New("unexpected text delimiter")
		}
		return Raw(p.s[start:p.p]), nil
	}
}
func (p *textParser) sequence(depth int) ([]any, error) {
	v, e := p.value(depth)
	if e != nil {
		return nil, e
	}
	out := []any{v}
	p.space()
	for p.p < len(p.s) && p.s[p.p] == ',' {
		p.p++
		v, e = p.value(depth)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
		p.space()
	}
	return out, nil
}
func ParseText(b []byte) ([]any, error) {
	if len(b) > MaxText || !bytes.HasPrefix(b, bom) || !utf8.Valid(b) {
		return nil, errors.New("invalid text record")
	}
	p := textParser{s: string(b[3:])}
	v, e := p.sequence(0)
	if e != nil {
		return nil, e
	}
	p.space()
	if p.p != len(p.s) {
		return nil, errors.New("unparsed text tail")
	}
	return v, nil
}
func EncodeText(top []any) ([]byte, error) {
	var b strings.Builder
	b.Write(bom)
	var write func(any, int) error
	write = func(v any, d int) error {
		if d > 32 {
			return errors.New("text depth exceeded")
		}
		if b.Len() > MaxText {
			return errors.New("text limit exceeded")
		}
		switch x := v.(type) {
		case []any:
			b.WriteByte('{')
			for i, item := range x {
				if i > 0 {
					b.WriteByte(',')
				}
				if e := write(item, d+1); e != nil {
					return e
				}
			}
			b.WriteByte('}')
		case Raw:
			if x == "" || strings.ContainsAny(string(x), ",{}\"") || strings.IndexFunc(string(x), unicode.IsSpace) >= 0 {
				return errors.New("invalid raw text token")
			}
			b.WriteString(string(x))
		case UUID:
			b.WriteString(x.String())
		case int:
			b.WriteString(strconv.Itoa(x))
		case uint32:
			b.WriteString(strconv.FormatUint(uint64(x), 10))
		case string:
			if !utf8.ValidString(x) {
				return errors.New("invalid UTF-8")
			}
			b.WriteByte('"')
			b.WriteString(strings.ReplaceAll(x, "\"", "\"\""))
			b.WriteByte('"')
		default:
			return errors.New("unsupported text value")
		}
		return nil
	}
	for i, v := range top {
		if i > 0 {
			b.WriteByte(',')
		}
		if e := write(v, 0); e != nil {
			return nil, e
		}
	}
	if b.Len() > MaxText {
		return nil, errors.New("text limit exceeded")
	}
	return []byte(b.String()), nil
}
func TextNumber(v any) (int64, error) {
	r, ok := v.(Raw)
	if !ok || len(r) > 21 {
		return 0, errors.New("expected text integer")
	}
	s := string(r)
	digits := strings.TrimPrefix(s, "-")
	if len(digits) == 0 || len(digits) > 20 || strings.IndexFunc(digits, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, errors.New("invalid text integer")
	}
	n, e := strconv.ParseInt(s, 10, 64)
	if e != nil {
		return 0, errors.New("text integer outside range")
	}
	return n, nil
}

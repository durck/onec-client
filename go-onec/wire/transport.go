package wire

import (
	"bytes"
	"errors"
)

var Greeting = []byte{0x53, 0xf5, 0xc6, 0x1a, 0x7b}
var Escape = []byte{0x65, 0x52, 0xb1, 0xa5}
var End = []byte{0x66, 0x53, 0xb2, 0xa6}
var Control2 = []byte{0x21, 0x47, 0x54, 0xb3}
var Control3 = []byte{0x22, 0x48, 0x55, 0xb5}
var tokens = [][]byte{Escape, End, Control2, Control3}

type Event struct {
	Kind    string
	Payload []byte
	WireEnd int64
}
type Decoder struct {
	pending, record []byte
	consumed        int64
	limit           int
	failed          bool
}

func NewDecoder(limit int) (*Decoder, error) {
	if limit < 1 {
		return nil, errors.New("invalid record limit")
	}
	return &Decoder{limit: limit}, nil
}
func tokenIndex(b []byte) int {
	for i, t := range tokens {
		if bytes.Equal(b, t) {
			return i
		}
	}
	return -1
}
func tokenPrefix(b []byte) bool {
	for _, t := range tokens {
		if bytes.HasPrefix(t, b) {
			return true
		}
	}
	return false
}
func (d *Decoder) Feed(data []byte) ([]Event, error) {
	if d.failed {
		return nil, errors.New("decoder is unusable after failure")
	}
	d.pending = append(d.pending, data...)
	events := []Event{}
	pos := 0
	// Only these leading bytes can begin a transport token. Copy ordinary
	// spans together; candidate tokens still use the existing fragmented-token
	// state machine below. Read from tokens so their byte definitions agree.
	first0, first1, first2, first3 := tokens[0][0], tokens[1][0], tokens[2][0], tokens[3][0]
	add := func(b []byte) error {
		if len(b) > d.limit-len(d.record) {
			d.failed = true
			return errors.New("record limit exceeded")
		}
		d.record = append(d.record, b...)
		return nil
	}
	for pos < len(d.pending) {
		end := pos
		for end < len(d.pending) {
			b := d.pending[end]
			if b == first0 || b == first1 || b == first2 || b == first3 {
				break
			}
			end++
		}
		if end > pos {
			if e := add(d.pending[pos:end]); e != nil {
				return nil, e
			}
			pos = end
			if pos == len(d.pending) {
				break
			}
		}
		n := min(4, len(d.pending)-pos)
		head := d.pending[pos : pos+n]
		if n < 4 && tokenPrefix(head) {
			break
		}
		switch tokenIndex(head) {
		case 0:
			next := d.pending[pos+4 : min(pos+8, len(d.pending))]
			if len(next) < 4 && tokenPrefix(next) {
				goto done
			}
			if tokenIndex(next) >= 0 {
				if e := add(next); e != nil {
					return nil, e
				}
				pos += 8
			} else {
				if e := add(Escape); e != nil {
					return nil, e
				}
				pos += 4
			}
		case 1:
			pos += 4
			events = append(events, Event{"record", append([]byte{}, d.record...), d.consumed + int64(pos)})
			d.record = d.record[:0]
		case 2:
			pos += 4
			events = append(events, Event{"control_2", nil, d.consumed + int64(pos)})
		case 3:
			if len(d.pending)-pos < 20 {
				goto done
			}
			v := append([]byte(nil), d.pending[pos+4:pos+20]...)
			pos += 20
			events = append(events, Event{"control_3", v, d.consumed + int64(pos)})
		default:
			if e := add(d.pending[pos : pos+1]); e != nil {
				return nil, e
			}
			pos++
		}
	}
done:
	d.pending = append(d.pending[:0], d.pending[pos:]...)
	d.consumed += int64(pos)
	return events, nil
}
func (d *Decoder) Finish() error {
	if d.failed || len(d.pending) > 0 || len(d.record) > 0 {
		return errors.New("incomplete framed stream")
	}
	return nil
}
func EncodeRecord(p []byte) []byte {
	out := make([]byte, 0, len(p)+4)
	for len(p) > 0 {
		if len(p) >= 4 && tokenIndex(p[:4]) >= 0 {
			out = append(out, Escape...)
			out = append(out, p[:4]...)
			p = p[4:]
		} else {
			out = append(out, p[0])
			p = p[1:]
		}
	}
	return append(out, End...)
}

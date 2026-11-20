package ntlmauth

import (
	"bytes"
	"encoding/binary"
)

type avPair struct {
	id    uint16
	value []byte
}
type challenge struct {
	flags            uint32
	nonce, timestamp [8]byte
	hasTimestamp     bool
	pairs            []avPair
}

func parseChallenge(b []byte) (challenge, error) {
	var c challenge
	if len(b) < 48 || len(b) > maxToken || !bytes.Equal(b[:8], signature) || binary.LittleEndian.Uint32(b[8:12]) != 2 {
		return c, errChallenge
	}
	c.flags = binary.LittleEndian.Uint32(b[20:24])
	// Never accept LM_KEY, anonymous, datagram, local-call, non-NT keys or sealing
	// that this authentication-only provider did not negotiate.
	if c.flags&requiredFlags != requiredFlags || c.flags&(0x40|0x80|0x800|0x4000|0x400000|0x20) != 0 {
		return c, errChallenge
	}
	header := 48
	if c.flags&versionFlag != 0 {
		header = 56
	}
	if len(b) < header {
		return c, errChallenge
	}
	field := func(at int) ([]byte, int, bool) {
		n := int(binary.LittleEndian.Uint16(b[at:]))
		offset := uint64(binary.LittleEndian.Uint32(b[at+4:]))
		// MaxLen is ignored on receipt per MS-NLMP; only Len/Offset describe data.
		if n == 0 {
			return nil, 0, true
		}
		if offset < uint64(header) || offset+uint64(n) > uint64(len(b)) {
			return nil, 0, false
		}
		return b[int(offset) : int(offset)+n], int(offset), true
	}
	name, no, ok := field(12)
	if !ok || !validUTF16(name) {
		return c, errChallenge
	}
	info, io, ok := field(40)
	if !ok || len(info) < 4 || len(info) > 16384 || (len(name) > 0 && no < io+len(info) && io < no+len(name)) {
		return c, errChallenge
	}
	copy(c.nonce[:], b[24:32])
	seen := map[uint16]bool{}
	for at := 0; at < len(info); {
		if len(c.pairs) >= 64 || len(info)-at < 4 {
			return c, errChallenge
		}
		id, n := binary.LittleEndian.Uint16(info[at:]), int(binary.LittleEndian.Uint16(info[at+2:]))
		at += 4
		if n > len(info)-at || seen[id] {
			return c, errChallenge
		}
		seen[id] = true
		v := info[at : at+n]
		at += n
		if id == 0 {
			if n != 0 || at != len(info) {
				return c, errChallenge
			}
			if c.flags&signFlag != 0 && (!seen[1] || !seen[2]) {
				return c, errChallenge
			}
			return c, nil
		}
		switch id {
		case 1, 2, 3, 4, 5, 9:
			if !validUTF16(v) {
				return c, errChallenge
			}
		case 6:
			if n != 4 || binary.LittleEndian.Uint32(v)&^uint32(7) != 0 {
				return c, errChallenge
			}
		case 7:
			if n != 8 {
				return c, errChallenge
			}
			copy(c.timestamp[:], v)
			c.hasTimestamp = true
		case 10:
			// No TLS/channel binding exists on this raw TCP route. Never reflect
			// a server-provided nonzero binding as if it were locally verified.
			if n != 16 || !bytes.Equal(v, make([]byte, 16)) {
				return c, errChallenge
			}
		}
		c.pairs = append(c.pairs, avPair{id, v})
	}
	return c, errChallenge // missing AV_EOL
}

func validUTF16(b []byte) bool {
	if len(b)%2 != 0 || len(b) > 2048 {
		return false
	}
	for i := 0; i < len(b); i += 2 {
		u := binary.LittleEndian.Uint16(b[i:])
		if u >= 0xd800 && u <= 0xdbff {
			i += 2
			if i >= len(b) {
				return false
			}
			v := binary.LittleEndian.Uint16(b[i:])
			if v < 0xdc00 || v > 0xdfff {
				return false
			}
		} else if u >= 0xdc00 && u <= 0xdfff {
			return false
		}
	}
	return true
}

func (c challenge) responseInfo() []byte {
	out := make([]byte, 0, 16384+32)
	foundFlags := false
	add := func(id uint16, v []byte) {
		out = binary.LittleEndian.AppendUint16(out, id)
		out = binary.LittleEndian.AppendUint16(out, uint16(len(v)))
		out = append(out, v...)
	}
	for _, p := range c.pairs {
		if p.id == 6 {
			foundFlags = true
			v := binary.LittleEndian.AppendUint32(nil, binary.LittleEndian.Uint32(p.value)|2)
			add(6, v)
		} else if p.id != 9 && p.id != 10 {
			add(p.id, p.value)
		}
	}
	if !foundFlags {
		add(6, []byte{2, 0, 0, 0})
	}
	// These values are client assertions, not values to reflect from the peer.
	// This provider has no channel binding or independently pinned service name.
	add(10, make([]byte, 16))
	add(9, nil)
	add(0, nil)
	return out
}

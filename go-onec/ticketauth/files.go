// Package ticketauth implements bounded, file-backed Kerberos credentials.
// It never imports credentials into the operating system or writes a cache.
package ticketauth

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

const maxFile = 4 << 20

var errFile = errors.New("invalid or unsupported Kerberos credential file")

type entry struct {
	client     types.PrincipalName
	realm      string
	ticket     messages.Ticket
	key        types.EncryptionKey
	start, end time.Time
	flags      asn1.BitString
}

func (e *entry) wipe() { clear(e.key.KeyValue); clear(e.ticket.EncPart.Cipher) }
func wipeEntries(entries []entry) {
	for i := range entries {
		entries[i].wipe()
	}
}

func validText(s string) bool {
	if s == "" || len(s) > 1024 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}
func validPrincipal(p types.PrincipalName) bool {
	if len(p.NameString) == 0 || len(p.NameString) > 16 {
		return false
	}
	for _, s := range p.NameString {
		if !validText(s) {
			return false
		}
	}
	return true
}
func validKey(k types.EncryptionKey) bool {
	// AES-SHA1 and legacy RC4 session keys. SHA2 etypes are deliberately excluded:
	// the pinned upstream implementation reports an incorrect etype-20 key size.
	if k.KeyType != 17 && k.KeyType != 18 && k.KeyType != 23 {
		return false
	}
	e, err := crypto.GetEtype(k.KeyType)
	return err == nil && len(k.KeyValue) == e.GetKeyByteSize()
}
func validateEntry(e entry) bool {
	return validPrincipal(e.client) && validText(e.realm) && e.ticket.TktVNO == 5 && validPrincipal(e.ticket.SName) && validText(e.ticket.Realm) && validKey(e.key) && !e.end.IsZero() && !e.end.Before(e.start) && len(e.ticket.EncPart.Cipher) > 0 && len(e.ticket.EncPart.Cipher) <= 65535 && e.flags.BitLength == 32
}

// checkDER bounds depth, item count and every definite-length ASN.1 field before
// invoking the upstream decoder. Primitive ciphertext is not traversed.
func checkDER(b []byte) bool {
	count := 0
	var walk func([]byte, int) bool
	walk = func(data []byte, depth int) bool {
		if depth > 24 {
			return false
		}
		for len(data) > 0 {
			count++
			if count > 8192 {
				return false
			}
			var v asn1.RawValue
			rest, err := asn1.Unmarshal(data, &v)
			if err != nil || len(rest) >= len(data) {
				return false
			}
			if v.IsCompound && !walk(v.Bytes, depth+1) {
				return false
			}
			data = rest
		}
		return true
	}
	var root asn1.RawValue
	rest, err := asn1.Unmarshal(b, &root)
	return err == nil && len(rest) == 0 && walk(b, 0)
}

func readFile(path string) ([]entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open Kerberos credential file")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxFile {
		return nil, errFile
	}
	b, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	defer clear(b)
	if err != nil || len(b) > maxFile {
		return nil, errFile
	}
	return parseFile(b)
}
func parseFile(b []byte) (entries []entry, err error) {
	// A final containment boundary for dependency decoders; sizes are checked first.
	defer func() {
		if recover() != nil {
			err = errFile
		}
		if err != nil {
			wipeEntries(entries)
			entries = nil
		}
	}()
	if len(b) < 2 || len(b) > maxFile {
		return nil, errFile
	}
	if b[0] == 5 {
		return parseCCache(b)
	}
	if b[0] != 0x76 || !checkDER(b) {
		return nil, errFile
	}
	var k messages.KRBCred
	if k.Unmarshal(b) != nil || k.PVNO != 5 || k.EncPart.EType != 0 || len(k.Tickets) == 0 || len(k.Tickets) > 256 || !checkDER(k.EncPart.Cipher) {
		return nil, errFile
	}
	var part messages.EncKrbCredPart
	if part.Unmarshal(k.EncPart.Cipher) != nil {
		return nil, errFile
	}
	// ASN.1 byte slices alias b. Copy all retained fields before readFile wipes b.
	if len(k.Tickets) != len(part.TicketInfo) {
		return nil, errFile
	}
	for i, info := range part.TicketInfo {
		e := entry{client: info.PName, realm: info.PRealm, ticket: k.Tickets[i], key: types.EncryptionKey{KeyType: info.Key.KeyType, KeyValue: append([]byte(nil), info.Key.KeyValue...)}, start: info.StartTime, end: info.EndTime, flags: info.Flags}
		e.ticket.EncPart.Cipher = append([]byte(nil), e.ticket.EncPart.Cipher...)
		e.flags.Bytes = append([]byte(nil), info.Flags.Bytes...)
		if e.start.IsZero() {
			e.start = info.AuthTime
		}
		entries = append(entries, e)
		if !validateEntry(e) || len(info.CAddr) > 0 || (info.SRealm != "" && info.SRealm != e.ticket.Realm) || (len(info.SName.NameString) > 0 && !info.SName.Equal(e.ticket.SName)) {
			return entries, errFile
		}
	}
	return entries, nil
}

type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if n < 0 || n > len(r.b) {
		r.err = errFile
		return nil
	}
	b := r.b[:n]
	r.b = r.b[n:]
	return b
}
func (r *reader) u16() uint16 {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}
func (r *reader) u32() uint32 {
	b := r.take(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
func (r *reader) data(max int) []byte {
	n := r.u32()
	if uint64(n) > uint64(max) {
		r.err = errFile
		return nil
	}
	return r.take(int(n))
}
func (r *reader) principal() (types.PrincipalName, string) {
	p := types.PrincipalName{NameType: int32(r.u32())}
	n := r.u32()
	if n > 16 {
		r.err = errFile
		return p, ""
	}
	realm := string(r.data(1024))
	for i := uint32(0); i < n; i++ {
		p.NameString = append(p.NameString, string(r.data(1024)))
	}
	return p, realm
}
func (r *reader) fields() uint32 {
	n := r.u32()
	if n > 256 {
		r.err = errFile
		return 0
	}
	for i := uint32(0); i < n; i++ {
		r.u16()
		r.data(65535)
	}
	return n
}
func parseCCache(b []byte) (entries []entry, err error) {
	defer func() {
		if err != nil {
			wipeEntries(entries)
			entries = nil
		}
	}()
	if len(b) < 4 || b[0] != 5 || (b[1] != 3 && b[1] != 4) {
		return nil, errFile
	}
	r := reader{b: b[2:]}
	if b[1] == 4 {
		h := reader{b: r.take(int(r.u16()))}
		for len(h.b) > 0 && h.err == nil {
			h.u16()
			h.take(int(h.u16()))
		}
		if h.err != nil {
			return nil, errFile
		}
	}
	def, realm := r.principal()
	if !validPrincipal(def) || !validText(realm) {
		return nil, errFile
	}
	for len(r.b) > 0 && r.err == nil {
		if len(entries) >= 256 {
			return entries, errFile
		}
		p, pr := r.principal()
		sp, sr := r.principal()
		kt := r.u16()
		if b[1] == 3 {
			if r.u16() != kt {
				return entries, errFile
			}
		}
		key := r.data(64)
		auth := r.u32()
		start := r.u32()
		end := r.u32()
		r.u32()
		skey := r.take(1)
		fl := append([]byte(nil), r.take(4)...)
		addresses := r.fields()
		r.fields()
		ticket := r.data(65535)
		second := r.data(65535)
		if r.err != nil {
			return entries, errFile
		}
		if sr == "X-CACHECONF:" && len(sp.NameString) > 0 && sp.NameString[0] == "krb5_ccache_conf_data" {
			continue
		}
		if len(skey) != 1 || skey[0] != 0 || len(second) > 0 || addresses > 0 || !p.Equal(def) || pr != realm || !checkDER(ticket) {
			return entries, errFile
		}
		var t messages.Ticket
		if t.Unmarshal(ticket) != nil || !t.SName.Equal(sp) || t.Realm != sr {
			return entries, errFile
		}
		if start == 0 {
			start = auth
		}
		e := entry{client: p, realm: pr, ticket: t, key: types.EncryptionKey{KeyType: int32(kt), KeyValue: append([]byte(nil), key...)}, start: time.Unix(int64(start), 0), end: time.Unix(int64(end), 0), flags: asn1.BitString{Bytes: fl, BitLength: 32}}
		e.ticket.EncPart.Cipher = append([]byte(nil), t.EncPart.Cipher...)
		entries = append(entries, e)
		if !validateEntry(e) {
			return entries, errFile
		}
	}
	if r.err != nil || len(entries) == 0 {
		return entries, errFile
	}
	return entries, nil
}

func sameIdentity(a, b entry) bool { return a.realm == b.realm && a.client.Equal(b.client) }
func identity(e entry) string      { return strings.Join(e.client.NameString, "/") + "@" + e.realm }

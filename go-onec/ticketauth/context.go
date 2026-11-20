package ticketauth

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

var kerberosOID = asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}
var errProof = errors.New("Kerberos server proof rejected")

// Options pins one service principal in the credential's realm. KDC is optional
// and used only when a service ticket must be obtained from a TGT.
type Options struct{ File, SPN, KDC string }

func Validate(o Options) error {
	if o.File == "" || !validText(o.SPN) || strings.ContainsAny(o.SPN, "@\\ ") {
		return errors.New("ticket authentication requires a file and an explicit service/host SPN")
	}
	parts := strings.Split(o.SPN, "/")
	if len(parts) < 2 || len(parts) > 3 {
		return errors.New("invalid Kerberos SPN")
	}
	for _, p := range parts {
		if p == "" {
			return errors.New("invalid Kerberos SPN")
		}
	}
	if strings.EqualFold(parts[0], "krbtgt") {
		return errors.New("a TGT is not an application service SPN")
	}
	if o.KDC != "" {
		host, port, err := net.SplitHostPort(o.KDC)
		p, pe := strconv.Atoi(port)
		if err != nil || pe != nil || host == "" || strings.Contains(host, ":") || p < 1 || p > 65535 {
			return errors.New("KDC must be an explicit IPv4 host:port")
		}
	}
	return nil
}

// Context owns private copies of file credentials. Use a fresh Context for each
// transport or inner authentication exchange, then Close it even after failure.
// A Context is not safe for concurrent use. Erasure is best-effort in managed
// memory; dependencies and the runtime can retain copies outside its control.
type Context struct {
	opts     Options
	entries  []entry
	selected int
	key      types.EncryptionKey
	ctime    time.Time
	cusec    int
	state    int // 0 initial, 1 awaiting proof, 2 complete, 3 failed/closed
}

func (c *Context) String() string   { return "Kerberos context (credentials redacted)" }
func (c *Context) GoString() string { return c.String() }
func New(o Options) (*Context, error) {
	if err := Validate(o); err != nil {
		return nil, err
	}
	entries, err := readFile(o.File)
	if err != nil {
		return nil, err
	}
	c := &Context{opts: o, entries: entries, selected: -1}
	for _, e := range entries {
		if !sameIdentity(e, entries[0]) {
			c.Close()
			return nil, errors.New("mixed client identities in credential file")
		}
	}
	for i, e := range entries {
		if usable(e, time.Now()) && e.ticket.Realm == e.realm && e.ticket.SName.Equal(types.NewPrincipalName(2, o.SPN)) {
			if c.selected < 0 || e.end.After(entries[c.selected].end) {
				c.selected = i
			}
		}
	}
	if c.selected < 0 {
		if o.KDC == "" {
			c.Close()
			return nil, errors.New("no valid ticket for the exact SPN; a TGT requires an explicit KDC")
		}
		for i, e := range entries {
			if usable(e, time.Now()) && e.ticket.Realm == e.realm && e.ticket.SName.Equal(types.PrincipalName{NameType: 2, NameString: []string{"krbtgt", e.realm}}) {
				if c.selected < 0 || e.end.After(entries[c.selected].end) {
					c.selected = i
				}
			}
		}
	}
	if c.selected < 0 {
		c.Close()
		return nil, errors.New("no usable same-realm service ticket or TGT")
	}
	return c, nil
}
func usable(e entry, now time.Time) bool {
	return !now.Before(e.start) && now.Before(e.end) && e.flags.At(7) == 0
}
func (c *Context) Name() (string, error) {
	if c.state == 3 {
		return "", errors.New("Kerberos context is closed")
	}
	return identity(c.entries[c.selected]), nil
}

// Mechanism reports a cryptographically established context, not a proposed mechanism.
func (c *Context) Mechanism() (string, error) {
	if c.state != 2 {
		return "", errors.New("Kerberos context is not established")
	}
	return "Kerberos", nil
}
func (c *Context) Close() error {
	if c == nil {
		return nil
	}
	wipeEntries(c.entries)
	c.entries = nil
	clear(c.key.KeyValue)
	c.key = types.EncryptionKey{}
	c.state = 3
	return nil
}
func (c *Context) Step(target string, input []byte) ([]byte, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return c.StepContext(ctx, target, input)
}

// StepContext emits only a fresh Kerberos GSS token. There is no NTLM fallback,
// delegation, OS-cache access or replay of a captured AP-REQ.
func (c *Context) StepContext(ctx context.Context, _ string, input []byte) (output []byte, complete bool, err error) {
	defer func() {
		if recover() != nil {
			err = errProof
		}
		if err != nil {
			clear(output)
			output = nil
			complete = false
			c.Close()
		}
	}()
	if err = ctx.Err(); err != nil {
		return
	}
	if c.state == 0 {
		if len(input) != 0 {
			return nil, false, errProof
		}
		e := c.entries[c.selected]
		if !usable(e, time.Now()) {
			return nil, false, errors.New("Kerberos credential expired or not yet valid")
		}
		if !e.ticket.SName.Equal(types.NewPrincipalName(2, c.opts.SPN)) {
			e, err = c.serviceTicket(ctx, e)
			if err != nil {
				return
			}
			c.entries = append(c.entries, e)
		}
		c.key = types.EncryptionKey{KeyType: e.key.KeyType, KeyValue: append([]byte(nil), e.key.KeyValue...)}
		a, err := types.NewAuthenticator(e.realm, e.client)
		if err != nil {
			return nil, false, errors.New("cannot create Kerberos authenticator")
		}
		// RFC 4121: no channel binding supplied; mutual/replay/sequence/integrity/confidentiality, no delegation.
		checksum := make([]byte, 24)
		binary.LittleEndian.PutUint32(checksum[:4], 16)
		binary.LittleEndian.PutUint32(checksum[20:], 0x3e)
		a.Cksum = types.Checksum{CksumType: 0x8003, Checksum: checksum}
		c.ctime = a.CTime.Truncate(time.Second)
		c.cusec = a.Cusec
		req, err := messages.NewAPReq(e.ticket, e.key, a)
		if err != nil {
			return nil, false, errors.New("cannot encrypt Kerberos authenticator")
		}
		types.SetFlag(&req.APOptions, 2) // mutual-required
		body, err := req.Marshal()
		if err != nil {
			return nil, false, errors.New("cannot encode Kerberos request")
		}
		output, err = wrapGSS(body, 1)
		if err != nil || len(output) > 65535 {
			return nil, false, errors.New("Kerberos request exceeds native token bounds")
		}
		c.state = 1
		return output, false, nil
	}
	if c.state != 1 || len(input) == 0 || len(input) > 65535 {
		return nil, false, errProof
	}
	body, err := unwrapGSS(input, 2)
	if err != nil {
		return nil, false, errProof
	}
	var rep messages.APRep
	if rep.Unmarshal(body) != nil || rep.PVNO != 5 || rep.EncPart.EType != c.key.KeyType {
		return nil, false, errProof
	}
	plain, err := crypto.DecryptEncPart(rep.EncPart, c.key, 12)
	if err != nil {
		return nil, false, errProof
	}
	defer clear(plain)
	var part messages.EncAPRepPart
	if !checkDER(plain) || part.Unmarshal(plain) != nil {
		return nil, false, errProof
	}
	defer clear(part.Subkey.KeyValue)
	if !part.CTime.Equal(c.ctime) || part.Cusec != c.cusec {
		return nil, false, errProof
	}
	clear(c.key.KeyValue)
	c.key = types.EncryptionKey{}
	wipeEntries(c.entries)
	c.state = 2
	return nil, true, nil
}
func wrapGSS(body []byte, id byte) ([]byte, error) {
	oid, err := asn1.Marshal(kerberosOID)
	if err != nil {
		return nil, err
	}
	payload := append(oid, id, 0)
	payload = append(payload, body...)
	return asn1.Marshal(asn1.RawValue{Class: 1, Tag: 0, IsCompound: true, Bytes: payload})
}
func unwrapGSS(b []byte, id byte) ([]byte, error) {
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(b, &outer)
	if err != nil || len(rest) != 0 || outer.Class != 1 || outer.Tag != 0 || !outer.IsCompound {
		return nil, errProof
	}
	var oid asn1.ObjectIdentifier
	data, err := asn1.Unmarshal(outer.Bytes, &oid)
	if err != nil || !oid.Equal(kerberosOID) || len(data) < 3 || data[0] != id || data[1] != 0 || !checkDER(data[2:]) {
		return nil, errProof
	}
	return data[2:], nil
}

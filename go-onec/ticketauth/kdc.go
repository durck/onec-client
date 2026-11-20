package ticketauth

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"time"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// One same-realm TGS request to an explicitly configured KDC. No AS exchange,
// password, renewal, referrals, S4U, DNS discovery or cache writes are performed.
func (c *Context) serviceTicket(ctx context.Context, tgt entry) (entry, error) {
	cfg := config.New()
	cfg.LibDefaults.DefaultTGSEnctypeIDs = []int32{18, 17}
	cfg.LibDefaults.Forwardable = false
	cfg.LibDefaults.Proxiable = false
	cfg.LibDefaults.Canonicalize = false
	cfg.LibDefaults.RenewLifetime = 0
	cfg.LibDefaults.NoAddresses = true
	cfg.LibDefaults.TicketLifetime = time.Until(tgt.end)
	spn := types.NewPrincipalName(2, c.opts.SPN)
	req, err := messages.NewTGSReq(tgt.client, tgt.realm, cfg, tgt.ticket, tgt.key, spn, false)
	if err != nil {
		return entry{}, errors.New("cannot construct TGS request")
	}
	request, err := req.Marshal()
	if err != nil {
		return entry{}, errors.New("cannot encode TGS request")
	}
	defer clear(request)
	response, err := exchangeKDC(ctx, c.opts.KDC, request)
	if err != nil {
		return entry{}, err
	}
	defer clear(response)
	if !checkDER(response) {
		return entry{}, errors.New("invalid bounded KDC response")
	}
	var rep messages.TGSRep
	if rep.Unmarshal(response) != nil {
		var kerr messages.KRBError
		if kerr.Unmarshal(response) == nil {
			return entry{}, fmt.Errorf("KDC rejected TGS request (code %d)", kerr.ErrorCode)
		}
		return entry{}, errors.New("invalid TGS response")
	}
	if rep.EncPart.EType != tgt.key.KeyType {
		return entry{}, errors.New("unexpected TGS reply encryption type")
	}
	plain, err := crypto.DecryptEncPart(rep.EncPart, tgt.key, 8)
	if err != nil {
		return entry{}, errors.New("TGS response decryption failed")
	}
	defer clear(plain)
	if !checkDER(plain) || rep.DecryptedEncPart.Unmarshal(plain) != nil {
		return entry{}, errors.New("invalid TGS encrypted response")
	}
	part := rep.DecryptedEncPart
	defer clear(part.Key.KeyValue)
	// Upstream Verify omits the requested service-name checks; enforce both here.
	ok, verifyErr := rep.Verify(cfg, req)
	if !ok || verifyErr != nil || rep.PVNO != 5 || rep.CRealm != tgt.realm || !rep.Ticket.SName.Equal(spn) || !part.SName.Equal(spn) || rep.Ticket.Realm != tgt.realm || part.SRealm != tgt.realm || part.EndTime.After(tgt.end) || part.EndTime.After(req.ReqBody.Till.Add(time.Second)) {
		return entry{}, errors.New("TGS response identity, nonce, service or lifetime mismatch")
	}
	e := entry{client: rep.CName, realm: rep.CRealm, ticket: rep.Ticket, key: types.EncryptionKey{KeyType: part.Key.KeyType, KeyValue: append([]byte(nil), part.Key.KeyValue...)}, start: part.StartTime, end: part.EndTime, flags: part.Flags}
	e.ticket.EncPart.Cipher = append([]byte(nil), rep.Ticket.EncPart.Cipher...)
	e.flags.Bytes = append([]byte(nil), part.Flags.Bytes...)
	if e.start.IsZero() {
		e.start = part.AuthTime
	}
	if !validateEntry(e) || !usable(e, time.Now()) || len(part.CAddr) > 0 || !slices.Contains(req.ReqBody.EType, e.key.KeyType) {
		e.wipe()
		return entry{}, errors.New("unusable TGS credential")
	}
	return e, nil
}
func exchangeKDC(ctx context.Context, address string, request []byte) ([]byte, error) {
	if len(request) == 0 || len(request) > maxFile {
		return nil, errors.New("KDC request size limit")
	}
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp4", address)
	if err != nil {
		return nil, errors.New("KDC connection failed")
	}
	defer conn.Close()
	deadline := time.Now().Add(15 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if conn.SetDeadline(deadline) != nil {
		return nil, errors.New("KDC deadline failed")
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	frame := make([]byte, 4+len(request))
	defer clear(frame)
	binary.BigEndian.PutUint32(frame, uint32(len(request)))
	copy(frame[4:], request)
	for offset := 0; offset < len(frame); {
		n, e := conn.Write(frame[offset:])
		if e != nil || n == 0 {
			return nil, errors.New("KDC request write failed")
		}
		offset += n
	}
	var length [4]byte
	if _, err = io.ReadFull(conn, length[:]); err != nil {
		return nil, errors.New("KDC response read failed")
	}
	n := binary.BigEndian.Uint32(length[:])
	if n == 0 || n > maxFile {
		return nil, errors.New("KDC response size limit")
	}
	response := make([]byte, int(n))
	if _, err = io.ReadFull(conn, response); err != nil {
		clear(response)
		return nil, errors.New("truncated KDC response")
	}
	return response, nil
}

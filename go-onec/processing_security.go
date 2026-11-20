package onec

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"onec/wire"
	"strings"
)

// ProcessingSecurityError is the server's interactive confirmation challenge
// for opening an external processing file. It is distinct from a rights denial.
// No approval or operation replay occurs automatically.
type ProcessingSecurityError struct {
	owner     *Client
	signature string
	digest    [32]byte
	attempted *bool // Shared by copies, protected by owner.mu.
}

func (*ProcessingSecurityError) Error() string {
	return "server requires explicit confirmation to open this external processing file"
}
func (e *ProcessingSecurityError) String() string   { return e.Error() }
func (e *ProcessingSecurityError) GoString() string { return e.Error() }
func (*ProcessingSecurityError) Unwrap() error {
	return &StatusError{Operation: "processing security confirmation", Status: 400}
}
func (e *ProcessingSecurityError) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"error": e.Error(), "epf_sha256": e.EPFSHA256()})
}

// EPFSHA256 identifies the exact upload bytes that triggered the challenge.
// It is not the platform's opaque module signature.
func (e *ProcessingSecurityError) EPFSHA256() string { return hex.EncodeToString(e.digest[:]) }

func (c *Client) processingUploadError(h *wire.HTTP, epf []byte, operation string) error {
	fallback := &StatusError{Operation: operation, Status: h.Status}
	if h.Status != 400 {
		return fallback
	}
	types := h.Header("content-type")
	if len(types) != 1 || !strings.EqualFold(strings.TrimSpace(strings.Split(types[0], ";")[0]), "application/json") {
		return fallback
	}
	body, err := decodeBody(h, 64*1024)
	if err != nil {
		return fallback
	}
	doc, err := strictJSON(body)
	if err != nil {
		return fallback
	}
	exception, ok := doc["exception"].(map[string]any)
	if !ok || !strings.EqualFold(snapshotString(exception, "clsid"), "330CDBE8-FFEF-47E5-B574-38A1BA2368A6") {
		return fallback
	}
	operationType, ok := exception["operationType"].(json.Number)
	if !ok || operationType.String() != "2" {
		return fallback
	}
	if _, ok := exception["commandCouldNotRestart"].(bool); !ok {
		return fallback
	}
	signature, ok := exception["moduleSignature"].(string)
	if !ok || len(signature) != 28 {
		return fallback
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(signature)
	if err != nil || len(decoded) != 20 {
		return fallback
	}
	return &ProcessingSecurityError{owner: c, signature: signature, digest: sha256.Sum256(epf), attempted: new(bool)}
}

// ConfirmProcessingSecurity explicitly accepts this session's server challenge
// for the exact uploaded EPF. The platform may retain the decision beyond this
// connection. It does not disable safe mode, alter user roles, or open a form.
// Callers must obtain approval for the identified file before calling this
// method, then explicitly upload that same file again if confirmation succeeds.
// Failure has an unknown outcome and cannot be retried with this challenge.
func (c *Client) ConfirmProcessingSecurity(ctx context.Context, challenge *ProcessingSecurityError) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.applicationReady(); err != nil {
		return err
	}
	if challenge == nil || challenge.owner != c || challenge.attempted == nil || *challenge.attempted {
		return errors.New("a fresh processing security challenge from this client is required")
	}
	// Shipped mh/$g uses an unwrapped ordered JSON object and no sync pragma.
	body, err := json.Marshal(struct {
		Sign string `json:"sign"`
		Oper int    `json:"oper"`
	}{challenge.signature, 2})
	if err != nil {
		return errors.New("cannot encode processing security confirmation")
	}
	pdu, err := c.pdu("POST", "/e1cib/opersec/insert", body,
		"application/json; charset=utf-8", "application/json", c.session.raw, 0)
	if err != nil {
		return err
	}
	*challenge.attempted = true
	h, err := c.exchangeHTTP(ctx, pdu)
	if err != nil {
		return err
	}
	if h.Status != 200 && h.Status != 201 && h.Status != 204 {
		return &StatusError{Operation: "processing security confirmation", Status: h.Status}
	}
	body, err = decodeBody(h, wire.MaxFile)
	if err != nil {
		return err
	}
	if len(body) != 0 {
		doc, err := strictJSON(body)
		if err != nil {
			return errors.New("unsupported processing confirmation response")
		}
		if _, ok := doc["exception"]; ok {
			return errors.New("processing confirmation returned an application exception")
		}
	}
	return nil
}
